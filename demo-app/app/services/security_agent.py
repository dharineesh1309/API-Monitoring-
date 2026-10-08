"""Read-only AWS security assessment with explicitly approved remediation.

The agent scans only the AWS resources configured for this CentralWatch
deployment. A scan never mutates AWS. Remediation is allowlisted, idempotent,
disabled by default, and requires a recent scan plus an exact acknowledgement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

from botocore.exceptions import ClientError

from ..config.settings import Settings
from ..telemetry.logging import get_logger
from ..utils.aws import make_client

logger = get_logger(__name__)

ACKNOWLEDGEMENT = "APPLY_SELECTED_REMEDIATIONS"

RISK_DESCRIPTIONS = {
    "s3_public_access": (
        "Without a complete public access block, bucket data could be exposed through "
        "a public ACL or bucket policy."
    ),
    "s3_default_encryption": (
        "New objects could be stored without explicit server-side encryption, increasing "
        "the impact of unauthorized storage access."
    ),
    "s3_versioning": (
        "Accidental deletion, overwrite, or malicious modification could be difficult to recover."
    ),
    "dynamodb_pitr": (
        "Accidental deletion, corruption, or unauthorized changes could cause permanent data loss."
    ),
    "sqs_encryption": (
        "Queued message payloads could remain readable at rest if the storage layer is accessed."
    ),
    "sns_encryption": (
        "Notification payloads are not protected by KMS encryption at rest."
    ),
    "lambda_tracing": (
        "Reduced request visibility can delay incident detection and make forensic investigation harder."
    ),
}


class AwsSecurityAgent:
    """Assess the configured AWS resources and apply selected baseline fixes."""

    def __init__(self, session, settings: Settings, metrics) -> None:
        self.session = session
        self.settings = settings
        self.metrics = metrics
        self._scans: dict[str, dict[str, Any]] = {}
        self._latest_scan_id: str | None = None
        self._lock = RLock()

    def scan(self) -> dict[str, Any]:
        """Run the minimum-security baseline without changing AWS state."""

        with self._lock:
            findings: list[dict[str, Any]] = []
            findings.extend(self._scan_s3())
            findings.extend(self._scan_dynamodb())
            findings.extend(self._scan_sqs())
            findings.extend(self._scan_sns())
            findings.extend(self._scan_lambda())

            summary = {
                "total": len(findings),
                "passed": sum(item["status"] == "pass" for item in findings),
                "failed": sum(item["status"] == "fail" for item in findings),
                "unavailable": sum(item["status"] == "unavailable" for item in findings),
                "errors": sum(item["status"] == "error" for item in findings),
                "remediable": sum(
                    item["status"] == "fail" and item["remediable"] for item in findings
                ),
            }
            result = {
                "scan_id": f"scan_{uuid4().hex}",
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "environment": self.settings.environment,
                "region": self.settings.aws_region,
                "scope": "Configured CentralWatch AWS resources",
                "remediation_enabled": self.settings.aws_security_agent_allow_remediation,
                "summary": summary,
                "findings": findings,
            }
            self._scans[result["scan_id"]] = result
            self._latest_scan_id = result["scan_id"]
            while len(self._scans) > 20:
                self._scans.pop(next(iter(self._scans)))

            self.metrics.security_scans.add(
                1,
                {
                    "environment": self.settings.environment,
                    "result": "findings" if summary["failed"] else "pass",
                },
            )
            logger.info(
                "AWS security scan complete: scan_id=%s passed=%d failed=%d unavailable=%d errors=%d",
                result["scan_id"],
                summary["passed"],
                summary["failed"],
                summary["unavailable"],
                summary["errors"],
            )
            return result

    def latest_scan(self) -> dict[str, Any] | None:
        with self._lock:
            return self._scans.get(self._latest_scan_id) if self._latest_scan_id else None

    def remediate(
        self,
        scan_id: str,
        finding_ids: list[str],
        confirm: bool,
        acknowledgement: str,
    ) -> dict[str, Any]:
        """Apply only selected fixes after every permission gate is satisfied."""

        if not self.settings.aws_security_agent_allow_remediation:
            raise PermissionError(
                "AWS remediation is disabled by server policy. Set "
                "AWS_SECURITY_AGENT_ALLOW_REMEDIATION=true only after approval."
            )
        if not confirm or acknowledgement != ACKNOWLEDGEMENT:
            raise PermissionError(
                f"Explicit confirmation is required. acknowledgement must be {ACKNOWLEDGEMENT}."
            )

        with self._lock:
            source_scan = self._scans.get(scan_id)
            if not source_scan:
                raise LookupError("The referenced scan is unavailable. Run a new scan before remediation.")

            selected_ids = list(dict.fromkeys(finding_ids))
            available = {item["finding_id"]: item for item in source_scan["findings"]}
            invalid = [finding_id for finding_id in selected_ids if finding_id not in available]
            if invalid:
                raise ValueError(f"Unknown finding IDs: {', '.join(invalid)}")

            selected = [available[finding_id] for finding_id in selected_ids]
            not_actionable = [
                item["finding_id"]
                for item in selected
                if item["status"] != "fail" or not item["remediable"]
            ]
            if not_actionable:
                raise ValueError(
                    "Only failed, remediable findings can be applied: " + ", ".join(not_actionable)
                )

            handlers: dict[str, Callable[[dict[str, Any]], None]] = {
                "s3_public_access": self._fix_s3_public_access,
                "s3_default_encryption": self._fix_s3_encryption,
                "s3_versioning": self._fix_s3_versioning,
                "dynamodb_pitr": self._fix_dynamodb_pitr,
                "sqs_encryption": self._fix_sqs_encryption,
                "sns_encryption": self._fix_sns_encryption,
                "lambda_tracing": self._fix_lambda_tracing,
            }
            actions: list[dict[str, str]] = []
            for finding in selected:
                try:
                    handlers[finding["check_id"]](finding)
                    action_status = "applied"
                    message = "Baseline configuration applied."
                    logger.warning(
                        "AWS security remediation applied: finding_id=%s service=%s resource=%s",
                        finding["finding_id"],
                        finding["service"],
                        finding["resource"],
                    )
                except Exception as exc:  # noqa: BLE001
                    action_status = "failed"
                    message = self._error_message(exc)
                    logger.exception(
                        "AWS security remediation failed: finding_id=%s service=%s resource=%s",
                        finding["finding_id"],
                        finding["service"],
                        finding["resource"],
                    )
                actions.append(
                    {
                        "finding_id": finding["finding_id"],
                        "service": finding["service"],
                        "resource": finding["resource"],
                        "status": action_status,
                        "message": message,
                    }
                )
                self.metrics.security_remediations.add(
                    1,
                    {
                        "service": finding["service"],
                        "check_id": finding["check_id"],
                        "status": action_status,
                    },
                )

            return {"source_scan_id": scan_id, "actions": actions, "scan": self.scan()}

    def _scan_s3(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "s3", self.settings)
        bucket = self.settings.s3_bucket
        findings: list[dict[str, Any]] = []

        try:
            config = client.get_public_access_block(Bucket=bucket).get(
                "PublicAccessBlockConfiguration", {}
            )
            keys = (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
            enabled = all(config.get(key) is True for key in keys)
            findings.append(
                self._finding(
                    "s3_public_access",
                    "S3",
                    bucket,
                    "Block all public S3 access",
                    "high",
                    enabled,
                    str(config or "not configured"),
                    "All four S3 Public Access Block controls enabled",
                    "Prevents public ACLs and bucket policies on the application bucket.",
                    "Enable all S3 Public Access Block controls.",
                )
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
                findings.append(
                    self._finding(
                        "s3_public_access", "S3", bucket, "Block all public S3 access", "high",
                        False, "not configured", "All four S3 Public Access Block controls enabled",
                        "The bucket does not have a complete public access block.",
                        "Enable all S3 Public Access Block controls.",
                    )
                )
            else:
                findings.append(self._error_finding("s3_public_access", "S3", bucket, "Block all public S3 access", "high", exc))

        try:
            rules = client.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
            algorithms = [
                rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
                for rule in rules
            ]
            enabled = any(value in {"AES256", "aws:kms"} for value in algorithms)
            findings.append(
                self._finding(
                    "s3_default_encryption", "S3", bucket, "Encrypt new S3 objects", "high",
                    enabled, ", ".join(filter(None, algorithms)) or "not configured",
                    "AES256 or AWS KMS default bucket encryption",
                    "Default encryption protects newly stored files and images at rest.",
                    "Enable default AES256 server-side encryption.",
                )
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchConfiguration"}:
                findings.append(
                    self._finding(
                        "s3_default_encryption", "S3", bucket, "Encrypt new S3 objects", "high",
                        False, "not configured", "AES256 or AWS KMS default bucket encryption",
                        "The bucket has no explicit default encryption configuration.",
                        "Enable default AES256 server-side encryption.",
                    )
                )
            else:
                findings.append(self._error_finding("s3_default_encryption", "S3", bucket, "Encrypt new S3 objects", "high", exc))

        try:
            status = client.get_bucket_versioning(Bucket=bucket).get("Status", "Disabled")
            findings.append(
                self._finding(
                    "s3_versioning", "S3", bucket, "Enable S3 versioning", "medium",
                    status == "Enabled", status, "Enabled",
                    "Versioning improves recovery from accidental overwrite or deletion.",
                    "Enable versioning on the application bucket.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(self._error_finding("s3_versioning", "S3", bucket, "Enable S3 versioning", "medium", exc))
        return findings

    def _scan_dynamodb(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "dynamodb", self.settings)
        findings: list[dict[str, Any]] = []
        for table in (
            self.settings.dynamodb_users_table,
            self.settings.dynamodb_orders_table,
            self.settings.dynamodb_files_table,
        ):
            try:
                response = client.describe_continuous_backups(TableName=table)
                status = response.get("ContinuousBackupsDescription", {}).get(
                    "PointInTimeRecoveryDescription", {}
                ).get("PointInTimeRecoveryStatus", "DISABLED")
                findings.append(
                    self._finding(
                        "dynamodb_pitr", "DynamoDB", table, "Enable point-in-time recovery", "medium",
                        status == "ENABLED", status, "ENABLED",
                        "Point-in-time recovery protects application records from accidental changes.",
                        "Enable point-in-time recovery for this table.",
                    )
                )
            except Exception as exc:  # noqa: BLE001
                findings.append(self._error_finding("dynamodb_pitr", "DynamoDB", table, "Enable point-in-time recovery", "medium", exc))
        return findings

    def _scan_sqs(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "sqs", self.settings)
        queue = self.settings.sqs_queue
        try:
            url = client.get_queue_url(QueueName=queue)["QueueUrl"]
            attributes = client.get_queue_attributes(
                QueueUrl=url,
                AttributeNames=["SqsManagedSseEnabled", "KmsMasterKeyId"],
            ).get("Attributes", {})
            enabled = (
                attributes.get("SqsManagedSseEnabled", "false").lower() == "true"
                or bool(attributes.get("KmsMasterKeyId"))
            )
            current = attributes.get("KmsMasterKeyId") or attributes.get("SqsManagedSseEnabled", "false")
            return [
                self._finding(
                    "sqs_encryption", "SQS", queue, "Encrypt SQS messages", "high",
                    enabled, current, "SQS-managed SSE or AWS KMS",
                    "Server-side encryption protects queued message bodies at rest.",
                    "Enable SQS-managed server-side encryption.",
                )
            ]
        except Exception as exc:  # noqa: BLE001
            return [self._error_finding("sqs_encryption", "SQS", queue, "Encrypt SQS messages", "high", exc)]

    def _scan_sns(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "sns", self.settings)
        topic = self.settings.sns_topic
        try:
            arn = self._find_topic_arn(client, topic)
            attributes = client.get_topic_attributes(TopicArn=arn).get("Attributes", {})
            key_id = attributes.get("KmsMasterKeyId", "")
            return [
                self._finding(
                    "sns_encryption", "SNS", topic, "Encrypt SNS messages", "high",
                    bool(key_id), key_id or "not configured", "AWS managed SNS KMS key",
                    "Topic encryption protects notification payloads at rest.",
                    "Enable encryption with alias/aws/sns.",
                )
            ]
        except Exception as exc:  # noqa: BLE001
            return [self._error_finding("sns_encryption", "SNS", topic, "Encrypt SNS messages", "high", exc)]

    def _scan_lambda(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "lambda", self.settings)
        function = self.settings.lambda_function
        try:
            config = client.get_function_configuration(FunctionName=function)
            mode = config.get("TracingConfig", {}).get("Mode", "PassThrough")
            return [
                self._finding(
                    "lambda_tracing", "Lambda", function, "Enable Lambda active tracing", "low",
                    mode == "Active", mode, "Active",
                    "Active tracing provides an audit trail for the image-processing function.",
                    "Enable active AWS X-Ray tracing for the function.",
                )
            ]
        except Exception as exc:  # noqa: BLE001
            return [self._error_finding("lambda_tracing", "Lambda", function, "Enable Lambda active tracing", "low", exc)]

    def _finding(
        self,
        check_id: str,
        service: str,
        resource: str,
        title: str,
        severity: str,
        passed: bool,
        current_value: str,
        desired_value: str,
        description: str,
        remediation: str,
    ) -> dict[str, Any]:
        return {
            "finding_id": f"{check_id}:{resource}",
            "check_id": check_id,
            "service": service,
            "resource": resource,
            "title": title,
            "severity": severity,
            "status": "pass" if passed else "fail",
            "description": description,
            "risk": RISK_DESCRIPTIONS[check_id],
            "current_value": str(current_value),
            "desired_value": desired_value,
            "remediation": remediation,
            "remediable": not passed,
            "requires_confirmation": not passed,
        }

    def _error_finding(
        self,
        check_id: str,
        service: str,
        resource: str,
        title: str,
        severity: str,
        exc: Exception,
    ) -> dict[str, Any]:
        message = self._error_message(exc)
        unavailable = self._is_unsupported(exc)
        return {
            "finding_id": f"{check_id}:{resource}",
            "check_id": check_id,
            "service": service,
            "resource": resource,
            "title": title,
            "severity": severity,
            "status": "unavailable" if unavailable else "error",
            "description": "This check is not supported by the current AWS-compatible endpoint." if unavailable else "AWS did not return a usable assessment result.",
            "risk": RISK_DESCRIPTIONS[check_id],
            "current_value": message,
            "desired_value": "Check completes successfully",
            "remediation": "Review the endpoint capability and IAM read permissions before making changes.",
            "remediable": False,
            "requires_confirmation": False,
        }

    @staticmethod
    def _is_unsupported(exc: Exception) -> bool:
        if isinstance(exc, ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            return code in {"NotImplemented", "UnsupportedOperation", "UnknownOperationException"} or status == 501
        return isinstance(exc, NotImplementedError)

    @staticmethod
    def _error_message(exc: Exception) -> str:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            return f"{error.get('Code', 'ClientError')}: {error.get('Message', str(exc))}"
        return f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _find_topic_arn(client, topic_name: str) -> str:
        paginator = client.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                arn = topic.get("TopicArn", "")
                if arn.rsplit(":", 1)[-1] == topic_name:
                    return arn
        raise LookupError(f"SNS topic not found: {topic_name}")

    def _fix_s3_public_access(self, finding: dict[str, Any]) -> None:
        make_client(self.session, "s3", self.settings).put_public_access_block(
            Bucket=finding["resource"],
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

    def _fix_s3_encryption(self, finding: dict[str, Any]) -> None:
        make_client(self.session, "s3", self.settings).put_bucket_encryption(
            Bucket=finding["resource"],
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

    def _fix_s3_versioning(self, finding: dict[str, Any]) -> None:
        make_client(self.session, "s3", self.settings).put_bucket_versioning(
            Bucket=finding["resource"],
            VersioningConfiguration={"Status": "Enabled"},
        )

    def _fix_dynamodb_pitr(self, finding: dict[str, Any]) -> None:
        make_client(self.session, "dynamodb", self.settings).update_continuous_backups(
            TableName=finding["resource"],
            PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
        )

    def _fix_sqs_encryption(self, finding: dict[str, Any]) -> None:
        client = make_client(self.session, "sqs", self.settings)
        url = client.get_queue_url(QueueName=finding["resource"])["QueueUrl"]
        client.set_queue_attributes(
            QueueUrl=url,
            Attributes={"SqsManagedSseEnabled": "true"},
        )

    def _fix_sns_encryption(self, finding: dict[str, Any]) -> None:
        client = make_client(self.session, "sns", self.settings)
        arn = self._find_topic_arn(client, finding["resource"])
        client.set_topic_attributes(
            TopicArn=arn,
            AttributeName="KmsMasterKeyId",
            AttributeValue="alias/aws/sns",
        )

    def _fix_lambda_tracing(self, finding: dict[str, Any]) -> None:
        make_client(self.session, "lambda", self.settings).update_function_configuration(
            FunctionName=finding["resource"],
            TracingConfig={"Mode": "Active"},
        )

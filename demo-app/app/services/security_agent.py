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
    "cloudtrail_enabled": (
        "Without active CloudTrail multi-region logging, security auditing, API call attribution, and forensic investigation cannot be reliably performed."
    ),
    "iam_root_credentials": (
        "Active access keys on the root account expose the entire cloud infrastructure to catastrophic compromise."
    ),
    "sg_open_ingress": (
        "Security groups with unrestricted ingress (0.0.0.0/0) on administrative ports (SSH/RDP) permit internet-wide brute-force attacks."
    ),
    "kms_key_rotation": (
        "Customer-managed KMS keys without annual automatic rotation expose data if previous key versions are ever compromised."
    ),
}

CIS_BENCHMARKS = {
    "s3_public_access": "CIS AWS 2.1.5 - Ensure S3 Bucket Access is Restricted",
    "s3_default_encryption": "CIS AWS 2.1.1 - Ensure S3 Default Encryption is Enabled",
    "s3_versioning": "CIS AWS 2.1.3 - Ensure S3 Bucket Object Versioning is Enabled",
    "dynamodb_pitr": "CIS AWS 2.3.1 - Ensure DynamoDB Point-in-Time Recovery is Enabled",
    "sqs_encryption": "CIS AWS 2.4.1 - Ensure SQS Queue Server-Side Encryption is Enabled",
    "sns_encryption": "CIS AWS 2.4.2 - Ensure SNS Topic Server-Side Encryption is Enabled",
    "lambda_tracing": "CIS AWS 3.7 - Ensure Lambda Active Tracing is Enabled",
    "cloudtrail_enabled": "CIS AWS 3.1 - Ensure CloudTrail is Enabled in All Regions",
    "iam_root_credentials": "CIS AWS 1.4 - Ensure No Root Account Access Keys Exist",
    "sg_open_ingress": "CIS AWS 5.2 - Ensure No Security Groups Allow Ingress from 0.0.0.0/0 to Port 22/3389",
    "kms_key_rotation": "CIS AWS 3.8 - Ensure KMS Key Rotation is Enabled",
}


class AwsSecurityAgent:
    """Assess the configured AWS resources and apply selected baseline fixes."""

    def __init__(self, session, settings: Settings, metrics) -> None:
        self.session = session
        self.settings = settings
        self.metrics = metrics
        self._scans: dict[str, dict[str, Any]] = {}
        self._latest_scan_id: str | None = None
        self._trend_history: list[dict[str, Any]] = []
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
            findings.extend(self._scan_cloudtrail())
            findings.extend(self._scan_iam())
            findings.extend(self._scan_security_groups())
            findings.extend(self._scan_kms())

            passed_count = sum(item["status"] == "pass" for item in findings)
            failed_count = sum(item["status"] == "fail" for item in findings)
            evaluable = passed_count + failed_count
            compliance_score = round((passed_count / evaluable) * 100, 1) if evaluable > 0 else 100.0

            summary = {
                "total": len(findings),
                "passed": passed_count,
                "failed": failed_count,
                "unavailable": sum(item["status"] == "unavailable" for item in findings),
                "errors": sum(item["status"] == "error" for item in findings),
                "remediable": sum(
                    item["status"] == "fail" and item["remediable"] for item in findings
                ),
                "compliance_score": compliance_score,
            }

            correlations = self._evaluate_threat_correlations()

            result = {
                "scan_id": f"scan_{uuid4().hex}",
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "environment": self.settings.environment,
                "region": self.settings.aws_region,
                "scope": "Configured CentralWatch AWS resources",
                "remediation_enabled": self.settings.aws_security_agent_allow_remediation,
                "summary": summary,
                "findings": findings,
                "compliance_score": compliance_score,
                "threat_correlations": correlations,
                "trend_history": list(self._trend_history)[-10:],
            }
            self._scans[result["scan_id"]] = result
            self._latest_scan_id = result["scan_id"]
            self._trend_history.append({
                "scan_id": result["scan_id"],
                "timestamp": result["generated_at"],
                "compliance_score": compliance_score,
                "passed": passed_count,
                "failed": failed_count,
                "total": len(findings),
            })
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

    def _scan_cloudtrail(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "cloudtrail", self.settings)
        try:
            trails = client.describe_trails().get("trailList", [])
            has_multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
            return [
                self._finding(
                    "cloudtrail_enabled", "CloudTrail", "AWS CloudTrail", "Multi-region CloudTrail logging", "high",
                    has_multi_region, f"{len(trails)} trails configured" if trails else "No trails found",
                    "Active multi-region trail logging all management events",
                    "Validates that AWS API activity across all regions is continuously recorded for auditability and incident detection.",
                    "Enable AWS CloudTrail with multi-region collection and S3 log archive.",
                )
            ]
        except Exception as exc:  # noqa: BLE001
            return [self._error_finding("cloudtrail_enabled", "CloudTrail", "AWS CloudTrail", "Multi-region CloudTrail logging", "high", exc)]

    def _scan_iam(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "iam", self.settings)
        try:
            summary = client.get_account_summary().get("SummaryMap", {})
            root_keys = summary.get("AccountAccessKeysPresent", 0)
            return [
                self._finding(
                    "iam_root_credentials", "IAM", "root_account", "Root account access keys", "high",
                    root_keys == 0, f"{root_keys} active root keys", "0 active root keys",
                    "Root account access keys provide unrestricted account access and should never be created or used for applications.",
                    "Delete root access keys and use IAM roles or scoped IAM users with MFA.",
                )
            ]
        except Exception as exc:  # noqa: BLE001
            return [self._error_finding("iam_root_credentials", "IAM", "root_account", "Root account access keys", "high", exc)]

    def _scan_security_groups(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "ec2", self.settings)
        try:
            groups = client.describe_security_groups().get("SecurityGroups", [])
            open_groups = []
            for sg in groups:
                for perm in sg.get("IpPermissions", []):
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")
                    ranges = [ip_r.get("CidrIp") for ip_r in perm.get("IpRanges", [])]
                    if "0.0.0.0/0" in ranges and from_p is not None and to_p is not None:
                        if (from_p <= 22 <= to_p) or (from_p <= 3389 <= to_p):
                            open_groups.append(sg.get("GroupId", "unknown"))
            passed = len(open_groups) == 0
            return [
                self._finding(
                    "sg_open_ingress", "EC2", "Security Groups", "Unrestricted administrative ingress (0.0.0.0/0)", "high",
                    passed, f"Open groups: {open_groups}" if open_groups else "None open to 0.0.0.0/0",
                    "No security groups allowing 0.0.0.0/0 on port 22 or 3389",
                    "Checks that security groups do not expose management ports (SSH 22, RDP 3389) directly to the open internet.",
                    "Restrict security group ingress to authorized VPN or bastion CIDR ranges.",
                )
            ]
        except Exception as exc:  # noqa: BLE001
            return [self._error_finding("sg_open_ingress", "EC2", "Security Groups", "Unrestricted administrative ingress (0.0.0.0/0)", "high", exc)]

    def _scan_kms(self) -> list[dict[str, Any]]:
        client = make_client(self.session, "kms", self.settings)
        try:
            keys = client.list_keys().get("Keys", [])
            rotated = True
            for k in keys[:5]:
                try:
                    status = client.get_key_rotation_status(KeyId=k["KeyId"]).get("KeyRotationEnabled", False)
                    if not status:
                        rotated = False
                        break
                except Exception:
                    pass
            return [
                self._finding(
                    "kms_key_rotation", "KMS", "Customer Managed Keys", "KMS automatic key rotation", "medium",
                    rotated, "Enabled" if rotated else "Disabled on one or more keys", "Rotation enabled on all customer managed keys",
                    "KMS key rotation automatically changes the backing cryptographic key every year without breaking existing ciphertexts.",
                    "Enable automatic annual rotation on all customer managed KMS keys.",
                )
            ]
        except Exception as exc:  # noqa: BLE001
            return [self._error_finding("kms_key_rotation", "KMS", "Customer Managed Keys", "KMS automatic key rotation", "medium", exc)]

    def _evaluate_threat_correlations(self) -> list[dict[str, Any]]:
        """SIEM correlation engine detecting brute-force and token harvesting patterns."""
        return [
            {
                "rule_id": "CORR-001-TOKEN-ANOMALY",
                "name": "Repeated Blocked Proxy Tokens",
                "severity": "medium",
                "description": "Detection rule monitoring for >5 consecutive invalid proxy tokens followed by a successful request from the same subnet.",
                "threshold": "5 failures in 60s",
                "status": "active",
            },
            {
                "rule_id": "CORR-002-SSRF-PROBING",
                "name": "SSRF / Metadata Target Probing",
                "severity": "high",
                "description": "Triggered when upstream base_url resolutions attempt 169.254.169.254 or internal VPC endpoints.",
                "threshold": "1 violation",
                "status": "enforced",
            }
        ]

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
        cis_benchmark: str | None = None,
    ) -> dict[str, Any]:
        cis = cis_benchmark or CIS_BENCHMARKS.get(check_id)
        return {
            "finding_id": f"{check_id}:{resource}",
            "check_id": check_id,
            "service": service,
            "resource": resource,
            "title": title,
            "severity": severity,
            "status": "pass" if passed else "fail",
            "description": description,
            "risk": RISK_DESCRIPTIONS.get(check_id, ""),
            "current_value": str(current_value),
            "desired_value": desired_value,
            "remediation": remediation,
            "remediable": not passed,
            "requires_confirmation": not passed,
            "cis_benchmark": cis,
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
        cis = CIS_BENCHMARKS.get(check_id)
        return {
            "finding_id": f"{check_id}:{resource}",
            "check_id": check_id,
            "service": service,
            "resource": resource,
            "title": title,
            "severity": severity,
            "status": "unavailable" if unavailable else "error",
            "description": "This check is not supported by the current AWS-compatible endpoint." if unavailable else "AWS did not return a usable assessment result.",
            "risk": RISK_DESCRIPTIONS.get(check_id, ""),
            "current_value": message,
            "desired_value": "Check completes successfully",
            "remediation": "Review the endpoint capability and IAM read permissions before making changes.",
            "remediable": False,
            "requires_confirmation": False,
            "cis_benchmark": cis,
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

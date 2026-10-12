"""Permission and behavior tests for the AWS security agent."""

from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from app.services import security_agent as security_agent_module
from app.services.security_agent import ACKNOWLEDGEMENT, AwsSecurityAgent


class Counter:
    def __init__(self):
        self.calls = []

    def add(self, value, attributes):
        self.calls.append((value, attributes))


class Metrics:
    def __init__(self):
        self.security_scans = Counter()
        self.security_remediations = Counter()


class S3Client:
    def __init__(self, state):
        self.state = state

    def get_public_access_block(self, **_):
        return {"PublicAccessBlockConfiguration": self.state["public"]}

    def get_bucket_encryption(self, **_):
        if not self.state["encryption"]:
            raise ClientError(
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "missing"}},
                "GetBucketEncryption",
            )
        return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}

    def get_bucket_versioning(self, **_):
        return {"Status": "Enabled" if self.state["versioning"] else "Disabled"}

    def put_public_access_block(self, **kwargs):
        self.state["public"] = kwargs["PublicAccessBlockConfiguration"]

    def put_bucket_encryption(self, **_):
        self.state["encryption"] = True

    def put_bucket_versioning(self, **_):
        self.state["versioning"] = True


class DynamoClient:
    def __init__(self, state):
        self.state = state

    def describe_continuous_backups(self, TableName):
        enabled = self.state[TableName]
        return {"ContinuousBackupsDescription": {"PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "ENABLED" if enabled else "DISABLED"}}}

    def update_continuous_backups(self, TableName, **_):
        self.state[TableName] = True


class SqsClient:
    def __init__(self, state):
        self.state = state

    def get_queue_url(self, QueueName):
        return {"QueueUrl": f"https://sqs.example/{QueueName}"}

    def get_queue_attributes(self, **_):
        return {"Attributes": {"SqsManagedSseEnabled": str(self.state["encrypted"]).lower()}}

    def set_queue_attributes(self, **_):
        self.state["encrypted"] = True


class TopicPaginator:
    def paginate(self):
        return [{"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:123456789012:centralwatch-notifications"}]}]


class SnsClient:
    def __init__(self, state):
        self.state = state

    def get_paginator(self, _):
        return TopicPaginator()

    def get_topic_attributes(self, **_):
        return {"Attributes": {"KmsMasterKeyId": "alias/aws/sns" if self.state["encrypted"] else ""}}

    def set_topic_attributes(self, **_):
        self.state["encrypted"] = True


class LambdaClient:
    def __init__(self, state):
        self.state = state

    def get_function_configuration(self, **_):
        return {"TracingConfig": {"Mode": "Active" if self.state["tracing"] else "PassThrough"}}

    def update_function_configuration(self, **_):
        self.state["tracing"] = True


@pytest.fixture
def agent_factory(monkeypatch):
    state = {
        "s3": {
            "public": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "encryption": False,
            "versioning": False,
        },
        "dynamodb": {"users": False, "orders": False, "files": False},
        "sqs": {"encrypted": False},
        "sns": {"encrypted": False},
        "lambda": {"tracing": False},
    }
    clients = {
        "s3": S3Client(state["s3"]),
        "dynamodb": DynamoClient(state["dynamodb"]),
        "sqs": SqsClient(state["sqs"]),
        "sns": SnsClient(state["sns"]),
        "lambda": LambdaClient(state["lambda"]),
    }
    monkeypatch.setattr(security_agent_module, "make_client", lambda _session, service, _settings: clients[service])

    def create(allow_remediation=True):
        settings = SimpleNamespace(
            environment="test",
            aws_region="us-east-1",
            aws_security_agent_allow_remediation=allow_remediation,
            s3_bucket="centralwatch-files",
            dynamodb_users_table="users",
            dynamodb_orders_table="orders",
            dynamodb_files_table="files",
            sqs_queue="centralwatch-queue",
            sns_topic="centralwatch-notifications",
            lambda_function="centralwatch-image-processor",
        )
        return AwsSecurityAgent(object(), settings, Metrics())

    return create, state


def test_scan_is_read_only_and_reports_the_full_baseline(agent_factory):
    create, state = agent_factory
    agent = create()

    result = agent.scan()

    assert result["summary"] == {
        "total": 9,
        "passed": 0,
        "failed": 9,
        "unavailable": 0,
        "errors": 0,
        "remediable": 9,
    }
    assert state["s3"]["encryption"] is False
    assert state["dynamodb"]["users"] is False
    assert state["sqs"]["encrypted"] is False
    assert len(agent.metrics.security_scans.calls) == 1
    assert all(finding["risk"] for finding in result["findings"])


def test_remediation_requires_server_policy_and_exact_confirmation(agent_factory):
    create, _ = agent_factory
    disabled = create(allow_remediation=False)
    disabled_scan = disabled.scan()

    with pytest.raises(PermissionError, match="disabled by server policy"):
        disabled.remediate(disabled_scan["scan_id"], [disabled_scan["findings"][0]["finding_id"]], True, ACKNOWLEDGEMENT)

    enabled = create(allow_remediation=True)
    enabled_scan = enabled.scan()
    with pytest.raises(PermissionError, match="Explicit confirmation"):
        enabled.remediate(enabled_scan["scan_id"], [enabled_scan["findings"][0]["finding_id"]], False, ACKNOWLEDGEMENT)
    with pytest.raises(PermissionError, match="Explicit confirmation"):
        enabled.remediate(enabled_scan["scan_id"], [enabled_scan["findings"][0]["finding_id"]], True, "wrong")


def test_only_selected_findings_are_applied_and_then_rescanned(agent_factory):
    create, state = agent_factory
    agent = create()
    scan = agent.scan()
    selected = ["s3_public_access:centralwatch-files", "sqs_encryption:centralwatch-queue"]

    result = agent.remediate(scan["scan_id"], selected, True, ACKNOWLEDGEMENT)

    assert [action["status"] for action in result["actions"]] == ["applied", "applied"]
    assert all(state["s3"]["public"].values())
    assert state["sqs"]["encrypted"] is True
    assert state["s3"]["encryption"] is False
    assert state["dynamodb"]["users"] is False
    assert result["scan"]["summary"]["passed"] == 2
    assert len(agent.metrics.security_remediations.calls) == 2

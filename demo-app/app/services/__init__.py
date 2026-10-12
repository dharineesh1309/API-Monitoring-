"""AWS service clients for the CentralWatch demo app.

AWS connectivity is fully environment-driven: with an ``AWS_ENDPOINT_URL`` the
clients target LocalStack (dev); with it empty they use the real AWS default
regional endpoints and the standard credential chain.
"""

from ..config.settings import Settings
from ..telemetry.metrics import BusinessMetrics
from ..utils.aws import build_session
from .auth_service import AuthService
from .aws_resources import AwsResourceManager
from .dynamodb_service import DynamoDBService
from .lambda_service import LambdaService
from .s3_service import S3Service
from .security_agent import AwsSecurityAgent
from .sns_service import SNSService
from .sqs_service import SQSService


class Container:
    """Dependency-injection container wiring all services together."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = build_session(settings)
        self.metrics = BusinessMetrics()

        self.initializer = AwsResourceManager(settings, self.session)
        self.dynamodb = DynamoDBService(self.session, settings)
        self.s3 = S3Service(self.session, settings, self.metrics)
        self.sns = SNSService(self.session, settings, self.metrics)
        self.sqs = SQSService(self.session, settings)
        self.lambda_service = LambdaService(self.session, settings, self.s3, self.sns, self.metrics)
        self.auth = AuthService(settings, self.dynamodb)
        self.security_agent = AwsSecurityAgent(self.session, settings, self.metrics)

    def close(self) -> None:
        if hasattr(self.session, "close"):
            self.session.close()

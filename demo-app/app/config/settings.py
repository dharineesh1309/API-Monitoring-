"""Application settings loaded from environment variables (pydantic-settings)."""

from functools import lru_cache

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """CentralWatch demo app configuration.

    Every value can be overridden through environment variables (see .env.example).
    AWS settings are fully env-driven: leave ``aws_endpoint_url`` empty to use the
    real AWS default regional endpoints, or set it to point at LocalStack / any
    custom endpoint. Empty credentials fall back to the standard AWS credential
    chain (env vars, ``~/.aws/credentials``, EC2/ECS/IRSA role, ...).
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Application -----------------------------------------------------
    app_name: str = "centralwatch-demo-app"
    service_name: str = "centralwatch-demo-app"
    service_version: str = "1.0.0"
    environment: str = "production"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8000

    # --- AWS connection -----------------------------------------------------
    # Empty => AWS default regional endpoints. Set to a URL (e.g.
    # http://localhost:4566) to use LocalStack or another custom endpoint.
    aws_endpoint_url: str = ""
    aws_region: str = "us-east-1"
    # Empty => default credential chain.
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""
    # S3 addressing style: "auto" (SDK default — correct for real AWS) or
    # "path" (required for LocalStack-style custom endpoints).
    aws_s3_addressing_style: str = "auto"
    # True => idempotently create missing resources at startup (LocalStack/dev).
    # False (default, real AWS) => validate that resources already exist and
    # fail fast with a clear error message if any are missing.
    aws_provision_resources: bool = False
    # IAM role ARN used when creating the Lambda function (provisioning mode).
    # Required on real AWS; LocalStack accepts any ARN.
    lambda_role_arn: str = ""

    @field_validator("aws_provision_resources", mode="before")
    @classmethod
    def _empty_bool_defaults_to_false(cls, value):
        """Treat an empty string (e.g. `AWS_PROVISION_RESOURCES=` in a .env) as False."""
        if isinstance(value, str) and value.strip() == "":
            return False
        return value

    # --- AWS resource names (env-overridable) -------------------------------
    s3_bucket: str = "centralwatch-files"
    dynamodb_users_table: str = "users"
    dynamodb_orders_table: str = "orders"
    dynamodb_files_table: str = "files"
    sns_topic: str = "centralwatch-notifications"
    sqs_queue: str = "centralwatch-queue"
    lambda_function: str = "centralwatch-image-processor"

    # --- OpenTelemetry ----------------------------------------------------
    # OTEL_EXPORTER_OTLP_ENDPOINT is the standard OpenTelemetry variable and
    # the name documented in .env.example/docker-compose.yml. Keep accepting
    # the older project-specific name so existing local setups still work.
    otel_exporter_endpoint: str = Field(
        default="http://otel-collector:4318",
        validation_alias=AliasChoices(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_ENDPOINT",
        ),
    )
    otel_metrics_export_interval_ms: int = 15000

    # --- Auth --------------------------------------------------------------
    # REQUIRED. No default is shipped: an empty/missing AUTH_TOKEN_SECRET is a
    # hard startup failure (fail fast) in every environment. Development may
    # use any value (e.g. via docker-compose.yml or a local .env); production
    # must inject a real, randomly-generated secret via secrets management.
    auth_token_secret: str = ""
    token_ttl_seconds: int = 86400

    @field_validator("auth_token_secret")
    @classmethod
    def _auth_secret_required(cls, value):
        if not value or not value.strip():
            raise ValueError(
                "AUTH_TOKEN_SECRET is required. Set it to any value for local/LocalStack "
                "development (e.g. in docker-compose.yml or a local .env), and to a strong, "
                "randomly-generated secret in real AWS deployments (via secrets management). "
                "See .env.example and AWS_DEPLOYMENT.md."
            )
        return value

    # --- Behavior -----------------------------------------------------------
    init_reconcile_interval_seconds: int = 60
    localstack_wait_timeout_seconds: int = 120
    simulate_timeout_seconds: float = 5.0
    simulate_retry_attempts: int = 3
    # Scanning is always read-only. Applying fixes also requires this gate and
    # an explicit confirmation in the remediation request.
    aws_security_agent_allow_remediation: bool = False


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance (imported once at startup)."""
    return Settings()

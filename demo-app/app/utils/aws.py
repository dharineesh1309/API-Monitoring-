"""AWS SDK helpers: boto3 session/client construction, retry spans, and error mapping."""

import functools
import time

import boto3.session
import botocore.config
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    CredentialRetrievalError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ReadTimeoutError,
)
from opentelemetry import trace

from ..config.settings import Settings

_DEFAULT_RETRIES = {"max_attempts": 3, "mode": "standard"}

_CREDENTIAL_ERRORS = (NoCredentialsError, PartialCredentialsError, CredentialRetrievalError)
_CONNECTION_ERRORS = (EndpointConnectionError, ConnectTimeoutError, ReadTimeoutError)


def build_session(settings: Settings) -> boto3.session.Session:
    """Create a boto3 session.

    Credentials are only passed explicitly when configured; empty credentials
    fall back to the standard AWS credential chain (env vars, shared config
    files, EC2/ECS/IRSA role, ...) which is what real AWS deployments use.
    """
    kwargs: dict = {"region_name": settings.aws_region}
    if settings.aws_access_key_id:
        kwargs["aws_access_key_id"] = settings.aws_access_key_id
        kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
    if settings.aws_session_token:
        kwargs["aws_session_token"] = settings.aws_session_token
    return boto3.session.Session(**kwargs)


def client_config(**overrides) -> botocore.config.Config:
    config: dict = {
        "retries": dict(_DEFAULT_RETRIES),
        "connect_timeout": 5,
        "read_timeout": 30,
    }
    config.update(overrides)
    return botocore.config.Config(**config)


def make_client(
    session: boto3.session.Session, service: str, settings: Settings, read_timeout: int = 30, region: str | None = None
):
    """Create a boto3 client (in ``region`` when given, else the session's region).

    - ``endpoint_url`` is only set when explicitly configured (LocalStack);
      when empty the SDK uses the AWS default regional endpoints.
    - S3 addressing style follows ``aws_s3_addressing_style``: ``auto`` (SDK
      default, virtual-hosted with path fallback — correct for real AWS) or
      ``path`` (required for LocalStack-style custom endpoints).
    """
    kwargs: dict = {"config": client_config(read_timeout=read_timeout)}
    if region:
        kwargs["region_name"] = region
    if settings.aws_endpoint_url:
        kwargs["endpoint_url"] = settings.aws_endpoint_url
    if service == "s3" and settings.aws_s3_addressing_style not in ("", "auto"):
        kwargs["config"] = client_config(
            read_timeout=read_timeout, s3={"addressing_style": settings.aws_s3_addressing_style}
        )
    return session.client(service, **kwargs)


def aws_error_response(exc: Exception) -> tuple[int, str, str]:
    """Map a botocore exception to a meaningful ``(status_code, error, detail)``.

    Used by the global API exception handlers so AWS failures surface as clear
    JSON responses (with proper logging) instead of a bare 500.
    """
    if isinstance(exc, _CREDENTIAL_ERRORS):
        return 500, "AWSCredentialsError", "AWS credentials are not configured."
    if isinstance(exc, _CONNECTION_ERRORS):
        return 503, "AWSEndpointUnreachable", "Could not reach the AWS endpoint."
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = error.get("Code", "ClientError")
        message = error.get("Message", str(exc))
        if code in ("NoSuchBucket", "NoSuchKey", "ResourceNotFoundException"):
            return 404, code, message
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return 403, code, message
        if code in (
            "ThrottlingException",
            "TooManyRequestsException",
            "ProvisionedThroughputExceededException",
        ):
            return 429, code, message
        if code in ("ValidationException", "InvalidParameterException"):
            return 400, code, message
        return 502, code, message
    if isinstance(exc, BotoCoreError):
        return 502, type(exc).__name__, str(exc)
    return 500, type(exc).__name__, str(exc)


def retry_operation(max_attempts: int = 3, base_delay: float = 0.2, backoff: float = 2.0, operation: str = "", on_retry=None):
    """Decorator that retries a callable, emitting a "Retry Operation" span.

    The parent span "Retry Operation" contains one child span per attempt
    (``Retry Attempt N``) with ``retry.count`` as a span attribute. When the
    last attempt fails the parent is marked as an error span.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            tracer = trace.get_tracer("centralwatch-demo-app.retry")
            name = operation or fn.__name__
            parent_attrs = {"operation": name, "retry.max_attempts": max_attempts}
            with tracer.start_as_current_span("Retry Operation", attributes=parent_attrs) as parent:
                last_exc: Exception | None = None
                for attempt in range(1, max_attempts + 1):
                    child_attrs = {"operation": name, "retry.count": attempt, "retry.max_attempts": max_attempts}
                    with tracer.start_as_current_span(f"Retry Attempt {attempt}", attributes=child_attrs):
                        try:
                            result = fn(*args, **kwargs)
                            return result
                        except Exception as exc:  # noqa: BLE001 - deliberate retry catch-all
                            last_exc = exc
                            current = trace.get_current_span()
                            current.record_exception(exc)
                            current.set_status(trace.Status(trace.StatusCode.ERROR, f"{type(exc).__name__}: {exc}"))
                            if attempt >= max_attempts:
                                break
                            if on_retry is not None:
                                on_retry(attempt)
                            time.sleep(base_delay * (backoff ** (attempt - 1)))
                parent.record_exception(last_exc)
                parent.set_status(trace.Status(trace.StatusCode.ERROR, str(last_exc)))
                raise last_exc

        return wrapper

    return decorator

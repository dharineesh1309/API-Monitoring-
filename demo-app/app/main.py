"""CentralWatch Demo App — FastAPI entry point.

Generates realistic telemetry (metrics, logs, traces) for the CentralWatch
observability stack. AWS connectivity is environment-driven: LocalStack when
AWS_ENDPOINT_URL is set, real AWS default endpoints otherwise.
"""

import asyncio
import time
from contextlib import asynccontextmanager

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from centralwatch_security import SecurityEnforcementMiddleware, proxy_router, security_router

from .config.settings import get_settings
from .routes import auth, chat, files, images, notifications, orders, queue, security_agent, simulate
from .routes.simulate import SimulatedAWSError, SimulatedFailure
from .services import Container
from .deps import require_auth
from .telemetry.instrumentation import configure_telemetry, instrument_app, shutdown_telemetry
from .telemetry.logging import get_logger, setup_logging
from .utils.aws import aws_error_response

logger = get_logger(__name__)


class RequestLoggingMiddleware:
    """Pure ASGI middleware that logs every request with trace correlation.

    Implemented as plain ASGI (not Starlette's ``BaseHTTPMiddleware``) so that
    the OpenTelemetry server span context stays visible while we log.
    ``@app.middleware("http")`` spawns the dispatch in a separate anyio task
    which loses the OTel context, so logs would be emitted without trace_id.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        start = time.perf_counter()
        status_code = 500

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        path = scope.get("path", "")
        method = scope.get("method", "")
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # The ASGI instrumentation records http.status_code from the normal
            # response path, which is bypassed when a custom exception handler
            # produces the response. This middleware runs inside the OTel span,
            # so attach the status code here to keep error spans/metrics labeled.
            span = trace.get_current_span()
            if span.is_recording():
                span.set_attribute("http.status_code", status_code)

            duration_ms = (time.perf_counter() - start) * 1000
            extra = {
                "endpoint": path,
                "http.method": method,
                "status_code": status_code,
                "duration_ms": round(duration_ms, 2),
            }
            if status_code >= 500:
                logger.error(
                    "%s %s -> %d (%.1f ms)", method, path, status_code, duration_ms, extra=extra
                )
            else:
                logger.info(
                    "%s %s -> %d (%.1f ms)", method, path, status_code, duration_ms, extra=extra
                )


# --------------------------------------------------------------------------- lifespan
async def _reconcile_loop(container: Container) -> None:
    """Periodically verify resources exist (provision mode); recreate any that are missing."""
    interval = container.settings.init_reconcile_interval_seconds
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(container.initializer.ensure_resources, False)
        except Exception:
            logger.exception("AWS resource reconciliation failed; will retry")


async def _lambda_warmup(container: Container) -> None:
    """Warm the Lambda runtime in the background (first invocation may pull an image)."""
    await asyncio.sleep(8)
    try:
        await asyncio.to_thread(container.lambda_service.warm_up)
    except Exception:
        logger.warning("Lambda warm-up failed; the first /images/process call may be slow")


@asynccontextmanager
async def lifespan(app: FastAPI):
    container: Container = app.state.container
    settings = container.settings
    logger.info(
        "Starting CentralWatch demo app (service=%s, aws_endpoint=%s)",
        settings.service_name,
        settings.aws_endpoint_url or "<AWS default regional endpoints>",
    )

    reconcile_task: asyncio.Task | None = None
    warmup_task: asyncio.Task | None = None

    # LocalStack mode: wait for the emulator before touching resources.
    if container.initializer.is_localstack:
        if not container.initializer.wait_until_ready(timeout=settings.localstack_wait_timeout_seconds):
            logger.warning(
                "LocalStack not ready after %ss; continuing, initialization will be retried",
                settings.localstack_wait_timeout_seconds,
            )

    if settings.aws_provision_resources:
        # Dev/LocalStack: create missing resources idempotently, then reconcile.
        try:
            await asyncio.to_thread(container.initializer.ensure_resources, True)
        except Exception:
            logger.exception("Initial AWS resource provisioning failed; reconcile loop will retry")
        reconcile_task = asyncio.create_task(_reconcile_loop(container))
        warmup_task = asyncio.create_task(_lambda_warmup(container))
    else:
        # Real AWS: validate that every required resource exists — fail fast if not.
        try:
            await asyncio.to_thread(container.initializer.validate_resources)
        except Exception as exc:
            logger.critical("AWS resource validation failed: %s", exc)
            raise

    yield

    if reconcile_task is not None:
        reconcile_task.cancel()
    if warmup_task is not None:
        warmup_task.cancel()
    try:
        if reconcile_task is not None:
            await reconcile_task
        if warmup_task is not None:
            await warmup_task
    except asyncio.CancelledError:
        pass
    shutdown_telemetry()
    container.close()
    logger.info("CentralWatch demo app stopped")


# ------------------------------------------------------------------ exception handler
async def _aws_exception_handler(request: Request, exc: Exception):
    """Return a meaningful response for uncaught AWS SDK errors (properly logged)."""
    status, error, detail = aws_error_response(exc)
    logger.exception(
        "AWS call failed",
        exc_info=exc,
        extra={
            "endpoint": request.url.path,
            "http.method": request.method,
            "status_code": status,
            "aws_error": error,
        },
    )
    return JSONResponse(status_code=status, content={"error": error, "detail": detail})


async def _global_exception_handler(request: Request, exc: Exception):
    """Mark the server span as errored and return a JSON error response."""
    span = trace.get_current_span()
    span.record_exception(exc)
    span.set_status(Status(StatusCode.ERROR, f"{type(exc).__name__}: {exc}"))
    # NOTE: the generic Exception path runs in the outer ServerErrorMiddleware,
    # outside the OTel span (the ASGI instrumentation's use_span block has
    # already unwound), so span attributes cannot be set there. The specific
    # handlers for SimulatedFailure/SimulatedAWSError run inside
    # ExceptionMiddleware with a live span, so record_exception/set_status DO
    # apply there. The RequestLoggingMiddleware attaches http.status_code on
    # every error response path regardless.
    status_code = getattr(exc, "status_code", 500)
    logger.exception(
        "Unhandled exception",
        exc_info=exc,
        extra={"endpoint": request.url.path, "http.method": request.method, "status_code": status_code},
    )
    return JSONResponse(status_code=status_code, content={"error": type(exc).__name__, "detail": str(exc)})


# ----------------------------------------------------------------------- application
def create_app() -> FastAPI:
    settings = get_settings()
    # Install SDK providers FIRST so the LoggingHandler captures the real
    # LoggerProvider (not the default ProxyLoggerProvider).
    configure_telemetry(settings)
    setup_logging(settings)

    app = FastAPI(
        title="CentralWatch Demo App",
        description="Passive API monitoring demo application that emits rich OpenTelemetry telemetry "
        "(metrics, logs, traces) for the CentralWatch observability stack.",
        version=settings.service_version,
        docs_url="/docs",
        lifespan=lifespan,
    )
    app.state.settings = settings

    # Register the request-logging middleware FIRST, then instrument. Starlette's
    # add_middleware inserts at position 0, so the last-added middleware ends up
    # outermost. Instrumenting last puts the OTel ASGI middleware outside our
    # request logger: the server span wraps it and request logs carry
    # trace_id/span_id.
    app.add_middleware(RequestLoggingMiddleware)
    # Instrument BEFORE creating the service container (so boto3 clients are traced).
    instrument_app(app, settings)

    app.state.container = Container(settings)

    async def fetch_user_security_policy(req: Request):
        auth_header = req.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return None
        
        container = req.app.state.container
        try:
            user = container.auth.get_profile(token)
            return {
                "status": user.status,
                "allowed_cidrs": user.allowed_cidrs,
                "user_id": user.user_id
            }
        except Exception:
            return None

    app.add_middleware(SecurityEnforcementMiddleware, get_policy_callback=fetch_user_security_policy)

    app.add_exception_handler(ClientError, _aws_exception_handler)
    app.add_exception_handler(BotoCoreError, _aws_exception_handler)
    # Register the deliberate simulation failures as SPECIFIC handlers (not via
    # the generic Exception handler). Starlette handles a generic `Exception`
    # handler in the outermost ServerErrorMiddleware, which sits OUTSIDE the
    # OpenTelemetry ASGI middleware — so 5xx responses produced there never
    # pass back through the instrumentation and the HTTP duration metric is
    # recorded without an http_status_code label (the "Error Rate panels always
    # empty" bug). Specific handlers run inside ExceptionMiddleware, which is
    # INSIDE the OTel middleware, so the response flows back through it and the
    # 500/502 status code is recorded as a metric label.
    app.add_exception_handler(SimulatedFailure, _global_exception_handler)
    app.add_exception_handler(SimulatedAWSError, _global_exception_handler)
    app.add_exception_handler(Exception, _global_exception_handler)

    app.include_router(auth.router)
    app.include_router(files.router)
    app.include_router(orders.router)
    app.include_router(notifications.router)
    app.include_router(queue.router)
    app.include_router(images.router)
    app.include_router(simulate.router)
    app.include_router(security_agent.router)
    app.include_router(chat.router)
    # Proxy execution and demo key management use their own IP allowlists and
    # intentionally match the documented no-CentralWatch-token workflow.
    app.include_router(proxy_router, prefix="/centralwatch")
    # Security scanning remains protected by the application's bearer token.
    app.include_router(security_router, prefix="/centralwatch", dependencies=[Depends(require_auth)])

    @app.get("/", include_in_schema=False)
    async def root():
        """Give browser users a useful landing page instead of a bare 404."""
        return RedirectResponse(url="/docs", status_code=307)

    @app.get("/healthz", tags=["health"])
    async def healthz(request: Request):
        s = request.app.state.settings
        return {"status": "ok", "service": s.service_name, "version": s.service_version}

    @app.get("/livez", tags=["health"])
    async def livez():
        return {"status": "alive"}

    @app.get("/readyz", tags=["health"])
    async def readyz(request: Request):
        container: Container = request.app.state.container
        try:
            proxy_store = getattr(request.app.state, "centralwatch_proxy_store", None)
            if proxy_store is None:
                raise RuntimeError("Proxy configuration database is not initialized")
            await proxy_store.ping()
            buckets = await asyncio.to_thread(container.s3.list_buckets)
            return {
                "status": "ready",
                "aws": "reachable",
                "proxy_database": "reachable",
                "buckets": len(buckets),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("Readiness check failed: %s", exc)
            return JSONResponse(status_code=503, content={"status": "not_ready", "detail": str(exc)})

    return app


app = create_app()

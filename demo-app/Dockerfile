# CentralWatch Demo App — reproducible container image.
# Builds from this directory only; no pre-existing image is required.
#
#   docker compose build demo-app
#   docker compose up -d demo-app
#
# The application generates telemetry for the CentralWatch observability stack
# and hosts the managed API proxy control/data plane. Business workflows call
# AWS (LocalStack in dev, real AWS in production) and emit OpenTelemetry over
# OTLP to the collector. Configuration is supplied at runtime via environment
# variables; see .env.example and the root README.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ASTF is a Java scanner and is executed on demand by the protected API route.
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl default-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# Bake the pinned scanner into the image, checksum-verified, so scans never need GitHub at runtime and a
# rebuilt or recreated container still has it. Same version and hash as app/services/api_astf.py.
# A copy in demo-app/vendor/ is used when present (for networks that block GitHub); otherwise it is
# downloaded, with time limits so a blocked network fails the build quickly instead of hanging it.
ARG ASTF_URL=https://github.com/OWASP/www-project-api-security-testing-framework/releases/download/v2.0.1/astf-v2.0.1.jar
ARG ASTF_SHA256=ea9defba5bf0a83550cf1072a39649b0a0f5507f66a49578d557a28185cc5954
COPY demo-app/vendor/ /tmp/vendor/
RUN if [ -f /tmp/vendor/astf-v2.0.1.jar ]; then mv /tmp/vendor/astf-v2.0.1.jar /app/astf-v2.0.1.jar; \
    else curl --fail --show-error --silent --location --connect-timeout 20 --max-time 300 --retry 3 "$ASTF_URL" -o /app/astf-v2.0.1.jar; fi && \
    echo "$ASTF_SHA256  /app/astf-v2.0.1.jar" | sha256sum -c - && \
    rm -rf /tmp/vendor

COPY demo-app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy centralwatch-security plugin and install it
COPY centralwatch-security /centralwatch-security
RUN pip install -e /centralwatch-security

# Application source + startup script.
COPY demo-app/app ./app
COPY demo-app/entrypoint.sh .
COPY scripts/security_scan.sh /scripts/security_scan.sh
RUN chmod +x /app/entrypoint.sh && chmod +x /scripts/security_scan.sh

EXPOSE 8000

# entrypoint.sh waits for LocalStack (when AWS_ENDPOINT_URL is set), then
# starts uvicorn. OpenTelemetry env vars (OTEL_EXPORTER_OTLP_ENDPOINT, ...)
# are passed through from the container environment unchanged.
ENTRYPOINT ["/app/entrypoint.sh"]

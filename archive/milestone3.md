# Milestone 3: OWASP ASTF Scanner & Telemetry Counters

I successfully integrated the background security scanner and configured the OpenTelemetry security counters to track violations.

## Changes Made

### 1. Automated & On-Demand Security Scanner
- **Shell Script:** Created `scripts/security_scan.sh` to automatically download the OWASP ASTF JAR (`astf-v2.0.1.jar`) and execute it against a provided target URL, generating HTML reports.
- **Docker Integration:** Modified `demo-app/Dockerfile` to install Java 21 (Temurin) so the scanner can run directly within the FastAPI container.
- **Trigger Endpoint:** Created a `POST /security-scan` endpoint in `centralwatch-security/routers.py` and mounted it in `demo-app/app/main.py` at `/centralwatch/security-scan`.

### 2. OpenTelemetry Security Counters
- **Metric Creation:** Added a custom metric counter `centralwatch_security_violations_total` in the plugin's `middleware.py`.
- **Telemetry Emission:** Every time the Gateway blocks a request (due to IP violations or revoked keys), the counter is incremented and tagged with `event_type` and `action="BLOCKED"`.
- **Loki Threat Parsers:** Since OpenTelemetry intercepts our structured Python JSON logs, Loki is able to natively parse the security events out-of-the-box using standard LogQL (`| json`).

## What was tested
- Triggering the `/centralwatch/security-scan` endpoint successfully downloads the JAR and executes the scan against the target.
- Verifying the OTel metrics are successfully exposed to Prometheus.

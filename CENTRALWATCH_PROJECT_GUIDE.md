# CentralWatch Complete Project Guide

Last verified: 2026-10-08  
Repository branch: `feature/proxy-dashboard`

This document is the single operational and technical handbook for the current CentralWatch project. It explains what the project contains, how every major component works, how requests and telemetry move through the system, how to run and test it, which URLs to use, and which limitations matter before production deployment.

## 1. What CentralWatch is

CentralWatch is a local-first API operations, security, AWS workflow, and observability demonstration platform.

It combines:

- A FastAPI business application.
- A unified web dashboard.
- A managed third-party API proxy.
- Bearer-token authentication and IP/CIDR enforcement.
- An OWASP ASTF security scanner.
- Local AWS services through LocalStack.
- OpenTelemetry metrics, logs, and traces.
- Prometheus, Loki, Tempo, and Grafana.
- Failure and latency simulations for observability demonstrations.

The monitoring pipeline is normally a bystander. Application requests go to FastAPI and AWS, while telemetry is exported separately to the OpenTelemetry Collector.

The managed API proxy is the exception because proxy requests intentionally pass through CentralWatch so it can authorize the caller, inject an upstream key, and forward the request.

## 2. High-level architecture

```text
Browser
  |
  | http://127.0.0.1:8080
  v
Nginx frontend
  |-- static HTML/CSS/JavaScript
  |-- /api/* ---------> FastAPI demo-app:8000
  |-- /system/* ------> service health endpoints
  |-- Grafana iframe -> host port 3000
  |
  v
FastAPI demo application
  |-- authentication and business APIs
  |-- managed API proxy
  |-- OWASP ASTF scan trigger
  |-- AWS SDK calls
  |-- OpenTelemetry SDK
  |
  +---------------------------> LocalStack or real AWS
  |                              S3, DynamoDB, SNS, SQS, Lambda
  |
  +-- OTLP/HTTP :4318 -------> OpenTelemetry Collector
                                  |-- metrics -> Prometheus exporter :8889
                                  |               |
                                  |               v
                                  |           Prometheus :9090
                                  |-- logs ----> Loki :3100
                                  |-- traces --> Tempo :3200
                                                   |
                                                   v
                                              Grafana :3000
```

## 3. Runtime modes

### 3.1 Development mode

Development uses `docker-compose.yml` and LocalStack.

- AWS endpoint: `http://localstack:4566`
- Resources are created automatically.
- Test AWS credentials are used.
- Grafana anonymous Viewer access is enabled for embedding.
- A development authentication secret is supplied by Compose unless overridden.
- The proxy maps the Docker Desktop bridge gateway to `127.0.0.1` for the documented local allowlist behavior.

Start it with:

```powershell
docker compose up -d --build
```

### 3.2 Real AWS mode

Production-oriented mode uses `docker-compose.aws.yml`.

- LocalStack is removed from the stack.
- `AWS_ENDPOINT_URL` is empty.
- The normal AWS credential chain is used.
- `AWS_PROVISION_RESOURCES=false` makes the application validate resources and fail fast if they are absent.
- `AUTH_TOKEN_SECRET` and `GRAFANA_ADMIN_PASSWORD` must be supplied securely.
- AWS resources and IAM roles must already exist.

Start it with:

```powershell
docker compose -f docker-compose.aws.yml up -d --build
```

Read `AWS_DEPLOYMENT.md` before using this mode. The real-AWS path has been reviewed statically, but it has not been exercised against a live AWS account in this workspace.

## 4. Container inventory

| Compose service | Container | Image or build | Host port | Responsibility |
|---|---|---|---:|---|
| `frontend` | `centralwatch-frontend` | `nginx:1.27-alpine` | 8080 | Unified dashboard and reverse proxy |
| `demo-app` | `centralwatch-demo-app` | Built from `demo-app/Dockerfile` | 8000 | FastAPI APIs, proxy, scanner, AWS workflows, telemetry |
| `localstack` | `centralwatch-localstack` | `localstack/localstack:3.4.0` | 4566 | Local S3, DynamoDB, SNS, SQS, and Lambda |
| `otel-collector` | `centralwatch-otel-collector` | `otel/opentelemetry-collector-contrib:0.95.0` | 4317, 4318, 8889 | OTLP ingestion and telemetry export |
| `prometheus` | `centralwatch-prometheus` | `prom/prometheus:v2.49.1` | 9090 | Metrics storage and PromQL |
| `loki` | `centralwatch-loki` | `grafana/loki:2.9.4` | 3100 | Log storage and LogQL |
| `tempo` | `centralwatch-tempo` | `grafana/tempo:2.6.1` | 3200 | Trace storage and TraceQL |
| `grafana` | `centralwatch-grafana` | `grafana/grafana:12.4.0` | 3000 | Dashboards and exploration |

All services share the explicitly named Docker bridge network `centralwatch-network`.

## 5. URLs and access points

Use `127.0.0.1` on this Windows machine. Requests made through `localhost` currently hit a Windows/Docker Desktop loopback path that resets some connections.

| Interface | URL | Notes |
|---|---|---|
| Unified dashboard | http://127.0.0.1:8080 | Main entry point |
| Dashboard overview | http://127.0.0.1:8080/#overview | Service status and activity |
| API proxy page | http://127.0.0.1:8080/#proxy | Manage proxy services |
| Security scanner | http://127.0.0.1:8080/#security | Run and open ASTF reports |
| Embedded observability | http://127.0.0.1:8080/#observability | Grafana dashboards inside CentralWatch |
| Orders | http://127.0.0.1:8080/#orders | DynamoDB order workflow |
| Files | http://127.0.0.1:8080/#files | S3 and DynamoDB file workflow |
| AWS workflows | http://127.0.0.1:8080/#aws | SNS, SQS, and Lambda workflows |
| Simulations | http://127.0.0.1:8080/#simulations | Error, delay, AWS failure, and retry generation |
| FastAPI Swagger | http://127.0.0.1:8000/docs | Direct backend API documentation |
| Swagger through frontend | http://127.0.0.1:8080/docs | Redirects through Nginx to FastAPI |
| OpenAPI specification | http://127.0.0.1:8000/openapi.json | Machine-readable API schema |
| Grafana | http://127.0.0.1:3000 | Default local admin credentials: `admin` / `admin` |
| Prometheus | http://127.0.0.1:9090 | Metrics and target status |
| Loki readiness | http://127.0.0.1:3100/ready | Loki has an API, not a normal user dashboard |
| Tempo readiness | http://127.0.0.1:3200/ready | Use Grafana to explore traces |
| LocalStack | http://127.0.0.1:4566/_localstack/health | Local AWS health |
| Collector metrics | http://127.0.0.1:8889/metrics | Prometheus-format exported application metrics |
| OTLP gRPC | `127.0.0.1:4317` | Protocol endpoint, not a browser page |
| OTLP HTTP | `http://127.0.0.1:4318` | Protocol endpoint, not a dashboard |

## 6. Project directory structure

```text
API-Monitoring--1/
|-- frontend/dist/
|   |-- index.html                 Unified dashboard markup
|   |-- styles.css                 Light/dark themes and responsive UI
|   `-- app.js                     Routing, state, API calls, and interactions
|-- demo-app/
|   |-- Dockerfile                 Python 3.11, Java, curl, app dependencies
|   |-- entrypoint.sh              Waits for LocalStack and starts Uvicorn
|   |-- requirements.txt           Pinned Python dependencies
|   |-- .env.example               Application configuration reference
|   `-- app/
|       |-- main.py                FastAPI app, lifespan, middleware, routes
|       |-- deps.py                Service container and bearer dependencies
|       |-- config/settings.py     Environment-driven settings
|       |-- routes/                HTTP route handlers
|       |-- schemas/               Pydantic API contracts
|       |-- models/                User, order, and file models
|       |-- services/              Auth, AWS, storage, queues, Lambda
|       |-- telemetry/             Metrics, logs, traces, instrumentation
|       `-- utils/                 IDs and timestamps
|-- centralwatch-security/
|   |-- pyproject.toml             Installable FastAPI security package
|   |-- centralwatch_security/
|   |   |-- middleware.py          Token status and CIDR enforcement
|   |   `-- routers.py             Proxy and ASTF routes
|   `-- tests/                      Proxy and scanner tests
|-- configs/
|   |-- nginx/frontend.conf        Static serving, API proxy, health mesh
|   |-- collector/config.yaml      OTLP pipelines
|   |-- prometheus/prometheus.yml  Prometheus scrape configuration
|   |-- loki/loki-config.yaml      Loki storage and server configuration
|   |-- tempo/tempo.yaml           Tempo trace storage
|   `-- grafana/provisioning/      Datasources, dashboards, plugins, alerts
|-- scripts/
|   |-- start.sh                   Start development stack
|   |-- stop.sh                    Stop development stack
|   |-- healthcheck.sh             Deep health and scrape verification
|   `-- security_scan.sh           Download and run OWASP ASTF
|-- docker-compose.yml             LocalStack development stack
|-- docker-compose.aws.yml         Real AWS stack override
|-- .env.aws.example               Real AWS environment template
|-- README.md                      Main overview
|-- AWS_DEPLOYMENT.md              Detailed AWS and IAM guide
|-- PROXY_FEATURE_TESTING.md       Proxy-specific test guide
`-- CENTRALWATCH_PROJECT_GUIDE.md  This file
```

## 7. Unified dashboard

### 7.1 Current frontend technology

The current frontend is a static application written in HTML, CSS, and vanilla JavaScript. Nginx bind-mounts `frontend/dist` directly, so frontend edits appear without a JavaScript build step.

Some older comments describe the frontend as a prebuilt React SPA. The files currently executed by the browser do not require React, Node modules, or a bundler.

### 7.2 Dashboard sections

| Section | Purpose | Authentication |
|---|---|---|
| Overview | Shows eight system checks, proxy count, telemetry state, quick links, and browser-local activity | No |
| API proxy | Lists, searches, and registers managed upstream services | No CentralWatch token in the local demo |
| Security scan | Starts ASTF and opens the generated HTML report | Yes |
| AWS security agent | Reads the configured AWS security baseline and asks approval before selected fixes | Yes |
| Observability | Embeds seven Grafana dashboards and provides full-screen links | No in local mode because Grafana anonymous Viewer is enabled |
| Orders | Creates, lists, filters, sorts, and opens orders | Yes |
| Files | Uploads, lists, filters, sorts, views, downloads, and deletes files | Yes |
| AWS workflows | Publishes SNS notifications, sends/receives SQS messages, and runs image processing | Yes |
| Simulations | Generates deliberate HTTP 500, latency, S3 failure, and retry telemetry | Yes |

### 7.3 Browser state

The dashboard stores the following in browser `localStorage`:

- `cw-token`: current bearer token.
- `cw-activity`: recent actions performed from that browser.
- `centralwatch-theme`: `light` or `dark`.

The theme toggle also reloads the embedded Grafana iframe with the matching Grafana theme.

### 7.4 Nginx routing

| Browser path | Nginx behavior |
|---|---|
| `/` and hash routes | Serves `index.html` |
| `/styles.css` | Serves current CSS with cache disabled |
| `/app.js` | Serves current JavaScript with cache disabled |
| `/api/*` | Removes `/api` and proxies to `demo-app:8000` |
| `/api/centralwatch/security-scan` | Special proxy route with a 1,900-second read timeout |
| `/docs` | Redirects to `/api/docs` |
| `/openapi.json` | Proxies to FastAPI's OpenAPI document |
| `/system/demo` | Proxies to FastAPI health |
| `/system/grafana` | Proxies to Grafana health |
| `/system/prometheus` | Proxies to Prometheus readiness |
| `/system/loki` | Proxies to Loki readiness |
| `/system/tempo` | Proxies to Tempo readiness |
| `/system/localstack` | Proxies to LocalStack health |
| `/system/collector` | Proxies to Collector metrics |

The `/system/*` mesh allows the browser to check services through one origin without CORS problems.

## 8. FastAPI application lifecycle

At application startup:

1. Settings are loaded from environment variables.
2. Missing `AUTH_TOKEN_SECRET` causes an immediate startup failure.
3. OpenTelemetry providers are configured.
4. JSON and OTLP logging are configured.
5. Request logging and automatic FastAPI/botocore instrumentation are installed.
6. The application service container creates AWS clients and business services.
7. In LocalStack mode, required AWS resources are created idempotently.
8. In real AWS mode, required resources are validated instead.
9. A reconciliation loop periodically checks development resources.
10. The Lambda function is warmed in the background when appropriate.

The container starts one Uvicorn worker on port 8000. Proxy services and roles are shared through PostgreSQL; the current sanitized usage-history buffer is local to the worker process.

## 9. Authentication and request security

### 9.1 Account registration

`POST /auth/register` validates the request, checks the DynamoDB `email-index`, hashes the password with PBKDF2-HMAC-SHA256 using 100,000 iterations and a random salt, and writes the user to DynamoDB.

User records contain:

- `user_id`
- `email`
- `name`
- `created_at`
- `status`
- `allowed_cidrs`
- `password_hash` in storage only

### 9.2 Login and token format

`POST /auth/login` verifies the password and issues a stateless, URL-safe Base64 token containing:

```text
user_id.expiry_timestamp.HMAC_SHA256_signature
```

The signature uses `AUTH_TOKEN_SECRET`. The default lifetime is 86,400 seconds.

### 9.3 Protected endpoints

Protected routes require:

```http
Authorization: Bearer <token>
```

The route dependency verifies the token and loads the user profile. The security middleware also reads the profile policy:

- `status=REVOKED` returns HTTP 403.
- A client outside `allowed_cidrs` returns HTTP 403.
- Blocked events increment `centralwatch_security_violations_total` and add trace/log attributes.

### 9.4 Important security boundaries

- Authentication is suitable for the demonstration, but it is not an OAuth/OIDC implementation.
- Tokens are stateless and cannot be individually revoked without changing user status or the signing secret.
- The development Compose secret must not be used in shared or production environments.
- Grafana anonymous viewing is intended only for local dashboard embedding.

## 10. Complete API inventory

Direct backend URLs start with `http://127.0.0.1:8000`. Through the unified dashboard, prefix the same paths with `http://127.0.0.1:8080/api`.

### 10.1 Health and documentation

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | No | Redirects to Swagger |
| GET | `/docs` | No | Swagger UI |
| GET | `/openapi.json` | No | OpenAPI specification |
| GET | `/healthz` | No | Basic service health |
| GET | `/livez` | No | Liveness |
| GET | `/readyz` | No | AWS and proxy-database readiness |

### 10.2 Authentication

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/auth/register` | No | Create a DynamoDB-backed user |
| POST | `/auth/login` | No | Issue bearer token |
| GET | `/auth/profile` | Yes | Return current user |

### 10.3 Orders

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/orders` | Yes | Calculate total and create an order |
| GET | `/orders` | Yes | Return up to 50 orders |
| GET | `/orders/{order_id}` | Yes | Return one order |

### 10.4 Files

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/files/upload` | Yes | Upload to S3 and write DynamoDB metadata |
| GET | `/files` | Yes | Return up to 50 metadata records |
| GET | `/files/{file_id}` | Yes | Return metadata and a presigned S3 URL |
| DELETE | `/files/{file_id}` | Yes | Delete S3 object and DynamoDB metadata |

### 10.5 Notifications, queue, and images

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/notifications/email` | Yes | Publish email-style message through SNS |
| POST | `/notifications/sms` | Yes | Publish SMS-style message through SNS |
| POST | `/queue/send` | Yes | Send a message to SQS |
| GET | `/queue/messages` | Yes | Receive and delete up to 10 SQS messages |
| POST | `/images/process` | Yes | Upload to S3, invoke Lambda, publish SNS result |

### 10.6 Simulations

| Method | Path | Auth | Expected behavior |
|---|---|---|---|
| GET | `/simulate/error` | Yes | Deliberate HTTP 500 |
| GET | `/simulate/timeout` | Yes | Delayed successful response, default five seconds |
| GET | `/simulate/s3-error` | Yes | Deliberate AWS failure returned as HTTP 502 |
| GET | `/simulate/retry` | Yes | Retry sequence that succeeds after configured attempts |
| POST | `/chat` | CentralWatch proxy token | Send a prompt to Gemini through the managed proxy |

### 10.7 Security plugin

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/centralwatch/proxy/keys` | No in demo | List services with masked keys |
| POST | `/centralwatch/proxy/keys` | No in demo | Add or replace a proxy registration |
| GET/POST | `/centralwatch/proxy/roles` | No in demo | List or create service/method access roles |
| POST | `/centralwatch/proxy/keys/{service}/rotate-token` | No in demo | Rotate a service's proxy token and invalidate the old token |
| GET | `/centralwatch/proxy/history` | No in demo | Return recent sanitized API usage history |
| GET | `/centralwatch/proxy/metrics` | No in demo | Return aggregate proxy traffic metrics |
| Multiple | `/centralwatch/proxy/{service}/{path}` | IP allowlist + proxy token + role | Forward request with injected upstream credential |
| POST | `/centralwatch/security-scan?target_url=...` | Yes | Run OWASP ASTF synchronously |
| GET | `/centralwatch/security-scan/report` | Yes | Return latest report inline |

### 10.8 AWS minimum-security agent

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/security-agent/scan` | Yes | Run a read-only baseline scan of configured AWS resources |
| GET | `/security-agent/latest` | Yes | Return the latest in-memory scan |
| POST | `/security-agent/remediate` | Yes + explicit approval | Apply only selected failed controls and return a fresh scan |

Remediation is additionally controlled by `AWS_SECURITY_AGENT_ALLOW_REMEDIATION`. The request must reference a current scan, contain only failed/remediable finding IDs, set `confirm` to `true`, and use the exact acknowledgement `APPLY_SELECTED_REMEDIATIONS`. See `AWS_SECURITY_AGENT.md` for the complete security model and IAM permissions.

## 11. Managed API proxy

### 11.1 Registration model

Each proxy service contains:

```json
{
  "service_name": "test_service",
  "base_url": "https://jsonplaceholder.typicode.com",
  "api_key": "my_fake_secret_123",
  "allowed_ips": ["127.0.0.1", "10.0.0.0/8"],
  "role_name": "proxy_reader",
  "auth_type": "bearer",
  "timeout_seconds": 10
}
```

Validation rules include:

- Service names are 1-64 characters and use letters, numbers, underscores, or hyphens.
- Base URLs must be absolute HTTP or HTTPS URLs.
- Embedded URL credentials, query strings, and fragments are rejected.
- API keys cannot be blank or contain newlines.
- Every allowlist entry must be a valid IP address or CIDR.

### 11.2 Proxy request flow

1. An application calls CentralWatch without the upstream secret.
2. CentralWatch looks up the service name.
3. The direct client IP is checked against the configured networks.
4. The submitted proxy token is hashed and compared with the service's stored token hash.
5. The service's assigned role must permit both the service and HTTP method.
6. Allowed request headers, query parameters, method, and body are preserved.
7. CentralWatch injects either `Authorization: Bearer <managed-api-key>` or `x-goog-api-key: <managed-api-key>`, according to `auth_type`.
8. The request is sent to the registered upstream URL with the service's configured timeout.
9. Hop-by-hop response headers are removed before the response is returned.
10. A sanitized history record and request/latency metrics are emitted for successful and blocked attempts.

Example:

```powershell
curl.exe http://127.0.0.1:8000/centralwatch/proxy/test_service/users/1 -H "X-CentralWatch-Proxy-Token: <generated-proxy-token>"
```

Through Nginx:

```powershell
curl.exe http://127.0.0.1:8080/api/centralwatch/proxy/test_service/users/1 -H "X-CentralWatch-Proxy-Token: <generated-proxy-token>"
```

### 11.3 Proxy limitations

- Registrations are stored in the Python process and disappear when `demo-app` is recreated or restarted.
- Roles, service token hashes, and the latest 1,000 usage records are also process-local.
- Management endpoints are intentionally unauthenticated for the local demonstration.
- Upstream authentication supports Bearer tokens and Gemini's `x-goog-api-key` header.
- A production version needs encrypted persistent secret storage, admin authorization, durable audit history, token expiry, and rate limits.
- Caller-supplied `X-Forwarded-For` is not trusted by the proxy implementation.

### 11.4 Gemini chatbot flow

CentralWatch seeds an unusable `gemini_api` placeholder and a `gemini_chat` role that permits only POST. The dashboard replaces the placeholder with an operator-supplied Gemini key and receives a one-time proxy token. `POST /chat` then forwards the prompt through the local CentralWatch proxy, which injects `x-goog-api-key` and calls Gemini's `generateContent` endpoint. The Gemini key is never read from the demo application's environment. See `GEMINI_CHATBOT.md`.

## 12. OWASP ASTF security scanning

The demo-app image contains Java and curl. The scanner JAR is downloaded from the OWASP release on the first scan and stored at `/app/astf-v2.0.1.jar`.

The scan flow is:

1. An authenticated operator submits a target URL.
2. Nginx keeps the request open for up to 1,900 seconds.
3. FastAPI invokes `/scripts/security_scan.sh` in a worker thread.
4. The script downloads ASTF v2.0.1 if necessary.
5. ASTF scans the target and writes `/app/reports/security-report.html`.
6. Exit code 0 means completed with no findings.
7. Exit code 1 means completed with findings.
8. Exit code 2 or greater is treated as a scanner failure.
9. FastAPI verifies that the report exists and is non-empty.
10. The dashboard changes from Scanning to Complete or Findings and enables the report action.

The progress indicator is shown only while an actual scan request is active.

The default scan timeout is 1,800 seconds. The first run can take longer than later runs because it downloads the scanner.

CLI example:

```powershell
$body = '{"email":"operator@example.com","password":"secret123"}'
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType application/json -Body $body
$headers = @{ Authorization = "Bearer $($login.token)" }
Invoke-RestMethod -Method Post -Headers $headers -Uri "http://127.0.0.1:8000/centralwatch/security-scan?target_url=http%3A%2F%2F127.0.0.1%3A8000"
```

## 13. AWS resources and workflows

### 13.1 Resources

| Service | Default resource | Use |
|---|---|---|
| S3 | `centralwatch-files` | Uploaded files and images |
| DynamoDB | `users` | Accounts and password hashes |
| DynamoDB GSI | `email-index` | Login lookup by email |
| DynamoDB | `orders` | Order records |
| DynamoDB | `files` | File metadata |
| SNS | `centralwatch-notifications` | Email, SMS, and image-processing notifications |
| SQS | `centralwatch-queue` | Demo message workflow |
| Lambda | `centralwatch-image-processor` | Reads image, simulates work, publishes result |

### 13.2 Order workflow

1. The API validates at least one item.
2. Total is calculated from quantity times unit price.
3. A generated `ord_*` ID and timestamp are added.
4. The order is written to DynamoDB.
5. A business span and `orders.created_total` metric are emitted.

### 13.3 File workflow

1. File content is read from multipart upload.
2. The object is stored at `uploads/{file_id}/{filename}` in S3.
3. Metadata is written to DynamoDB.
4. Listing reads up to 50 metadata records.
5. Detail lookup creates a presigned S3 URL.
6. Delete removes both the S3 object and DynamoDB metadata.

### 13.4 Notification workflow

Email and SMS endpoints publish an SNS message with channel and recipient context. In LocalStack this demonstrates the AWS call and telemetry; it does not deliver a real external email or SMS.

### 13.5 Queue workflow

- Send writes a message to the configured SQS queue.
- Receive fetches up to 10 messages and deletes them after receipt.

### 13.6 Image-processing workflow

```text
Upload image
  -> store object in S3
  -> invoke Lambda synchronously
  -> Lambda reads S3 object
  -> Lambda simulates processing
  -> Lambda publishes result to SNS
  -> API returns processing result
```

LocalStack creates a Lambda runtime sidecar through the Docker socket. Its first invocation can be slow while the runtime image is prepared.

## 14. Observability pipeline

### 14.1 OpenTelemetry SDK

The FastAPI application sends all three signals through OTLP/HTTP:

- Traces: `/v1/traces`
- Metrics: `/v1/metrics`
- Logs: `/v1/logs`

Default container endpoint: `http://otel-collector:4318`.

Every signal receives resource attributes including:

- `service.name`
- `service.version`
- `deployment.environment`
- `cloud.provider=aws`
- `cloud.region`
- `host.name`
- `container.id`

### 14.2 Collector pipelines

The Collector applies memory limiting and batching, then exports:

| Signal | Destination |
|---|---|
| Metrics | Prometheus exporter on `otel-collector:8889` |
| Logs | Loki push API |
| Traces | Tempo through OTLP/gRPC |

Prometheus scrapes the Collector every five seconds.

### 14.3 Metrics

Important application metrics include:

- HTTP request count and duration from FastAPI instrumentation.
- `centralwatch_orders_created_total`
- `centralwatch_files_uploaded_total`
- `centralwatch_images_processed_total`
- `centralwatch_notifications_sent_total`
- `centralwatch_retry_attempts_total`
- `centralwatch_security_violations_total`
- `centralwatch_security_scans_total`
- `centralwatch_security_remediations_total`
- `centralwatch_proxy_requests_total`
- `centralwatch_proxy_request_duration_milliseconds_bucket`, `_sum`, and `_count`

The Collector's `centralwatch` namespace creates the final Prometheus names. Resource attributes are converted into metric labels.

### 14.4 Logs

Application logs are JSON to stdout and OTLP to Loki. They can contain:

- Timestamp and level.
- Logger and message.
- Service name.
- Trace and span IDs.
- Endpoint, method, status, and duration.
- AWS service and operation.
- Resource names and business context.
- Security event and blocked-client information.

Example LogQL:

```logql
{job="centralwatch-demo-app"} | json | trace_id != ""
{job="centralwatch-demo-app", level="ERROR"}
```

### 14.5 Traces

Tracing includes:

- Automatic FastAPI and ASGI server spans.
- Automatic botocore AWS spans.
- Manual business spans for registration, login, order creation, notification, image processing, and retry attempts.

Example TraceQL:

```traceql
{ resource.service.name = "centralwatch-demo-app" } && { name = "S3.PutObject" }
```

## 15. Grafana

Three datasources are provisioned automatically:

- Prometheus, UID `prometheus`
- Loki, UID `loki`
- Tempo, UID `tempo`

Seven dashboards are provisioned in the CentralWatch folder:

1. CentralWatch Overview
2. API Monitoring
3. AWS Services
4. Business Metrics
5. Application Logs
6. Distributed Tracing
7. Security and Threat Intelligence

The dashboard embeds these Grafana pages in kiosk mode with a 30-second refresh. Full-screen links open the same dashboard directly on port 3000.

New installations may initially show no data. Generate API traffic, wait for the metric export and Prometheus scrape intervals, then refresh Grafana.

## 16. Configuration reference

### 16.1 Application

| Variable | Development value | Meaning |
|---|---|---|
| `SERVICE_NAME` | `centralwatch-demo-app` | OTel and application service name |
| `SERVICE_VERSION` | `1.0.0` | Service version |
| `ENVIRONMENT` | `development` | Deployment environment resource label |
| `LOG_LEVEL` | `INFO` | Python log level |
| `AUTH_TOKEN_SECRET` | Dev default from Compose | Token signing secret |
| `TOKEN_TTL_SECONDS` | `86400` | Token lifetime |

### 16.2 AWS

| Variable | Development value | Meaning |
|---|---|---|
| `AWS_ENDPOINT_URL` | `http://localstack:4566` | Empty means real AWS |
| `AWS_REGION` | `us-east-1` | AWS region |
| `AWS_ACCESS_KEY_ID` | `test` | LocalStack credential |
| `AWS_SECRET_ACCESS_KEY` | `test` | LocalStack credential |
| `AWS_S3_ADDRESSING_STYLE` | `path` | Required by local S3 routing |
| `AWS_PROVISION_RESOURCES` | `true` | Create resources in development |
| `LAMBDA_ROLE_ARN` | Local placeholder ARN | Lambda role used during creation |
| `S3_BUCKET` | `centralwatch-files` | S3 bucket |
| `DYNAMODB_USERS_TABLE` | `users` | User table |
| `DYNAMODB_ORDERS_TABLE` | `orders` | Order table |
| `DYNAMODB_FILES_TABLE` | `files` | File table |
| `SNS_TOPIC` | `centralwatch-notifications` | SNS topic |
| `SQS_QUEUE` | `centralwatch-queue` | SQS queue |
| `LAMBDA_FUNCTION` | `centralwatch-image-processor` | Lambda function |

### 16.3 Telemetry and behavior

| Variable | Default | Meaning |
|---|---:|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4318` in Compose | Collector endpoint |
| `OTEL_METRICS_EXPORT_INTERVAL_MS` | `15000` | Metric export interval |
| `INIT_RECONCILE_INTERVAL_SECONDS` | `60` | Resource reconciliation interval |
| `LOCALSTACK_WAIT_TIMEOUT_SECONDS` | `120` | Startup wait |
| `SIMULATE_TIMEOUT_SECONDS` | `5` | Slow simulation duration |
| `SIMULATE_RETRY_ATTEMPTS` | `3` | Retry simulation attempts |
| `ASTF_SCAN_TIMEOUT_SECONDS` | `1800` | Scanner execution timeout |
| `PROXY_DOCKER_HOST_AS_LOOPBACK` | `true` in dev Compose | Docker Desktop loopback compatibility |
| `AWS_SECURITY_AGENT_ALLOW_REMEDIATION` | `true` in LocalStack dev; `false` in production | Server-side gate for approved AWS baseline changes; scans remain read-only |

Never commit a populated `.env` file containing production credentials or secrets.

## 17. Setup and operation

### 17.1 Prerequisites

- Docker Desktop or Docker Engine.
- Docker Compose v2 (`docker compose`, not `docker-compose` or `docker compoese`).
- Enough free memory for eight containers and the LocalStack Lambda sidecar.
- Internet access during the first image build and first ASTF scan.

Python is not required to run the normal Docker stack. The container uses Python 3.11.

### 17.2 Start

```powershell
Set-Location D:\API-Monitoring--1
docker compose up -d --build
docker compose ps
```

### 17.3 View logs

```powershell
docker compose logs --tail 200 demo-app
docker compose logs --tail 200 frontend
docker compose logs --tail 200 grafana
docker compose logs -f demo-app otel-collector
```

### 17.4 Restart selected services

```powershell
docker compose restart frontend demo-app grafana
```

### 17.5 Stop without deleting data

```powershell
docker compose down
```

### 17.6 Full data reset

This deletes named volumes and therefore removes LocalStack data, metrics, logs, traces, and Grafana state:

```powershell
docker compose down -v
```

Only use the volume-removal command when a full reset is intended.

## 18. End-to-end demonstration

### 18.1 Start and verify

```powershell
docker compose up -d --build
docker compose ps
curl.exe http://127.0.0.1:8000/healthz
curl.exe http://127.0.0.1:3000/api/health
curl.exe http://127.0.0.1:9090/-/ready
```

### 18.2 Register and sign in

Use the dashboard account button, or PowerShell:

```powershell
$register = @{
  email = "operator@example.com"
  password = "secret123"
  name = "Operator"
  allowed_cidrs = @("0.0.0.0/0", "::/0")
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/register -ContentType application/json -Body $register

$loginBody = @{ email = "operator@example.com"; password = "secret123" } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/auth/login -ContentType application/json -Body $loginBody
$headers = @{ Authorization = "Bearer $($login.token)" }
```

### 18.3 Create an order

```powershell
$order = @{
  user_id = $login.user.user_id
  items = @(@{ product_id = "p1"; name = "Widget"; quantity = 2; unit_price = 9.99 })
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Headers $headers -Uri http://127.0.0.1:8000/orders -ContentType application/json -Body $order
```

### 18.4 Exercise telemetry

```powershell
Invoke-RestMethod -Headers $headers -Uri http://127.0.0.1:8000/simulate/timeout
Invoke-RestMethod -Headers $headers -Uri http://127.0.0.1:8000/simulate/retry
```

The error simulations intentionally return error status codes:

```powershell
curl.exe -i -H "Authorization: Bearer $($login.token)" http://127.0.0.1:8000/simulate/error
curl.exe -i -H "Authorization: Bearer $($login.token)" http://127.0.0.1:8000/simulate/s3-error
```

Wait approximately 15-30 seconds, then inspect the Grafana dashboards.

### 18.5 Test the managed proxy

Register `test_service` from the dashboard, then run:

```powershell
curl.exe http://127.0.0.1:8000/centralwatch/proxy/test_service/users/1 `
  -H "X-CentralWatch-Proxy-Token: <generated-proxy-token>"
```

The request includes the one-time CentralWatch proxy token, not the managed third-party key.

The proxy forwards upstream calls through one shared asynchronous HTTP client per
application worker. Its bounded connection pool reuses TCP/TLS connections while
preserving each service's configured timeout and closes during application shutdown.

## 19. Persistence behavior

| Data | Storage | Survives restart | Survives `docker compose down` | Survives `down -v` |
|---|---|---|---|---|
| Users, orders, files metadata, local AWS state | `localstack-storage` | Yes | Yes | No |
| Uploaded local S3 objects | `localstack-storage` | Yes | Yes | No |
| Prometheus metrics | `prometheus-storage` | Yes | Yes | No |
| Loki logs | `loki-storage` | Yes | Yes | No |
| Tempo traces | `tempo-storage` | Yes | Yes | No |
| Grafana state | `grafana-storage` | Yes | Yes | No |
| Proxy services, roles, encrypted API keys, token hashes | `proxy-db-storage` (PostgreSQL) | Yes | Yes | No |
| Sanitized proxy usage history | Python process memory | No | No | No |
| Browser token, theme, activity | Browser localStorage | Yes | Yes | Not controlled by Docker |
| ASTF JAR and latest report | Demo-app container writable layer | Yes for simple restart | No after recreation | No |

## 20. Testing and validation

### 20.1 Security package tests

The test suite is in `centralwatch-security/tests`.

```powershell
python -m pytest centralwatch-security\tests -q --basetemp D:\API-Monitoring--1\.tmp\pytest-run
```

The Python environment running this command must have pytest and the package dependencies installed. The repository `.venv` currently does not include pytest; the Docker stack itself does not require host pytest.

Current verified result: 22 tests passed. A Starlette deprecation warning may appear and does not fail the suite.

### 20.2 Frontend checks

```powershell
node --check frontend\dist\app.js
docker compose exec -T frontend nginx -t
```

### 20.3 Service checks

```powershell
curl.exe -I http://127.0.0.1:8080/
curl.exe http://127.0.0.1:8000/healthz
curl.exe http://127.0.0.1:3000/api/health
curl.exe http://127.0.0.1:9090/-/ready
curl.exe http://127.0.0.1:3100/ready
curl.exe http://127.0.0.1:3200/ready
curl.exe http://127.0.0.1:4566/_localstack/health
curl.exe http://127.0.0.1:8889/metrics
```

At the last verification, the dashboard assets and all listed service endpoints returned HTTP 200 on `127.0.0.1`.

## 21. Troubleshooting

### 21.1 Browser says connection reset

Use:

```text
http://127.0.0.1:8080
```

Do not use `http://localhost:8080` on the affected Windows/Docker Desktop setup. The IPv4 address bypasses the resetting loopback route.

### 21.2 CSS or JavaScript appears stale

1. Open the `127.0.0.1` URL.
2. Hard-refresh with `Ctrl+F5`.
3. Confirm assets return HTTP 200:

```powershell
curl.exe -I http://127.0.0.1:8080/styles.css
curl.exe -I http://127.0.0.1:8080/app.js
```

Nginx disables caching for these files, and `frontend/dist` is bind-mounted. A rebuild is normally unnecessary for frontend-only edits.

### 21.3 Grafana does not load

```powershell
docker compose ps grafana
curl.exe http://127.0.0.1:3000/api/health
docker compose logs --tail 200 grafana
```

If Grafana works directly but not inside the dashboard, confirm `GF_SECURITY_ALLOW_EMBEDDING=true` and anonymous Viewer mode in the development Compose file.

### 21.4 Grafana shows no data

Generate application traffic first. Then verify:

```powershell
curl.exe http://127.0.0.1:8889/metrics
curl.exe http://127.0.0.1:9090/api/v1/targets
```

Allow time for the 15-second application metric export and five-second Prometheus scrape.

### 21.5 Security scanner stays on Scanning

The first scan downloads the ASTF JAR and can take several minutes. Check:

```powershell
docker compose logs --tail 300 demo-app
docker compose exec -T demo-app sh -c "ls -lah /app/astf-v2.0.1.jar /app/reports"
```

The UI hides the loading state in the request `finally` block, including failures. If the browser is indefinitely loading, verify it is using the current `app.js` and that Nginx has the long scanner timeout route.

### 21.6 Image processing remains pending or fails

The LocalStack Lambda sidecar may need to pull a runtime image on first use.

```powershell
docker compose logs --tail 300 localstack demo-app
docker compose restart localstack demo-app
```

On Docker Desktop, the configured socket is `/run/host-services/docker.proxy.sock`. On Linux, set:

```powershell
$env:DOCKER_SOCK_PATH = "/var/run/docker.sock"
docker compose up -d
```

### 21.7 `centralwatch-network` is still in use after Compose down

Another container is still attached to the network. Find it with:

```powershell
docker network inspect centralwatch-network
docker ps -a --filter network=centralwatch-network
```

Remove or disconnect only the specific stale container. `docker compose down` cannot delete a network that still has attached endpoints.

### 21.8 Port already in use

Identify the process or container using the port, or change only the host side of the Compose mapping. For example:

```yaml
ports:
  - "8081:80"
```

Internal container ports and service-to-service URLs should remain unchanged.

### 21.9 Demo app fails with `AUTH_TOKEN_SECRET` error

Set a value before starting. Use a strong random secret outside local development.

```powershell
$env:AUTH_TOKEN_SECRET = "replace-with-a-secure-random-value"
docker compose up -d --build demo-app
```

### 21.10 Collector cannot resolve another service

Recreate the stack so every container joins the same explicit network:

```powershell
docker compose down
docker compose up -d --build
```

## 22. Production readiness notes

Before exposing CentralWatch outside a trusted development environment:

- Protect and back up `PROXY_SECRET_ENCRYPTION_KEY` separately from PostgreSQL; define a tested key-rotation procedure.
- Require TLS for external PostgreSQL connections and configure restricted database credentials, backups, and restore testing.
- Require administrative authorization for proxy registration and listing.
- Add key rotation, deletion, ownership, audit trails, and rate limiting.
- Replace the custom token scheme with an appropriate identity provider if required.
- Disable Grafana anonymous access and use secure embedding or authenticated access.
- Supply strong secrets through a secret manager.
- Use TLS at the ingress.
- Configure trusted proxy IPs before relying on forwarded client addresses.
- Apply the IAM policies documented in `AWS_DEPLOYMENT.md`.
- Configure backups, retention, alert receivers, and production storage for telemetry.
- Review CORS, CSP, upload limits, request size limits, and egress restrictions.
- Pin and regularly update dependencies and container images.
- Run the real-AWS validation and end-to-end test against the target AWS account.

## 23. How to extend the project

### Add a FastAPI endpoint

1. Add or update a schema in `demo-app/app/schemas`.
2. Add a route module in `demo-app/app/routes`.
3. Put AWS/business behavior in `demo-app/app/services`.
4. Protect business routes with `Depends(require_auth)`.
5. Register the router in `demo-app/app/main.py`.
6. Add business metrics only when automatic HTTP telemetry is insufficient.
7. Add tests and verify the OpenAPI document.

### Add a dashboard workflow

1. Add markup to `frontend/dist/index.html`.
2. Add styles using existing semantic CSS variables in `frontend/dist/styles.css`.
3. Add API calls and events in `frontend/dist/app.js`.
4. Preserve existing element IDs used by JavaScript.
5. Add loading, empty, success, and error states.
6. Test light theme, dark theme, desktop, and narrow layouts.
7. Verify assets through `http://127.0.0.1:8080`.

### Add a Grafana dashboard

1. Add the JSON model under `configs/grafana/provisioning/dashboards`.
2. Use the provisioned datasource UIDs.
3. Add its tab path to `frontend/dist/index.html` if it should be embedded.
4. Recreate or restart Grafana.
5. Verify queries against actual metric, log, or trace labels.

## 24. Related documentation

- `README.md`: concise setup and feature overview.
- `CENTRALWATCH_END_TO_END.md`: previous end-to-end architecture report.
- `FullProjectDoc.md`: earlier detailed codebase report.
- `AWS_DEPLOYMENT.md`: AWS resources, IAM policies, and production runbook.
- `AWS_SECURITY_AGENT.md`: minimum-security controls, permission gates, IAM actions, and usage.
- `PROXY_FEATURE_TESTING.md`: focused proxy testing instructions.
- `CENTRALWATCH_AWS_INTEGRATION_READINESS_REPORT.md`: AWS readiness analysis.
- `milestone1.md` through `milestone5.md`: historical milestone notes.

## 25. Current verification summary

At the time this guide was created:

- All eight Compose services were running.
- The stateful services and demo app reported healthy where health checks exist.
- The unified dashboard, CSS, JavaScript, backend docs, Grafana, Prometheus, Loki, Tempo, LocalStack, and Collector endpoints responded successfully through `127.0.0.1`.
- Nginx configuration validation passed.
- Frontend JavaScript syntax validation passed.
- All static JavaScript ID references resolved to elements in the dashboard markup.
- The demo application and `centralwatch-security` suites passed all 18 tests.
- No commit or push was performed as part of the local work.

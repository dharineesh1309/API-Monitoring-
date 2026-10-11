# CentralWatch

CentralWatch is an end-to-end **observability demo**: a FastAPI application (`demo-app`) that
performs real business workflows against AWS and generates rich OpenTelemetry telemetry —
metrics, logs, and traces — which flow through an OpenTelemetry Collector into
**Prometheus** (metrics), **Loki** (logs) and **Tempo** (traces), visualized in **Grafana**.

The monitoring system is a **bystander**. It never sits in the application's request path:

```
                      Application traffic
  Browser ──> nginx (frontend) ──/api──> FastAPI (demo-app) ──boto3──> AWS
                                                    │
                                        OpenTelemetry SDK (OTLP over HTTP)
                                                    │
                                             otel-collector :4318
                                              ┌──────┼──────┐
                                              ▼      ▼      ▼
                                         Prometheus  Loki  Tempo
                                              └──────┼──────┘
                                                     ▼
                                                  Grafana
```

Two runtime modes are supported with **the same codebase** (everything is environment-driven):

| Mode | `AWS_ENDPOINT_URL` | `AWS_PROVISION_RESOURCES` | Backend |
| :--- | :--- | :--- | :--- |
| **LocalStack (dev, default)** | `http://localstack:4566` | `true` — resources auto-created | offline emulator |
| **Real AWS (production)** | empty | `false` — resources validated, fail fast | real AWS |

---

## 1. Quick start (LocalStack / dev)

Requires Docker + Docker Compose v2 only — **no pre-built images, no manually created
networks, no pre-created resources**.

```bash
docker compose up -d --build
```

This builds and starts all 9 services on one shared network (`centralwatch-network`):

| Service | Container | Host port | Purpose |
| :--- | :--- | :--- | :--- |
| `proxy-db` | `centralwatch-proxy-db` | internal only | PostgreSQL store for proxy services, roles, encrypted API keys, and token hashes |
| `frontend` | `centralwatch-frontend` | `8080` | Serves the built React SPA, proxies `/api/*` → backend |
| `demo-app` | `centralwatch-demo-app` | `8000` | FastAPI app (`/docs` for Swagger) |
| `localstack` | `centralwatch-localstack` | `4566` | AWS emulation (S3, DynamoDB, SNS, SQS, Lambda) |
| `otel-collector` | `centralwatch-otel-collector` | `4317`/`4318`/`8889` | OTLP ingress, Prometheus endpoint |
| `prometheus` | `centralwatch-prometheus` | `9090` | Metrics store + query |
| `loki` | `centralwatch-loki` | `3100` | Logs store + query |
| `tempo` | `centralwatch-tempo` | `3200` | Traces store + TraceQL |
| `grafana` | `centralwatch-grafana` | `3000` | Dashboards (`admin` / `admin` by default) |

The demo app waits for LocalStack, then **auto-provisions** (idempotently): S3 bucket
`centralwatch-files`, DynamoDB tables `users` (with `email-index` GSI), `orders`, `files`,
SNS topic `centralwatch-notifications`, SQS queue `centralwatch-queue`, and Lambda function
`centralwatch-image-processor`. A reconcile loop re-creates anything that disappears.

Verify:

```bash
./scripts/healthcheck.sh          # deep health of every component
curl -s http://localhost:8000/healthz
curl -s http://localhost:8080/    # frontend
```

## 2. Authentication

Business endpoints (`/orders`, `/files`, `/images`, `/notifications`, `/queue`,
`/simulate`) require a **Bearer token** issued by `/auth/login`. Public endpoints:
`/auth/register`, `/auth/login`, `/healthz`, `/livez`, `/readyz`, `/docs`.

```bash
# Register + login
curl -s -X POST http://localhost:8000/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"secret123","name":"Alice"}'
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"secret123"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Protected call
curl -s -X POST http://localhost:8000/orders -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"usr_demo","items":[{"product_id":"p1","name":"Widget","quantity":2,"unit_price":9.99}]}'

# Without a token you get 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8000/orders \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"x","items":[{"product_id":"p1","name":"W","quantity":1,"unit_price":1}]}'
```

Tokens are HMAC-signed (PBKDF2-hashed passwords, stateless tokens). The signing secret comes
from **`AUTH_TOKEN_SECRET`** — there is no default in code and the app **fails fast** at
startup if it is missing. The dev compose ships a documented dev-only default; the AWS compose
requires it with no default (see [AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md)).

## 3. Real AWS mode (production)

See **[AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md)** for the complete guide: the exact AWS resources
the code uses, least-privilege IAM policies (app role + Lambda execution role), and the
production compose file:

```bash
docker compose -f docker-compose.aws.yml up -d --build
```

In production mode the app **validates** every required resource at startup and exits with a
clear error if any are missing. `AUTH_TOKEN_SECRET` and `GRAFANA_ADMIN_PASSWORD` are required
(no defaults).

A ready-to-fill template with every real-AWS variable is provided at **`.env.aws.example`**
(copy it to `.env` for `docker compose` substitution, or to `demo-app/.env` for a bare uvicorn
run). Never commit the filled-in file — `.env` is gitignored.

> **Real-AWS verification status:** the real-AWS code path (empty endpoint, default credential
> chain, `AWS_PROVISION_RESOURCES=false` validation) is verified statically against the exact
> SDK calls in the source. It has **not** been exercised against a live AWS account in this
> environment — see the limitation note in `AWS_DEPLOYMENT.md`.

## 4. Unified CentralWatch dashboard

The `frontend/dist/` directory contains the static CentralWatch control plane. `nginx` serves it
at `http://127.0.0.1:8080`, proxies `/api/*` to FastAPI, and exposes same-origin `/system/*`
health checks for the Docker services. The dashboard combines live service status, centralized
proxy registration, authenticated OWASP scans, a permission-gated AWS minimum-security agent,
embedded Grafana dashboards, and the complete
demo-app workflow set: authentication, orders, files, notifications, queues, image processing,
and telemetry simulations. No separate frontend build step is required.

### AWS minimum-security agent

Open `http://127.0.0.1:8080/#aws-security` after signing in. The agent performs a read-only scan of the configured S3 bucket, DynamoDB tables, SQS queue, SNS topic, and Lambda function. It reports minimum-security gaps for public access, encryption, recovery/versioning, and tracing.

The agent does not make changes during a scan. Applying a fix requires the server policy `AWS_SECURITY_AGENT_ALLOW_REMEDIATION=true`, selected failed findings, an explicit dashboard confirmation, `confirm: true`, and the exact acknowledgement `APPLY_SELECTED_REMEDIATIONS`. Production Compose defaults remediation to disabled. See [`AWS_SECURITY_AGENT.md`](AWS_SECURITY_AGENT.md) for the complete baseline, API, IAM permissions, and operational limits.

## 5. Telemetry contract (what the dashboards query)

### Metrics (Prometheus — via the Collector's `centralwatch` namespace)

| Metric | Labels |
| :--- | :--- |
| `centralwatch_http_server_duration_milliseconds_{bucket,sum,count}` | `http_method`, `http_status_code`, `http_target`, `service`, `instance`, `deployment_environment` |
| `centralwatch_orders_created_total` | `status` |
| `centralwatch_files_uploaded_total` | `status` |
| `centralwatch_images_processed_total` | `status` |
| `centralwatch_notifications_sent_total` | `channel`, `status` |
| `centralwatch_retry_attempts_total` | `operation` |
| `centralwatch_security_scans_total` | `environment`, `result` |
| `centralwatch_security_remediations_total` | `service`, `check_id`, `status` |
| `centralwatch_proxy_requests_total` | `service`, `method`, `status_code`, `outcome`, `role` |
| `centralwatch_proxy_request_duration_milliseconds_{bucket,sum,count}` | `service`, `method`, `status_code`, `outcome`, `role` |

> The `environment` label is emitted as **`deployment_environment`** (the collector's
> `resource_to_telemetry_conversion` copies the app's `deployment.environment` resource
> attribute onto every metric) — `development` in dev mode, `production` on real AWS.
>
> **Label semantics:** in Prometheus the `service` label is the scrape-job static label (`centralwatch-collector`, the exporter hosting `/metrics`), while `service_name` is the app's OTel resource attribute (`centralwatch-demo-app`). In Tempo, `service.name` is the app (`centralwatch-demo-app`). Dashboards are consistent with this per datasource.


### Logs (Loki)

Labels: `job` (= `service.name`), `level` (**uppercase**: `INFO`/`ERROR`/`WARN`), `exporter`.
Every line is structured JSON with `traceid` / `spanid`, `endpoint`, `http.method`,
`status_code`, `duration_ms`, plus AWS fields (`aws.service`, `aws.operation`, `channel`, …).
`traceid` and `endpoint` are **JSON fields** — query them with the `| json` parser:

```logql
{job="centralwatch-demo-app"} | json | traceid != ""
{job="centralwatch-demo-app", level="ERROR"}
```

### Traces (Tempo)

`service.name=centralwatch-demo-app`. Automatic FastAPI/ASGI server spans, botocore AWS spans
(`S3.PutObject`, `S3.GetObject`, `S3.DeleteObject`, `S3.ListBuckets`, `DynamoDB.PutItem`,
`DynamoDB.GetItem`, `DynamoDB.Query`, `DynamoDB.Scan`, `DynamoDB.DeleteItem`, `centralwatch-notifications send`,
`SQS.SendMessage`, `SQS.ReceiveMessage`, `SQS.DeleteMessageBatch`, `Lambda.Invoke`), and manual
business spans (`User Registration`, `User Login`, `Order Creation`, `Notification Workflow`,
`Image Processing Workflow`, `Retry Operation` → `Retry Attempt N`).

```traceql
{ resource.service.name = "centralwatch-demo-app" } && { name = "S3.PutObject" }
```

## 6. Grafana dashboards

Seven dashboards are provisioned into the **CentralWatch** folder (auto-loading via
`configs/grafana/provisioning/`):

1. **CentralWatch — Overview** (`overview.json`) — requests/sec, avg/P95/P99 latency, error &
   success rate, business totals.
2. **CentralWatch — API Monitoring** (`api-monitoring.json`) — requests by route/method/status,
   latency by route, error rate, duration histogram, top slow APIs.
3. **CentralWatch — AWS Services** (`aws-services.json`) — S3/Lambda/SNS/SQS/DynamoDB trace
   tables + waterfall.
4. **CentralWatch — Business Metrics** (`business-metrics.json`) — orders/files/images/
   notifications/retries with `channel`/`status`/`operation` breakdowns.
5. **CentralWatch — Tracing** (`tracing.json`) — recent/slowest traces, AWS & business span
   segments, waterfall.
6. **CentralWatch — Logs** (`logs.json`) — recent logs, ERROR/WARN streams, logs-by-traceid,
   logs-by-endpoint.
7. **Security & Threat Intelligence** (`security.json`) — blocked-request metrics, structured
   security logs, and a link to the authenticated OWASP scan control.

## 7. Health checks

```bash
./scripts/healthcheck.sh          # all containers + readiness + Prometheus scrape targets
curl -s http://localhost:8000/healthz    # liveness
curl -s http://localhost:8000/livez      # liveness
curl -s http://localhost:8000/readyz     # readiness (checks AWS and proxy database reachability)
```

## 8. Troubleshooting

| Symptom | Cause / fix |
| :--- | :--- |
| `Failed to resolve 'otel-collector'` in app logs | containers on different networks — recreate with `docker compose down && docker compose up -d --build` (the compose file pins one explicit network) |
| `/images/process` returns 502/`Pending` Lambda | first Lambda sidecar pull is slow on LocalStack; the app warms it up in the background — wait ~60 s and retry. If permanently `Pending`, `docker compose restart localstack demo-app` |
| Lambda needs the Docker socket | required **only** in LocalStack mode. Docker Desktop path `/run/host-services/docker.proxy.sock`; on Linux set `DOCKER_SOCK_PATH=/var/run/docker.sock` |
| Grafana dashboards show "No data" | generate traffic first (see §2 / `AWS_DEPLOYMENT.md` runbook), then check Prometheus `http://localhost:9090` for `centralwatch_*` series |
| Tempo panels empty | traces are retained per the tempo config; re-run `/images/process` etc. and refresh |
| `AUTH_TOKEN_SECRET` startup error | set the env var (dev: any value; prod: strong secret) |
| Port already in use | change the host mapping in `docker-compose.yml` (`8000:8000` → `8010:8000`, …) |

## 9. Project layout

```
├── demo-app/                    # FastAPI application (built by Docker, no pre-built image)
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── requirements.txt
│   ├── .env.example
│   └── app/
│       ├── main.py              # app factory, middleware, exception handlers
│       ├── deps.py              # DI container + auth dependency
│       ├── config/              # pydantic-settings
│       ├── routes/              # auth, orders, files, images, notifications, queue, simulate
│       ├── services/            # boto3 clients + AWS resource manager + Lambda code
│       ├── telemetry/           # instrumentation, logging, metrics, tracing
│       ├── models/ schemas/ utils/
├── configs/
│   ├── collector/config.yaml    # OTel collector pipelines
│   ├── prometheus/prometheus.yml
│   ├── loki/loki-config.yaml
│   ├── tempo/tempo.yaml
│   ├── nginx/frontend.conf
│   └── grafana/provisioning/    # datasources + 6 dashboards
├── frontend/dist/               # unified CentralWatch control-plane dashboard
├── scripts/                     # start.sh, stop.sh, healthcheck.sh
├── docker-compose.yml           # dev stack (LocalStack)
├── docker-compose.aws.yml       # production stack (real AWS)
└── AWS_DEPLOYMENT.md            # resources, IAM, production runbook
```

## 10. CentralWatch Security Plugin

We provide an enterprise-grade API Security plugin built as a standalone Python package: `centralwatch-security`. This plugin provides:
- **Hybrid Security Gateway:** Automatic IP CIDR whitelisting and API Key Revocation checks via a generic middleware.
- **OWASP ASTF Scanner Trigger:** A built-in FastAPI router to trigger automated OWASP API Top 10 vulnerability scans (`/security-scan`).
- **Managed API Proxy:** IP/CIDR-authorized upstream requests with server-side Bearer or API-key-header injection (`/proxy`).
- **Telemetry Integration:** Automatic logging of security violations into OpenTelemetry traces and Loki.

### Managed API proxy

The proxy dashboard is available at `http://127.0.0.1:8080/#proxy`. It registers an
upstream base URL, secret key, caller allowlist, and service/method role through
`POST /centralwatch/proxy/keys`. Registration returns a separate proxy access token
once; CentralWatch stores only its SHA-256 hash. Applications call
`/centralwatch/proxy/{service}/{path}` with that token in
`X-CentralWatch-Proxy-Token`, without storing or sending the upstream key.
`GET /centralwatch/proxy/keys` returns only masked key values and token hints.

The same dashboard displays sanitized API usage history and aggregate totals for
requests, successes, policy blocks, errors, bytes, methods, status codes, average/P95
latency, and per-service traffic. OpenTelemetry exports proxy request and duration
metrics into the existing Prometheus pipeline.

Upstream traffic uses one lifecycle-managed asynchronous HTTP client per application
worker. Connections are pooled and reused by origin (up to 100 active connections and
20 idle keep-alive connections, with a 30-second idle expiry), avoiding a new TCP/TLS
setup for every proxied request. Each service's configured timeout still applies to
every request, redirects remain disabled, and the pool closes cleanly on shutdown.

Registrations, roles, and token hashes are persisted in CentralWatch's PostgreSQL
database. Upstream API keys are encrypted with AES-256-GCM in the application before
they are stored; the encryption key is supplied separately through
`PROXY_SECRET_ENCRYPTION_KEY`. Sanitized usage history remains in process memory.
The local demo exposes management without a CentralWatch bearer token so the dashboard
works immediately. Add administrative authentication before exposing management
endpoints to a network. See `PROXY_FEATURE_TESTING.md` for the tested Docker workflow,
key-management requirements, and Docker Desktop loopback behavior.

### Gemini chatbot

Open `http://127.0.0.1:8080/#chat` to configure and use the demo chatbot. The
predefined `gemini_chat` role permits only POST requests to the `gemini_api`
service. The Gemini key is stored by CentralWatch, while the demo application
uses a separate proxy token. CentralWatch injects the key as `x-goog-api-key`
and returns Gemini's generated text through `POST /chat`. See
`GEMINI_CHATBOT.md` for setup and security boundaries.

### Installation
You can install the plugin in any FastAPI project locally:
```bash
pip install -e ./centralwatch-security
```

### Running the ASTF scan in CentralWatch

In the Docker image, the scanner runtime includes Java and `curl`. The first scan
downloads the official OWASP ASTF v2.0.1 JAR. A scan runs synchronously and the API
returns success only after ASTF has completed and written a non-empty HTML report.

The CentralWatch application protects this endpoint with the same bearer-token and
CIDR enforcement as the other business endpoints:

For the normal dashboard flow, open
`http://127.0.0.1:8080/#security-scan`, create or sign in to an operator
session, and select **Trigger security scan**. When it finishes, select
**Open HTML report**. The Security Grafana dashboard's scan button opens this
same authenticated control.

The equivalent CLI flow is:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
   -H 'Content-Type: application/json' \
   -d '{"email":"alice@example.com","password":"secret123"}' \
   | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -s -X POST \
   'http://127.0.0.1:8000/centralwatch/security-scan?target_url=http://127.0.0.1:8000' \
   -H "Authorization: Bearer $TOKEN"
```

The report is generated inside the demo-app container at
`/app/reports/security-report.html`. ASTF exit code `0` means no findings; exit code
`1` means the scan completed with findings. Both are successful scan executions when
the report exists and is non-empty. Download, Java, execution, timeout, exit code `2+`,
missing-report, and empty-report failures return an error response.

Verify the generated report:

```bash
docker exec centralwatch-demo-app sh -c "ls -lah /app/reports/"
docker exec centralwatch-demo-app sh -c \
   "test -s /app/reports/security-report.html && echo 'REPORT EXISTS'"
```

The authenticated dashboard retrieves the report through
`GET /centralwatch/security-scan/report`. You can also copy it directly from the
container. On Windows, run this from the repository root to save it as
`D:\API-Monitoring--1\security-report.html`:

```powershell
docker cp centralwatch-demo-app:/app/reports/security-report.html .\security-report.html
```

You can then open `security-report.html` locally with a browser or inspect its first
lines with:

```powershell
Get-Content .\security-report.html -TotalCount 20
```

### Usage in FastAPI
In your FastAPI application (`main.py`):
```python
from fastapi import FastAPI, Request
from centralwatch_security import SecurityEnforcementMiddleware, proxy_router, security_router

app = FastAPI()

# 1. Define how your app retrieves policies (from a DB like DynamoDB or Postgres)
async def fetch_user_security_policy(request: Request):
    # Retrieve user token from header, fetch from DB
    # Example return format:
    return {
        "status": "ACTIVE",              # or "REVOKED"
        "allowed_cidrs": ["10.0.0.0/8"], # list of allowed IPs
        "user_id": "usr_123"
    }

# 2. Attach the Middleware
app.add_middleware(
    SecurityEnforcementMiddleware, 
    get_policy_callback=fetch_user_security_policy
)

# 3. Mount the OWASP Scanner Endpoint
app.include_router(security_router, prefix="/centralwatch")

# 4. Mount the managed proxy endpoints
app.include_router(proxy_router, prefix="/centralwatch")
```

### Testing the Plugin
To test the plugin locally:
1. Ensure the package is installed: `pip install -e centralwatch-security`.
2. Start your FastAPI server.
3. Make a request from an IP address not listed in `allowed_cidrs` (e.g., `192.168.1.5`).
4. You will receive a `403 Forbidden` with the message: `Access denied: IP outside allowed subnet`.
5. Check your Loki logs and OpenTelemetry traces to see the generated `IP_SUBNET_VIOLATION` security event.

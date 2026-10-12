# CentralWatch Demo App

A production-style **FastAPI demo application** for the [CentralWatch](../README.md) observability
stack. It does **not** perform monitoring — it **generates** realistic telemetry:

```
                    FastAPI Demo Application
                              │
                  OpenTelemetry Python SDK
                              │
                              ▼
                OpenTelemetry Collector
          ┌────────────┬─────────────┬────────────┐
          ▼            ▼             ▼            │
     Prometheus      Loki         Tempo           │
     Metrics         Logs         Traces          │
          └────────────┼────────────┘             │
                       ▼                          │
                    Grafana                       │
```

By default all AWS SDK calls (`boto3`) go to **LocalStack**, so the entire demo
runs **fully offline** — no real AWS account, no cloud credentials. The same
backend also runs against **real AWS**: leave `AWS_ENDPOINT_URL` empty, provide
AWS credentials, pre-create the resources, and set `AWS_PROVISION_RESOURCES=false`
(the app validates them at startup). See **[AWS_DEPLOYMENT.md](../AWS_DEPLOYMENT.md)**
for the complete guide.

---

## 1. Quick start (already integrated)

```bash
cd ..                       # project root
docker compose up -d        # starts the whole platform, including this app
```

The app waits for LocalStack to become healthy, then **automatically creates**:

| Resource            | Name                          |
| :------------------ | :---------------------------- |
| S3 bucket           | `centralwatch-files`          |
| DynamoDB tables     | `users`, `orders`, `files`    |
| SNS topic           | `centralwatch-notifications`  |
| SQS queue           | `centralwatch-queue`          |
| Lambda function     | `centralwatch-image-processor`|

Creation is **idempotent**: it runs at startup, on a periodic reconciliation loop
(60 s), and safely recreates resources after LocalStack restarts. No manual setup.

> **Real AWS mode:** the auto-provisioning above runs when `AWS_PROVISION_RESOURCES=true`
> (the LocalStack/dev default in `docker-compose.yml`). For real AWS set it to `false`
> and pre-create the resources — the app validates them at startup and fails fast.
> See [AWS_DEPLOYMENT.md](../AWS_DEPLOYMENT.md).

### Run locally (outside Docker)

Use Python **3.11**, which is also the version used by the Docker image. From the
repository root on Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\demo-app\requirements.txt
python -m pip install -e .\centralwatch-security

# The host-run app still needs these two Docker services.
docker compose up -d localstack otel-collector
Copy-Item .\demo-app\.env.example .\demo-app\.env

# Configure demo-app/.env for local development:
# AWS_ENDPOINT_URL=http://127.0.0.1:4566
# AWS_ACCESS_KEY_ID=test
# AWS_SECRET_ACCESS_KEY=test
# AWS_S3_ADDRESSING_STYLE=path
# AWS_PROVISION_RESOURCES=true
# LAMBDA_ROLE_ARN=arn:aws:iam::000000000000:role/centralwatch-lambda-role
# OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
# AUTH_TOKEN_SECRET=choose-a-local-development-secret

Set-Location .\demo-app
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

If the Compose `demo-app` is already running, port 8000 is occupied. Stop that
one service first (`docker compose stop demo-app`) or use `--port 8001` for the
venv process. Activating the venv starts only FastAPI; Grafana, the frontend,
Prometheus, Loki, Tempo, LocalStack, and the collector are Docker services.

---

## 2. API surface

Interactive docs: **http://localhost:8000/docs** (Swagger UI)

> **Auth:** every business endpoint below (files, orders, notifications, queue, images,
> simulate) requires `Authorization: Bearer <token>` from `/auth/login` (401 without it).
> Public: `/auth/register`, `/auth/login`, `/auth/profile` (with token), health endpoints, `/docs`.

| Method | Endpoint                  | Backing AWS service | Notes                                   |
| :----- | :------------------------ | :------------------ | :-------------------------------------- |
| POST   | `/auth/register`          | DynamoDB            | PBKDF2-hashed password                  |
| POST   | `/auth/login`             | DynamoDB            | Returns HMAC-signed bearer token        |
| GET    | `/auth/profile`           | DynamoDB            | `Authorization: Bearer <token>`         |
| POST   | `/files/upload`           | S3 + DynamoDB       | Multipart upload, metadata in DynamoDB  |
| GET    | `/files/{id}`             | S3                  | Returns presigned download URL          |
| DELETE | `/files/{id}`             | S3 + DynamoDB       | Removes object + metadata               |
| POST   | `/orders`                 | DynamoDB            | Business span "Order Creation"          |
| GET    | `/orders`                 | DynamoDB            | Scan                                  |
| GET    | `/orders/{id}`            | DynamoDB            | GetItem                                 |
| POST   | `/notifications/email`    | SNS                 | Business span "Notification Workflow"   |
| POST   | `/notifications/sms`      | SNS                 | Business span "Notification Workflow"   |
| POST   | `/queue/send`             | SQS                 | SendMessage                             |
| GET    | `/queue/messages`         | SQS                 | Receive + delete                        |
| POST   | `/images/process`         | S3 → Lambda → SNS   | Distributed trace workflow              |
| GET    | `/simulate/error`         | —                   | Deliberate 500                          |
| GET    | `/simulate/timeout`       | —                   | Sleeps `SIMULATE_TIMEOUT_SECONDS` (5 s) |
| GET    | `/simulate/s3-error`      | S3 (bad bucket)     | Deliberate AWS failure (502)            |
| GET    | `/simulate/retry`         | S3                  | Throttled twice, then succeeds          |
| POST   | `/chat`                   | CentralWatch + Gemini | Requires `X-CentralWatch-Proxy-Token`  |
| GET    | `/healthz` `/livez` `/readyz` | S3 (readyz)     | Liveness/readiness probes               |

---

## 3. Telemetry design

| Signal   | How it is produced                                                                       | Where it lands        |
| :------- | :--------------------------------------------------------------------------------------- | :-------------------- |
| **Metrics** | Automatic FastAPI/ASGI HTTP metrics (request count, duration, P95/P99, error rate, active requests) + business counters `centralwatch.orders.created_total`, `centralwatch.images.processed_total`, `centralwatch.notifications.sent_total`, `centralwatch.retry.attempts_total`, `centralwatch.files.uploaded_total` | OTLP → Collector → Prometheus |
| **Logs** | Structured JSON (stdout) + OTLP log records. Every record carries `trace_id` / `span_id`, `service.name`, `endpoint`, `method`, `status_code`, `duration_ms`, AWS service/operation, exception details | OTLP → Collector → Loki |
| **Traces** | Automatic FastAPI/ASGI server spans; automatic `botocore` spans (`S3.PutObject`, `DynamoDB.PutItem`, `SNS.Publish`→`centralwatch-notifications send`, `SQS.SendMessage`, `Lambda.Invoke`, …); manual business spans only for complex workflows (User Registration, User Login, Order Creation, Notification Workflow, Image Processing Workflow, Retry Operation) | OTLP → Collector → Tempo |

### Trace correlation

- `telemetry/logging.py` attaches the active `trace_id`/`span_id` to every log record
  (stdout JSON **and** OTLP→Loki).
- The image-processing Lambda receives the W3C `traceparent` of the invoking span in
  its event payload, so the workflow can be correlated end-to-end.
- Resource attributes are set once at startup: `service.name=centralwatch-demo-app`,
  `service.version`, `deployment.environment`, `cloud.provider=aws`, `cloud.region`,
  `host.name`, `container.id`, `telemetry.sdk.*`.

> ℹ️ The botocore instrumentation names spans like `S3.PutObject` / `DynamoDB.PutItem`
> (standard OpenTelemetry AWS API naming) and attaches `aws.*`/`rpc.*` attributes.
> Note: with this instrumentation version, SNS producers are named `<topic> send`
> (e.g. `centralwatch-notifications send`) rather than `SNS.Publish`. Manual business
> spans use the consistent `aws.service` / `aws.operation` attribute keys.

---

## 4. Verification guide

### 4.1 App is running

```bash
curl http://localhost:8000/healthz
# {"status":"ok","service":"centralwatch-demo-app","version":"1.0.0"}
```

### 4.2 LocalStack resources were auto-created

```bash
# S3
aws --endpoint-url http://localhost:4566 s3 ls
# DynamoDB
aws --endpoint-url http://localhost:4566 dynamodb list-tables
# SNS
aws --endpoint-url http://localhost:4566 sns list-topics
# SQS
aws --endpoint-url http://localhost:4566 sqs list-queues
# Lambda
aws --endpoint-url http://localhost:4566 lambda list-functions
```

*(No AWS CLI installed? Use the AWS API via the container:
`docker exec centralwatch-localstack awslocal s3 ls`)*

### 4.3 Generate sample traffic

```bash
# Scenario 1 — auth (DynamoDB)
curl -s -X POST http://localhost:8000/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"secret123","name":"Alice"}'
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"secret123"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -s http://localhost:8000/auth/profile -H "Authorization: Bearer $TOKEN"

# Scenario 2 — file upload (S3)
curl -s -X POST http://localhost:8000/files/upload -H "Authorization: Bearer $TOKEN" -F 'file=@README.md;type=text/markdown'

# Scenario 3 — orders (DynamoDB)
curl -s -X POST http://localhost:8000/orders -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"user_id":"usr_demo","items":[{"product_id":"p1","name":"Widget","quantity":2,"unit_price":9.99}]}'

# Scenario 4 — image processing (S3 -> Lambda -> SNS distributed trace)
curl -s -X POST http://localhost:8000/images/process -H "Authorization: Bearer $TOKEN" -F 'file=@README.md;type=text/markdown'

# Scenario 5 — queue (SQS)
curl -s -X POST http://localhost:8000/queue/send -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"body":"hello queue"}'
curl -s http://localhost:8000/queue/messages -H "Authorization: Bearer $TOKEN"

# Scenario 6 — timeout   Scenario 7 — AWS failure   Scenario 8 — retry
curl -s http://localhost:8000/simulate/timeout -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8000/simulate/s3-error -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8000/simulate/retry -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8000/simulate/error -H "Authorization: Bearer $TOKEN"
```

### 4.4 Metrics in Prometheus

Open http://localhost:9090 and run (the Collector's Prometheus exporter applies the
`centralwatch` namespace, and the ASGI instrumentation names the HTTP duration
histogram `http.server.duration`):

```promql
centralwatch_http_server_duration_milliseconds_count          # request count
sum(rate(centralwatch_http_server_duration_milliseconds_count[5m])) by (http_target)
histogram_quantile(0.95, sum(rate(centralwatch_http_server_duration_milliseconds_bucket[5m])) by (le))
histogram_quantile(0.99, sum(rate(centralwatch_http_server_duration_milliseconds_bucket[5m])) by (le))
sum(centralwatch_http_server_duration_milliseconds_count{http_status_code=~"5.."})  # error rate
centralwatch_orders_created_total                            # business metrics
centralwatch_images_processed_total
centralwatch_notifications_sent_total
centralwatch_retry_attempts_total
centralwatch_files_uploaded_total
```

Each HTTP series is labeled with `http_method`, `http_status_code`, `http_target`,
`http_target`, `exported_job`, `deployment_environment`.

### 4.5 Logs in Loki

Open http://localhost:3100 → API, or in Grafana → Explore → Loki. The new Loki
exporter maps the OTel `service.name` resource attribute to the `job` label:

```logql
{job="centralwatch-demo-app"}
{job="centralwatch-demo-app"} |= "exception"
{job="centralwatch-demo-app"} |= "traceid"
{job="centralwatch-demo-app"} | json | traceid != ""
```

Every log line is JSON with `traceid` / `spanid` — copy a `traceid` into the Tempo
query below to jump to its trace.

### 4.6 Traces in Tempo / Grafana

- **Grafana (recommended):** http://localhost:3000 → *Explore* → **Tempo** datasource →
  search `service.name = "centralwatch-demo-app"`.
- Open a trace: you should see the HTTP server span, child AWS spans
  (`S3.PutObject`, `DynamoDB.PutItem`, `SNS.Publish` (emitted as `centralwatch-notifications send`), `SQS.SendMessage`,
  `Lambda.Invoke`), and business spans (`User Login`, `Order Creation`,
  `Image Processing Workflow`, `Retry Operation` with `Retry Attempt N` children).
- `/simulate/error` and `/simulate/s3-error` produce **error traces** (red).
- `/images/process` produces the **longest distributed trace** (S3 → Lambda → SNS).

### 4.7 Metrics ↔ Logs ↔ Traces correlation

Because every log carries the `trace_id`/`span_id` and metrics/traces share the
`service.name` resource attribute, you can:

1. **Logs → Trace:** copy a `trace_id` from a Loki log line into Tempo's "Find trace by ID".
2. **Trace → Logs:** note the trace id of a Tempo trace, filter Loki on that id.
3. **Metrics → Trace:** select a slow/erroring route in Prometheus, note the time window,
   then query Tempo for traces in that window.

> Optional deep linking (one-time, in Grafana UI — the provisioned datasources are
> intentionally not modified): Tempo → *Settings → Datasources → Tempo → "Trace to logs"*
> (`traceToLogs`, Loki datasource, query ``{job="centralwatch-demo-app"} | json | traceid=="${__trace.traceId}"``)
> and Loki → "Derived fields" (regex `"traceid":"([0-9a-f]{32})"`, Tempo datasource).

---

## 5. Project structure

```
demo-app/
├── app/
│   ├── main.py                 # app factory: lifespan, middleware, exception handler, health
│   ├── deps.py                 # DI container + auth dependency (require_auth)
│   ├── config/settings.py      # pydantic-settings (env-driven)
│   ├── routes/                 # auth, files, orders, notifications, queue, images, simulate
│   ├── services/               # auth, s3, dynamodb, sns, sqs, lambda + aws_resources
│   ├── telemetry/              # instrumentation, logging, tracing, metrics (centralized)
│   ├── models/                 # User, Order, FileRecord
│   ├── schemas/                # request/response pydantic models
│   └── utils/                  # ids, aws session/retry helpers
├── Dockerfile
├── entrypoint.sh               # waits for LocalStack (when configured), then starts uvicorn
├── requirements.txt
├── .env.example
└── README.md
```

## 6. Environment variables

See [`.env.example`](.env.example). Key ones: `AWS_ENDPOINT_URL`, `AWS_REGION`,
`OTEL_EXPORTER_OTLP_ENDPOINT`, `SERVICE_NAME`, `SIMULATE_TIMEOUT_SECONDS`,
`SIMULATE_RETRY_ATTEMPTS`, `INIT_RECONCILE_INTERVAL_SECONDS`, and **`AUTH_TOKEN_SECRET`**
(required — the app fails fast at startup without it).

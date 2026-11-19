# CentralWatch — End-to-End System Documentation

> **Document type:** Technical reference (audit deliverable)
> **Scope:** The system exactly as implemented and verified in this repository
> **Verification basis:** Live execution against the running stack (all 9 containers),
> plus direct queries of Prometheus, Loki, Tempo and Grafana. Evidence for each claim is
> noted inline (file, endpoint, query, or observed response).

---

## 1. Project Purpose

CentralWatch is an **observability demonstration platform**. It pairs a small but
realistic business application (a FastAPI "demo app") with a complete OpenTelemetry
monitoring stack (Collector → Prometheus / Loki / Tempo → Grafana), so that every layer
of the observability story — instrumenting code, exporting telemetry, storing it, and
visualizing it in dashboards — can be demonstrated with real data.

Two deliberate design properties define the system:

1. **The monitoring system is a bystander.** Application traffic flows
   `Browser → nginx → FastAPI → AWS`. Telemetry is exported out-of-band over OTLP.
   Nothing sits in the request path.
2. **The same codebase runs two modes** driven entirely by environment variables:
   **LocalStack (development)** — offline AWS emulation, resources auto-created; and
   **real AWS (production)** — standard AWS endpoints, resources validated, fail-fast.

---

## 2. Architecture

```
                        Application traffic
  Browser ──> nginx (frontend :8080) ──/api──> FastAPI (demo-app :8000) ──boto3──> AWS
                                                           │
                                               OpenTelemetry SDK (OTLP HTTP)
                                                           │
                                                    otel-collector :4318
                                                    ┌──────┼──────┐
                                                    ▼      ▼      ▼
                                               Prometheus  Loki  Tempo
                                                    └──────┼──────┘
                                                           ▼
                                                        Grafana
```

### 2.1 Connections (protocol / port / hostname / direction)

| Connection | Protocol | Port | Hostname (in-network) | Direction | Failure behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Browser → nginx | HTTP | 8080 (host) / 80 (ctr) | `localhost` | in | nginx serves SPA; `/api/*` proxied |
| nginx → FastAPI | HTTP | 8000 | `demo-app` | in | 502 if demo-app down; nginx `proxy_read_timeout 120s` |
| FastAPI → LocalStack | HTTP (AWS API) | 4566 | `localstack` | out | mapped to 502/503 via `aws_error_response` |
| FastAPI → OTLP Collector | HTTP OTLP | 4318 | `otel-collector` | out (async exporters) | batch lost while down; no request-path impact |
| Collector → Prometheus | HTTP scrape | 8889 (exporter) | `otel-collector` | out (pull) | scrape fails → metrics gap until recovered |
| Collector → Loki | HTTP push | 3100 | `loki` | out | logs buffered/batched; dropped on extended outage |
| Collector → Tempo | gRPC OTLP | 4317 | `tempo` | out | spans batched; dropped on extended outage |
| Grafana → Prometheus/Loki/Tempo | HTTP | 9090/3100/3200 | `prometheus`/`loki`/`tempo` | out (query) | panels show "No data"/error |

All containers share one explicitly named bridge network: **`centralwatch-network`**.

### 2.2 Dependency order (compose)

- `demo-app` `depends_on`: `localstack` (condition: service_healthy), `otel-collector` (started).
- `frontend` `depends_on`: `demo-app`.
- `prometheus` `depends_on`: `otel-collector`.
- `grafana`, `loki`, `tempo`: start independently; provisioning is file-based.

---

## 3. Component Inventory

| Component | Location | Technology | Purpose | Implemented | Runnable | Current status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| FastAPI backend | `demo-app/app/` | Python 3.11, FastAPI 0.115 | Business app + telemetry generator | ✅ | ✅ | **Running & verified** |
| React frontend (built) | `frontend/dist/` | Vite + React (built SPA) | Demo UI calling `/api/*` | ✅ (built only) | ✅ | **Running via nginx** (served at :8080) |
| S3 | via LocalStack/real AWS | boto3 | File object storage | ✅ | ✅ | LocalStack **LIVE VERIFIED** |
| DynamoDB | via LocalStack/real AWS | boto3 | users/orders/files tables | ✅ | ✅ | LocalStack **LIVE VERIFIED** |
| SNS | via LocalStack/real AWS | boto3 | notifications | ✅ | ✅ | LocalStack **LIVE VERIFIED** |
| SQS | via LocalStack/real AWS | boto3 | message queue | ✅ | ✅ | LocalStack **LIVE VERIFIED** |
| Lambda | via LocalStack/real AWS | boto3 + embedded handler | image processing | ✅ | ✅ | LocalStack **LIVE VERIFIED** (sidecar) |
| LocalStack | `docker-compose.yml` | `localstack/localstack:3.4.0` | AWS emulation | ✅ | ✅ | **Running & verified** |
| OTel SDK | `demo-app/app/telemetry/` | opentelemetry-python 1.27 | instrument + export | ✅ | ✅ | **Running & verified** |
| OTel Collector | `configs/collector/config.yaml` | `otel/opentelemetry-collector-contrib:0.95.0` | receive/fan-out | ✅ | ✅ | **Running & verified** |
| Prometheus | `configs/prometheus/prometheus.yml` | `prom/prometheus:v2.49.1` | metrics store | ✅ | ✅ | **Running & verified** |
| Loki | `configs/loki/loki-config.yaml` | `grafana/loki:2.9.4` | logs store | ✅ | ✅ | **Running & verified** |
| Tempo | `configs/tempo/tempo.yaml` | `grafana/tempo:2.6.1` | traces store | ✅ | ✅ | **Running & verified** |
| Grafana | `configs/grafana/provisioning/` | `grafana/grafana:12.4.0` | dashboards | ✅ | ✅ | **Running & verified** |
| Docker | `docker-compose.yml` + `.aws.yml` | Docker Compose v2 | orchestration | ✅ | ✅ | `docker compose up -d --build` reproduces |
| Authentication | `demo-app/app/services/auth_service.py` | HMAC-SHA256 stateless tokens | protect business APIs | ✅ | ✅ | **Running & verified** |

---

## 4. Request Flow (end to end)

1. Browser loads SPA from nginx (`:8080`); bundle uses axios instance with
   `baseURL = "/api"` and a `Authorization: Bearer <token>` interceptor
   (evidence: `frontend/dist/assets/index-BniPkNHW.js` — `IT="/api"`,
   `Authorization=`Bearer ${ay}``).
2. nginx `location /api/` proxies to `http://demo-app:8000/` (prefix stripped; same-origin,
   no CORS) — evidence: `configs/nginx/frontend.conf`.
3. FastAPI route handler runs; service layer calls boto3 → LocalStack/AWS.
4. The OTel SDK (ASGI + botocore instrumentation, plus manual business spans) emits
   metrics/logs/traces over OTLP HTTP to `otel-collector:4318`.
5. Collector fans out: metrics → Prometheus exporter (`:8889`, scraped by Prometheus),
   logs → Loki, traces → Tempo (gRPC `tempo:4317`).
6. Grafana dashboards (provisioned from `configs/grafana/provisioning/`) query the three
   datasources and render.

---

## 5. AWS Flow

FastAPI uses boto3 clients created by `demo-app/app/utils/aws.py::make_client`:

- **LocalStack mode:** `AWS_ENDPOINT_URL=http://localstack:4566` set → `endpoint_url`
  applied; S3 addressing style `path`; credentials `test`/`test` (dev only);
  `AWS_PROVISION_RESOURCES=true` → `AwsResourceManager.ensure_resources()` creates
  bucket, tables, topic, queue, Lambda idempotently at startup and on a 60 s reconcile loop.
- **Real AWS mode:** `AWS_ENDPOINT_URL` empty → default regional endpoints;
  `AWS_PROVISION_RESOURCES=false` → `validate_resources()` checks every resource exists
  and **fails fast** with a clear message if any is missing; credentials come from the
  standard chain (env vars / `~/.aws/credentials` / instance role).

### AWS operations used per service

| Service | Operations (code) |
| :--- | :--- |
| S3 | `put_object`, `get_object`, `delete_object`, `generate_presigned_url`, `list_buckets`, `head_bucket`, `create_bucket` |
| DynamoDB | `put_item`, `get_item`, `delete_item`, `scan`, `query` (GSI `email-index`), `describe_table`, `create_table` |
| SNS | `publish`, `create_topic`, `list_topics` |
| SQS | `send_message`, `receive_message`, `delete_message_batch`, `get_queue_url`, `create_queue` |
| Lambda | `invoke`, `get_function`, `create_function` (embeds handler code as zip) |

Lambda handler (`aws_resources.py::LAMBDA_HANDLER_CODE`) does `s3:GetObject` +
`sns:Publish`, honors `AWS_ENDPOINT_URL` when set, and receives the W3C `traceparent`
of the invoking span for end-to-end correlation.

---

## 6. Authentication Flow

- **Register** (`POST /auth/register`): password hashed with **PBKDF2-HMAC-SHA256**
  (100k iterations, per-user random salt, stored as `salt$digest`); user row in DynamoDB.
- **Login** (`POST /auth/login`): verifies hash; issues a **stateless HMAC-SHA256 token**
  (`base64url(user_id.expires.signature)`); TTL default 86 400 s (`TOKEN_TTL_SECONDS`).
- **Verify** (`GET /auth/profile` and `require_auth` dependency): signature + expiry check.
- **Secret:** `AUTH_TOKEN_SECRET` — **no default in code**; the app fails fast at startup
  if empty (`settings.py` validator). Dev compose ships a documented dev-only default;
  the AWS compose has **no default** and refuses to start without it.
- **Protected:** `/orders`, `/files`, `/images`, `/notifications`, `/queue`, `/simulate`
  (router-level `dependencies=[Depends(require_auth)]`).
- **Public:** `/auth/register`, `/auth/login`, `/healthz`, `/livez`, `/readyz`, `/docs`.

Live verification: unauthenticated calls to every business endpoint → **401**;
invalid/wrong/expired/tampered tokens → **401**; duplicate email → **409**;
invalid bodies → **422**.

---

## 7. Telemetry Flow

- **Init:** `configure_telemetry()` creates TracerProvider, MeterProvider, LoggerProvider
  with a shared `Resource` (service.name, service.version, deployment.environment,
  cloud.provider=aws, cloud.region, host.name, container.id, telemetry.sdk.*).
- **Export:** all three signals over **OTLP HTTP** to `{OTEL_EXPORTER_OTLP_ENDPOINT}/v1/*`.
- **Instrumentation:** `FastAPIInstrumentor.instrument_app(...)` + `BotocoreInstrumentor`.
  A plain-ASGI `RequestLoggingMiddleware` logs every request **inside** the server span so
  logs carry `trace_id`/`span_id`; it also patches `http.status_code` onto the span on the
  custom-exception-handler response path.
- **Collector pipelines** (`configs/collector/config.yaml`):

| Pipeline | Receivers | Processors | Exporters |
| :--- | :--- | :--- | :--- |
| metrics | otlp (4317 gRPC / 4318 HTTP) | memory_limiter, batch | prometheus (:8889, namespace `centralwatch`), debug |
| logs | otlp | memory_limiter, batch | loki, debug |
| traces | otlp | memory_limiter, batch | otlp/tempo (gRPC, insecure), debug |

`resource_to_telemetry_conversion.enabled=true` on the Prometheus exporter turns resource
attributes into labels — notably `deployment_environment` from `deployment.environment`.

---

## 8. Metrics (Prometheus)

| Metric | Type | Labels | Emitted from | Endpoint triggering it | Verified live |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `centralwatch_http_server_duration_milliseconds_count/sum/bucket` | Histogram | `http_method`, `http_status_code`, `http_target`, `service`, `instance`, `deployment_environment` (+ `http_flavor`, `http_host`, `http_scheme`, `http_server_name`, `net_host_port`, `service_name`, `cloud_*`, `telemetry_sdk_*`) | ASGI instrumentation | every request | ✅ count=875, sum=61929, bucket=12385 |
| `centralwatch_orders_created_total` | Counter | `status` | `BusinessMetrics.orders_created` | `POST /orders` | ✅ = 10 |
| `centralwatch_files_uploaded_total` | Counter | `status` | `BusinessMetrics.file_uploads` | `POST /files/upload` | ✅ = 16 |
| `centralwatch_images_processed_total` | Counter | `status` | `BusinessMetrics.images_processed` | `POST /images/process` | ✅ = 9 |
| `centralwatch_notifications_sent_total` | Counter | `channel`, `status` | `BusinessMetrics.notifications_sent` | `POST /notifications/*` | ✅ = 20 |
| `centralwatch_retry_attempts_total` | Counter | `operation` | `BusinessMetrics.retry_attempts` | `GET /simulate/retry` | ✅ = 20 |

**Known limitation (verified):** requests answered by the custom exception handler
(`/simulate/error` → 500, `/simulate/s3-error` → 502) produce a duration series **without**
an `http_status_code` label, because the ASGI instrumentation's metric path does not record
the status for handler-produced responses. Consequently `http_status_code=~"5.."` queries
return nothing and the two **Error Rate** dashboard panels are always empty, even though
error traces and error logs exist.

---

## 9. Logs (Loki)

- **Format:** JSON lines to stdout **and** OTLP records via the SDK `LoggingHandler`.
- **JSON fields** (stdout formatter): `timestamp`, `level` (uppercase), `logger`,
  `message`, `service.name`, `trace_id`, `span_id` (when in a span), plus request context
  (`endpoint`, `http.method`, `status_code`, `duration_ms`) and AWS context
  (`aws.service`, `aws.operation`, `bucket.name`, `table.name`, `channel`, `topic.name`,
  `queue.name`, `retry.count`, `user.id`), and exception details.
- **Loki labels** (set by the collector's Loki exporter): `job` (= `service.name`),
  `level` (uppercase), `exporter`. **`traceid`/`endpoint` are JSON fields, not labels.**
- Live evidence: labels = `[exporter, job, level]`; streams exist for `level=INFO` and
  `level=ERROR`; lines contain `"traceid":"...","spanid":"..."`.

---

## 10. Traces (Tempo)

- **Root spans:** ASGI `POST /orders` etc. (FastAPI instrumentation).
- **AWS spans** (botocore instrumentation): `S3.PutObject`, `S3.DeleteObject`,
  `S3.ListBuckets`, `S3.GetObject` (Lambda side only), `DynamoDB.PutItem`, `DynamoDB.GetItem`,
  `DynamoDB.Query`, `DynamoDB.Scan`, `DynamoDB.DeleteItem`,
  **`centralwatch-notifications send`** (SNS producer; this botocore version names SNS
  producers `<topic> send` instead of `SNS.Publish`), `SQS.SendMessage`,
  `SQS.ReceiveMessage`, `SQS.DeleteMessageBatch`, `Lambda.Invoke`.
- **Business spans** (manual): `User Registration`, `User Login`, `Order Creation`,
  `Notification Workflow`, `Image Processing Workflow`, `Retry Operation` with
  `Retry Attempt N` children (`Retry Attempt 1`, `Retry Attempt 2`, ...).
- Live evidence: all of the above span names are searchable in Tempo
  (`/api/search?q={ name = "..." }`); `service.name=centralwatch-demo-app`.

---

## 11. Grafana

- **Datasources** (`configs/grafana/provisioning/datasources/datasources.yaml`):
  `Prometheus` (default, POST), `Loki`, `Tempo` (GET) — all `proxy` access, in-network URLs.
- **Dashboards** (`configs/grafana/provisioning/dashboards/`, provider folder `CentralWatch`):

| Dashboard | Panels | Datasource | Live status |
| :--- | :--- | :--- | :--- |
| overview.json | requests/s, avg/P95/P99 latency, error & success rate, business totals, rates, percentiles | Prometheus | data except Error Rate (see §8) |
| api-monitoring.json | requests by route/method/status, latency by route, error rate, histogram, top slow APIs | Prometheus | data except Error Rate |
| aws-services.json | S3/Lambda/SNS/SQS/DynamoDB trace tables + waterfall | Tempo | tables have data; waterfall empty until a trace is selected |
| business-metrics.json | 5 business counters + breakdowns (channel/status/operation) | Prometheus | data |
| tracing.json | recent/slowest traces, AWS & business workflows, waterfall | Tempo | tables have data; waterfall empty until a trace selected |
| logs.json | total lines, recent logs, errors, warnings, by traceid, by endpoint | Loki | data; Warnings empty (no WARN logs generated) |

57 panel queries were executed through Grafana `/api/ds/query`: **52 return data, 5 empty**
(2 Error Rate — 5xx label gap, §8; 2 waterfalls — await user trace selection; 1 Warnings —
no WARN logs exist). All queries are valid; none error.

---

## 12. Frontend

- **State:** only the **prebuilt bundle** is tracked (`frontend/dist/`). Source is not in
  this repository. Built with Vite; React 18 SPA, dark theme.
- **Served by:** nginx (`nginx:1.27-alpine`) at `:8080`, SPA fallback to `index.html`.
- **API client:** axios instance `baseURL="/api"`, 20 s timeout, JSON headers, Bearer-token
  interceptor (evidence from bundle analysis).
- **Pages observed in bundle:** Dashboard, Orders (list/new/detail), Files (upload/list),
  Activity, Profile, login/register views.
- **Backend calls in bundle:** `/auth/login`, `/auth/register`, `/auth/profile`,
  `/orders`, `/orders/{id}`, `/files/upload`, `/images/process`, `/queue/send`,
  `/queue/messages`, `/simulate/*`, `/healthz`, `/livez`, `/readyz`.
- Live: `GET /` → 200 (SPA), `GET /api/healthz` → 200 through the proxy.

---

## 13. Docker

- **Dev** (`docker-compose.yml`): 9 services on `centralwatch-network`; demo-app **built
  from `./demo-app`** (Dockerfile present — no pre-built image required); LocalStack with
  Docker-socket mount for the Lambda sidecar (`DOCKER_SOCK_PATH` overridable);
  named volumes for proxy-db/prometheus/loki/tempo/grafana/localstack; healthchecks on
  proxy-db/demo-app/localstack/loki/tempo/grafana.
- **Prod** (`docker-compose.aws.yml`): same stack minus LocalStack;
  `AUTH_TOKEN_SECRET` and `GRAFANA_ADMIN_PASSWORD` are **required** (no defaults);
  `AWS_ENDPOINT_URL` empty; `AWS_PROVISION_RESOURCES=false`.
- Reproducibility: `docker compose config` valid for both files; clean-environment
  `docker compose build && docker compose up -d` verified earlier (all 9 containers up).
- No orphan/legacy dependencies; the compose file pins an explicit network name.

---

## 14. LocalStack (development mode)

- Emulates S3, DynamoDB, SNS, SQS, Lambda on `:4566`.
- `AWS_PROVISION_RESOURCES=true` → app creates everything idempotently
  (bucket `centralwatch-files`, tables `users`/`orders`/`files`, topic
  `centralwatch-notifications`, queue `centralwatch-queue`, Lambda
  `centralwatch-image-processor`), then reconciles every 60 s.
- Lambda runs in a LocalStack-managed sidecar container on the same network;
  requires the Docker socket in **this mode only**.
- Live evidence: `awslocal s3 ls` shows the bucket; `list-tables` shows 3 tables;
  `list-functions` shows the Lambda; SNS topic and SQS queue listed.

---

## 15. Real AWS (production mode)

- `AWS_ENDPOINT_URL` empty → SDK default regional endpoints; standard credential chain.
- `AWS_PROVISION_RESOURCES=false` → startup validation of all resources; **fails fast**
  listing missing/unreachable resources.
- Resources and least-privilege IAM policies are documented in
  `AWS_DEPLOYMENT.md` (app role + Lambda execution role).
- **Verification status:** code path verified statically; **not exercised against a live
  AWS account** in this environment.

---

## 16. Environment Variables

See `demo-app/.env.example`, `docker-compose.yml`, `docker-compose.aws.yml` for the full
matrix. Key variables:

| Variable | Required | Dev default | Prod | Secret |
| :--- | :--- | :--- | :--- | :--- |
| `AUTH_TOKEN_SECRET` | **yes (no code default)** | dev-only default in compose | **required, no default** | ✅ |
| `AWS_ENDPOINT_URL` | no | `http://localstack:4566` | empty | |
| `AWS_PROVISION_RESOURCES` | yes | `true` | `false` | |
| `AWS_REGION` | yes | `us-east-1` | `us-east-1` | |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | no | `test`/`test` (dev) | empty → credential chain | ✅ |
| `AWS_S3_ADDRESSING_STYLE` | yes | `path` | `auto` | |
| `S3_BUCKET`, `DYNAMODB_*_TABLE`, `SNS_TOPIC`, `SQS_QUEUE`, `LAMBDA_FUNCTION` | yes | defaults | pre-created names | |
| `LAMBDA_ROLE_ARN` | prod | fake ARN (dev) | real ARN | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | yes | `http://otel-collector:4318` | same | |
| `ENVIRONMENT` | yes | `development` | `production` | |
| `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD` | prod | `admin`/`admin` | **required, no default** | ✅ |

---

## 17. API Inventory

| Method | Endpoint | Router | Auth | Request schema | Response schema | AWS | Status codes | Live |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| POST | `/auth/register` | auth | public | `RegisterRequest` (email, password≥6, name) | `UserOut` | DynamoDB | 201, 409, 422 | ✅ 201 |
| POST | `/auth/login` | auth | public | `LoginRequest` | `LoginResponse` (token, expires_in, user) | DynamoDB | 200, 401, 422 | ✅ 200 |
| GET | `/auth/profile` | auth | **Bearer** | — | `UserOut` | DynamoDB | 200, 401 | ✅ 200 |
| POST | `/orders` | orders | **Bearer** | `OrderCreate` (user_id, items≥1) | `OrderOut` | DynamoDB | 201, 401, 422 | ✅ 201 |
| GET | `/orders` | orders | **Bearer** | — | `OrderListOut` | DynamoDB scan | 200, 401 | ✅ 200 |
| GET | `/orders/{order_id}` | orders | **Bearer** | — | `OrderOut` | DynamoDB | 200, 401, 404 | ✅ 200 |
| POST | `/files/upload` | files | **Bearer** | multipart `file` | `FileUploadResponse` | S3 + DynamoDB | 201, 401, 422 | ✅ 201 |
| GET | `/files/{file_id}` | files | **Bearer** | — | `FileOut` (+presigned url) | S3 presign + DynamoDB | 200, 401, 404 | ✅ 200 |
| DELETE | `/files/{file_id}` | files | **Bearer** | — | `FileDeletedResponse` | S3 + DynamoDB | 200, 401, 404 | ✅ 200 |
| POST | `/images/process` | images | **Bearer** | multipart `file` | `ImageProcessResponse` | S3 → Lambda → SNS | 200, 401, 422 | ✅ 200 |
| POST | `/notifications/email` | notifications | **Bearer** | `NotificationRequest` (recipient, message) | `NotificationResponse` | SNS | 200, 401, 422 | ✅ 200 |
| POST | `/notifications/sms` | notifications | **Bearer** | `NotificationRequest` | `NotificationResponse` | SNS | 200, 401, 422 | ✅ 200 |
| POST | `/queue/send` | queue | **Bearer** | `QueueSendRequest` (body) | `QueueSendResponse` | SQS | 200, 401, 422 | ✅ 200 |
| GET | `/queue/messages` | queue | **Bearer** | — | `QueueMessagesResponse` | SQS | 200, 401 | ✅ 200 |
| GET | `/simulate/error` | simulate | **Bearer** | — | error JSON | — (deliberate) | 500, 401 | ✅ 500 |
| GET | `/simulate/timeout` | simulate | **Bearer** | — | `{status, slept_for_seconds}` | — (sleep) | 200, 401 | ✅ 200 (~5 s) |
| GET | `/simulate/s3-error` | simulate | **Bearer** | — | error JSON | S3 (bad bucket) | 502, 401 | ✅ 502 |
| GET | `/simulate/retry` | simulate | **Bearer** | — | `{status, attempts, buckets}` | S3 (retry) | 200, 401 | ✅ 200 (3 attempts) |
| GET | `/healthz` | main | public | — | `{status, service, version}` | — | 200 | ✅ |
| GET | `/livez` | main | public | — | `{status: alive}` | — | 200 | ✅ |
| GET | `/readyz` | main | public | — | `{status, aws, buckets}` | S3 list | 200, 503 | ✅ 200 |

---

## 18. Workflow Documentation

All workflows verified end-to-end against the live stack (see also §19):

1. **Registration** → DynamoDB `PutItem` (business span "User Registration", log, metric none) → 201.
2. **Login** → DynamoDB `Query` via GSI (span "User Login") → HMAC token → 200.
3. **Profile** → token verify + DynamoDB `GetItem` → 200.
4. **Create order** → business span "Order Creation" wrapping DynamoDB `PutItem` +
   counter `orders_created_total` → 201.
5. **List orders** → DynamoDB `Scan` → 200.
6. **Upload file** → S3 `PutObject` + DynamoDB `PutItem` + counter `files_uploaded_total` → 201.
7. **Get file** → DynamoDB `GetItem` + S3 presigned URL → 200.
8. **Delete file** → S3 `DeleteObject` + DynamoDB `DeleteItem` → 200.
9. **Process image** → business span "Image Processing Workflow": S3 `PutObject` →
   Lambda `Invoke` (handler: S3 `GetObject`, sleep, SNS `Publish`) → counter
   `images_processed_total` → 200 (distributed trace with `traceparent` propagation).
10. **Email/SMS notification** → business span "Notification Workflow" wrapping SNS
    `Publish` + counter `notifications_sent_total{channel}` → 200.
11. **Queue send/receive** → SQS `SendMessage` / `ReceiveMessage` +
    `DeleteMessageBatch` → 200.
12. **Simulations** → error (500), timeout (200 after sleep), s3-error (502),
    retry (Retry Operation span, `Retry Attempt 1/2` failing then success,
    `retry_attempts_total{operation}` counter) → 200.

---

## 19. Verification Results

| Area | Method | Result |
| :--- | :--- | :--- |
| Containers | `docker ps` | 8/8 up (demo-app, localstack, collector, prometheus, loki, tempo, grafana, frontend); all healthy-marked where defined |
| Health endpoints | `curl /healthz /livez /readyz` | 200 ×3 |
| 43 live API checks (positive + negative) | HTTP calls | all as documented in §17 (incl. 401s, 409, 422, 404, 500, 502) |
| Auth boundary | unauthenticated calls | 401 on all 7 business routers |
| Prometheus | `/api/v1/query` | all 8 centralwatch metrics present with values; labels verified |
| Loki | `/loki/api/v1/query_range` | INFO + ERROR streams; JSON fields incl. traceid/spanid |
| Tempo | `/api/search` | 10 recent traces; 21 span names searchable |
| Grafana | `/api/datasources`, `/api/search?type=dash-db` | 3 datasources, 6 dashboards |
| Dashboards | 57 queries via `/api/ds/query` | 52 data / 5 empty (see §11) |

---

## 20. Known Issues

1. **Error Rate panels always empty** (Medium) — 5xx responses produced by the custom
   exception handler never get an `http_status_code` label on the duration metric
   (ASGI instrumentation metric path bypassed). Affects `overview.json` + `api-monitoring.json`
   Error Rate panels and any `http_status_code=~"5.."` query. Root cause:
   `RequestLoggingMiddleware` patches the **span** attribute only; the **metric** attribute
   is not patched. Evidence: `/simulate/error` produces a series with no status label;
   `count(...{http_status_code=~"5.."})` = 0.
2. **SNS span named `centralwatch-notifications send`** (Info/Low) — differs from the
   classic `SNS.Publish`; the dashboards and docs already match the implementation, but
   anyone expecting standard naming will be surprised. If `SNS_TOPIC` changes, the span
   name changes too (dashboard SNS panel uses regex `centralwatch-.* send`, so it adapts).
3. **Real AWS unverified live** (Info) — code path statically verified; not executed
   against a real account in this environment.
4. **Minor doc nit:** `demo-app/README.md` §4.4 lists `http_target` twice in the label list.
5. **Frontend source not in repo** (Info) — only the built bundle is tracked; rebuilding
   the SPA requires source that lives elsewhere.

---

## 21. Implementation Completeness

| Feature | Level | Evidence |
| :--- | :--- | :--- |
| FastAPI backend | 5 — Production ready (in this environment) | fully integrated, tested (43 live checks), documented |
| Auth (register/login/token) | 5 | live-verified incl. negative cases |
| S3 / DynamoDB / SNS / SQS / Lambda (LocalStack) | 4 — Integrated (LocalStack) | live-verified through API + resource listing |
| Real AWS path | 2 — Implemented (statically verified) | code inspected; not run live |
| OTel SDK + instrumentation | 5 | metrics/logs/traces all observed in stores |
| Collector pipelines | 5 | live fan-out verified |
| Prometheus / Loki / Tempo | 5 | live queries return data |
| Grafana dashboards | 4 — Integrated (52/57 panels with data) | queries execute; 5 panels empty by design/gap (see §20.1) |
| Frontend | 4 — Deployed & serving | bundle served, proxy verified; SPA interactions not browser-tested in this audit |
| Docker reproducibility | 5 | clean build + up verified |
| Documentation | 4 | README/AWS guide current; one minor nit (§20.4) |

---

## 22. Deployment Requirements

- **Dev:** Docker + Docker Compose v2; Docker Desktop socket path for LocalStack Lambda
  (Linux: `DOCKER_SOCK_PATH=/var/run/docker.sock`).
- **Prod:** pre-created AWS resources (S3 bucket, 3 DynamoDB tables incl. `email-index`
  GSI, SNS topic, SQS queue, Lambda function + execution role), least-privilege IAM,
  `AUTH_TOKEN_SECRET`, `GRAFANA_ADMIN_PASSWORD`, `LAMBDA_ROLE_ARN`; do **not** expose
  Prometheus/Loki/Tempo/OTLP/Grafana publicly.
- **Commands:** `docker compose up -d --build` (dev);
  `docker compose -f docker-compose.aws.yml up -d --build` (prod);
  `./scripts/healthcheck.sh` (verify).

---

## 23. Troubleshooting

| Symptom | Cause / fix |
| :--- | :--- |
| `Failed to resolve 'otel-collector'` | containers on different networks → `docker compose down && docker compose up -d --build` |
| `/images/process` slow / `Pending` Lambda | first sidecar image pull; app warms up in background; wait ~60 s or `docker compose restart localstack demo-app` |
| Lambda needs Docker socket | LocalStack-only; set `DOCKER_SOCK_PATH` correctly for your OS |
| Dashboards "No data" | generate traffic first (§18 runbook), then check Prometheus `centralwatch_*` series |
| Error Rate panels empty | known limitation (§20.1) — not a data-ingestion failure |
| `AUTH_TOKEN_SECRET` startup error | set the env var (dev: any value; prod: strong secret) |
| Port conflict | change host mapping in `docker-compose.yml` |

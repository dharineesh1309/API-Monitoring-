# CentralWatch — API Key Usage Monitoring and API Security

CentralWatch keeps third-party API keys out of applications, records how they are used, monitors the
whole stack with OpenTelemetry, and scans an AWS account for APIs that are open to the internet.

It has two web portals: the **CentralWatch platform** for administrators (`:8080`) and a **demo
application** for ordinary users (`:8090`). Both are served by the same FastAPI backend (`:8000`), which
carries the `centralwatch-security` plugin. The demo application exists to generate real traffic for
CentralWatch to watch.

## Contents

1. [What it does](#1-what-it-does)
2. [Architecture](#2-architecture)
3. [Services and ports](#3-services-and-ports)
4. [Getting started](#4-getting-started)
5. [Where to find each feature](#5-where-to-find-each-feature)
6. [Configuration](#6-configuration)
7. [Tests and CI](#7-tests-and-ci)
8. [Project layout](#8-project-layout)
9. [Troubleshooting](#9-troubleshooting)
10. [More documentation](#10-more-documentation)

---

## 1. What it does

### API key vault and proxy
- **Keys stay in the vault.** Upstream API keys are encrypted with AES-256-GCM before they are stored in
  PostgreSQL. The service name is bound to the ciphertext, so a key copied to another service's row
  will not decrypt. AWS KMS can be used instead, and the master key can be rotated, which re-encrypts
  every stored key.
- **Applications get a proxy token instead of the key.** Only the token's SHA-256 hash is stored. Tokens
  expire after 90 days and can be rotated. An application calls
  `http://<host>:8000/centralwatch/proxy/<service>/<path>` with the header `X-CentralWatch-Proxy-Token`.
- **Roles and services are many-to-many.** A role (with its own token and allowed HTTP methods) can reach
  any number of services, and a service can be used by any number of roles; both forms on the API proxy
  page take several picks. A role token works on every service its role reaches; a service's own token
  may do on that service whatever any of its roles allows.
- **Every call passes the same checks, in this order:** quarantined IP → IP allowlist → token and expiry
  → role (allowed services and HTTP methods) → rate limit (60-second sliding window, 120 requests per
  minute by default) → circuit breaker (opens for 15 s after 5 upstream failures) → 15-second cache for
  GET requests → SSRF guard (no loopback, private or cloud-metadata addresses). Only then is the real
  key added and the request forwarded. If the provider answers 429 and a second key is configured, the
  call is retried with that key.
- **Every call is recorded:** caller IP, service, outcome, status and latency. Request bodies, secrets
  and query values are never stored. For language-model responses (Gemini, OpenAI and Claude formats)
  the token count and an estimated cost are recorded and shown against each service's monthly budget.
  Budgets are tracked and displayed; they do not block calls.
- **Administrative actions are written to a signed audit log** (HMAC-SHA256): `SERVICE_UPSERTED`,
  `ROLE_UPSERTED`, `TOKEN_ROTATED`, `MASTER_KEY_ROTATED`, `SERVICE_TOKEN_REVEALED`,
  `ROLE_TOKEN_REVEALED`, `IP_UNBLOCKED`.
- **Management is admin-only.** Listing keys, roles, history, metrics, the quarantine list and the audit
  log, unblocking IPs and changing configuration all require an administrator. Revealing a stored token
  also requires the administrator to re-enter their own password.
- **Quarantine:** addresses on the quarantine list are refused on every call until an administrator
  unblocks them. In this version an address is quarantined by the brute-force defence routine, which
  the brute-force simulation triggers.

### Monitoring
- The backend and the inventory service are instrumented with OpenTelemetry: every HTTP request, outgoing
  HTTP call and AWS SDK call becomes a span, plus custom business metrics. Log lines carry the trace ID,
  so Grafana links a log line to its trace.
- The OpenTelemetry Collector sends metrics to Prometheus, logs to Loki (kept 7 days) and traces to
  Tempo (kept 48 hours).
- Nine Grafana dashboards are provisioned automatically: Overview, API Monitoring, AWS Services, Business
  Metrics, Logs, Tracing, SLO & Error Budget, Distributed Services, and Security & Threat Intelligence.
- Thirteen Prometheus alert rules: `ApplicationErrorDetected`, `AWSS3FailureDetected`,
  `IPBruteForceBlocked`, `HTTP5xxErrorsDetected`, `HighErrorRate`, `HighLatencyP99` (evaluates the 95th
  percentile, above 1 s), `ServiceDown`, `ProxySecurityViolationsSpike`, `SSRFBlockedAttempt`,
  `RateLimitExceededSpike`, `ExposedApiDown`, `ExposedApiSecretLeak`, `ExposedApiDataLeak`. Alerts are
  shown on the platform's Alerts page; no outgoing notifications (e-mail, Slack) are configured yet.

### Exposed API scanner
- Reads every enabled AWS region (read-only) and lists every API the account exposes: API Gateway REST,
  HTTP and WebSocket APIs, Lambda function URLs, AppSync, CloudFront, load balancers and EC2 instances
  with a public IP.
- Reports risky settings (no authorizer, open CORS, no throttling, no access logs, no WAF, old TLS,
  plain HTTP, open admin ports, secrets in environment or stage variables, public test stages). Each
  finding has a severity, an OWASP API Security Top 10 (2023) category, evidence, a fix and an AWS CLI
  command for the fix.
- An optional **safe probe** sends at most 10 unauthenticated GET requests per API and two TLS
  handshakes per host. It confirms open routes, records health, response time and certificate expiry,
  and looks for leaked data in responses (AWS keys, private keys, card numbers that pass the Luhn check,
  JWTs, e-mail addresses, phone numbers, stack traces, internal IPs). Leaked values are masked.
- Runs at startup, every 5 minutes and on demand, within a 60-second time budget. Results become metrics
  and the three `ExposedApi*` alerts.

### OWASP ASTF security testing
- **Security scan page:** runs the OWASP API Security Testing Framework against any URL you enter. One
  scan at a time, at most 10 minutes, with a live progress bar and a Stop button. Closing or refreshing
  the page also stops the scan. Your login token is passed to the scanner only when the target is
  CentralWatch itself.
- **Deep test:** runs ASTF against public APIs from the inventory whose names match `API_SCAN_ALLOWLIST`
  (default `cw-lab-*`), using their real routes. ASTF sends attack traffic, so only list APIs you are
  allowed to test.

### AWS security agent
- Checks the project's own AWS resources against 11 controls based on the CIS AWS Foundations Benchmark
  (13 results: S3 public access, encryption and versioning, DynamoDB point-in-time recovery for each
  table, SQS and SNS encryption, Lambda tracing, CloudTrail, root access keys, open SSH/RDP, KMS rotation).
- Scans never change AWS. Seven of the controls can be fixed from the page, but only when
  `AWS_SECURITY_AGENT_ALLOW_REMEDIATION=true` is set for the backend (see [Configuration](#6-configuration)),
  after a recent scan, and after typing the confirmation phrase.

### Reliability
- Scans work within time budgets and return partial results instead of hanging.
- A DNS watchdog restarts the backend if DNS lookups hang (this happens with Docker Desktop on WSL2
  after sleep or a network change); Docker's restart policy brings it back within seconds.
- Proxy usage history is reloaded from PostgreSQL at startup.
- Health endpoints: `/healthz`, `/livez`, `/readyz`.

### Demo application
Orders (DynamoDB, plus a call to the inventory service), file storage (S3), e-mail and SMS notifications
(SNS), queue messages (SQS), image processing (S3 → Lambda → SNS), failure simulations (application
error, slow request, S3 failure, retry, brute force) and a Gemini chat that goes through the proxy.

---

## 2. Architecture

```
  Users  ──:8090──▶ Demo portal (nginx) ────────┐
                                                ├──▶ Backend API :8000  (FastAPI + centralwatch-security)
  Admins ──:8080──▶ CentralWatch platform (nginx)┘        │
                                                          ├──▶ AWS: S3, DynamoDB, SQS, SNS, Lambda
                                                          │       (real account, or LocalStack offline)
                                                          ├──▶ Scanners: read-only reads of every region,
                                                          │       safe probes of public APIs, OWASP ASTF
                                                          ├──▶ API proxy ──▶ third-party APIs (e.g. Gemini)
                                                          │       the real key is added here
                                                          ├──▶ PostgreSQL: key vault, roles, usage history,
                                                          │       audit log, quarantine list
                                                          └──▶ Inventory service :8001 (second microservice)

  Telemetry:  backend + inventory ──OTLP──▶ OTel Collector ──┬──▶ Prometheus (metrics, alert rules) ──▶ Alertmanager
                                                             ├──▶ Loki (logs)
                                                             └──▶ Tempo (traces)
                                       Prometheus, Loki and Tempo ──▶ Grafana :3000
```

---

## 3. Services and ports

| Compose service | Container | Host port | Role |
|---|---|---|---|
| `frontend` | centralwatch-frontend | 8080 | CentralWatch platform (administrators) |
| `demo-frontend` | centralwatch-demo-frontend | 8090 | Demo application portal (users) |
| `demo-app` | centralwatch-demo-app | 8000 | FastAPI backend: business APIs, security plugin, scanners, AWS agent |
| `inventory-service` | centralwatch-inventory | 8001 | Second microservice, called when an order is created |
| `proxy-db` | centralwatch-proxy-db | internal | PostgreSQL for the key vault |
| `otel-collector` | centralwatch-otel-collector | 4317, 4318, 8889 | Receives OTLP telemetry; exposes metrics for Prometheus |
| `prometheus` | centralwatch-prometheus | 9091 (also 9090 in AWS mode) | Metrics and alert rules |
| `alertmanager` | centralwatch-alertmanager | 9093 | Groups active alerts |
| `loki` | centralwatch-loki | 3100 | Logs |
| `tempo` | centralwatch-tempo | 3200 | Traces |
| `grafana` | centralwatch-grafana | 3000 | Dashboards (anonymous access with the Admin role) |
| `localstack` | centralwatch-localstack | 4566 | Local AWS emulation (local mode only) |
| `redis` | centralwatch-redis | internal | Provisioned for a shared rate limiter; not used by the current code |
| `traffic-generator` | centralwatch-traffic-gen | – | Optional background traffic to keep the dashboards busy |

---

## 4. Getting started

**You need:** Docker with Docker Compose v2 (Docker Desktop on Windows or macOS). For AWS mode, an AWS
account. Use `127.0.0.1` rather than `localhost` in the browser on Windows (see
[Troubleshooting](#9-troubleshooting)).

### Option A: local mode (LocalStack, no AWS account)

```bash
make up            # or: docker compose up -d --build
make health        # checks every service
```

LocalStack emulates S3, DynamoDB, SQS, SNS and Lambda, and the backend creates the resources it needs.
A local administrator is created: `operator@example.com` / `Password123!` (local mode only; change it for
anything shared).

### Option B: real AWS

1. Create the AWS resources and IAM permissions listed in
   [archive/AWS_DEPLOYMENT.md](archive/AWS_DEPLOYMENT.md).
2. Copy the template and fill it in. The values marked "must be set" have no default:

   ```bash
   cp .env.aws.example .env
   ```

   | Variable | Value |
   |---|---|
   | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Your account (or leave the keys empty to use an IAM role) |
   | `DYNAMODB_*_TABLE`, `SNS_TOPIC`, `SQS_QUEUE`, `LAMBDA_FUNCTION` | Names of the resources from step 1 |
   | `AUTH_TOKEN_SECRET` | Must be set. A long random string, e.g. `python -c "import secrets; print(secrets.token_hex(32))"` |
   | `PROXY_SECRET_ENCRYPTION_KEY` | Must be set. 32 random bytes, URL-safe base64: `python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"` |
   | `PROXY_DB_PASSWORD`, `GRAFANA_ADMIN_PASSWORD` | Must be set. Passwords of your choice |

3. Start the stack:

   ```bash
   make up-aws
   # same as: docker compose -f docker-compose.yml -f docker-compose.aws.yml --env-file .env up -d --build
   ```

   Always start the stack with the same Compose project name, so it reuses the same data volumes. If you
   started it with `-p <name>`, keep passing the same `-p <name>`.

4. Make yourself an administrator: sign up in the demo portal, then in the DynamoDB `users` table set
   `is_admin` to `true` and `role` to `admin` on your item.
5. Optional: create three deliberately weak test APIs for the scanner and the deep test. They are public
   with no authentication, so remove them when you are done:

   ```bash
   docker exec -i centralwatch-demo-app python - up   < scripts/api_lab.py
   docker exec -i centralwatch-demo-app python - down < scripts/api_lab.py
   ```

### Stopping

```bash
make down          # or: docker compose down   (data volumes are kept)
```

---

## 5. Where to find each feature

| Address | What is there |
|---|---|
| http://127.0.0.1:8080 → **Overview** | Service status, active alerts, API security dashboard (exposed APIs, findings, leaks, health) |
| http://127.0.0.1:8080 → **API proxy** | Services and keys, roles, tokens, usage history, token cost against budget, quarantined IPs |
| http://127.0.0.1:8080 → **Security scan** | OWASP ASTF scan of a URL, with progress, Stop and the report |
| http://127.0.0.1:8080 → **AWS security agent** | AWS baseline and approved fixes, exposed API inventory, findings and fixes, deep test |
| http://127.0.0.1:8080 → **Alerts & Incidents** | Alerts currently active in Alertmanager |
| http://127.0.0.1:8080 → **Observability** | The Grafana dashboards, embedded |
| http://127.0.0.1:8090 | Demo application: orders, files, AWS workflows, simulations, Gemini chat |
| http://127.0.0.1:3000 | Grafana (admin / `admin` in local mode, or `GRAFANA_ADMIN_PASSWORD`) |
| http://127.0.0.1:9091 | Prometheus targets, rules and alerts |
| http://127.0.0.1:9093 | Alertmanager |
| http://127.0.0.1:8000/docs | Backend API (Swagger UI) |
| http://127.0.0.1:8001/docs | Inventory service API |

---

## 6. Configuration

These settings are passed to the backend by the compose files, so they can be set in `.env`:

| Variable | Default | Purpose |
|---|---|---|
| `TOKEN_TTL_SECONDS` | `86400` | Lifetime of a sign-in session |
| `API_SCAN_ALLOWLIST` | `cw-lab-*` | Comma-separated name patterns of APIs the deep test may attack |
| `API_RESCAN_INTERVAL_SECONDS` | `300` | How often the exposed API scan runs (`0` turns it off) |
| `API_DEEP_TEST_INTERVAL_SECONDS` | `86400` | How often the deep test runs (`0` turns it off) |
| `ASTF_SCAN_TIMEOUT_SECONDS` | `900` | Backstop for a Security scan (ASTF itself stops after 10 minutes) |

The backend also reads the settings below, but the compose files do not pass them in yet. To use one,
add it to the `environment:` list of the `demo-app` service in `docker-compose.yml` (or
`docker-compose.aws.yml`), for example `- AWS_SECURITY_AGENT_ALLOW_REMEDIATION=true`:

| Variable | Default | Purpose |
|---|---|---|
| `AWS_SECURITY_AGENT_ALLOW_REMEDIATION` | `false` | Allow the AWS security agent to apply approved fixes |
| `AWS_KMS_KEY_ID` | – | Encrypt stored keys with AWS KMS instead of the local master key |
| `ADMIN_PASSWORD` | – | Optional extra password accepted when revealing a token (no default) |
| `API_SCAN_TIME_BUDGET_SECONDS` | `60` | Time limit for reading the AWS settings of all regions |
| `DNS_WATCHDOG_INTERVAL_SECONDS` | `60` | How often the DNS watchdog checks lookups |

Alert rules are in `configs/prometheus/alerts.yml`; to send notifications, add a receiver
(e-mail, Slack, webhook) in `configs/alertmanager/alertmanager.yml`.

---

## 7. Tests and CI

```bash
pip install -r demo-app/requirements.txt -e ./centralwatch-security pytest
make test
```

`make test` runs the plugin tests (54) and the demo-app tests (21) on your machine. They use fake AWS
clients and a fake database, so no AWS account is needed.

GitHub Actions runs both suites and builds all three images on every push and pull request
(`.github/workflows/ci.yml`). A weekly workflow starts the stack and runs the health check
(`.github/workflows/security-scan.yml`).

---

## 8. Project layout

```
.
├── centralwatch-security/      Security plugin (installed into the backend image)
│   ├── centralwatch_security/
│   │   ├── routers.py          Proxy, key vault routes, OWASP ASTF scan routes
│   │   ├── proxy_store.py      PostgreSQL store, AES-256-GCM / KMS encryption, signed audit log
│   │   └── middleware.py       IP and key-status checks for the backend's own routes
│   └── tests/
├── demo-app/                   FastAPI backend (image includes Java for OWASP ASTF)
│   ├── app/
│   │   ├── main.py             App factory, background scan loops, DNS watchdog
│   │   ├── routes/             auth, orders, files, images, notifications, queue, chat, simulate, security_agent
│   │   ├── services/           AWS wrappers, api_inventory (scanner), api_watch, api_astf, security_agent
│   │   ├── telemetry/          OpenTelemetry setup, metrics, structured logging
│   │   └── config/settings.py  All settings and their defaults
│   └── tests/
├── inventory-service/          Second FastAPI microservice
├── traffic-generator/          Optional background traffic
├── frontend/
│   ├── platform/               CentralWatch platform (:8080)
│   └── demo/                   Demo application portal (:8090)
├── configs/                    nginx, OTel Collector, Prometheus + alerts, Alertmanager, Loki, Tempo, Grafana
├── scripts/                    security_scan.sh (ASTF), healthcheck.sh, api_lab.py (test APIs)
├── deploy/k8s/                 Kubernetes manifests
├── migrations/                 Reference SQL schema (the backend creates and upgrades its tables itself)
├── examples/                   curl examples, Python client example, OpenAPI generator
├── archive/                    Earlier guides, milestone notes and reports (not used by the build)
├── docker-compose.yml          Local mode (with LocalStack)
├── docker-compose.aws.yml      Overrides for real AWS
└── Makefile                    up, up-aws, down, health, test, logs, status, traffic
```

---

## 9. Troubleshooting

- **Pages do not open at `localhost` on Windows.** Use `http://127.0.0.1:8080` and `:8090`. After sleep or
  a network change, WSL can hold on to `localhost` and leave requests hanging.
- **A scan seems stuck.** A Security scan stops by itself after 10 minutes; use the Stop button to end it
  sooner. Refreshing or closing the page also stops it. The exposed API scan returns within about a minute
  even when some regions do not answer.
- **Gemini chat answers 503 or times out.** Google's model is overloaded; wait a moment and send again.
  The model name can be changed in the chat form.
- **The proxy page shows nothing.** The proxy management data is admin-only; sign in as an administrator.
- **Containers will not start after the laptop slept.** If Docker Desktop itself is stuck, restart Docker
  Desktop (or the computer). The backend restarts itself when only its DNS lookups hang.

---

## 10. More documentation

Older and longer guides are kept in [`archive/`](archive/):

- [AWS_DEPLOYMENT.md](archive/AWS_DEPLOYMENT.md): AWS resources, IAM policies and environment variables
- [CENTRALWATCH_PROJECT_GUIDE.md](archive/CENTRALWATCH_PROJECT_GUIDE.md): full project guide with the API reference
- [DEMO_PRESENTATION_GUIDE.md](archive/DEMO_PRESENTATION_GUIDE.md): step-by-step demo script
- [AWS_SECURITY_AGENT.md](archive/AWS_SECURITY_AGENT.md): the AWS security agent in detail
- [GEMINI_CHATBOT.md](archive/GEMINI_CHATBOT.md): Gemini chat through the proxy
- [PROXY_FEATURE_TESTING.md](archive/PROXY_FEATURE_TESTING.md): manual tests for the proxy

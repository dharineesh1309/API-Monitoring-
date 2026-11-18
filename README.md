# CentralWatch — Production-Grade Cloud & API Observability Platform

CentralWatch is an enterprise-grade **API Security, Monitoring, and Observability Platform** designed to provide full-stack visibility, credential governance, active threat defense, and distributed tracing across cloud-native architectures.

The architecture strictly separates the **CentralWatch Management Platform** (`:8080`) from client-facing **Business Applications** (`:8090`). The observability pipeline acts as a **non-intrusive bystander** that never sits on the critical data path of application requests.

```
                         APPLICATION TRAFFIC (Decoupled & Monitored)
   Browser ───[ :8090 ]───> Demo App (FastAPI :8000) ──W3C Trace──> Inventory Service (:8001)
                                      │                                       │
                                      ▼ (boto3)                               ▼ (boto3)
                            LocalStack / AWS Services               LocalStack / AWS Services
                                      │                                       │
                                      └───────────────────┬───────────────────┘
                                                          │ OpenTelemetry SDK (OTLP HTTP/gRPC)
                                                          ▼
                                              OTel Collector (:4317 / :4318)
                                               ┌──────────┼──────────┐
                                               ▼          ▼          ▼
                                          Prometheus    Loki       Tempo
                                            (:9090)    (:3100)    (:3200)
                                               │          │          │
                                               ├──────────┴──────────┘
                                               ▼
                                            Grafana (:3000)
                                               ▲
                                               │ Embedded Deep Links
   Operator ──[ :8080 ]───> CentralWatch Platform Gateway ──> Security & Proxy Store (Postgres)
```

---

## 1. System Port & Service Architecture

CentralWatch runs 12 integrated services on a dedicated Docker network (`centralwatch-network`):

| Service | Container | Host Port | Purpose & Architectural Role |
| :--- | :--- | :--- | :--- |
| **Platform UI** | `centralwatch-frontend` | `8080` | Dedicated operations portal: Overview, Proxy, ASTF Scanner, AWS CSPM, Observability |
| **Demo Application** | `centralwatch-demo-frontend` | `8090` | Client portal: Gemini Chatbot, Orders, S3 Files, AWS Workflows, Simulations |
| **Demo API Backend** | `centralwatch-demo-app` | `8000` | FastAPI core service emitting rich OpenTelemetry logs, metrics, and traces |
| **Inventory Microservice** | `centralwatch-inventory` | `8001` | Downstream microservice for multi-hop distributed tracing via W3C TraceContext |
| **Traffic Generator** | `centralwatch-traffic-gen` | *background* | Continuous autonomous workload generator exercising auth, orders, and traces |
| **PostgreSQL Proxy DB** | `centralwatch-proxy-db` | *internal:5432* | Tamper-evident audit logs, encrypted proxy secrets, multi-worker persistent state |
| **Prometheus** | `centralwatch-prometheus` | `9090` | Metrics time-series database with automated SLO & alert evaluation |
| **Alertmanager** | `centralwatch-alertmanager` | `9093` | Alert grouping, deduplication, and notification routing (Slack / Webhook) |
| **Grafana** | `centralwatch-grafana` | `3000` | Pre-provisioned dashboards with direct Loki-to-Tempo log-to-trace navigation |
| **Loki** | `centralwatch-loki` | `3100` | High-efficiency structured log aggregation with 7-day retention policy |
| **Tempo** | `centralwatch-tempo` | `3200` | High-throughput distributed tracing with TraceQL query engine |
| **LocalStack** | `centralwatch-localstack` | `4566` | Offline cloud emulator for S3, DynamoDB, SNS, SQS, and Lambda |
| **OTel Collector** | `centralwatch-otel-collector` | `4317`/`4318`/`8889` | Unified OpenTelemetry telemetry ingestion pipeline and Prometheus exporter |

---

## 2. Directory Layout & Important Files

```
API-Monitoring-/
├── centralwatch-security/          # Standalone enterprise API security & proxy engine package
│   ├── pyproject.toml              # Pinned build definition and package metadata
│   └── centralwatch_security/
│       ├── __init__.py             # Public exports: middleware, proxy store, security routers
│       ├── middleware.py           # Generic IP CIDR allowlisting & token verification ASGI middleware
│       ├── proxy_store.py          # Postgres-backed proxy store, KMS envelope cipher, HMAC audit logger
│       └── routers.py              # Proxy reverse gateway, SSRF firewall, sliding rate limiter, circuit breaker
│
├── demo-app/                       # Main FastAPI business backend application
│   ├── Dockerfile                  # Container build with Java runtime for OWASP scanner
│   ├── requirements.txt            # Pinned dependencies for reproducible production builds
│   ├── app/
│   │   ├── main.py                 # ASGI application factory, lifespan management, router mounts
│   │   ├── deps.py                 # Dependency injection: authentication and RBAC admin checks
│   │   ├── models/                 # Domain dataclasses: user (with admin role), order, file
│   │   ├── routes/                 # Endpoint routers: auth, orders, files, chat, security_agent, simulate
│   │   ├── services/               # AWS service wrappers, security agent with CIS benchmark checks
│   │   └── telemetry/              # OTel instrumentation, structured JSON logging, business spans
│   └── tests/                      # Automated test suite
│       ├── test_business_routes.py # E2E tests for auth, order creation, S3 files, and RBAC rejection
│       ├── test_chat.py            # Gemini chatbot proxy contract tests
│       └── test_security_agent.py  # AWS security baseline scanner tests
│
├── inventory-service/              # Downstream microservice for distributed trace demonstration
│   ├── Dockerfile                  # Lightweight Python 3.12 alpine container
│   └── app/
│       ├── main.py                 # FastAPI stock check endpoint reading W3C traceparent headers
│       └── telemetry.py            # Microservice OpenTelemetry setup reporting to collector
│
├── traffic-generator/              # Autonomous continuous workload generator
│   ├── Dockerfile                  # Background container runner
│   ├── generator.py                # Concurrent workers generating auth, order, and simulation traffic
│   └── requirements.txt            # Minimal HTTPX client dependencies
│
├── frontend/                       # Decoupled web client applications
│   ├── platform/                   # CentralWatch Operator Console (served on :8080)
│   │   ├── index.html              # Management UI (Overview, Proxy, Security scan, AWS agent, Observability)
│   │   ├── app.js                  # Platform API integration and real-time health checks
│   │   └── styles.css              # Dark/light theme design system
│   └── demo/                       # Demo Business Application (served on :8090)
│       ├── index.html              # End-user UI (Chatbot, Orders, Files, AWS workflows, Simulations)
│       ├── app.js                  # Client state, auth token management, simulation runners
│       └── styles.css              # Consistent theme styling
│
├── configs/                        # Unified service configurations
│   ├── alertmanager/               # Alertmanager routing and webhook configurations
│   ├── collector/                  # OpenTelemetry collector pipelines and processors
│   ├── grafana/provisioning/       # Auto-provisioned datasources and production dashboards
│   │   ├── dashboards/             # SLO, Services, Overview, API monitoring, Security, Traces, Logs
│   │   └── datasources/yaml        # Loki derivedFields for one-click log-to-trace deep linking
│   ├── loki/                       # Loki configuration with 7-day retention and compactor
│   ├── nginx/                      # Separate reverse proxy configs: centralwatch.conf and demo.conf
│   ├── prometheus/                 # Prometheus scrape configs and alerts.yml rule definitions
│   └── tempo/                      # Tempo distributed tracing and block retention rules
│
├── deploy/k8s/                     # Production Kubernetes manifests
│   ├── namespace.yaml              # Isolated `centralwatch` namespace
│   ├── configmap.yaml              # Production environment configurations
│   ├── deployment.yaml             # Deployments for demo-app, inventory, and dual nginx frontends
│   ├── service.yaml                # ClusterIP services
│   └── ingress.yaml                # NGINX Ingress Controller rules with TLS termination
│
├── migrations/                     # Database schema migrations
│   └── 001_initial_proxy_schema.sql# PostgreSQL tables: proxy_services, roles, audit_logs, usage_history
│
├── examples/                       # Developer SDK and integration tooling
│   ├── python_sdk_example.py       # Python SDK showing credential-less proxy calls with tracing
│   ├── curl_examples.sh            # Complete bash cURL walk-through for CLI operators
│   └── generate_openapi.py         # Static OpenAPI schema generation utility
│
├── Makefile                        # Command-line developer workflow orchestration
├── docker-compose.yml              # LocalStack development multi-container composition
├── docker-compose.aws.yml          # Production AWS multi-container composition
├── progress.md                     # Detailed engineering tracking of all 6 production upgrade phases
└── ARCHITECTURE_AND_IMPROVEMENTS.md# Deep technical architecture documentation and specifications
```

---

## 3. Production-Grade Features Implemented

CentralWatch has been upgraded from a basic telemetry sample into an enterprise-grade platform across 6 major categories:

### 1. Security Basics (Must-Haves)
* **RBAC & Admin Route Protection:** All proxy credential management routes require authentication and admin privileges (`is_admin: true` / `role: "admin"`). Non-admin users are rejected with `403 Forbidden`.
* **SSRF (Server-Side Request Forgery) Firewall:** Pre-flight DNS resolution blocks requests to loopback (`127.0.0.0/8`, `::1`), private RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local IPs (`169.254.0.0/16`, `fe80::/10`), and cloud metadata services (`169.254.169.254`).
* **AWS KMS & Key Rotation:** Master secrets support AWS KMS envelope encryption with annual rotation and automated database re-encryption (`rotate_master_encryption_key`).
* **Tamper-Evident Audit Logging:** Every administrative action (`SERVICE_CREATED`, `TOKEN_ROTATED`, `ROLE_MODIFIED`) is signed using HMAC-SHA256 and stored in `proxy_audit_logs`.
* **Sliding Rate Limiter & Budget Quotas:** Token and service quotas prevent downstream API exhaustion, returning standard HTTP 429 with `Retry-After` headers.

### 2. Alerting Pipeline
* **Prometheus Alert Rules:** Pre-configured alerts for `HighErrorRate` (>5% 5xx for 2m), `HighLatencyP99` (>1000ms), `ServiceDown`, `ProxySecurityViolationsSpike`, and `SSRFBlockedAttempt`.
* **Alertmanager Routing:** Automated deduplication, grouping, and webhook dispatching for critical alerts.
* **Log-to-Trace Deep Links in Grafana:** Loki datasource configured with `derivedFields` regex matching `"trace_id"`, allowing one-click navigation directly from log lines into Tempo trace waterfalls.

### 3. Proxy Upgrades (Star Feature)
* **Per-Service Budgets & Cost Tracking:** Automatic tracking of prompt and completion tokens for LLM providers (Gemini, Claude, OpenAI) with cost estimation per caller.
* **Token Expiry & Schedules:** Proxy tokens enforce expiration (`token_expires_at`) with a single-click rotation endpoint.
* **Secret Redaction:** Outbound logs and audit records automatically scrub sensitive headers (`Authorization`, `x-goog-api-key`, `api-key`, `cookie`).
* **Resilience Mechanisms:** Sliding TTL response caching for idempotent GETs, exponential retries on upstream 5xx errors, and an in-memory circuit breaker that trips after 5 consecutive failures.
* **Multi-Key Failover:** Configurable secondary upstream keys that automatically activate when an upstream provider returns HTTP 429 (quota exhausted).

### 4. Reliability and Scale
* **PostgreSQL State Persistence:** Replaced in-memory usage dictionaries with persistent tables (`proxy_services`, `proxy_roles`, `proxy_usage_history`, `proxy_audit_logs`) enabling horizontal multi-worker scaling.
* **Async Boto3 Operations:** Wrapped DynamoDB calls in `asyncio.to_thread` across auth and orders routes to eliminate event loop blocking.
* **Database Migrations:** Schema migrations managed via versioned SQL scripts in `migrations/`.
* **Kubernetes Manifests & Retention Policies:** Production Kubernetes manifests in `deploy/k8s/` and enforced 7-day Loki / 48-hour Tempo retention limits.

### 5. Security Depth (CSPM / SIEM)
* **CloudTrail Multi-Region Ingestion:** Verifies active multi-region logging mapped to CIS AWS Benchmark 3.1.
* **CIS Benchmark-Mapped CSPM Checks:** Evaluates IAM root account keys (CIS 1.4), S3 default encryption & public blocks (CIS 2.1.1, 2.1.5), unrestricted security groups (CIS 5.2), and KMS key rotation (CIS 3.8).
* **SIEM Threat Correlation Engine:** Flags brute-force token harvesting and reconnaissance scans.
* **Compliance Scoring & Trend History:** Computes real-time compliance scores (0–100%) stored with historical timestamp trends.

### 6. Engineering Hygiene
* **CI/CD Automation:** GitHub Actions workflows (`.github/workflows/ci.yml` and `security-scan.yml`) with Python 3.12, linting, security tests, and container builds.
* **Business-Route Tests:** Comprehensive test suite in `demo-app/tests/test_business_routes.py` covering auth, orders, files, and RBAC rejection.
* **Developer SDK & OpenAPI Spec:** Standalone Python client SDK, bash cURL examples, and automated OpenAPI specification generator in `examples/`.

---

## 4. Quick Start & Developer Workflow

### Using the Makefile (Recommended)

```bash
# Display all available developer commands
make help

# Build and start all 12 services
make up

# Verify end-to-end health across all services
make health

# View live traffic generator logs
make traffic

# Run automated test suite
make test

# Shut down all services
make down
```

### Manual Docker Compose

```bash
# Build and run in detached mode
docker compose up -d --build

# Run the comprehensive health check script
./scripts/healthcheck.sh
```

---

## 5. Endpoints & Access Points

* **CentralWatch Platform Console:** `http://localhost:8080`
* **Demo Business Application:** `http://localhost:8090`
* **Demo API Swagger Documentation:** `http://localhost:8000/docs`
* **Inventory Microservice API:** `http://localhost:8001/docs`
* **Grafana Dashboards:** `http://localhost:3000` (User: `admin`, Password: `admin`)
* **Prometheus Targets & Alerts:** `http://localhost:9090`
* **Alertmanager UI:** `http://localhost:9093`
* **Loki Log Aggregator:** `http://localhost:3100`
* **Tempo Tracing Engine:** `http://localhost:3200`
* **LocalStack Gateway:** `http://localhost:4566`

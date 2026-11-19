# CentralWatch — Architecture, Port Separation & 3-4 Month Feature Roadmap

This document outlines the architectural changes, port separation, and newly implemented features that elevate **CentralWatch** into a production-grade, multi-service API Observability & Security platform worthy of a 3 to 4 month capstone or production portfolio project.

---

## 1. Port Separation Architecture

Previously, the CentralWatch management platform and the sample business applications were served through the same frontend proxy at port `8080`, while the backend API was reachable directly at port `8000`.

To establish a clear separation of concerns between **Platform Operators** (SREs, SecOps) and **End-User Application Consumers**, the system has been decoupled into dedicated endpoints:

| Service / Interface | URL / Port | Audience | Purpose |
|---|---|---|---|
| **CentralWatch Platform UI** | `http://localhost:8080` | SREs, SecOps, Admins | System Overview, API Proxy Firewall, OWASP Security Scanners, AWS Security Agent, Observability Links |
| **Demo Application UI** | `http://localhost:8090` | End Users, Customers | Order Management, S3 File Uploads, Gemini AI Chatbot, Failure & Error Simulations |
| **CentralWatch Backend API** | `http://localhost:8000` | Microservices / Gateways | Core FastAPI application exposing business APIs, proxy routes, and telemetry middleware |
| **Inventory Microservice** | `http://localhost:8001` | Internal Services | Downstream stock & inventory service for cross-service distributed tracing |
| **Grafana Observability** | `http://localhost:3000` | SREs / Monitoring | Dashboards: Overview, SLO & Error Budget, Distributed Services, API Monitoring, Security, Traces, Logs |
| **Prometheus Metrics** | `http://localhost:9090` | Monitoring / Alerts | Metric time-series storage, alert evaluation, scrape targets |
| **Alertmanager** | `http://localhost:9093` | Alert Dispatching | Real-time alert routing, grouping, and deduplication for SLO breaches |
| **Loki Log Aggregator** | `http://localhost:3100` | Log Analysis | Log aggregation with LogQL and direct Log-to-Trace deep linking |
| **Tempo Distributed Tracing**| `http://localhost:3200` | Trace Analysis | High-scale trace storage supporting TraceQL queries and span waterfalls |
| **LocalStack AWS Emulation** | `http://localhost:4566` | Cloud Services | Emulated S3, DynamoDB, SNS, SQS, and Lambda runtime |
| **Redis Cache & Limiter** | `internal:6379` | API Gateway | High-speed cache for sliding-window IP/Token rate limiting |

---

## 2. System Architecture Diagram

```
                             [ Traffic Generator ]
                              (continuous synthetic
                               realistic traffic)
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │  CentralWatch Platform│             │   Demo Application    │
        │      (Port :8080)     │             │      (Port :8090)     │
        │  configs/nginx/       │             │  configs/nginx/       │
        │  centralwatch.conf    │             │  demo.conf            │
        └───────────┬───────────┘             └───────────┬───────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼ (Reverse Proxy /api/*)
                         ┌───────────────────────────┐
                         │   FastAPI Demo Backend    │ (Port :8000)
                         │   - Security Middleware   │
                         │   - OTel Auto-Tracing     │
                         │   - DynamoDB / S3 / SNS   │
                         └─────────────┬─────────────┘
                                       │ (TraceContext HTTP call)
                                       ▼
                         ┌───────────────────────────┐
                         │    Inventory Service      │ (Port :8001 - Microservice)
                         │    - Stock Checks         │
                         │    - Simulated Latency    │
                         │    - Distributed Tracing  │
                         └─────────────┬─────────────┘
                                       │
                                       ▼ (OTLP gRPC/HTTP :4317/:4318)
                         ┌───────────────────────────┐
                         │   OpenTelemetry Collector │
                         │   - Memory Limiter        │
                         │   - Batching & Processing │
                         └──────┬────────────┬───────┘
                                │            │
                 ┌──────────────┘            └──────────────┐
                 ▼ (Prometheus Exporter)                    ▼ (OTLP Tempo / Loki Push)
        ┌──────────────────┐                     ┌──────────────────┐
        │    Prometheus    │                     │   Loki & Tempo   │
        │   (Port :9090)   │                     │  (:3100 / :3200) │
        └────────┬─────────┘                     └────────┬─────────┘
                 │ (Alert Rules evaluation)               │
                 ▼                                        │
        ┌──────────────────┐                              │
        │   Alertmanager   │                              │
        │   (Port :9093)   │                              │
        └────────┬─────────┘                              │
                 │                                        │
                 └──────────────────┬─────────────────────┘
                                    ▼
                         ┌───────────────────────────┐
                         │          Grafana          │ (Port :3000)
                         │  - SLO & Error Budgets    │
                         │  - Cross-Service Tracing  │
                         │  - Log-to-Trace Links     │
                         └───────────────────────────┘
```

---

## 3. Comprehensive Improvements & New Features

### Feature 1: Multi-Service Distributed Tracing (`inventory-service/`)
- **Location:** `inventory-service/`
- **What it solves:** Single-service traces look like basic server logs. Distributed tracing across multiple independent microservices is what real-world SRE and backend architectures demand.
- **Implementation:**
  - Dedicated FastAPI service running on port `8001`.
  - Configured with `TracerProvider`, `OTLPSpanExporter`, and `FastAPIInstrumentor`.
  - `demo-app/app/routes/orders.py` injects the W3C `traceparent` context header into outgoing HTTP requests when placing an order.
  - Generates cross-service spans in Tempo waterfalls showing:
    `demo-app: POST /orders` ➔ `inventory-service: GET /inventory/{product}` ➔ `LocalStack DynamoDB: PutItem`.

### Feature 2: Automated Continuous Traffic Generator (`traffic-generator/`)
- **Location:** `traffic-generator/`
- **What it solves:** Monitoring dashboards usually look empty and stagnant unless somebody is clicking through the UI.
- **Implementation:**
  - Python 3.12 asynchronous background worker using `httpx`.
  - Automatically authenticates against the demo application on startup.
  - Emits steady, randomized traffic (with ±20% jitter) across:
    - Normal business traffic: `/healthz` (10s), `/orders` (15s), `POST /orders` (20s), `/files` (30s), `/queue` (45s).
    - Fault-injection traffic: `/simulate/error` (60s), `/simulate/timeout` (90s), `/simulate/retry` (120s).
  - Keeps Prometheus rate graphs, Loki log streams, and Tempo trace timelines continuously populated.

### Feature 3: Production Alerting Engine (`configs/alertmanager/`, `configs/prometheus/alerts.yml`)
- **Location:** `configs/alertmanager/alertmanager.yml` & `configs/prometheus/alerts.yml`
- **What it solves:** Observability without alerting is passive. Modern systems notify engineers immediately when Service Level Objectives (SLOs) are threatened.
- **Implementation:**
  - Added official Prometheus Alertmanager container on port `9093`.
  - Prometheus configured with lifecycle hooks and rule evaluation:
    - `HighErrorRate`: triggers when 5xx responses exceed 5% over a 5-minute rolling window (`critical`).
    - `HighLatencyP99`: triggers when p99 latency exceeds 1,000ms (`warning`).
    - `ServiceDown`: triggers when any monitored scrape target is unreachable for >1 minute (`critical`).

### Feature 4: SLO & Error Budget Dashboard in Grafana (`slo.json`)
- **Location:** `configs/grafana/provisioning/dashboards/slo.json`
- **What it provides:**
  - **30-Day Error Budget Remaining Gauge:** Visualizes burning through the 99.9% availability target.
  - **Request Success Rate KPI:** Real-time percentile health with green/yellow/red degradation thresholds.
  - **P50 / P95 / P99 Latency Curves:** Sub-second percentile distributions over time.
  - **Active Firing Alerts Table:** Integrated view of active Prometheus alerts directly within Grafana.

### Feature 5: Distributed Services Dashboard (`services.json`)
- **Location:** `configs/grafana/provisioning/dashboards/services.json`
- **What it provides:**
  - Multi-service latency and request breakdown comparing `centralwatch-demo-app` and `centralwatch-inventory`.
  - Deep-link panels into Tempo's service graph and trace explorer.

### Feature 6: Log-to-Trace Deep Correlation (Loki ➔ Tempo)
- **Location:** `configs/grafana/provisioning/datasources/datasources.yaml`
- **What it provides:**
  - Configured `derivedFields` in the Loki datasource matching regex `"trace_id":"(\w+)"`.
  - In Grafana's Log Viewer, clicking any log line with a `trace_id` instantly opens the trace waterfall in Tempo with zero context switching.

### Feature 7: Unified Developer Workflow (`Makefile`)
- **Location:** `Makefile`
- **Commands:**
  - `make help`: Display interactive CLI target reference.
  - `make up`: Start entire stack in LocalStack development mode.
  - `make up-aws`: Start stack in AWS production mode.
  - `make health`: Execute deep container and HTTP health check.
  - `make logs` / `make logs-<service>`: Tail streaming logs.
  - `make traffic`: Inspect background traffic generator state.
  - `make clean`: Tear down containers and wipe persistent data volumes.

### Feature 8: CI & Scheduled Security Automation (`.github/workflows/`)
- **Location:** `.github/workflows/ci.yml` & `.github/workflows/security-scan.yml`
- **What it provides:**
  - Automated test runs for `centralwatch-security` and `demo-app`.
  - Parallel Docker build verification for all custom containers (`demo-app`, `inventory-service`, `traffic-generator`).
  - Weekly scheduled cron job running the OWASP security compliance scan.

---

## 4. How to Verify and Run

To launch the upgraded stack with all new components:

```bash
# Start all services with automated builds
make up

# Run deep health verification
make health

# Check live traffic generation
make traffic
```

You can now visit:
- **CentralWatch Platform Dashboard:** `http://localhost:8080`
- **Demo Application UI:** `http://localhost:8090`
- **Grafana Dashboards:** `http://localhost:3000` (Browse ➔ CentralWatch ➔ "SLO & Error Budget" or "Distributed Services")
- **Alertmanager:** `http://localhost:9093`
- **Prometheus Alerts:** `http://localhost:9090/alerts`



---

## 5. End-to-End Demo Script & Step-by-Step Testing Procedure

Here is the exact procedure to showcase every feature in an impressive, structured 5-to-10 minute project walkthrough.

### Phase 1: Stack Startup & Health Verification
1. **Show the Developer CLI:**
   ```bash
   # Display all targets with descriptions
   make help

   # Start the entire ecosystem (builds custom images automatically)
   make up
   ```
2. **Run Deep Verification:**
   ```bash
   make health
   ```
   - **What to highlight:** The automated test checks all 10 containers, verifies HTTP readiness on both ports `:8080` (Platform) and `:8090` (Demo App), and confirms Prometheus target scrape status.

---

### Phase 2: CentralWatch Platform UI (`http://localhost:8080`)
Open `http://localhost:8080` in your browser.

1. **Overview Dashboard (`#overview`):**
   - Point out that **only Platform tabs** (Overview, API Proxy, Security Scan, AWS Security Agent, Observability) are present.
   - Show the **Health Mesh**: Green indicators for Demo App, OTel Collector, Prometheus, Loki, Tempo, and LocalStack.
   - Point out the topbar link: **Demo App (:8090) ↗**.

2. **API Proxy Firewall (`#proxy`):**
   - **The Story:** Instead of letting microservices hold raw upstream API keys, CentralWatch acts as a security firewall. It injects AES-encrypted credentials and checks caller CIDR subnets before proxying.
   - Show registered upstream services and active access roles.

3. **Security Audit & Automated Vulnerability Scanning (`#security`):**
   - View the embedded OWASP API Security Top 10 report.
   - Explain how any CIDR violation or revoked token returns `403 Forbidden` and instantly emits a structured security audit event into OpenTelemetry and Loki.

4. **AWS Security Agent (`#aws-security`):**
   - Run an automated scan of emulated AWS cloud infrastructure (S3 bucket public access, DynamoDB encryption, IAM roles).
   - Show compliance baselines and remediation status.

5. **Observability Tab (`#observability`):**
   - Switch between provisioned Grafana dashboards without leaving the CentralWatch UI:
     - **Overview**
     - **API Monitoring**
     - **SLO & Error Budget** (30-day budget burn rate, p95/p99 latency)
     - **Distributed Services** (Multi-service tracing)
     - **Security Threat Intelligence**

---

### Phase 3: The Demo Application (`http://localhost:8090`)
Open `http://localhost:8090` in another browser tab.

1. **Clear Separation of Concerns:**
   - Point out the UI difference: this application is strictly for business operations (Chatbot, Orders, Files, AWS, Simulations). All platform administration links have been cleanly removed.
2. **Gemini AI Chatbot (`#chat`):**
   - Configure a Gemini API key or proxy token.
   - Send a prompt (e.g., *"Explain how OpenTelemetry distributed tracing works"*).
   - **What to highlight:** The demo app never stores the Gemini API key in its own environment. CentralWatch securely injects it upstream.
3. **Orders & Distributed Tracing (`#orders`):**
   - Sign in or create an account (e.g. `alice@example.com` / `password123`).
   - Click **New order**, add items (e.g., "Widget", quantity: 3, unit price: $19.99), and submit.
   - **What happened under the hood:**
     `demo-app` created the order in DynamoDB, and made an HTTP call to the downstream `inventory-service` (:8001) passing the W3C `traceparent` header.
4. **AWS Cloud Workflows (`#aws`):**
   - Upload a test file to S3.
   - Send a message to the SQS queue and click **Receive** to retrieve it.
5. **Simulations (`#simulations`):**
   - Trigger deliberate error scenarios to test observability:
     - Click **Application error** (produces an intentional 500).
     - Click **Slow request** (generates a 5-second latency trace).
     - Click **S3 failure** (attempts invalid bucket access, produces a 502).

---

### Phase 4: Observability in Action (Grafana & Alertmanager)
Open `http://localhost:3000` (Grafana) and `http://localhost:9093` (Alertmanager).

1. **Live Traffic Generation:**
   ```bash
   make traffic
   ```
   - Show the continuous background worker sending authenticated requests and injecting faults.
2. **Distributed Trace Waterfalls in Tempo:**
   - In Grafana, navigate to **Explore ➔ Tempo** (or the **Distributed Services** dashboard).
   - Search for recent traces with `service.name = "centralwatch-demo-app"`.
   - Open a trace: Show the cross-service waterfall spanning `demo-app: POST /orders` ➔ `inventory-service: GET /inventory/Widget` ➔ `DynamoDB: PutItem`.
3. **Log-to-Trace Deep Correlation:**
   - In Grafana, navigate to **Explore ➔ Loki**.
   - Query `{compose_service="centralwatch-demo-app"}`.
   - Find any log line containing a `trace_id`.
   - Click the blue **View Trace in Tempo** button next to the trace ID: it directly opens the corresponding trace waterfall with zero searching!
4. **Inspect Alerting Engine:**
   - Visit `http://localhost:9090/alerts` in Prometheus to view the evaluation rules (`HighErrorRate`, `HighLatencyP99`, `ServiceDown`).
   - Visit `http://localhost:9093` in Alertmanager to inspect active alerts and suppression groups.

---

## Phase 5: Security Operations, Quarantined IPs & Zero-Trust RBAC

### Feature 1: Quarantined & Blocked IP Management
- **Architecture:** Persistent PostgreSQL table `proxy_quarantined_ips` coupled with zero-latency in-memory cache set (`_quarantined_ips`) in `PostgresProxyStore`.
- **Automated Defense:** When an untrusted host executes repeated unauthorized attempts or brute-force credential stuffing (tested via `/simulate/brute-force`), the firewall immediately quarantines the attacker IP (e.g. `198.51.100.42`), raises a critical alert in Alertmanager (`IPBruteForceBlocked`), and blocks all subsequent proxy traffic from that IP with `HTTP 403` (`outcome: blocked_quarantine`).
- **Administrative Control Panel:** The CentralWatch Platform UI (`http://localhost:8080/#proxy`) features a dedicated **Quarantined & Blocked IPs** management card displaying:
  - Blocked IP address
  - Reason & attack vector
  - Detection timestamp & mechanism (`firewall_auto_defense`)
  - Incident attempt count
  - Instant one-click **Unblock IP** action with tamper-evident audit logging (`IP_UNBLOCKED`).

### Feature 2: Cryptographically Secure Random Tokens & Dynamic RBAC
- **Cryptographic Generation:** All machine-to-machine proxy access tokens are generated as high-entropy 24-byte URL-safe base64 strings (`cw_role_<random_token>`) using Python `secrets`, eliminating human-predictable identifiers.
- **Dynamic Role Lookup by Token Hash:** The security engine resolves incoming tokens via constant-time SHA-256 digests across all provisioned roles (`get_role_by_token_hash`).
- **Strict Role Boundaries (RBAC):** Roles enforce granular service and method permissions:
  - `gemini_chat`: Permitted for `gemini_api` with `POST`.
  - `proxy_reader`: Permitted for read-only inspection across all services (`GET`, `HEAD`, `OPTIONS`).
  - `non_chat_role`: Restricted to non-AI services. When an authorized caller attempts to use this token for Gemini chat, CentralWatch enforces the boundary, rejects the request with `403 Forbidden`, and records `blocked_role` in the immutable audit trail.
- **Password-Protected Token Reveal:** To comply with least-privilege security, token secrets are masked in the UI. Revealing any service or role token requires a signed-in administrator to re-enter their own password (or `ADMIN_PASSWORD`, if set; there is no built-in default), logged in the audit trail.

### Feature 3: Linux Host Docker Socket & AWS Lambda Runtime
- **Problem Resolved:** LocalStack emulates AWS Lambda by spawning Docker execution containers. On Linux hosts, the default Docker Desktop path (`/run/host-services/docker.proxy.sock`) was nonexistent, leaving the Lambda function in a `State: Failed` condition.
- **Solution:** Configured `DOCKER_SOCK_PATH=/var/run/docker.sock` in `.env` and `docker-compose.yml`, mounting the host Docker daemon socket into LocalStack.
- **Workflow Verified:** End-to-end asynchronous **S3 ➔ Lambda ➔ SNS** image processing (`centralwatch-image-processor`) processes images, invokes the containerized runtime, and broadcasts completion events.

### Feature 4: Seamless Grafana Trace Inspection & Anonymous Admin Access
- **Frictionless Tracing:** Set `GF_AUTH_ANONYMOUS_ORG_ROLE=Admin` in `docker-compose.yml`. Anonymous viewers navigating to Grafana Explore or clicking trace links are never redirected to the login screen or homepage.
- **Direct Trace Detail Links:** Configured dual data links on `traceID` columns in both `tracing.json` and `aws-services.json`:
  1. **View Trace Details in Explore:** Opens Grafana's native Tempo trace viewer in a new tab, displaying the full span tree, durations, HTTP/AWS tags, and correlated Loki logs.
  2. **Open Trace in Waterfall Panel:** Dynamically updates the embedded waterfall panel directly on the CentralWatch dashboard.

### Feature 5: Managed Workload Traffic Generator
- Reconnected and natively integrated `traffic-generator` into `docker-compose.yml` (`centralwatch-traffic-gen`), enabling autonomous workload simulation that can be started, stopped, or inspected via `docker compose stop/start traffic-generator` or `make traffic`.

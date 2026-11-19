# CentralWatch — 15 to 20 Minute Production Demo Guide

A complete, step-by-step presentation script and operational runbook designed for portfolio reviews, technical interviews, and stakeholder demos.

---

## Demo Overview & Timing Breakdown

| Segment | Topic | Target Time | Interface / Tool |
| :---: | :--- | :---: | :--- |
| **Phase 1** | Architecture Overview & Clean Port Separation | 0:00 – 3:00 | System diagram & Browser (`:8080`, `:8090`) |
| **Phase 2** | Demo App Workflows & Distributed Microservices | 3:00 – 7:00 | Demo UI (`:8090`) & Inventory (`:8001`) |
| **Phase 3** | Zero-Trust API Proxy & Credential Firewall | 7:00 – 11:00 | Platform UI (`:8080`) & Gemini Chatbot |
| **Phase 4** | Security Operations: ASTF & AWS CIS CSPM Agent | 11:00 – 15:00 | Platform UI (`:8080`) |
| **Phase 5** | Observability, SLO Dashboards & Log-to-Trace Links | 15:00 – 18:00 | Grafana (`:3000`), Loki, Tempo |
| **Phase 6** | Reliability, Kubernetes & Engineering Hygiene | 18:00 – 20:00 | Terminal, Makefile, k8s manifests |

---

## Phase 1: Architecture Overview & Port Separation (0:00 – 3:00)

### 1. The Opening Pitch
> *"Welcome! Today I am presenting **CentralWatch**, an enterprise-grade API monitoring, security, and observability platform. 
> A common flaw in monitoring systems is that they sit in the critical path of application requests or combine user workflows with administrative consoles. 
> In CentralWatch, we designed the monitoring system as a completely non-intrusive **bystander**, and we strictly decoupled the platform operator console from the business application onto independent ports."*

### 2. Live Verification
1. **Show the Platform Operator Console:**
   * Open `http://localhost:8080` in your browser.
   * Highlight the navigation items: **Overview**, **API Proxy**, **Security Scan**, **AWS Security Agent**, and **Observability**.
   * Note the top-right button: `Demo App (:8090) ↗`.
2. **Show the Business Application:**
   * Open `http://localhost:8090` in a side-by-side or second tab.
   * Highlight the navigation items: **Gemini Chatbot**, **Orders**, **Files**, **AWS Workflows**, and **Simulations**.
   * Note the top-right button: `CentralWatch (:8080) ↗`.

### 3. What That Does & Why It's Needed
* **What it does:** Uses separate NGINX reverse-proxy instances (`centralwatch.conf` and `demo.conf`) binding to distinct host ports. The Platform UI (`:8080`) proxies to administrative health mesh endpoints and proxy engines, while the Demo App (`:8090`) only touches business endpoints.
* **Why it's needed:** Prevents security privilege escalation, avoids cross-site DOM contamination, and enforces least-privilege access where end users cannot access proxy management routes or internal security scanners.

---

## Phase 2: Demo App Workflows & Distributed Microservices (3:00 – 7:00)

### 1. User Authentication & Profile
1. On `http://localhost:8090`, click **Sign in** in the bottom left sidebar.
2. In the dialog, sign in with:
   * **Email:** `operator@example.com`
   * **Password:** `Password123!`
3. Notice the status indicator changes to **Signed in** and displays your operator badge.

### 2. Multi-Hop Distributed Tracing (Orders Workflow)
1. Navigate to the **Orders** tab on `http://localhost:8090/#orders`.
2. Click **New order**. Add an item (e.g. `Widget Pro`, Quantity `2`, Unit Price `$29.99`).
3. Click **Create order**. The order is created immediately and appears in the history table.

### 3. S3 Uploads & LocalStack Workflows
1. Navigate to **Files** (`http://localhost:8090/#files`).
2. Upload a small image or text file.
3. Show the file appearing with its S3 bucket name and DynamoDB metadata record.
4. Navigate to **AWS Workflows** (`http://localhost:8090/#aws`).
5. Send an SNS notification (Email/SMS) and publish a message to the SQS queue. Click **Receive** to dequeue and verify consumption.

### 4. What That Does & Why It's Needed
* **What it does:**
  * When an order is created, the demo app doesn't just write to DynamoDB; it propagates the W3C `traceparent` HTTP header to the downstream **Inventory Microservice** (`inventory-service:8001/inventory/{product}`).
  * All AWS calls (S3, DynamoDB, SNS, SQS) are instrumented via OpenTelemetry Botocore instrumentation.
  * Synchronous Boto3 calls are offloaded using `asyncio.to_thread` so that heavy AWS operations never block FastAPI's async event loop.
* **Why it's needed:** In production, e-commerce workflows involve microservice interdependencies. Without W3C header propagation, traces terminate at the service boundary. This demonstrates real-world cross-service distributed observability.

---

## Phase 3: Zero-Trust API Proxy & Credential Firewall (7:00 – 11:00)

### 1. The Problem with Upstream API Keys
> *"Modern apps rely heavily on third-party APIs like Google Gemini, Stripe, or OpenAI. The common anti-pattern is distributing API keys across frontend applications, mobile clients, or microservices, risking leakages and budget exhaustion. CentralWatch solves this with a Zero-Trust Credential Firewall."*

### 2. Managed API Proxy Console
1. Switch to `http://localhost:8080/#proxy`.
2. Show the pre-registered `gemini_api` service:
   * **Base URL:** `https://generativelanguage.googleapis.com`
   * **Role:** `gemini_chat` (POST only)
   * **Status:** Encrypted in PostgreSQL using AES-256-GCM / AWS KMS.
3. Point out the **Security Controls**:
   * **SSRF Protection:** Explain that any upstream target resolving to `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, or `169.254.169.254` is blocked at the gateway before an HTTP request is made.
   * **Sliding Rate Limiter & Budget Quotas:** Limits callers to 120 RPM and caps monthly token spend.
   * **Circuit Breaker:** Automatically trips to OPEN if upstream 5xx errors persist.
   * **Multi-Key Failover:** Configurable primary and secondary keys; if Gemini returns `429 Quota Exceeded`, CentralWatch transparently retries with the fallback key without user disruption.

### 3. Credential-Less Gemini Chatbot in Action
1. Switch to `http://localhost:8090/#chat`.
2. Notice the setup card: the demo application only holds a proxy token (`cw_proxy_...`), **not** the raw Gemini key.
3. Type a prompt: `"Explain distributed tracing in 2 sentences."` and click **Send prompt**.
4. Show the response streaming back.
5. Switch back to `http://localhost:8080/#proxy`:
   * Point out the **Usage History** and **Audit Log** tables.
   * Show that the request was logged, sensitive tokens were redacted, and LLM token counts/costs were calculated.

---

## Phase 4: Security Operations: ASTF & AWS CIS CSPM Agent (11:00 – 15:00)

### 1. Authenticated OWASP ASTF Security Scan
1. Navigate to **Security scan** (`http://localhost:8080/#security`).
2. Click **Trigger security scan**.
3. Explain:
   * CentralWatch launches the automated OWASP API Security Top 10 scanner in the background.
   * The scanner executes checks against authenticated endpoints using the operator session token.
4. When complete, click **Open HTML report** to display the rendered ASTF report detailing vulnerabilities and endpoint hardening verification.

### 2. AWS Security Agent (CIS Foundations Benchmark CSPM)
1. Navigate to **AWS security agent** (`http://localhost:8080/#aws-security`).
2. Show the latest compliance score (e.g. `85.7%`) and trend history chart.
3. Explain the CIS Benchmark mappings:
   * **CIS 1.4:** IAM root account access key verification.
   * **CIS 2.1.1 & 2.1.5:** S3 default encryption and complete Public Access Block.
   * **CIS 3.1:** Multi-region CloudTrail logging verification.
   * **CIS 5.2:** Security Group ingress check (blocking `0.0.0.0/0` on SSH port 22 and RDP port 3389).
4. Point out the **SIEM Threat Correlation Engine**:
   * Displays detected attack patterns (e.g. repeated invalid proxy token attempts or SSRF probing attempts).
5. Explain the safety gates: Remediation is allowlisted, idempotent, requires `confirm: true`, and the exact server acknowledgement string `APPLY_SELECTED_REMEDIATIONS`.

---

## Phase 5: Observability, SLO Dashboards & Log-to-Trace Links (15:00 – 18:00)

### 1. Grafana Integration & SLO Dashboards
1. Navigate to **Observability** (`http://localhost:8080/#observability`) or open `http://localhost:3000` directly.
2. Sign in (`admin` / `admin`).
3. Open the **SLO & Error Budget** (or **CentralWatch — Overview**) dashboard:
   * Direct Link: `http://localhost:3000/d/centralwatch-slo` (SLO & Error Budget)
   * Direct Link: `http://localhost:3000/d/centralwatch-overview` (Golden Signals: Rate, Errors, Duration)
   * Embedded in Platform UI: `http://localhost:8080/#observability` -> Click the **SLO** or **Overview** tab.
   * **Rate:** Requests per second across services.
   * **Errors:** HTTP 5xx error percentage compared against the 99.9% SLO target.
   * **Duration:** P50, P95, and P99 latency percentiles.
   * **Saturation:** Container CPU and connection pool utilization.

### 2. The Star Feature: Seamless Log-to-Trace Deep Linking
1. Open the **CentralWatch — Logs** dashboard (or Grafana Explore with Loki).
2. Filter for recent logs: `{job="centralwatch-demo-app"}`.
3. Expand any log entry containing an error or order event.
4. Notice the **`tempo`** badge attached to the `trace_id` field!
5. **Click the `tempo` badge:**
   * Grafana splits the screen and renders the exact **Tempo trace waterfall** corresponding to that log line!
   * Highlight the spans:
     1. Ingress request at `centralwatch-demo-app` (`/orders`).
     2. DynamoDB `PutItem` internal span.
     3. Outbound HTTP client call to `inventory-service:8001`.
     4. Downstream server span inside `inventory-service`.
6. Explain: *"In production incident response, engineers waste 80% of their time copying trace IDs between log analyzers and APM tools. CentralWatch eliminates this with automatic Loki-to-Tempo correlation."*

### 3. Alertmanager & Synthetic Simulations
1. Switch to `http://localhost:8090/#simulations`.
2. Click **Application error** (returns 500) and **Slow request** (injects 5000ms latency).
3. Open Prometheus (`http://localhost:9090/alerts`) or Alertmanager (`http://localhost:9093`):
   * Show `HighErrorRate` and `HighLatencyP99` alert rules evaluating.
   * Show that notifications are grouped and routed according to severity.

---

## Phase 6: Reliability, Scale & Engineering Hygiene (18:00 – 20:00)

### 1. Production Architecture & Scale
* **Multi-Worker Postgres Persistence:**
  Show `migrations/001_initial_proxy_schema.sql`. Explain that proxy state, roles, and audit trails are persisted in PostgreSQL, allowing CentralWatch gateway instances to scale horizontally behind a load balancer without state desynchronization.
* **Kubernetes Ready:**
  Open `deploy/k8s/` and show the production manifests:
  * `deployment.yaml` with resource requests/limits, readiness, and liveness probes.
  * `ingress.yaml` with TLS termination and traffic routing for platform vs demo UI.
* **Automated Background Traffic:**
  Run `make traffic` in the terminal to show the continuous traffic generator simulating realistic production workloads.
* **Engineering Hygiene:**
  * Pinned dependencies in `requirements.txt`.
  * Comprehensive E2E test suite in `demo-app/tests/test_business_routes.py` covering auth, orders, and RBAC rejection.
  * CI/CD pipelines in `.github/workflows/ci.yml`.

---

## Conclusion & Demo Wrap-Up

> *"To summarize: CentralWatch isn't just a monitoring dashboard. It is a complete, production-grade observability and security ecosystem featuring:
> 1. Strict UI and service decoupling (`:8080` vs `:8090`).
> 2. Zero-trust API proxying with SSRF defense and token budgeting.
> 3. Cloud security posture management mapped to CIS benchmarks.
> 4. Multi-hop distributed tracing with instantaneous log-to-trace navigation.
> 5. Cloud-native reliability with Kubernetes manifests and database migrations.
> Thank you! I would love to take any questions."*


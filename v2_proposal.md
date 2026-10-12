# CentralWatch v2 Proposal: Enterprise API Security & Observability

An enterprise-grade architectural evolution of **CentralWatch**, transforming it from an API Observability platform into an integrated **API Security Defense, Threat Detection & Automated Vulnerability Scanning Platform**.

---

## 🏛️ Executive Summary of V2 Enhancements

Based on the feedback review:
1. **Hybrid Security Enforcement (Prevention + Reporting):** Unauthorized requests outside allowed IP subnets or with revoked keys are **immediately blocked with 403 Forbidden** AND simultaneously emit structured security audit events into OpenTelemetry, Loki, and Prometheus.
2. **Fully Automated & On-Demand OWASP Security Scans:**
   - **Automated Daily Scan:** A background container service (`astf-scanner`) automatically runs OWASP API Security Top 10 vulnerability scans on a 24-hour schedule.
   - **1-Click Dashboard Trigger:** A dedicated FastAPI trigger endpoint (`POST /simulate/security-scan`) and frontend dashboard button allow admins to trigger an instant security scan on-demand and view live results/reports.

---

## 📐 Architecture Diagram

```
                                      Client / User Request
                                                │
                          ┌─────────────────────┴─────────────────────┐
                          ▼                                           ▼
             [ 1. HYBRID SECURITY GATEWAY ]                 [ 2. AUTOMATED OWASP ASTF SCANNER ]
             (FastAPI Security Middleware)                   (Containerized Scanner + Trigger)
              - CIDR Subnet Whitelist Check                   - Daily Automated Cron Schedule
              - Key Revocation Verification                   - On-Demand Scan API Trigger
              - Immediate 403 Forbidden Block                 - OWASP API Top 10 Vulnerability Audit
              - Real-Time Audit Event Emission                - HTML/JSON Audit Report Generator
                          │                                           │
                          └─────────────────────┬─────────────────────┘
                                                ▼
                                  [ 3. OPENTELEMETRY PIPELINE ]
                                  (Metrics, Logs, Trace Attributes)
                                   - centralwatch_security_violations_total
                                   - Structured Loki security logs (security.event_type)
                                   - Tempo trace span correlation
                                                │
                                                ▼
                                  [ 4. GRAFANA SECURITY DASHBOARD ]
                                  (Threat Intelligence & Audit UI)
                                   - Live 401/403 Attack Rate & Threat Map
                                   - IP Velocity & Impossible Travel Panels
                                   - 1-Click "Trigger OWASP Security Scan" Button
                                   - Embedded OWASP Vulnerability Audit Viewer
```

---

## 🛠️ Detailed Component Specifications

### Component 1: **Hybrid Security Gateway (Prevention + Telemetry)**
* **Location:** `demo-app/app/main.py`, `demo-app/app/services/auth_service.py`
* **Functionality:**
  - Dynamic CIDR IP check: Evaluates `request.client.host` against allowed subnet rules (e.g. `10.0.0.0/8`, `192.168.1.0/24`, or custom user CIDRs).
  - API Key / JWT Revocation: Queries table for key status (`ACTIVE`, `REVOKED`, `SUSPENDED`).
  - **Action:** If invalid, immediately raises `403 Forbidden` AND logs structured JSON event:
    ```json
    {
      "security_event": "IP_SUBNET_VIOLATION",
      "client_ip": "198.51.100.22",
      "user_id": "usr_alice",
      "status_code": 403,
      "action": "BLOCKED_AND_REPORTED"
    }
    ```

---

### Component 2: **Automated & On-Demand OWASP ASTF Scanner**
* **Location:** `docker-compose.yml`, `scripts/security_scan.sh`, `demo-app/app/routes/simulate.py`
* **Functionality:**
  - **Background Docker Service (`astf-scanner`):** Runs OWASP ASTF JAR (`astf-v2.0.1.jar`) against CentralWatch every 24 hours automatically.
  - **On-Demand API Endpoint:** `POST /simulate/security-scan` allows triggering a scan at any time programmatically.
  - **Report Server:** Serves interactive HTML/JSON vulnerability reports at `GET /reports/latest`.

---

### Component 3: **OpenTelemetry Security Telemetry**
* **Location:** `demo-app/app/telemetry/instrumentation.py`
* **Functionality:**
  - Metric: `centralwatch_security_violations_total{event_type="IP_VIOLATION|TOKEN_REVOKED", action="BLOCKED"}`.
  - Context Correlation: Injects `security.client_ip` and `security.user_id` onto all active OTel trace spans.

---

### Component 4: **Grafana Security & Threat Intelligence Dashboard**
* **Location:** `configs/grafana/provisioning/dashboards/security.json`
* **Panels Included:**
  1. **Security Attack Rate:** Live 401 & 403 block rate charts.
  2. **IP Violation Log Stream (Loki):** Real-time log table filtering blocked IP access attempts.
  3. **IP Velocity & Threat Analysis:** Identifies single API keys accessed from multiple distinct IPs.
  4. **On-Demand Scan Control Panel:** Embedded link/button to trigger on-demand scan and view generated OWASP security report.

---

## 🚦 Implementation Plan & Milestones

1. **Milestone 1:** Implement Hybrid Security Gateway Middleware (403 Block + Security Audit Telemetry).
2. **Milestone 2:** Set up OWASP ASTF Security Scanner container service & `/simulate/security-scan` on-demand endpoint.
3. **Milestone 3:** Configure OpenTelemetry security counters & Loki threat log parsers.
4. **Milestone 4:** Provision Grafana Security & Threat Intelligence Dashboard (`security.json`).
5. **Milestone 5:** Verification & End-to-End Walkthrough testing.

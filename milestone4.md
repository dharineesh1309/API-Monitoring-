# Milestone 4: Grafana Security & Threat Intelligence Dashboard

I designed and provisioned a custom Grafana dashboard to visualize all the security metrics and logs emitted by the Hybrid Security Gateway, with a live one-click OWASP ASTF scanner control panel.

## Changes Made

### 1. Dashboard Provisioning
- **Location:** `configs/grafana/provisioning/dashboards/security.json`
- Created a brand new JSON dashboard tailored specifically for security observability (loaded by Grafana's provisioning pipeline into the "CentralWatch" folder).

### 2. Panels Included
- 📈 **Security Attack Rate:** A Prometheus timeseries panel showing the rate of `IP_SUBNET_VIOLATION` and `TOKEN_REVOKED` blocks using `sum by (event_type) (increase(centralwatch_centralwatch_security_violations_total[5m]))`. The metric name includes the collector's `centralwatch` namespace prefix (the meter is `centralwatch_security_violations_total`, exported by the collector as `centralwatch_centralwatch_security_violations_total`).
- 🪵 **Live Threat Intelligence Log Stream:** A real-time Loki log stream (`{job="centralwatch-demo-app"} |= \`"security_event"\``) isolating Gateway block events, with LogQL `| json` parsing of `security_event`, `user_id`, `client_ip`, `action`, and `status_code` so unauthorized actors can be watched in real time. Note that Loki's label for the app's resource `service.name` is `job` (verified against the running stack), not `service_name`.
- 🛡️ **Threat Scanner Control Panel:** A custom HTML control panel with a working **Trigger Scan** button. Grafana strips `<script>` tags from text panels by default, so executing the button needed two things:
  1. `GF_PANELS_DISABLE_SANITIZE_HTML=true` on the Grafana service (see `docker-compose.yml` / `docker-compose.aws.yml`) — without it Grafana renders the button but the inline JavaScript never runs.
  2. The panel prompts for an admin bearer token and issues a `POST /centralwatch/security-scan?target_url=http://127.0.0.1:8000` with the `Authorization: Bearer <token>` header, then renders the scan result inline.

## What was verified
- Grafana 12.4.0 provisioning loads the dashboard and all three panels.
- The `centralwatch_centralwatch_security_violations_total` counter and its `event_type` label are confirmed present in Prometheus after a block event.
- The security WARN log line is confirmed present in Loki under the `job` label and is parseable with `| json`.
- The scan endpoint is callable over `POST` only (GET was removed to avoid a browser/prefetch accidentally re-triggering a multi-minute scanner run).

## Implementation notes (bug fixes applied in the milestone review)
- The Loki panel originally queried `{service_name=...}`, which does not exist in this stack's label schema — fixed to `{job=...}`.
- The Prometheus panel originally queried `centralwatch_security_violations_total` without the collector's namespace prefix — fixed to the full exported name.
- Blocked (403) responses from the outermost Security Gateway now carry CORS headers so the browser-driven control panel sees the real error instead of a CORS failure.
- Provisioned datasources now declare explicit, deterministic `uid`s (`prometheus`, `loki`, `tempo`) in `configs/grafana/provisioning/datasources/datasources.yaml`, matching the `uid`s referenced by the dashboard's panels. Without them Grafana auto-generates random UIDs (`PBFA97CFB590B2093`, etc.), and every panel silently renders "No data" because it can't reach its datasource.
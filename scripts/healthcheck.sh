#!/usr/bin/env bash
# healthcheck.sh - Deep health verification for CentralWatch monitoring stack.
# Checks container status, HTTP readiness, and Prometheus target scrape status.
#
# Mode-aware:
#   localstack (default) - the dev stack (docker-compose.yml); verifies the
#                          LocalStack container as well.
#   aws                  - the production stack (docker-compose.aws.yml); never
#                          requires LocalStack. Verifies demo-app,
#                          otel-collector, prometheus, loki, tempo, grafana and
#                          their HTTP health endpoints.
#
# Usage:
#   ./scripts/healthcheck.sh [localstack|aws]

set -eo pipefail

MODE="${1:-localstack}"
case "$MODE" in
  localstack|aws) ;;
  *) echo "Error: unknown mode '$MODE' (use 'localstack' or 'aws')." >&2; exit 2 ;;
esac

echo "=================================================="
echo "Starting CentralWatch Health Check (mode: $MODE)..."
echo "=================================================="

# Check if curl is installed
if ! command -v curl &> /dev/null; then
  echo "Error: curl is required but not installed." >&2
  exit 1
fi

# 1. Verify Docker containers are running
echo "Checking Docker containers..."
if [ "$MODE" = "aws" ]; then
  # Real AWS stack: no LocalStack container (and the frontend is optional there).
  CONTAINERS=("centralwatch-otel-collector" "centralwatch-prometheus" "centralwatch-loki" "centralwatch-tempo" "centralwatch-grafana" "centralwatch-demo-app")
else
  CONTAINERS=("centralwatch-otel-collector" "centralwatch-prometheus" "centralwatch-loki" "centralwatch-tempo" "centralwatch-grafana" "centralwatch-demo-app" "centralwatch-localstack" "centralwatch-frontend" "centralwatch-demo-frontend" "centralwatch-alertmanager")
fi
ALL_RUNNING=true

for container in "${CONTAINERS[@]}"; do
  STATUS=$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
  if [ "$STATUS" = "running" ]; then
    echo "  [PASS] $container is running."
  else
    echo "  [FAIL] $container status is: $STATUS"
    ALL_RUNNING=false
  fi
done

if [ "$ALL_RUNNING" = false ]; then
  echo "Error: One or more containers are not running." >&2
  exit 1
fi

MAX_RETRIES=6
RETRY_INTERVAL=5

# 2. Check OTel Collector metrics endpoint readiness
echo "Checking OTel Collector metrics endpoint (http://localhost:8889/metrics)..."
COLLECTOR_READY=false

for ((i=1; i<=MAX_RETRIES; i++)); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8889/metrics || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  [PASS] OTel Collector metrics endpoint responded with HTTP 200."
    COLLECTOR_READY=true
    break
  fi
  echo "  [RETRY $i/$MAX_RETRIES] Collector not ready yet (HTTP $HTTP_CODE). Retrying in ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

if [ "$COLLECTOR_READY" = false ]; then
  echo "Error: OTel Collector metrics endpoint is not reachable." >&2
  exit 1
fi

# 3. Check Prometheus server readiness
echo "Checking Prometheus readiness (http://localhost:9090/-/healthy)..."
PROM_READY=false

for ((i=1; i<=MAX_RETRIES; i++)); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/-/healthy || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  [PASS] Prometheus is healthy (HTTP 200)."
    PROM_READY=true
    break
  fi
  echo "  [RETRY $i/$MAX_RETRIES] Prometheus not ready yet (HTTP $HTTP_CODE). Retrying in ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

if [ "$PROM_READY" = false ]; then
  echo "Error: Prometheus is not reachable." >&2
  exit 1
fi

# 4. Check Loki readiness
echo "Checking Loki readiness (http://localhost:3100/ready)..."
LOKI_READY=false

for ((i=1; i<=MAX_RETRIES; i++)); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3100/ready || echo "000")
  if [ "$HTTP_CODE" = "200" ] || [ "$(curl -s http://localhost:3100/ready || true)" = "ready" ]; then
    echo "  [PASS] Loki is ready (HTTP $HTTP_CODE)."
    LOKI_READY=true
    break
  fi
  echo "  [RETRY $i/$MAX_RETRIES] Loki not ready yet (HTTP $HTTP_CODE). Retrying in ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

if [ "$LOKI_READY" = false ]; then
  echo "Error: Loki is not reachable or not ready." >&2
  exit 1
fi

# 5. Check Tempo readiness
echo "Checking Tempo readiness (http://localhost:3200/ready)..."
TEMPO_READY=false

for ((i=1; i<=MAX_RETRIES; i++)); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3200/ready || echo "000")
  if [ "$HTTP_CODE" = "200" ] || [ "$(curl -s http://localhost:3200/ready || true)" = "ready" ]; then
    echo "  [PASS] Tempo is ready (HTTP $HTTP_CODE)."
    TEMPO_READY=true
    break
  fi
  echo "  [RETRY $i/$MAX_RETRIES] Tempo not ready yet (HTTP $HTTP_CODE). Retrying in ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

if [ "$TEMPO_READY" = false ]; then
  echo "Error: Tempo is not reachable or not ready." >&2
  exit 1
fi

# 6. Check Grafana readiness
echo "Checking Grafana readiness (http://localhost:3000/api/health)..."
GRAFANA_READY=false

for ((i=1; i<=MAX_RETRIES; i++)); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  [PASS] Grafana is ready (HTTP $HTTP_CODE)."
    GRAFANA_READY=true
    break
  fi
  echo "  [RETRY $i/$MAX_RETRIES] Grafana not ready yet (HTTP $HTTP_CODE). Retrying in ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

if [ "$GRAFANA_READY" = false ]; then
  echo "Error: Grafana is not reachable or not ready." >&2
  exit 1
fi

# 6b. Check FastAPI demo app health (liveness)
echo "Checking demo app health (http://localhost:8000/healthz)..."
APP_READY=false

for ((i=1; i<=MAX_RETRIES; i++)); do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/healthz || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  [PASS] Demo app is healthy (HTTP 200)."
    APP_READY=true
    break
  fi
  echo "  [RETRY $i/$MAX_RETRIES] Demo app not ready yet (HTTP $HTTP_CODE). Retrying in ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

if [ "$APP_READY" = false ]; then
  echo "Error: demo app is not reachable." >&2
  exit 1
fi

# 6c. Check Platform UI (:8080) and Demo App UI (:8090)
echo "Checking Platform UI (http://localhost:8080)..."
PLATFORM_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ || echo "000")
if [ "$PLATFORM_CODE" = "200" ]; then
  echo "  [PASS] Platform UI is reachable on :8080 (HTTP 200)."
else
  echo "  [WARN] Platform UI returned HTTP $PLATFORM_CODE on :8080"
fi

echo "Checking Demo App UI (http://localhost:8090)..."
DEMO_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8090/ || echo "000")
if [ "$DEMO_CODE" = "200" ]; then
  echo "  [PASS] Demo App UI is reachable on :8090 (HTTP 200)."
else
  echo "  [WARN] Demo App UI returned HTTP $DEMO_CODE on :8090"
fi

# 6d. Check Alertmanager readiness (http://localhost:9093)
echo "Checking Alertmanager (http://localhost:9093/-/ready)..."
ALERT_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9093/-/ready || echo "000")
if [ "$ALERT_CODE" = "200" ]; then
  echo "  [PASS] Alertmanager is ready on :9093 (HTTP 200)."
else
  echo "  [WARN] Alertmanager returned HTTP $ALERT_CODE on :9093"
fi

# 7. Deep Scrape Verification: Check Prometheus target health
echo "Verifying Prometheus target scrape status for 'otel-collector'..."
TARGET_UP=false

# Wait for Prometheus to complete its initial scrape and mark target as up
for ((i=1; i<=MAX_RETRIES; i++)); do
  TARGETS_JSON=$(curl -s http://localhost:9090/api/v1/targets || echo "")
  
  if echo "$TARGETS_JSON" | grep -q '"job":"otel-collector"' && \
     echo "$TARGETS_JSON" | grep -q '"health":"up"'; then
    echo "  [PASS] Prometheus target 'otel-collector' is successfully scraped and health status is UP."
    TARGET_UP=true
    break
  fi
  
  echo "  [RETRY $i/$MAX_RETRIES] Scrape target 'otel-collector' not verified as UP yet. Retrying in ${RETRY_INTERVAL}s..."
  sleep $RETRY_INTERVAL
done

if [ "$TARGET_UP" = false ]; then
  echo "Warning: Scrape target 'otel-collector' is not reported as UP by Prometheus."
  echo "Full target status payload:"
  curl -s http://localhost:9090/api/v1/targets | grep -o '"job":"otel-collector"[^}]*' || true
  exit 1
fi

echo "=================================================="
echo "SUCCESS: CentralWatch monitoring stack is fully healthy!"
echo "=================================================="
exit 0

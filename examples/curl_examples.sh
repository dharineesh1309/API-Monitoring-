#!/bin/bash
# CentralWatch CLI & cURL API Examples

set -e

BASE_URL="http://localhost:8080/api"
DEMO_URL="http://localhost:8090/api"

echo "=== 1. Health & Readiness Checks ==="
curl -s "${DEMO_URL}/healthz" | jq .
curl -s "${DEMO_URL}/readyz" | jq .

echo -e "\n=== 2. User Registration & Login ==="
REGISTER_RES=$(curl -s -X POST "${DEMO_URL}/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "operator@example.com",
    "password": "Password123!",
    "name": "CentralWatch Admin",
    "allowed_cidrs": ["0.0.0.0/0", "::/0"]
  }')
echo "Register Response:"
echo "$REGISTER_RES" | jq .

LOGIN_RES=$(curl -s -X POST "${DEMO_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "operator@example.com",
    "password": "Password123!"
  }')
TOKEN=$(echo "$LOGIN_RES" | jq -r .token)
echo "Retrieved Bearer Token: ${TOKEN:0:15}..."

echo -e "\n=== 3. Query Active Upstream Proxies (Admin Route) ==="
curl -s "${BASE_URL}/centralwatch/proxy/keys" \
  -H "Authorization: Bearer ${TOKEN}" | jq .

echo -e "\n=== 4. Trigger AWS Security Baseline Scan ==="
curl -s -X POST "${DEMO_URL}/security-agent/scan" \
  -H "Authorization: Bearer ${TOKEN}" | jq '{scan_id, compliance_score, summary}'


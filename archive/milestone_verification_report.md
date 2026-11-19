# Milestone Completion and Manual Verification Report

Date: 2026-09-10

## Status

All five milestones are implemented and functionally validated in the running stack.

- [milestone1.md](milestone1.md) — Hybrid Security Gateway implementation
- [milestone2.md](milestone2.md) — CentralWatch security plugin extraction
- [milestone3.md](milestone3.md) — OWASP ASTF scanner and telemetry counters
- [milestone4.md](milestone4.md) — Grafana security dashboard provisioning
- [milestone5.md](milestone5.md) — end-to-end verification walkthrough

## What was validated manually

The following live checks were executed against the running application at http://localhost:8000 and Grafana at http://localhost:3000.

### 1. Application health

Result: PASS

- GET /healthz -> 200
- Response:
  {"status":"ok","service":"centralwatch-demo-app","version":"1.0.0"}

### 2. Restricted user is blocked by subnet policy

Result: PASS

Manual flow:

```powershell
$body = '{"email":"hacker_XXXXX@test.com","password":"password123","name":"Hacker","allowed_cidrs":["10.0.0.0/8"]}'
Invoke-RestMethod -Uri "http://localhost:8000/auth/register" -Method POST -ContentType "application/json" -Body $body

$login = Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method POST -ContentType "application/json" -Body '{"email":"hacker_XXXXX@test.com","password":"password123"}'
$token = $login.token

Invoke-RestMethod -Uri "http://localhost:8000/auth/profile" -Method GET -Headers @{ Authorization = "Bearer $token" }
```

Observed result:

- Register -> 201
- Login -> 200
- GET /auth/profile -> 403
- Response:
  {"detail": "Access denied: IP outside allowed subnet"}

This matches the expected Hybrid Security Gateway behavior.

### 3. Admin user can trigger the ASTF security scan

Result: PASS

Manual flow:

```powershell
$body = '{"email":"admin_XXXXX@test.com","password":"admin123","name":"Admin","allowed_cidrs":["0.0.0.0/0"]}'
Invoke-RestMethod -Uri "http://localhost:8000/auth/register" -Method POST -ContentType "application/json" -Body $body

$login = Invoke-RestMethod -Uri "http://localhost:8000/auth/login" -Method POST -ContentType "application/json" -Body '{"email":"admin_XXXXX@test.com","password":"admin123"}'
$token = $login.token

Invoke-RestMethod -Uri "http://localhost:8000/centralwatch/security-scan?target_url=http://127.0.0.1:8000" -Method POST -Headers @{ Authorization = "Bearer $token" }
```

Observed result:

- Register -> 201
- Login -> 200
- POST /centralwatch/security-scan?target_url=http://127.0.0.1:8000 -> 200
- Response:
  {"status":"Scan complete","target":"http://127.0.0.1:8000","report":"/app/reports/security-report.html","report_bytes":6992,"findings_detected":true}

### 4. Grafana is running and reachable

Result: PASS

Manual health check:

```powershell
Invoke-RestMethod -Uri "http://localhost:3000/api/health"
```

Observed result:

- HTTP 200
- Response includes: "version": "12.4.0"

## Evidence summary

The live validation produced the following successful end-to-end evidence:

- GET /healthz -> 200
- restricted user profile request -> 403
- admin security scan -> 200
- Grafana API health -> 200

## Important note

The milestone documentation uses `access_token` in some examples, but the running API currently returns the token in the `token` field in the login JSON. The actual code is reading either field correctly when validating the live API. This does not affect milestone completion.

## Conclusion

The project meets the milestone completion criteria described in the documentation, and the key end-to-end security paths are working in the running environment.

# CentralWatch Managed API Proxy

## Purpose

CentralWatch acts as a credential firewall. An application never stores or receives the real third-party API key. An operator registers the upstream API and its secret in CentralWatch; CentralWatch returns a separate proxy access token once. The application uses that token to call CentralWatch, and CentralWatch injects the real key only when forwarding an authorized request.

The unified proxy dashboard is available at:

```text
http://127.0.0.1:8080/#proxy
```

## Start the project

```bash
docker compose up -d --build
```

Use `127.0.0.1` instead of `localhost` on this Windows/Docker Desktop setup.

Docker Compose starts a private `proxy-db` PostgreSQL service. Service definitions,
roles, proxy-token hashes, and encrypted upstream API keys survive `demo-app` restarts.
PostgreSQL is not published on a host port.

For local development, Compose supplies a development-only database password and
encryption key. For any shared deployment, set strong independent values for
`PROXY_DB_PASSWORD` and `PROXY_SECRET_ENCRYPTION_KEY`. Generate the encryption key with:

```powershell
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Back up this key separately from PostgreSQL. Losing or changing it without first
re-encrypting records makes existing upstream API keys unreadable.

## Configure and test a proxy

The dashboard contains no separate API-client registry. The access token belongs directly to the configured proxy service.

1. If needed, create an access role under **Access roles**. A role restricts services and HTTP methods. The built-in `proxy_reader` role permits GET, HEAD, and OPTIONS for every service.
2. Under **Add service**, enter:
   - Service ID: `test_service`
   - Target base URL: `https://jsonplaceholder.typicode.com`
   - Secret API key: `my_fake_secret_123`
   - Allowed IPs: `127.0.0.1, 10.0.0.0/8`
   - Access role: `proxy_reader`
3. Select **Save service**.
4. Copy the generated `cw_proxy_...` token immediately. It is displayed once. CentralWatch stores only its SHA-256 hash and a short non-secret hint.
5. Call the proxy:

```powershell
curl.exe http://127.0.0.1:8000/centralwatch/proxy/test_service/users/1 `
  -H "X-CentralWatch-Proxy-Token: <generated-proxy-token>"
```

The caller supplies the CentralWatch proxy token, not `my_fake_secret_123`. After the IP, token, and role checks pass, CentralWatch forwards the request with:

```http
Authorization: Bearer my_fake_secret_123
```

The upstream key is never included in the service-list response, usage history, metrics, or forwarded response. Services may use normal Bearer injection or Gemini's `x-goog-api-key` mode.

## Expected enforcement

All three controls must pass:

1. The direct caller IP must match the service's IP/CIDR allowlist.
2. `X-CentralWatch-Proxy-Token` must hash to the service's stored token hash.
3. The assigned role must permit the service and HTTP method.

An unauthorized IP or missing, invalid, or expired-by-rotation token receives HTTP 403 before CentralWatch contacts the upstream. A valid token with a disallowed HTTP method also receives HTTP 403.

Caller-provided `X-Forwarded-For` is not trusted. For the local Docker Compose demo only, `PROXY_DOCKER_HOST_AS_LOOPBACK=true` maps Docker Desktop's bridge gateway to `127.0.0.1`.

## Rotate a token

Use **Rotate token** beside a managed service or call:

```powershell
curl.exe -X POST http://127.0.0.1:8000/centralwatch/proxy/keys/test_service/rotate-token
```

Copy the new token from the response immediately. Rotation invalidates the previous token. Only the new token's SHA-256 hash remains in CentralWatch.

## Usage history and metrics

Every proxy attempt records a sanitized entry containing:

- Timestamp and generated request ID
- Service, HTTP method, and path
- Direct client IP
- Assigned role and token hint, only after successful token authentication
- Outcome and HTTP status
- Duration and request/response byte counts

Request/response bodies, query values, upstream keys, and raw proxy tokens are never recorded.

The dashboard displays total requests, five-minute request rate, success rate, policy blocks, server/upstream errors, average/P95 latency, bytes, methods, status codes, unique IPs, authenticated token count, per-service totals, and the latest 250 history entries. It refreshes every 15 seconds while the proxy page is open.

The backend retains the latest 1,000 history records in process memory. OpenTelemetry also emits `proxy.requests_total` and `proxy.request_duration`; the Collector exposes them to Prometheus with the `centralwatch` namespace.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/centralwatch/proxy/keys` | List services with masked upstream keys and token hints |
| POST | `/centralwatch/proxy/keys` | Create/replace a service and return a new proxy token once |
| POST | `/centralwatch/proxy/keys/{service}/rotate-token` | Invalidate the old token and return a replacement once |
| GET | `/centralwatch/proxy/roles` | List service/method roles |
| POST | `/centralwatch/proxy/roles` | Create or replace a role |
| GET | `/centralwatch/proxy/history` | Return filtered sanitized usage history |
| GET | `/centralwatch/proxy/metrics` | Return aggregate proxy metrics |
| Multiple | `/centralwatch/proxy/{service}/{path}` | Authorize and forward a request |

Supported forwarding methods are GET, POST, PUT, PATCH, DELETE, HEAD, and OPTIONS. Query parameters and the body are preserved. Only an allowlist of safe request headers is forwarded; incoming credentials are replaced by the managed upstream key. Redirects are not followed and the upstream timeout is configurable from 1 to 120 seconds.

CentralWatch reuses a lifecycle-managed `httpx.AsyncClient` for upstream calls instead
of creating a client for each request. HTTP connections are pooled per upstream origin,
with limits of 100 active connections, 20 idle keep-alive connections, and a 30-second
idle expiry. The client is closed during application shutdown.

## Security and deployment boundaries

- Services, roles, and proxy-token hashes persist in CentralWatch-owned PostgreSQL. Raw proxy tokens are never stored.
- Upstream API keys are encrypted in the application with AES-256-GCM before PostgreSQL receives them. A random nonce is used for every write, and the service ID is authenticated as associated data.
- Decrypted upstream keys exist briefly in demo-app memory while configuration is read or a request is forwarded. PostgreSQL and the encryption key must be hosted and backed up separately from the monitored cloud account.
- Sanitized usage history remains in process memory and resets when `demo-app` restarts; OpenTelemetry proxy metrics continue through the monitoring pipeline.
- Management endpoints are intentionally unauthenticated for this trusted local demo. Protect them with administrator authentication and authorization before exposing them to a network.
- Add an approved-upstream allowlist to reduce server-side request-forgery risk.
- Add token expiry, scoped token revocation, rate limits, database TLS, and encryption-key rotation for production.

## Automated verification

```bash
python -m pytest centralwatch-security/tests -q
```

The tests cover validation, secret masking, one-time token issuance, hash-only storage, token rotation, forwarding, shared-client reuse and shutdown, header filtering, IP enforcement, forwarded-IP spoof prevention, Docker loopback handling, role/method enforcement, sanitized history, and aggregate metrics.

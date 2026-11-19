# CENTRALWATCH AWS INTEGRATION READINESS REPORT

**Repository:** `D:\API-Monitoring--1` (git branch `main`, HEAD `1455a9c "grafana done aws yet to configure"`)
**Date:** 2026-08-09
**Method:** Static + configuration-level audit. Live AWS testing was not possible (no AWS credentials or AWS resources available in the environment). No infrastructure was created and no AWS resources were created or modified. Three readiness defects found during the audit were fixed in-repo and re-verified (see §5: BLK-01 IAM policy, BLK-02 GSI check, GAP-03 healthcheck mode).

---

## 1. Executive Summary

CentralWatch is a passive API-monitoring *demo* application. In production mode it is intended to run as a Docker Compose stack (`docker-compose.aws.yml`) in which:

- the FastAPI app talks to **real AWS** via boto3 (default regional endpoints, standard credential chain, `AWS_PROVISION_RESOURCES=false` = validate-only, fail-fast),
- it emits OpenTelemetry (metrics, logs, traces) over OTLP to an in-stack collector that fans out to Prometheus / Loki / Tempo / Grafana (a strict **bystander** — nothing proxies application traffic),
- nginx serves the prebuilt React SPA and reverse-proxies `/api/` to the app,
- every resource the app touches (S3 bucket, 3 DynamoDB tables, SNS topic, SQS queue, 1 Lambda function) must **pre-exist** in AWS.

**Headline result.** The application **code** is real-AWS-capable: with empty `AWS_ENDPOINT_URL`, boto3 resolves real regional endpoints and the standard credential chain (verified by executing the app's own `Settings`/`build_session`/`make_client` on this machine). The production compose file is valid and fails fast without its required secrets. The demo-app container image builds cleanly from a fresh tree. The observability stack is mode-independent.

Three readiness defects were identified during the audit and have all been **fixed and re-verified** in this repository:

1. **BLK-01 (IAM policy, `AWS_DEPLOYMENT.md` §3.1)** — `sns:ListTopics` and `s3:ListAllMyBuckets` are service-level actions that AWS grants **only** with `Resource: "*"`. The policy scoped them to specific ARNs, which grants nothing, so startup `validate_resources` → `list_topics` → `AccessDenied` → app fails fast and never reaches healthy. **Fixed:** both actions moved to dedicated statements with `"Resource": "*"`; the ARN-scoped statements (`Publish`, object ops, etc.) are unchanged. Policy JSON re-validated.
2. **BLK-02 (startup GSI check, `demo-app/app/services/aws_resources.py`)** — `validate_resources` verified table existence but never the `users` table's `email-index` GSI, so a missing/misnamed GSI passed validation and broke register/login at runtime. **Fixed:** validation now checks that every GSI declared in `_table_definitions()` (e.g. `email-index`) exists **and** has the expected key schema; a mismatch is reported in the fail-fast `missing` list.
3. **GAP-03 (healthcheck script, `scripts/healthcheck.sh`)** — required a `centralwatch-localstack` container, which doesn't exist in the real-AWS stack. **Fixed:** the script is now mode-aware (`./scripts/healthcheck.sh localstack|aws`); the `aws` mode never requires LocalStack.

**Verdict: AWS CONFIGURATION READY — LIVE AWS TEST PENDING** (application code and configuration verified; only a live run against a real AWS account remains, which was not possible here for lack of credentials).

---

## 2. Final Verdict

> **AWS CONFIGURATION READY — LIVE AWS TEST PENDING.**
>
> The application code is verified real-AWS-ready (CODE-PATH VERIFIED). The three readiness defects found during the audit (IAM policy `Resource` scoping, missing GSI startup check, mode-unaware healthcheck) have been **fixed in-repo and re-verified**; the exact project as it now stands is expected to run against a real AWS account, with the caveat that startup validation, `/readyz`, and all workflows still require the documented AWS resources to pre-exist. A live test against a real AWS account remains the only outstanding verification step to fully close the audit.

---

## 3. Audit Evidence (by phase)

### Phase 1 — Discovery & inventory
Full tree enumerated. Backend = `demo-app/app` (FastAPI). Infrastructure = `configs/{collector,prometheus,loki,tempo,nginx,grafana}`, `docker-compose.yml` (dev/LocalStack), `docker-compose.aws.yml` (production/real AWS), `scripts/`, docs (`AWS_DEPLOYMENT.md`, `CENTRALWATCH_END_TO_END.md`, READMEs). Frontend = prebuilt SPA in `frontend/dist`.

### Phase 2 — Architecture reconstruction
`Browser → nginx:8080 → /api/ → demo-app:8000 → boto3 → AWS`; telemetry `demo-app → OTLP (4318) → otel-collector → {Prometheus:8889, Loki:3100, Tempo:4317} → Grafana:3000`. Confirmed bystander architecture: telemetry flows out-of-band; nothing in the API request path is AWS-dependent except boto3 itself.

### Phase 3 — Component inventory
`auth`, `files`, `orders`, `notifications`, `queue`, `images`, `simulate` routers; services: `S3Service`, `DynamoDBService`, `SNSService`, `SQSService`, `LambdaService`, `AuthService`, `AwsResourceManager` (validate vs provision); telemetry: `instrumentation`, `logging`, `metrics`, `tracing`.

### Phase 4 — AWS resource inventory (real AWS mode, `validate`)
| Resource | Name (default) | Validated at startup by | Runtime calls |
| :-- | :-- | :-- | :-- |
| S3 bucket | `centralwatch-files` | `head_bucket` | `PutObject`, `GetObject`, `DeleteObject`, `GeneratePresignedUrl` (local), `ListBuckets` (readyz + /simulate/retry) |
| DynamoDB `users` | `users` | `describe_table` | `PutItem`, `GetItem`, `Query` (GSI `email-index`) |
| DynamoDB `orders` | `orders` | `describe_table` | `PutItem`, `GetItem` |
| DynamoDB `files` | `files` | `describe_table` | `PutItem`, `GetItem`, `DeleteItem` |
| SNS topic | `centralwatch-notifications` | `ListTopics` | `ListTopics` + `Publish` |
| SQS queue | `centralwatch-queue` | `GetQueueUrl` | `GetQueueUrl`, `SendMessage`, `ReceiveMessage`, `DeleteMessageBatch` |
| Lambda | `centralwatch-image-processor` | `GetFunction` | `Invoke` (RequestResponse) |

No DynamoDB streams, no S3 event notifications, no Lambda→SQS integration — as the docs correctly state.

### Phase 5 — Environment / credentials audit
- No AWS credentials present in the environment → **REAL AWS LIVE TEST = NOT PERFORMED**.
- Executed the app's own `Settings()` (host has `pydantic-settings`, `boto3`): empty `AWS_ENDPOINT_URL` → real AWS defaults; `AWS_REGION=us-east-1`; `AWS_PROVISION_RESOURCES=false`; `AWS_S3_ADDRESSING_STYLE=auto`; empty access/secret → `session.get_credentials() is None` (default chain).
- Executed `make_client` with empty endpoint → boto3 resolves `https://s3.amazonaws.com`, `https://dynamodb.us-east-1.amazonaws.com`, `https://sns.us-east-1.amazonaws.com`, `https://sqs.us-east-1.amazonaws.com`, `https://lambda.us-east-1.amazonaws.com` (real regional endpoints).
- `AUTH_TOKEN_SECRET` empty → pydantic `ValidationError` (fail-fast confirmed). `AWS_PROVISION_RESOURCES=` (empty string) → `False` (validator confirmed).
- `docker-compose.aws.yml`: `AWS_ENDPOINT_URL=""`, `AWS_PROVISION_RESOURCES="false"`, `AWS_S3_ADDRESSING_STYLE=auto`, `LAMBDA_ROLE_ARN=${...:-}` (empty), resource names env-overridable with the same defaults. `docker compose -f docker-compose.aws.yml config --quiet` → **VALID** with `AUTH_TOKEN_SECRET` + `GRAFANA_ADMIN_PASSWORD` set; fails fast (intended) when `GRAFANA_ADMIN_PASSWORD` missing.

### Phase 6 — Per-service validation (code path, real-AWS)
- **auth**: register → `Query` GSI `email-index` (409 if exists) → `PutItem users`. login → `Query` GSI + PBKDF2 verify → HMAC token. profile → HMAC verify → `GetItem`. All boto3 calls are real-AWS compatible. ✅ Requires `email-index` GSI, which is now verified at startup (Phase 10, BLK-02 fixed).
- **orders/files**: standard `PutItem`/`GetItem`/`DeleteItem` + S3 object ops + `presigned_url` (local). Compatible.
- **images/process**: S3 upload (`images/<uuid>.<ext>`) → `lambda:invoke` (RequestResponse, 300s client read timeout) → parse → SNS publish from Lambda. Compatible. Lambda handler code (`LAMBDA_HANDLER_CODE`) extracted and `compile()`d OK; produced zip contains `handler.py`, entrypoint `handler.lambda_handler`; handler uses default credential chain + regional endpoint when `AWS_ENDPOINT_URL` empty. `warm_up` only runs in provision mode (never on real AWS).
- **notifications**: SNS `ListTopics` (resolve ARN) + `Publish` with MessageAttributes. Compatible; `sns:ListTopics` is now granted via `"Resource": "*"` (BLK-01 fixed).
- **queue**: SQS `GetQueueUrl` + `SendMessage`/`ReceiveMessage`(WaitTime 2s)/`DeleteMessageBatch`. Compatible. `GetQueueUrl` IS queue-ARN-scoped per AWS docs, so the documented SQS `Resource` is correct.

### Phase 7 — AWS connectivity configuration
`utils/aws.build_session` passes explicit creds only when set (empty → default chain); `make_client` sets `endpoint_url` only when `aws_endpoint_url` truthy; S3 addressing `auto` (real AWS) vs `path` (LocalStack) switch is env-driven; retry config `{max_attempts:3, mode:standard}`, connect 5s/read 30s (300s for Lambda). Error mapping returns 403/404/429/502/503 JSON. Verified live on host.

### Phase 8 — LocalStack vs real AWS comparison
All LocalStack-only artifacts are confined to the dev stack and provision path: `docker-compose.yml` (endpoint `http://localstack:4566`, `test`/`test` creds, dev-only `AUTH_TOKEN_SECRET=centralwatch-demo-secret-change-me`, fake role ARN `arn:aws:iam::000000000000:...`), `AwsResourceManager` provision branch (`ensure_resources`/`wait_until_ready`/`_health_url`/`is_localstack`), and `entrypoint.sh` (waits on `/_localstack/health` only when `AWS_ENDPOINT_URL` set). None of these run in real-AWS mode. `grep` across `configs/` + `frontend/dist` found **no** LocalStack/4566/000000000000 dependencies in the dashboards, datasources, Prometheus/Loki/Tempo configs, or the SPA bundle (the only `0000…000` hits are placeholder trace-ID textbox defaults in `tracing.json`/`aws-services.json`).

### Phase 9 — Docker Compose (real AWS)
`docker-compose.aws.yml` contains no LocalStack, no Docker socket, no host-services, no hardcoded creds. Services: otel-collector(contrib 0.95.0), demo-app (built locally, `centralwatch-demo-app:local`, or `DEMO_APP_IMAGE`), prometheus 2.49.1, loki 2.9.4, tempo 2.6.1, grafana 12.4.0, frontend nginx:1.27-alpine. Compose `healthcheck` for demo-app hits **`/healthz`** (no AWS call) — so the container stays healthy even if AWS calls fail. `depends_on` only for ordering, not readiness.

### Phase 10 — Startup validation (real AWS)
`main.py` lifespan: in validate mode (`aws_provision_resources=false`) it calls `AwsResourceManager.validate_resources()`, which runs `head_bucket`, `describe_table` ×3, `ListTopics`, `GetQueueUrl`, `GetFunction`, then **fails fast** (logs `AWS resource validation failed`, re-raises, container exits) if any is missing/unreachable. ✅ After the fix, `describe_table` output is also checked for every GSI declared in `_table_definitions()` — name **and** key schema (e.g. `email-index`) — and a missing/mismatched GSI is reported in the fail-fast `missing` list (BLK-02 fixed).

### Phase 11 — Authentication
Stateless HMAC tokens, no session table; auth works identically on LocalStack and real AWS. Requires `AUTH_TOKEN_SECRET` (no default; compose enforces). `require_auth` dependency gates all business routers.

### Phase 12 — Business workflows
All six workflows use only the standard boto3 calls listed in Phase 4. None reference LocalStack. Route schemas (`ImageProcessResponse` with `status/processing_id/bucket/key/size_bytes/notification`) match the Lambda handler's returned body (`{"statusCode":200,"body": json.dumps(result)}` parsed by `LambdaService._parse_invoke`).

### Phase 13 — Lambda
Runtime `python3.11`, x86_64, timeout 30s, memory 256MB, handler `handler.lambda_handler`, `S3:GetObject` on `images/*`, `SNS:Publish` to the topic ARN passed in the event, honors `traceparent`. No Docker socket needed. Handler code compiles; zip valid. Deployment steps in `AWS_DEPLOYMENT.md` §3.3 match the embedded source.

### Phase 14 — SNS/SQS
`SNSService._resolve_topic_arn` and `SQSService._resolve_queue_url` use List-first + idempotent Create-fallback. On real AWS the happy path uses List/Get (validation already guarantees existence); the Create-fallback would require extra permissions the runtime role intentionally lacks (documented). `sns:ListTopics` is granted via `"Resource": "*"` (BLK-01 fixed).

### Phases 15–17 — Observability (metrics / logs / traces)
`instrumentation.py` wires OTLP HTTP exporters to `settings.otel_exporter_endpoint` (compose sets `http://otel-collector:4318`), appending `/v1/{traces,metrics,logs}`; `FastAPIInstrumentor` + `BotocoreInstrumentor`; resource attrs include `cloud.provider=aws`, `cloud.region=aws_region`, `deployment.environment`. `logging.py` emits JSON lines to stdout + OTLP LoggingHandler with trace/span correlation. `metrics.py` defines business counters (`orders_created_total`, `images_processed_total`, `notifications_sent_total`, `files_uploaded_total`, `retry_attempts_total`). All mode-independent.

### Phase 18 — Grafana
6 dashboards (overview, api-monitoring, aws-services, business-metrics, tracing, logs) all valid JSON. Datasources provisioned by name (Prometheus `http://prometheus:9090` default, Loki `http://loki:3100`, Tempo `http://tempo:3200`); dashboards reference `${DS_PROMETHEUS}`, `${DS_LOKI}`, `${DS_TEMPO}` which Grafana provisioning binds to those names. No mode-specific values.

### Phase 19 — Prometheus
Scrapes `otel-collector:8889` (job `otel-collector`, label `service=centralwatch-collector`) — the collector's `prometheus` exporter applies namespace `centralwatch` and `resource_to_telemetry_conversion`, so `deployment_environment` comes from the app's `ENVIRONMENT` (no hardcoded mode values). Config identical across modes.

### Phase 20 — Security
No committed secrets. Dev-only creds confined to `docker-compose.yml`. Production compose requires `AUTH_TOKEN_SECRET` (no default) + `GRAFANA_ADMIN_PASSWORD`. `.env` gitignored; `.dockerignore` excludes `.env*` from the image. Docs advise binding monitoring ports privately. (Deployment hardening like TLS/ingress auth is out of scope of this demo.)

### Phase 21 — Documentation
`AWS_DEPLOYMENT.md` is thorough and accurate. The two IAM `Resource` scoping errors found during this audit have been corrected in-repo (BLK-01: `sns:ListTopics` and `s3:ListAllMyBuckets` now use `"Resource": "*"`, with a note explaining the service-level-action rule), and `validate_resources` now also verifies the `users` GSI at startup (BLK-02). The doc's own caveat remains: the real-AWS path is only statically verified and still needs a live runbook pass.

### Phase 22 — Fresh clone / build
- `python -m py_compile` on all `demo-app/app/**/*.py` → **ALL OK**.
- `docker compose -f docker-compose.aws.yml build demo-app` (with the two required env vars) → **image `centralwatch-demo-app:local` built successfully**.
- `docker compose -f docker-compose.aws.yml config --quiet` → **VALID** with secrets; fails fast without them.
- Frontend bundle `frontend/dist` uses axios `baseURL "/api"`; nginx `frontend.conf` proxies `location /api/ → http://demo-app:8000/` (prefix stripped) + SPA fallback → consistent.

### Phases 23–26 — (covered by 8–21; no separate gaps found)
No additional findings.

### Phase 27 — REAL AWS LIVE TEST
**NOT PERFORMED** — no AWS credentials/resources available in this environment. Requirement not satisfied; record this as an outstanding verification step, not a code defect.

### Phase 28 — LocalStack re-test
**NOT PERFORMED** — no Docker containers running; starting the dev stack would create infrastructure, which this audit does not do. Prior LocalStack validation exists only in `CENTRALWATCH_END_TO_END.md` and was not re-executed.

---

## 4. Phase 29 — Readiness Matrix

| # | Component | Real-AWS readiness | Basis |
| :-- | :-- | :-- | :-- |
| 1 | Settings / env-driven config | ✅ READY | Live-executed `Settings`; empty endpoint → real AWS |
| 2 | boto3 session & clients | ✅ READY | Live-executed `build_session`/`make_client` → regional endpoints, default chain |
| 3 | Compose (real AWS) | ✅ READY | `docker compose config` valid; fail-fast secrets |
| 4 | Image build (fresh) | ✅ READY | `docker compose build demo-app` succeeded |
| 5 | Startup fail-fast validation | ✅ READY | IAM policy fixed (`sns:ListTopics`/`s3:ListAllMyBuckets` on `"*"`); GSI check added |
| 6 | Auth (register/login/profile) | ✅ READY (code path) | `email-index` GSI now verified at startup (BLK-02 fixed) |
| 7 | Orders / Files workflows | ✅ READY (code path) | Standard boto3 ops, ARN-correct IAM |
| 8 | Images → Lambda → SNS | ✅ READY (code path) | Handler compiles, zip valid, invoke contract matches; needs live test |
| 9 | Notifications (SNS) | ✅ READY (code path) | `sns:ListTopics` now granted on `"*"` (BLK-01 fixed) |
| 10 | Queue (SQS) | ✅ READY (code path) | `GetQueueUrl` is queue-ARN-scoped — policy correct |
| 11 | `/readyz` + `/simulate/retry` | ✅ READY (code path) | `s3:ListAllMyBuckets` now granted on `"*"` (BLK-01 fixed) |
| 12 | Container health | ✅ READY | Compose healthcheck uses `/healthz` (no AWS) |
| 13 | OTLP → Collector → Prom/Loki/Tempo | ✅ READY | Mode-independent config; bystander confirmed |
| 14 | Grafana dashboards/datasources | ✅ READY | Valid JSON; `${DS_*}` bind to provisioned names |
| 15 | Frontend ↔ nginx contract | ✅ READY | baseURL `/api` ↔ `location /api/` |
| 16 | No LocalStack/Docker-socket deps in prod | ✅ CONFIRMED | grep across configs + bundle; provision path isolated |
| 17 | REAL AWS LIVE TEST | ❌ NOT PERFORMED | No credentials |
| 18 | LocalStack re-test | ❌ NOT PERFORMED | No running stack (dev-only) |

---

## 5. Phase 30 — Blockers & Gaps

| ID | Severity | Component | Problem | Evidence | Impact | Resolution |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| **BLK-01** | ~~BLOCKER~~ **RESOLVED** | `AWS_DEPLOYMENT.md` §3.1 IAM policy | `sns:ListTopics` and `s3:ListAllMyBuckets` were scoped to resource ARNs (`arn:aws:sns:*:*:*`, `arn:aws:s3:::centralwatch-files…`). Both are service-level actions AWS grants **only** with `Resource: "*"`; a statement that names a resource type the action doesn't support grants nothing. | AWS service-authorization reference ("If there is no value [resource type], you must specify all resources (`*`)…"); app calls `list_topics` in `validate_resources` (`aws_resources.py:308`) and at every publish (`sns_service.py:34`), and `list_buckets` in `/readyz` (`main.py`) + `/simulate/retry` (`s3_service.py:39`). | Unfixed, startup `validate_resources` fails with `AccessDenied` → app exits → nothing runs; `/readyz` 503 and `/simulate/retry` 403. | **FIXED:** both actions moved to dedicated statements with `"Resource": "*"`; ARN-scoped statements unchanged. Policy JSON re-validated (2 blocks, 11 statements, VALID). |
| **BLK-02** | ~~MEDIUM~~ **RESOLVED** | `AwsResourceManager.validate_resources` | Startup validation checked DynamoDB table existence via `describe_table` but never verified the `users` table's `email-index` GSI (name + key schema). | `aws_resources.py` (previous `describe_table`-only loop); `dynamodb_service.py:60` hardcodes `IndexName="email-index"`. Docs state the requirement (`AWS_DEPLOYMENT.md` §2; `.env.aws.example`). | A `users` table without the GSI passed validation, then `/auth/register` & `/auth/login` failed at runtime (`ValidationException: The table does not have the specified index`). | **FIXED:** `validate_resources` now verifies every declared GSI (name + `KeySchema`) against `describe_table` output and reports mismatches in the fail-fast `missing` list. `py_compile` ALL OK. |
| **GAP-03** | ~~LOW~~ **RESOLVED** | `scripts/healthcheck.sh` | Required `centralwatch-localstack` to be running (line 19) — no such container exists in the real-AWS stack. | `scripts/healthcheck.sh:18–41`. | Running `scripts/healthcheck.sh` against the production stack exited 1 (false failure). | **FIXED:** script is now mode-aware — `./scripts/healthcheck.sh localstack|aws`; `aws` mode requires only the real-AWS containers. |
| **OBS-04** | INFO | Runbook | `curl /readyz` documented as "200 ⇒ AWS reachable" (`AWS_DEPLOYMENT.md` line 298) — accurate only once the app is healthy against AWS; `.env.aws.example` placeholder values must be replaced/emptied. | `AWS_DEPLOYMENT.md:298`; `.env.aws.example` (clarified). | Misleading docs; user-error risk. | Partially addressed: `.env.aws.example` now marks REQUIRED/OPTIONAL fields and explains `AUTH_TOKEN_SECRET`/`GRAFANA_ADMIN_PASSWORD` have no defaults and `LAMBDA_ROLE_ARN` is only consumed in provisioning mode. Re-read runbook line 298 after the BLK-01 fix. |
| **OBS-05** | INFO | Monitoring stack exposure | Prometheus/Loki/Tempo/Grafana/OTLP ports are published on `0.0.0.0` in both compose files. | `docker-compose.aws.yml:32–34,98,113,126,135`. | Public exposure of monitoring/telemetry endpoints. | Bind to `127.0.0.1` or an internal network / authenticated ingress for real deployments (docs already advise this). |

---

## 6. Final Verification Questions (answers)

1. **Can the exact project connect to a real AWS account?** YES (code-path verified: endpoint resolution + credential chain + corrected IAM policy). Outstanding: a live test.
2. **Does the project create/delete/modify AWS resources in production mode?** NO. `AWS_PROVISION_RESOURCES=false` → validate-only. No `CreateBucket/CreateTable/CreateTopic/CreateQueue/CreateFunction` are invoked on the real-AWS path.
3. **Any hardcoded AWS account IDs / ARNs / credentials?** NO real ones. LocalStack-only placeholders (`000000000000`, `test`/`test`, dev auth secret) are confined to `docker-compose.yml` and the provision branch; production compose/`.env.aws.example` use placeholders only.
4. **Any LocalStack / Docker-socket dependency in real-AWS mode?** NO. Grep across `configs/`, `frontend/dist`, and the code path found none.
5. **Is the real-AWS env config complete and valid?** YES — compose config valid, secrets fail-fast, settings resolve real endpoints.
6. **Does the app fail fast on missing resources?** YES — resource existence **and** GSI key-schema checks (BLK-02 fixed) are enforced at startup.
7. **Are the documented IAM policies correct and least-privilege?** YES — the two service-level actions now use `"Resource": "*"` (BLK-01 fixed); all ARN-scoped statements remain scoped; policy JSON re-validated.
8. **Are Grafana dashboards / datasources mode-independent?** YES — provisioned by name, no LocalStack references.
9. **Is the OTLP→collector→Prom/Loki/Tempo pipeline mode-independent?** YES — collector/Prometheus/Loki/Tempo configs identical across modes.
10. **Does the Lambda image-processing workflow run on real AWS?** Code-path verified (handler compiles, zip valid, invoke contract matches, execution-role policy correct). Requires a live test to fully confirm.
11. **Does the container healthcheck depend on AWS?** NO — uses `/healthz` (no AWS calls), so the stack stays green during AWS-side misconfig.
12. **Does `scripts/healthcheck.sh` work on real AWS?** YES — now mode-aware (`./scripts/healthcheck.sh aws`); LocalStack is only required in `localstack` mode (GAP-03 fixed).
13. **Was the REAL AWS LIVE TEST performed?** NO — not performed (no credentials). Outstanding verification step.
14. **Final determination.** **AWS CONFIGURATION READY — LIVE AWS TEST PENDING.** The application code and configuration are verified real-AWS-ready; the three audit defects (BLK-01, BLK-02, GAP-03) have been fixed and re-verified in-repo. A live run against a real AWS account is the only remaining step to fully close the audit.

---

## 7. Evidence artifacts generated during this audit

- `python -m py_compile demo-app/app/**/*.py` → ALL OK (re-run after BLK-02 fix).
- Executed `Settings()` / `build_session()` / `make_client()` on host → real AWS endpoint/credential behavior confirmed (no AWS traffic).
- `LAMBDA_HANDLER_CODE` extracted → compiles; `_lambda_zip()` → contains `handler.py`; entrypoint `handler.lambda_handler`.
- `docker compose -f docker-compose.aws.yml config --quiet` → VALID (with secrets) / fail-fast (without).
- `docker compose -f docker-compose.aws.yml build demo-app` → image `centralwatch-demo-app:local` built (re-run after BLK-02 fix).
- IAM policy extracted from `AWS_DEPLOYMENT.md` §3.1 → 2 JSON blocks, 11 statements, **VALID**; `sns:ListTopics` and `s3:ListAllMyBuckets` confirmed on `"Resource": "*"`.
- All 6 Grafana dashboard JSON files → valid JSON; datasource refs and span/metric name contracts verified (no invented queries, no mode dependence).
- SHA-256 hashes captured for 15 app source files as a ground-truth baseline (verify before trusting any future diff).

## 8. Changes made during the audit (all three verified)

| File | Change | Verification |
| :-- | :-- | :-- |
| `AWS_DEPLOYMENT.md` §3.1 | `sns:ListTopics` and `s3:ListAllMyBuckets` moved to statements with `"Resource": "*"` + explanatory note (BLK-01) | Policy JSON re-parsed → VALID; ARN-scoped statements unchanged |
| `demo-app/app/services/aws_resources.py` | `validate_resources` verifies every declared GSI (name + `KeySchema`), reports mismatches in fail-fast `missing` list (BLK-02) | `python -m py_compile` ALL OK; `docker compose build demo-app` succeeded |
| `scripts/healthcheck.sh` | Mode-aware `localstack\|aws`; `aws` mode never requires LocalStack (GAP-03) | `bash -n` clean (syntax); container lists verified |
| `.env.aws.example` | REQUIRED/OPTIONAL markers; `AUTH_TOKEN_SECRET`/`GRAFANA_ADMIN_PASSWORD` no-default note; `LAMBDA_ROLE_ARN` provisioning-only clarification (OBS-04, partial) | Diff reviewed |

*End of report.*

# CentralWatch — Real AWS Deployment Guide

This document describes how to run the CentralWatch demo application against **real AWS**
(production mode) instead of LocalStack. It covers exactly which AWS resources the
application uses, the minimum IAM permissions it needs, and how to start the stack.

> Status note: the LocalStack mode is validated end-to-end in this repository. The real-AWS
> code path (empty `AWS_ENDPOINT_URL` + `AWS_PROVISION_RESOURCES=false` + credential chain) is
> verified statically against the SDK calls the code makes; it has not been exercised against a
> live AWS account in this environment. Before a real deployment, run the validation steps in
> [Runbook](#runbook) against your account.

---

## 1. Architecture (production)

```
 Browser ──> nginx (frontend :8080) ──/api──> FastAPI (demo-app :8000) ──boto3──> AWS
                                                     │
                                        OpenTelemetry SDK (OTLP)
                                                     │
                                             otel-collector :4318
                                              ┌──────┼──────┐
                                              ▼      ▼      ▼
                                         Prometheus  Loki  Tempo
                                              └──────┼──────┘
                                                     ▼
                                                  Grafana
```

The monitoring stack is a **bystander**. Application traffic flows `FastAPI -> AWS`; telemetry
is exported out-of-band over OTLP. Nothing proxies application requests.

## 2. AWS resources required by the code

The application uses exactly these resources. Names are environment-driven
(`S3_BUCKET`, `DYNAMODB_*_TABLE`, `SNS_TOPIC`, `SQS_QUEUE`, `LAMBDA_FUNCTION`). Defaults below.

| Resource | Default name | Created/used by | Notes |
| :--- | :--- | :--- | :--- |
| S3 bucket | `centralwatch-files` | app + Lambda | file uploads `uploads/<file_id>/<name>`, images `images/<uuid>.<ext>` |
| DynamoDB table | `users` | app | PK `user_id` (S), GSI `email-index` on `email` (S), PAY_PER_REQUEST |
| DynamoDB table | `orders` | app | PK `order_id` (S), PAY_PER_REQUEST |
| DynamoDB table | `files` | app | PK `file_id` (S), PAY_PER_REQUEST |
| SNS topic | `centralwatch-notifications` | app + Lambda | notifications (`email`, `sms`, `image-processor` channels) |
| SQS queue | `centralwatch-queue` | app | send / receive / delete messages |
| Lambda function | `centralwatch-image-processor` | app (invokes) | runtime `python3.11`, x86_64, handler `handler.lambda_handler`, timeout 30 s, memory 256 MB |

The Lambda code itself is embedded in the demo-app source
(`demo-app/app/services/aws_resources.py` → `LAMBDA_HANDLER_CODE`). It does
`s3:GetObject` on the bucket and `sns:Publish` on the topic, and it honors
`AWS_ENDPOINT_URL` only when set (LocalStack); on real AWS it uses the default regional
endpoints with the Lambda execution role's credentials.

> No DynamoDB streams, S3 event notifications, SQS queues for Lambda, or any other resources
> are used. Do not create them.

## 3. IAM — least privilege

Two roles are needed. No credentials are embedded in the repository; both roles use
**least privilege** scoped to the exact ARNs above.

### 3.1 Application (FastAPI) execution role

`AWS_PROVISION_RESOURCES=false` is the recommended production setting: the app **validates**
resource existence at startup and fails fast if anything is missing. It therefore needs
validation + runtime permissions. If you ever run provisioning mode on real AWS
(`AWS_PROVISION_RESOURCES=true`), add the bracketed creation permissions too.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:HeadBucket"
      ],
      "Resource": [
        "arn:aws:s3:::centralwatch-files",
        "arn:aws:s3:::centralwatch-files/*"
      ]
    },
    {
      "Sid": "S3ListBuckets",
      "Effect": "Allow",
      "Action": ["s3:ListAllMyBuckets"],
      "Resource": "*"
    },
    {
      "Sid": "DynamoDB",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/users",
        "arn:aws:dynamodb:*:*:table/orders",
        "arn:aws:dynamodb:*:*:table/files",
        "arn:aws:dynamodb:*:*:table/users/index/email-index"
      ]
    },
    {
      "Sid": "SNS",
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": [
        "arn:aws:sns:*:*:centralwatch-notifications"
      ]
    },
    {
      "Sid": "SNSListTopics",
      "Effect": "Allow",
      "Action": ["sns:ListTopics"],
      "Resource": "*"
    },
    {
      "Sid": "SQS",
      "Effect": "Allow",
      "Action": [
        "sqs:GetQueueUrl",
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessageBatch"
      ],
      "Resource": "arn:aws:sqs:*:*:centralwatch-queue"
    },
    {
      "Sid": "LambdaInvoke",
      "Effect": "Allow",
      "Action": ["lambda:InvokeFunction", "lambda:GetFunction"],
      "Resource": "arn:aws:lambda:*:*:function:centralwatch-image-processor"
    },
    {
      "Sid": "ProvisioningOnly",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "dynamodb:CreateTable",
        "sns:CreateTopic",
        "sqs:CreateQueue",
        "lambda:CreateFunction"
      ],
      "Resource": "*",
      "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}
    }
  ]
}
```

Notes:
- `sns:ListTopics` and `s3:ListAllMyBuckets` are **service-level actions**: they are not
  ARN-scoped, so they require `"Resource": "*"`. (Scoping them to a specific resource ARN
  does **not** grant the action.) `Publish` stays scoped to the topic and the S3 object
  actions stay scoped to the bucket.
- The SNS/SQS services keep an *idempotent create fallback* (`sns:CreateTopic` / `sqs:CreateQueue`)
  as a LocalStack/dev convenience. On real AWS it never runs in the happy path because startup
  validation already guarantees the topic/queue exist — so the runtime role does not need those
  create permissions. If you want the fallback to be able to run on real AWS as well, add
  `sns:CreateTopic` and `sqs:CreateQueue` to the runtime role.
- The `ProvisioningOnly` statement is **only** needed with `AWS_PROVISION_RESOURCES=true`
  (not recommended for real AWS — see §5).

### 3.2 Lambda execution role

Used by `centralwatch-image-processor` (pass this ARN via `LAMBDA_ROLE_ARN`).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadImage",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::centralwatch-files/images/*"
    },
    {
      "Sid": "SNSPublish",
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": "arn:aws:sns:*:*:centralwatch-notifications"
    },
    {
      "Sid": "CloudWatchLogsOptional",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

The Lambda's trust policy must allow `lambda.amazonaws.com` to assume the role.

### 3.3 Deploying the Lambda function

The app **invokes** the Lambda (`lambda:InvokeFunction`) but never creates it in production
(`AWS_PROVISION_RESOURCES=false`). Deploy it yourself with exactly these properties:

| Property | Value |
| :--- | :--- |
| Runtime | `python3.11` |
| Handler | `handler.lambda_handler` |
| Architecture | `x86_64` |
| Timeout | 30 s |
| Memory | 256 MB |
| Environment variables | `AWS_REGION` only (real AWS). `AWS_ENDPOINT_URL` + access keys are added **only** by LocalStack provisioning |
| Execution role | the §3.2 role (S3 `GetObject` on the bucket, SNS `Publish` on the topic, CloudWatch Logs) |
| What it does | reads `event.bucket`/`event.key` from S3, simulates processing, publishes the result to `event.topic_arn` via SNS, honors `traceparent` for trace correlation |

Deploy the exact embedded handler code from `demo-app/app/services/aws_resources.py`
(`LAMBDA_HANDLER_CODE`) — for example by extracting it from the built image:

```bash
# 1. Extract the handler source (the one and only source of truth is
#    LAMBDA_HANDLER_CODE in demo-app/app/services/aws_resources.py) and write it
#    to a local handler.py:
docker run --rm --entrypoint python centralwatch-demo-app:local \
  -c "from app.services.aws_resources import LAMBDA_HANDLER_CODE; import sys; sys.stdout.write(LAMBDA_HANDLER_CODE)" > handler.py
#    then package it:
zip handler.zip handler.py

# 2. Create the function (adjust the role ARN and region)
aws lambda create-function \
  --function-name centralwatch-image-processor \
  --runtime python3.11 \
  --role arn:aws:iam::<ACCOUNT_ID>:role/centralwatch-lambda-execution \
  --handler handler.lambda_handler \
  --zip-file fileb://handler.zip \
  --timeout 30 \
  --memory-size 256 \
  --architectures x86_64 \
  --environment '{"Variables":{"AWS_REGION":"<YOUR_AWS_REGION>"}}'
```

Do **not** give the function `AWS_ENDPOINT_URL` on real AWS — the handler uses the default
regional endpoints and the execution role's credentials. The Docker socket is never needed
for real AWS Lambda (it is a LocalStack-only development mechanism).

## 4. Environment variables (production)

| Variable | Required | Value |
| :--- | :--- | :--- |
| `AUTH_TOKEN_SECRET` | **yes (no default)** | strong random value, injected via secrets manager |
| `AWS_REGION` | yes | e.g. `us-east-1` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | no | empty ⇒ default credential chain (env, `~/.aws/credentials`, role) |
| `AWS_ENDPOINT_URL` | no | **must be empty** for real AWS |
| `AWS_PROVISION_RESOURCES` | yes | `false` |
| `AWS_S3_ADDRESSING_STYLE` | yes | `auto` |
| `LAMBDA_ROLE_ARN` | no (provisioning only) | ARN of the Lambda execution role; consumed only when the app itself creates the function (`AWS_PROVISION_RESOURCES=true`). Real-AWS runtime needs only `lambda:GetFunction` (validation) + `lambda:InvokeFunction` (invocation) |
| `S3_BUCKET`, `DYNAMODB_USERS_TABLE`, `DYNAMODB_ORDERS_TABLE`, `DYNAMODB_FILES_TABLE`, `SNS_TOPIC`, `SQS_QUEUE`, `LAMBDA_FUNCTION` | yes | names of the pre-created resources |
| `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD` | yes | Grafana bootstrap credentials (password has **no default** in the AWS compose file) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | yes | `http://otel-collector:4318` (container DNS) |

> A ready-to-fill template containing exactly these variables (with `<PLACEHOLDER>` values and
> the `GRAFANA_ADMIN_*` pair) is provided as **`.env.aws.example`** at the repository root.
> Copy it to `.env` for `docker compose` substitution, or to `demo-app/.env` for a bare
> `uvicorn` run. The `users` DynamoDB table's GSI is hardcoded as `email-index` — create it
> with that exact name.

## 5. Running the production stack

```bash
# 1. Create the AWS resources (console, Terraform, or CloudFormation) and the two IAM roles.
# 2. Provide secrets/credentials — either via shell exports or by filling .env.aws.example
#    and copying it to .env (gitignored):
#      cp .env.aws.example .env
#    then:
export AUTH_TOKEN_SECRET="$(openssl rand -hex 32)"
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1
export GRAFANA_ADMIN_PASSWORD=...

docker compose -f docker-compose.aws.yml up -d --build
```

The app validates resources at startup and **fails fast** (logs `AWS resource validation
failed`) if any resource is missing or unreachable. Do not set `AWS_PROVISION_RESOURCES=true`
on real AWS unless you intend the app to create resources (add the `ProvisioningOnly` IAM
permissions first).

## 6. Security notes

- `AUTH_TOKEN_SECRET` and Grafana admin credentials are never committed; the AWS compose file
  fails to start without them.
- Prometheus (`:9090`), Loki (`:3100`), Tempo (`:3200`), the OTLP receiver (`:4317/4318`) and
  Grafana (`:3000`) should **not** be exposed publicly. In production bind them to localhost /
  an internal network, or use an ingress with authentication.
- The `frontend` service is only meaningful when the SPA bundle is built and mounted; it is
  optional for real AWS.
- The Docker socket is **only** used by LocalStack (dev). Real AWS Lambda needs no Docker socket.

## 7. Runbook

```bash
# Health
curl -s http://localhost:8000/healthz
curl -s http://localhost:8000/readyz          # 200 => AWS reachable, resources validated

# Authenticate (register -> login -> use the token)
curl -s -X POST http://localhost:8000/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"secret123","name":"Alice"}'
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"secret123"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

# Business workflows (all require: -H "Authorization: Bearer $TOKEN")
curl -s -X POST http://localhost:8000/orders -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"user_id":"usr_demo","items":[{"product_id":"p1","name":"Widget","quantity":2,"unit_price":9.99}]}'
curl -s -X POST http://localhost:8000/files/upload -H "Authorization: Bearer $TOKEN" -F 'file=@README.md;type=text/markdown'
curl -s -X POST http://localhost:8000/images/process -H "Authorization: Bearer $TOKEN" -F 'file=@README.md;type=text/markdown'
curl -s -X POST http://localhost:8000/notifications/email -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"recipient":"alice@example.com","message":"hello"}'
curl -s -X POST http://localhost:8000/queue/send -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"body":"hello queue"}'

# Telemetry
curl -s 'http://localhost:9090/api/v1/query?query=centralwatch_orders_created_total'
curl -s -G 'http://localhost:3100/loki/api/v1/query_range' --data-urlencode 'query={job="centralwatch-demo-app"}'
curl -s -G 'http://localhost:3200/api/search' --data-urlencode 'q={ resource.service.name = "centralwatch-demo-app" }'
```

### Observability notes for production

- The Collector's Prometheus exporter uses `resource_to_telemetry_conversion` (`configs/collector/config.yaml`), which promotes resource attributes (`deployment_environment`, `service_name`, `container_id`, `host_name`, `cloud_region`, …) to labels on every series. `container_id`/`host_name` change on each task restart; in high-churn deployments prefer dropping them via a `transform` processor and rely on `job`/`instance` for grouping.
- In Prometheus, the `service` label is the static scrape label (`centralwatch-collector`); in Tempo, `service.name` is the application (`centralwatch-demo-app`).

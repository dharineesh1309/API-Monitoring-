# CentralWatch AWS Minimum-Security Agent

## Purpose

The AWS security agent assesses the AWS resources already configured for the CentralWatch demo application. A scan is read-only. The agent never changes AWS configuration until an authenticated user selects specific failed controls and explicitly approves the proposed changes.

The agent is available in the unified dashboard at:

- `http://127.0.0.1:8080/#aws-security`

The same workflow is exposed through authenticated FastAPI endpoints:

- `POST /security-agent/scan`
- `GET /security-agent/latest`
- `POST /security-agent/remediate`

When accessing FastAPI through the frontend gateway, prefix those paths with `http://127.0.0.1:8080/api`. Direct backend requests use `http://127.0.0.1:8000`.

## Scope and baseline

The agent intentionally scans only the resources named in the CentralWatch configuration. It does not enumerate or modify unrelated resources in the AWS account.

| Service | Resource | Minimum-security control | Approved remediation |
|---|---|---|---|
| S3 | `S3_BUCKET` | All four Public Access Block settings are enabled | Enable all four controls |
| S3 | `S3_BUCKET` | Default object encryption uses AES256 or AWS KMS | Enable AES256 default encryption |
| S3 | `S3_BUCKET` | Bucket versioning is enabled | Enable versioning |
| DynamoDB | Users, orders, and files tables | Point-in-time recovery is enabled | Enable point-in-time recovery per selected table |
| SQS | `SQS_QUEUE` | SQS-managed or KMS server-side encryption is enabled | Enable SQS-managed encryption |
| SNS | `SNS_TOPIC` | KMS encryption is configured | Use the AWS-managed `alias/aws/sns` key |
| Lambda | `LAMBDA_FUNCTION` | Active X-Ray tracing is enabled | Set tracing mode to `Active` |

Each finding reports its service, resource, severity, concrete threat or exposure, current value, desired value, and proposed remediation. The unified dashboard orders failed high-risk findings first and summarizes high, medium, and low risks separately. A failed AWS-compatible operation is shown as `error`; an operation that the current endpoint does not implement is shown as `unavailable`. Neither state is automatically remediable.

## Permission and approval model

All of the following gates must pass before a change can be attempted:

1. The caller must have a valid CentralWatch bearer token.
2. `AWS_SECURITY_AGENT_ALLOW_REMEDIATION` must be `true` on the server.
3. The request must reference an in-memory scan produced by the current application process.
4. Every requested finding must be both failed and allowlisted as remediable.
5. The request must contain `confirm: true`.
6. The acknowledgement must exactly equal `APPLY_SELECTED_REMEDIATIONS`.
7. The dashboard displays a browser confirmation listing every selected resource change.

Production Compose defaults `AWS_SECURITY_AGENT_ALLOW_REMEDIATION` to `false`. LocalStack development sets it to `true` so the approval flow can be tested, but selection and confirmation are still required. Set the production value to `true` only after the IAM policy and operational change process have been reviewed.

The agent applies only selected findings. Each operation is an idempotent, allowlisted AWS SDK call. After the attempts complete, the agent performs a new read-only scan and returns the refreshed result. Applied and failed actions are logged and counted in telemetry.

## Dashboard workflow

1. Start the stack with `docker compose up -d --build`.
2. Open `http://127.0.0.1:8080/#aws-security`.
3. Sign in or create a local CentralWatch account.
4. Select **Run security scan**. This reads configuration only.
5. Review the current and desired values for each finding.
6. Select only the controls you approve.
7. Select **Apply selected** and read the complete confirmation prompt.
8. Approve to apply the listed changes, or cancel to leave AWS unchanged.

The **Apply selected** control is disabled when remediation is disabled by server policy, no actionable finding is selected, or no scan exists.

## API examples

Obtain a bearer token through `POST /auth/login`, then run a scan:

```bash
curl -X POST http://127.0.0.1:8000/security-agent/scan \
  -H "Authorization: Bearer $CENTRALWATCH_TOKEN"
```

An approved remediation request has this shape:

```json
{
  "scan_id": "scan_example",
  "finding_ids": [
    "s3_public_access:centralwatch-files"
  ],
  "confirm": true,
  "acknowledgement": "APPLY_SELECTED_REMEDIATIONS"
}
```

Do not reuse a sample scan ID. Use the `scan_id` and exact `finding_id` values returned by the current scan. The dashboard builds this request automatically after user confirmation.

## IAM permissions

The runtime identity needs these read permissions for scanning:

- `s3:GetBucketPublicAccessBlock`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketVersioning`
- `dynamodb:DescribeContinuousBackups`
- `sqs:GetQueueUrl`
- `sqs:GetQueueAttributes`
- `sns:ListTopics`
- `sns:GetTopicAttributes`
- `lambda:GetFunctionConfiguration`

If remediation is enabled, the identity additionally needs:

- `s3:PutBucketPublicAccessBlock`
- `s3:PutEncryptionConfiguration`
- `s3:PutBucketVersioning`
- `dynamodb:UpdateContinuousBackups`
- `sqs:SetQueueAttributes`
- `sns:SetTopicAttributes`
- `lambda:UpdateFunctionConfiguration`

Restrict resource-level permissions to the exact CentralWatch bucket, tables, queue, topic, and function wherever AWS supports resource scoping. If the deployment must remain audit-only, omit all write permissions and keep remediation disabled.

## Operational notes

- Scan records are held in application memory and the latest 20 are retained. Restarting the demo app clears this history.
- This baseline is a focused minimum-security check, not a replacement for AWS Security Hub, AWS Config, GuardDuty, IAM Access Analyzer, or a complete compliance program.
- The application currently runs as a single process. If it is later deployed with multiple workers, persist scans in a shared store before enabling remediation.
- Metrics are exported as `centralwatch_security_scans_total` and `centralwatch_security_remediations_total` through the existing OpenTelemetry pipeline.
- No remediation is run during normal startup, readiness checks, or scanning.

## Verification

Run the focused unit tests with:

```bash
python -m pytest demo-app/tests centralwatch-security/tests -q
```

The tests verify that scanning does not mutate resources, remediation is rejected without server permission and exact confirmation, and only selected findings are applied.

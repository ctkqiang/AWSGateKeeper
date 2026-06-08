# AWSGateKeeper

AWS security auditing gateway with automated IAM role governance, CloudTrail event analysis, SIEM forwarding, and real-time wildcard policy detection. Deployable as an AWS Lambda function or standalone HTTP server.

---

## Architecture

```
                          ┌─────────────────────────────┐
                          │         API Gateway         │
                          │    (REST / HTTP / URL)      │
                          └─────────────┬───────────────┘
                                        │
                          ┌─────────────▼───────────────┐
                          │         Lambda (Go)         │
                          │                             │
                          │  ┌───────────────────────┐  │
                          │  │   ServeLambdaEndpoint  │  │
                          │  │      or local :8080    │  │
                          │  └───────────┬───────────┘  │
                          │              │              │
           ┌──────────────┼──────────────┼──────────────┼──────────────┐
           │              │              │              │              │
    ┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
    │ CloudTrail  │ │ IAM Roles │ │  Cognito    │ │ Wildcard  │ │   SIEM    │
    │  Lookup     │ │  Builder  │ │   Audit     │ │  Monitor  │ │ Forwarder │
    └──────┬──────┘ └─────┬─────┘ └──────┬──────┘ └─────┬─────┘ └─────┬─────┘
           │              │              │              │              │
    ┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
    │    S3 GUI   │ │  S3       │ │ CloudWatch  │ │ Audit Log │ │ Splunk/   │
    │  Glacier    │ │ (Roles)   │ │    Logs     │ │  (Stdout) │ │ Datadog   │
    └─────────────┘ └───────────┘ └─────────────┘ └───────────┘ └───────────┘
```

```
internal/
  model/                    Shared domain types
  preference/               YAML config → env var bridge
  routes/                   HTTP route handlers
  security/                 Credential loader, wildcard policy monitor
  services/
    aws/                    AWS SDK wrappers (IAM, STS, CloudTrail, S3, Lambda)
    governance/             Application-level audit logging
    siem/                   SIEM event forwarder (Splunk/Datadog/generic)
  utilities/                Structured logger with CloudWatch integration
rules/
  projcect.md               Audit rule definitions (IAM external-ID, Cognito)
```

---

## Audit Rules

| Rule ID | Risk | Description |
|---------|------|-------------|
| `IAM_VENDOR_EXTERNALID_REQUIRED` | **CRITICAL** | Cross-account IAM roles must enforce a unique `ExternalId` to prevent the confused-deputy problem |
| `COGNITO_PRIVILEGED_EXTERNAL_USERS` | **HIGH** | External users (non-corporate email domains) must not belong to privileged Cognito groups |

The audit engine evaluates both rules daily. CRITICAL findings trigger immediate alerts via CloudWatch → SIEM.

---

## Core Features

### IAM Role Governance
- 8 predefined privilege levels (Root, SOCAnalyst, FrontEndDeveloper, BackEndDeveloper, DeploymentOperation, ThirdParty dev variants, BillingOnly)
- Automatic role creation with scoped inline policies built from 20+ ActionGroup definitions
- Root receives `AdministratorAccess`; all others receive least-privilege inline policies
- Idempotent: existing roles have their trust policy updated in place

### Wildcard Policy Monitor
- Real-time detection of `"Resource": "*"` and `"Action": "*"` in IAM policy documents
- Severity classification: CRITICAL (both wildcards = full admin), HIGH (one wildcard)
- Immediate audit event raised with full context (entity name, ARN, statement index)
- One-line integration point: `RaiseWildcardAlert(operatorID, policyJSON, ...)`

### CloudTrail Integration
- Paginated event lookups filtered by event source (`iam.amazonaws.com`, `cognito-idp.amazonaws.com`)
- Configurable lookback window (hours)
- Flattens SDK event types into `EventSummary` (EventID, EventName, EventTime, UserARN, SourceIP, AccessKey)
- Source IP extracted from the embedded raw JSON payload
- S3 lifecycle policy automatically transitions trail logs to Glacier

### SIEM Forwarding
- Fire-and-forget HTTP delivery to Splunk HEC, Datadog, Sumo Logic, or any JSON collector
- Environment-toggleable (`SIEM_ENABLED=true`)
- Retries on 5xx errors with exponential backoff
- Splunk payloads include `sourcetype` and epoch timestamp
- Never blocks the caller — audit durability is secondary to availability

### Dual-Mode HTTP Server
- **Local**: `net/http` on `0.0.0.0:8080` with graceful shutdown (SIGINT/SIGTERM)
- **Lambda**: `lambda.Start(HandleAPIGatewayEvent)` — direct event handler for API Gateway
- Route table: `GET /` (index), `GET /health` (health check)
- Per-request logging with source IP

---

## Quick Start

### Prerequisites
- Go 1.26+
- AWS credentials with IAM, STS, CloudTrail, Cognito, and S3 permissions

### Configuration

```bash
cp aws-config.example.yaml aws-config.yaml
# Edit aws-config.yaml with your AWS credentials
```

```yaml
# aws-config.yaml
aws:
  access_key_id:     AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region:            ap-east-1
```

### Run Locally

```bash
go run .
# HTTP server starts on http://localhost:8080
# GET /         → {"message": "Hello from AWSGateKeeper in AWS Lambda!"}
# GET /health   → {"status": "healthy"}
```

### Deploy to Lambda

Build the binary and upload to AWS Lambda with a Go runtime. The `_LAMBDA_SERVER_PORT` and `AWS_LAMBDA_RUNTIME_API` environment variables are set automatically by the Lambda execution environment.

### SIEM Integration

```bash
export SIEM_ENABLED=true
export SIEM_BACKEND=splunk                          # or "generic"
export SIEM_ENDPOINT=https://hec.example.com:8088/services/collector/event
export SIEM_TOKEN=your-hec-token
export SIEM_TIMEOUT_MS=5000
export SIEM_RETRIES=2
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_ACCESS_KEY_ID` | Yes (or YAML) | — | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | Yes (or YAML) | — | IAM secret key |
| `AWS_REGION` | Yes (or YAML) | `us-east-1` | AWS region |
| `LOG_LEVEL` | No | `INFO` | DEBUG / INFO / WARN / ERROR / VVERBOSE |
| `SIEM_ENABLED` | No | `false` | Enable SIEM forwarding |
| `SIEM_BACKEND` | No | `generic` | splunk / generic |
| `SIEM_ENDPOINT` | Cond. | — | HTTP endpoint for SIEM |
| `SIEM_TOKEN` | Cond. | — | Auth token (HEC for Splunk, API key for others) |
| `SIEM_TIMEOUT_MS` | No | `5000` | Request timeout |
| `SIEM_RETRIES` | No | `2` | Retry count on 5xx |
| `AUDIT_S3_BUCKET` | No | — | S3 bucket for audit log archival |

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `aws-sdk-go-v2` | v1.41 | Core AWS SDK |
| `aws-lambda-go` | v1.54 | Lambda runtime support |
| `cloudtrail` | v1.56 | CloudTrail event lookup |
| `cognitoidentityprovider` | v1.61 | Cognito user pool inspection |
| `iam` | v1.54 | IAM role / policy management |
| `s3` | v1.103 | S3 bucket operations |
| `sts` | v1.43 | STS identity verification |
| `google/uuid` | v1.6 | Unique object key generation |
| `yaml.v3` | v3.0.1 | YAML config parsing |

---

## Security

- `aws-config.yaml` (and `.env`) are excluded from version control via `.gitignore`
- SSE-S3/AES-256 encryption enabled by default on CloudTrail and audit S3 buckets
- IAM trust policies restrict `sts:AssumeRole` to same-account principals
- Access keys with `ASIA...` prefix are STS temporary credentials — never hard-coded
- SIEM forwarding uses HTTPS with Bearer/Splunk token authentication

---

## License

Proprietary. All rights reserved.

# Architecture

## System Architecture

![](../out/docs/ARCHITECTURE_EN/ARCHITECTURE_EN-1.png)

AWSGateKeeper follows a **hexagonal / clean architecture** pattern with strict layer separation. The system is deployable as either an AWS Lambda function behind API Gateway or a standalone HTTP server on `0.0.0.0:8000`.

### Layered Design

```
┌─────────────────────────────────────────────────────┐
│  main.go                                            │
│  Initialize() → ServeLambdaEndpoint()               │
├─────────────────────────────────────────────────────┤
│  Transport Layer                                    │
│  internal/routes/        HTTP handlers              │
│  internal/services/aws/  Lambda + API Gateway       │
├─────────────────────────────────────────────────────┤
│  Service Layer                                      │
│  internal/services/aws/    IAM, CloudTrail, S3, STS │
│  internal/services/security/  Scan orchestration    │
│  internal/services/governance/  Audit logging       │
│  internal/services/siem/       SIEM forwarding      │
│  internal/security/       Wildcard policy monitor   │
├─────────────────────────────────────────────────────┤
│  Domain Model                                       │
│  internal/model/   User, Audit, Security finding    │
├─────────────────────────────────────────────────────┤
│  Infrastructure                                     │
│  internal/preference/   YAML config → env vars      │
│  internal/utilities/    Structured CloudWatch logs  │
└─────────────────────────────────────────────────────┘
```

### Dual-Mode Execution

```
isLambdaRuntime()
  ├── _LAMBDA_SERVER_PORT + AWS_LAMBDA_RUNTIME_API set?
  │     YES → lambda.Start(HandleAPIGatewayEvent)
  │     NO  → http.ListenAndServe(0.0.0.0:8000)
```

### Package Dependency Graph

```
main.go
  ├── internal/services/aws       (auth + routes)
  └── internal/services/security  (scan injection)

internal/services/aws
  ├── internal/routes              (HTTP handlers)
  ├── internal/model               (domain types)
  └── internal/utilities           (logging)

internal/services/security
  ├── internal/services/aws        (AWS clients)
  ├── internal/model               (security types)
  └── internal/utilities           (logging)

internal/routes
  └── internal/utilities           (logging only — no cycle)

internal/services/siem
  └── internal/model + utilities

internal/services/governance
  └── internal/model + utilities + siem

internal/security
  └── internal/model + governance
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Closure injection for routes** | Avoids import cycle between `services/aws` and `services/security` |
| **Singleton auth via STS** | One verified SDK config shared across all AWS clients |
| **errgroup for parallel scans** | GuardDuty and Inspector run concurrently; Detective is sequential |
| **Fire-and-forget SIEM** | Background goroutine delivery; never blocks scan completion |
| **Policy-as-Code** | 20 ActionGroups with typed constants generate IAM policies |
| **Idempotent role creation** | CreateRole fails → UpdateAssumeRolePolicy on existing roles |
| **Config hierarchy** | Environment variables > YAML file > SDK defaults |

### Audit Architecture (Three-Tier)

```
AuditEvent
  ├── Tier 1: Application Audit → JSON → stdout → CloudWatch
  ├── Tier 2: Infrastructure Audit → CloudTrail → S3 → Glacier
  └── Tier 3: SIEM Forwarding → HTTP POST → Splunk/Datadog
```

### No Import Cycles

The architecture avoids Go import cycles by injecting cross-package dependencies as closure parameters:

```
main → services/aws + services/security     (leaf imports)
services/aws → routes                        (one-way)
routes → stdlib only                         (no internal deps)
services/security → services/aws             (one-way)
```

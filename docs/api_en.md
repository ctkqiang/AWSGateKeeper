# API Reference

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | None | Service index |
| `GET` | `/health` | None | Service health check |
| `POST` | `/security/scan` | IAM (SDK) | Execute full security scan |
| `GET` | `/security/health` | IAM (SDK) | Security subsystem health |
| `GET` | `/guardduty/statistics` | IAM (SDK) | Finding counts by severity |
| `POST` | `/guardduty/findings` | IAM (SDK) | Archive / unarchive findings |
| `POST` | `/guardduty/sample` | IAM (SDK) | Generate synthetic test findings |
| `GET` | `/guardduty/threat-intel` | IAM (SDK) | List custom threat intelligence sets |
| `GET` | `/guardduty/destinations` | IAM (SDK) | List publishing destinations |
| `GET` | `/guardduty/coverage` | IAM (SDK) | Resource coverage statistics |
| `GET` | `/guardduty/members` | IAM (SDK) | List organization member accounts |
| `GET` | `/guardduty/organization-stats` | IAM (SDK) | Aggregated organization metrics |
| `DELETE` | `/guardduty/quarantine/{arn}` | IAM (SDK) | Remove Deny-* quarantine from an identity |
| `POST` | `/guardduty/quarantine` | IAM (SDK) | Force-quarantine an identity immediately |
| `GET` | `/security/kpi` | IAM (SDK) | KPI dashboard (MTTD/MTTC/MTTR/SLA) |
| `PATCH` | `/security/incident/{id}/phase` | IAM (SDK) | Advance IR phase (Detect→Recovery) |
| `PATCH` | `/security/incident/{id}/owner` | IAM (SDK) | Transfer incident ownership |

### Network Defense Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|

### Internal Service Functions

Security analysis functions callable from the scan orchestrator and incident handler.

| Function | Package | Description |
|----------|---------|-------------|
| `CorrelateAAWithGuardDuty()` | `aws` | Cross-reference Access Analyzer public-access findings with GuardDuty threat scores |
| `CorrelateMacieWithGuardDuty()` | `aws` | Cross-reference Macie sensitive-data findings with GuardDuty exfiltration anomalies |
| `ExtractDNSThreats()` | `aws` | Extract malicious domains from GuardDuty DNS/CryptoCurrency findings |
| `AnalyzeVPCFlowPatterns()` | `aws` | Aggregate GuardDuty VPC findings into port/protocol/source-IP pattern report |
| `CorrelateWithGuardDuty()` | `aws` | Generic threat-score enrichment for any finding type against GuardDuty data |

## GET /

Returns a simple greeting.

**Response** `200 OK`
```json
{
  "message": "Hello from AWSGateKeeper in AWS Lambda!"
}
```

## GET /health

Returns service health status.

**Response** `200 OK`
```json
{
  "status": "healthy"
}
```

## POST /security/scan

Executes a full security scan cycle: GuardDuty threat detection, Inspector CVE scan, and Detective root-cause investigation for high-severity findings. The AWS SDK configuration must be authenticated (via `aws.Initialize()` at startup).

**Response** `200 OK`
```json
{
  "report_id": "550e8400-e29b-41d4-a716-446655440000",
  "generated_at": "2026-06-09T12:00:00Z",
  "summary": "5 GuardDuty findings, 12 Inspector findings, 2 investigations completed, 1 automated actions taken.",
  "guardduty_findings": 5,
  "inspector_findings": 12,
  "investigations": 2,
  "actions_taken": ["IAM: deactivated 3 access keys for compromised finding abc123"],
  "markdown": "# Security Scan Report\n\n...",
  "status": "complete"
}
```

**Error Responses**

`400 Bad Request` — GuardDuty detector ID not configured:
```json
{
  "status": "error",
  "message": "GUARDDUTY_DETECTOR_ID must be set"
}
```

`503 Service Unavailable` — AWS not authenticated:
```json
{
  "error": "AWS not authenticated — service is initialising"
}
```

`500 Internal Server Error` — Scan execution failure:
```json
{
  "status": "error",
  "message": "security scan: guardduty: AccessDeniedException"
}
```

## GET /security/health

Returns the operational status of the security subsystem.

**Response** `200 OK` — All configured:
```json
{
  "status": "healthy",
  "guardduty": true,
  "messaging_url": true,
  "issues": [],
  "lookback_hours": 24
}
```

**Response** `200 OK` — Degraded:
```json
{
  "status": "degraded",
  "guardduty": false,
  "messaging_url": false,
  "issues": [
    "GUARDDUTY_DETECTOR_ID not set",
    "SECURITY_MESSAGING_URL not set — reports are generated but not transmitted"
  ],
  "lookback_hours": 24
}
```

## AWS Client Constructors

Available SDK wrappers for programmatic use within the security pipeline.

| Constructor | Package | Required IAM Permission |
|-------------|---------|------------------------|
| `NewGuardDutyClient(cfg, region)` | `aws` | `guardduty:ListFindings`, `guardduty:GetFindings`, `iam:UpdateAccessKey` |
| `NewInspectorClient(cfg)` | `aws` | `inspector2:ListFindings` |
| `NewDetectiveClient(cfg)` | `aws` | `cloudtrail:LookupEvents` |
| `NewSecurityHubClient(cfg)` | `aws` | `securityhub:GetFindings`, `securityhub:BatchUpdateFindings` |
| `NewAccessAnalyzerClient(cfg)` | `aws` | `access-analyzer:ListFindings` |
| `NewMacieClient(cfg)` | `aws` | `macie2:ListFindings`, `macie2:GetFindings` |
| `NewDNSFirewallClient(cfg)` | `aws` | `route53resolver:UpdateFirewallDomains` |
| `NewMetricsClient(cfg)` | `aws` | `cloudwatch:PutMetricData` |
| `NewEventPublisher(cfg, busName)` | `aws` | `events:PutEvents` |
| `NewCognitoAuditor(cfg)` | `aws` | `cognito-idp:ListGroups`, `cognito-idp:ListUsersInGroup` |
| `NewS3AuditLogger()` | `aws` | `s3:PutObject` |
| `NewTrailClient(cfg)` | `aws` | `cloudtrail:LookupEvents` |
| `NewQuarantineEngine(cfg)` | `security` | `iam:PutUserPolicy`, `iam:PutRolePolicy`, `iam:UpdateAccessKey` |
| `NewScanOrchestrator(cfg)` | `security` | Aggregate of GuardDuty + Inspector + Detective |
| `NewIncidentHandler(cfg)` | `security` | Aggregate of audit + quarantine + webhook |
| `NewKPIStore(maxSize)` | `security` | (in-memory, no IAM) |
| `NewSLATracker(escalateFn, sla)` | `security` | (in-memory, no IAM) |

```

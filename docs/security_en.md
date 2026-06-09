# Security Subsystem

## Overview

The security subsystem integrates three AWS security services into a unified scan orchestration pipeline. It processes threat findings, container vulnerabilities, and root-cause investigations, then generates a Markdown report and delivers it via HTTP messaging, S3, and DynamoDB.

## Architecture

```
ScanOrchestrator.RunFullScan(ctx)
  │
  ├── [parallel: errgroup]
  │   ├── GuardDuty.ListActiveFindings() → []GuardDutyFinding
  │   └── Inspector.ListContainerFindings() → []InspectorFinding
  │
  ├── [sequential: per finding]
  │   ├── ForEach(ConfirmedCompromised) → DisableCompromisedCredentials()
  │   └── ForEach(Severity >= High) → Detective.InvestigateFinding()
  │
  └── Report & Deliver
      ├── BuildReport() → Markdown string
      ├── SendToMessagingEndpoint() → HTTP POST (goroutine)
      ├── SaveReportToS3() → s3://bucket/security-reports/YYYY/MM/DD/{id}.md
      └── SaveReportToDynamoDB() → table (goroutine)
```

## GuardDuty Integration

### Finding Processing

The `GuardDutyClient` paginates through active GuardDuty findings from the last N hours, fetches detailed information per finding, and classifies each finding by severity, compromise status, and network-scan behaviour.

### Threat Classification

| Signal | Detection Method |
|--------|-----------------|
| Compromised credential | Keyword match on finding title + type (CredentialExposure, UnauthorizedAccess, Stealth) |
| Network scan anomaly | Keyword match on title + description + type (Recon, PortProbe, NetworkPortUnusual) |

### Automated Response

When `ConfirmedCompromised` is true:
1. Extract IAM user name from the finding's resource ARN
2. List all active access keys for that user
3. Deactivate each active key via `iam:UpdateAccessKey` to INACTIVE status

## Inspector Integration

### CVE Scanning

The `InspectorClient` lists active findings from Inspector v2, filtering for container image vulnerabilities. Each finding is parsed to extract:

- CVE identifier (e.g., `CVE-2024-1234`)
- CVSS score (highest BaseScore across all CVSS vectors)
- Vulnerable package name, installed version, and fixed version
- ECR registry, repository, and image tag
- Remediation recommendation text

### Severity Mapping

| Inspector Severity | Internal Severity |
|-------------------|-------------------|
| CRITICAL | SeverityCritical |
| HIGH | SeverityHigh |
| MEDIUM | SeverityMedium |
| LOW | SeverityLow |
| INFORMATIONAL | SeverityInformational |

## Detective Integration

### Root Cause Investigation

For each GuardDuty finding of High severity or above, the `DetectiveClient` queries CloudTrail for all events touching the affected resource ARN during the lookback window.

### Anomaly Detection

- **IP-hop analysis**: Multiple distinct source IP blocks → potential credential compromise
- **Sensitive operation detection**: AssumeRole, CreateAccessKey, AttachRolePolicy → privilege escalation
- **Timeline construction**: Chronological event list with user ARN, source IP, and event details

### Recommendation Engine

| Detected Pattern | Recommendation |
|-----------------|----------------|
| Access key creation | Deactivate keys immediately; rotate credentials; enable MFA |
| Role assumption | Review trust policy; enforce ExternalId; audit all sessions |
| No anomaly found | Manual review; tighten IAM permissions; enable GuardDuty anomaly detection |

## Report Format

The `BuildReport` function produces a GitHub-flavoured Markdown report with:

1. Report header (ID, timestamp)
2. Summary statistics
3. GuardDuty findings table (severity, type, title, resource, compromise status)
4. Inspector CVE table (severity, CVE, CVSS, package, image)
5. Root-cause investigation results with recommendations
6. Automated actions taken

## Delivery

| Destination | Method | Trigger |
|-------------|--------|---------|
| S3 | `SaveReportToS3()` → `PutObject` | Every scan (if `SECURITY_AUDIT_BUCKET` set) |
| DynamoDB | `SaveReportToDynamoDB()` → `PutItem` | Every scan (if `SECURITY_AUDIT_TABLE` set) |
| Messaging endpoint | `SendToMessagingEndpoint()` → HTTP POST | Every scan (if `SECURITY_MESSAGING_URL` set) |

S3 and DynamoDB deliveries run in background goroutines and do not block the HTTP response.

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GUARDDUTY_DETECTOR_ID` | *(required)* | GuardDuty detector ID |
| `SECURITY_LOOKBACK_HOURS` | `24` | Lookback window for scans |
| `SECURITY_MESSAGING_URL` | `""` | HTTP endpoint for report delivery |
| `SECURITY_AUDIT_BUCKET` | `""` | S3 bucket for report persistence |
| `SECURITY_AUDIT_TABLE` | `""` | DynamoDB table for report persistence |

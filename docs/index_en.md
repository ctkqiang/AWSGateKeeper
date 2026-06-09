# AWSGateKeeper — Documentation

AWS security auditing gateway with automated IAM role governance, real-time wildcard policy detection, GuardDuty threat response, Inspector CVE scanning, Detective root-cause analysis, and SIEM forwarding.

## Table of Contents

| Document | Description |
|----------|-------------|
| [Architecture](architecture_en.md) | System architecture, layered design, package dependency graph |
| [Security Subsystem](security_en.md) | GuardDuty, Inspector, Detective integration, scan orchestration, report generation |
| [API Reference](api_en.md) | HTTP endpoints, request/response formats, error codes |
| [Deployment](deployment_en.md) | Lambda deployment, Docker, environment variables, IAM permissions |
| [Development](development_en.md) | Local development, testing, project structure conventions |

## Quick Links

- [Chinese Documentation](index_zh.md)
- [PlantUML Diagrams](ARCHITECTURE.puml)
- [Project README](../README.md)

## Architecture Diagrams

| Diagram | File |
|----------|------|
| System Architecture | [ARCHITECTURE.puml](ARCHITECTURE.puml) |
| Security Scan Sequence | [SEQUENCE.puml](SEQUENCE.puml) |

Render with: `plantuml docs/ARCHITECTURE.puml -o ../out/docs/ARCHITECTURE`

## AWS Service Integration

| Service | Purpose | SDK Package |
|---------|---------|-------------|
| GuardDuty | Threat detection, compromised credential response | `guardduty` |
| Inspector | Container image CVE scanning | `inspector2` |
| Detective (CloudTrail) | Root-cause investigation via historical API events | `cloudtrail` |
| IAM | Role creation, policy generation, access key deactivation | `iam` |
| Cognito | User pool privileged group audit | `cognitoidentityprovider` |
| S3 | Audit log persistence, CloudTrail bucket management | `s3` |
| STS | Caller identity verification | `sts` |
| EventBridge | Event publishing (model defined) | *(pending)* |

## References

- [AWS Lambda Go Documentation](https://docs.aws.amazon.com/lambda/latest/dg/golang-handler.html)
- [AWS GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [AWS Inspector User Guide](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html)
- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [AWS IAM Documentation](https://docs.aws.amazon.com/iam/)

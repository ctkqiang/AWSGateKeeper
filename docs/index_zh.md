# AWSGateKeeper — 文档

AWS 安全审计网关，集成 IAM 角色自动化治理、通配符策略实时检测、GuardDuty 威胁响应、Inspector CVE 扫描、Detective 根因分析以及 SIEM 转发。

## 目录

| 文档 | 描述 |
|----------|-------------|
| [系统架构](architecture_zh.md) | 系统架构、分层设计、包依赖关系图 |
| [安全子系统](security_zh.md) | GuardDuty、Inspector、Detective 集成，扫描编排，报告生成 |
| [API 参考](api_zh.md) | HTTP 端点、请求/响应格式、错误码 |
| [部署指南](deployment_zh.md) | Lambda 部署、Docker、环境变量、IAM 权限 |
| [开发指南](development_zh.md) | 本地开发、测试、项目结构约定 |

## 快速链接

- [English Documentation](index_en.md)
- [PlantUML 图表](ARCHITECTURE.puml)
- [项目 README](../README.md)

## 架构图

| 图表 | 文件 |
|----------|------|
| 系统架构 | [ARCHITECTURE.puml](ARCHITECTURE.puml) |
| 安全扫描时序 | [SEQUENCE.puml](SEQUENCE.puml) |

渲染命令: `plantuml docs/ARCHITECTURE.puml -o ../out/docs/ARCHITECTURE`

## AWS 服务集成

| 服务 | 用途 | SDK 包 |
|---------|---------|-------------|
| GuardDuty | 威胁检测、受损凭证响应 | `guardduty` |
| Inspector | 容器镜像 CVE 扫描 | `inspector2` |
| Detective (CloudTrail) | 基于历史 API 事件的根因分析 | `cloudtrail` |
| IAM | 角色创建、策略生成、访问密钥停用 | `iam` |
| Cognito | 用户池特权组审计 | `cognitoidentityprovider` |
| S3 | 审计日志持久化、CloudTrail 桶管理 | `s3` |
| STS | 调用者身份验证 | `sts` |
| EventBridge | 事件发布（隔离 + 扫描完成事件） | `eventbridge` |
| Security Hub | 双向发现同步 | `securityhub` |
| CloudWatch | 自定义指标发布 | `cloudwatch` |

## 参考文档

- [AWS 安全成熟度模型 — 安全编排与工单](https://maturitymodel.security.aws.dev/en/4.-optimized/security-orchestration-ticketing/)

- [AWS Lambda Go 开发文档](https://docs.aws.amazon.com/zh_cn/lambda/latest/dg/golang-handler.html)
- [AWS GuardDuty 用户指南](https://docs.aws.amazon.com/zh_cn/guardduty/latest/ug/what-is-guardduty.html)
- [AWS Inspector 用户指南](https://docs.aws.amazon.com/zh_cn/inspector/latest/user/what-is-inspector.html)
- [AWS CloudTrail 文档](https://docs.aws.amazon.com/zh_cn/cloudtrail/)
- [AWS IAM 文档](https://docs.aws.amazon.com/zh_cn/iam/)

# API 参考

## 端点

| 方法 | 路径 | 认证 | 描述 |
|--------|------|------|-------------|
| `GET` | `/` | 无 | 服务索引 |
| `GET` | `/health` | 无 | 服务健康检查 |
| `POST` | `/security/scan` | IAM (SDK) | 执行完整安全扫描 |
| `GET` | `/security/health` | IAM (SDK) | 安全子系统健康状态 |
| `GET` | `/guardduty/statistics` | IAM (SDK) | 按严重级别统计发现数量 |
| `POST` | `/guardduty/findings` | IAM (SDK) | 归档 / 取消归档发现 |
| `POST` | `/guardduty/sample` | IAM (SDK) | 生成合成测试发现 |
| `GET` | `/guardduty/threat-intel` | IAM (SDK) | 列出自定义威胁情报集 |
| `GET` | `/guardduty/destinations` | IAM (SDK) | 列出发布目标 |
| `GET` | `/guardduty/coverage` | IAM (SDK) | 资源覆盖统计 |
| `GET` | `/guardduty/members` | IAM (SDK) | 列出组织成员账户 |
| `GET` | `/guardduty/organization-stats` | IAM (SDK) | 聚合组织指标 |

## GET /

返回简单问候。

**响应** `200 OK`
```json
{
  "message": "Hello from AWSGateKeeper in AWS Lambda!"
}
```

## GET /health

返回服务健康状态。

**响应** `200 OK`
```json
{
  "status": "healthy"
}
```

## POST /security/scan

执行完整安全扫描周期：GuardDuty 威胁检测、Inspector CVE 扫描、高严重级别发现的 Detective 根因调查。AWS SDK 配置必须在启动时完成认证（通过 `aws.Initialize()`）。

**响应** `200 OK`
```json
{
  "report_id": "550e8400-e29b-41d4-a716-446655440000",
  "generated_at": "2026-06-09T12:00:00Z",
  "summary": "5 条 GuardDuty 发现, 12 条 Inspector 发现, 2 项调查完成, 1 项自动操作已执行。",
  "guardduty_findings": 5,
  "inspector_findings": 12,
  "investigations": 2,
  "actions_taken": ["IAM: 已停用受损发现 abc123 的 3 个访问密钥"],
  "markdown": "# Security Scan Report\n\n...",
  "status": "complete"
}
```

**错误响应**

`400 Bad Request` — GuardDuty 检测器 ID 未配置：
```json
{
  "status": "error",
  "message": "GUARDDUTY_DETECTOR_ID must be set"
}
```

`503 Service Unavailable` — AWS 未认证：
```json
{
  "error": "AWS not authenticated — service is initialising"
}
```

`500 Internal Server Error` — 扫描执行失败：
```json
{
  "status": "error",
  "message": "security scan: guardduty: AccessDeniedException"
}
```

## GET /security/health

返回安全子系统的运行状态。

**响应** `200 OK` — 全部配置：
```json
{
  "status": "healthy",
  "guardduty": true,
  "messaging_url": true,
  "issues": [],
  "lookback_hours": 24
}
```

**响应** `200 OK` — 降级：
```json
{
  "status": "degraded",
  "guardduty": false,
  "messaging_url": false,
  "issues": [
    "GUARDDUTY_DETECTOR_ID 未设置",
    "SECURITY_MESSAGING_URL 未设置 — 报告已生成但未传输"
  ],
  "lookback_hours": 24
}
```

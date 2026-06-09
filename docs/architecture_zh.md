# 系统架构

## 系统架构

AWSGateKeeper 采用**六边形/清洁架构**模式，层间严格分离。可作为 API Gateway 后的 AWS Lambda 函数部署，也可作为 `0.0.0.0:8000` 上的独立 HTTP 服务器运行。

### 分层设计

```
┌─────────────────────────────────────────────────────┐
│  main.go                                            │
│  Initialize() → ServeLambdaEndpoint()               │
├─────────────────────────────────────────────────────┤
│  传输层                                             │
│  internal/routes/        HTTP 处理器                │
│  internal/services/aws/  Lambda + API Gateway       │
├─────────────────────────────────────────────────────┤
│  服务层                                             │
│  internal/services/aws/    IAM, CloudTrail, S3, STS │
│  internal/services/security/  扫描编排              │
│  internal/services/governance/  审计日志            │
│  internal/services/siem/       SIEM 转发            │
│  internal/security/        通配符策略监控           │
├─────────────────────────────────────────────────────┤
│  领域模型                                           │
│  internal/model/   User, Audit, Security finding    │
├─────────────────────────────────────────────────────┤
│  基础设施                                           │
│  internal/preference/   YAML 配置 → 环境变量        │
│  internal/utilities/    结构化 CloudWatch 日志      │
└─────────────────────────────────────────────────────┘
```

### 双模执行

```
isLambdaRuntime()
  ├── _LAMBDA_SERVER_PORT + AWS_LAMBDA_RUNTIME_API 均存在？
  │     YES → lambda.Start(HandleAPIGatewayEvent)
  │     NO  → http.ListenAndServe(0.0.0.0:8000)
```

### 包依赖关系

```
main.go
  ├── internal/services/aws       (认证 + 路由)
  └── internal/services/security  (扫描注入)

internal/services/aws
  ├── internal/routes              (HTTP 处理器)
  ├── internal/model               (领域类型)
  └── internal/utilities           (日志)

internal/services/security
  ├── internal/services/aws        (AWS 客户端)
  ├── internal/model               (安全类型)
  └── internal/utilities           (日志)

internal/routes
  └── internal/utilities           (仅日志 — 无循环)

internal/services/siem
  └── internal/model + utilities

internal/services/governance
  └── internal/model + utilities + siem

internal/security
  └── internal/model + governance
```

### 关键设计决策

| 决策 | 理由 |
|----------|-----------|
| **路由闭包注入** | 避免 `services/aws` 与 `services/security` 之间的循环导入 |
| **基于 STS 的单例认证** | 所有 AWS 客户端共享一个已验证的 SDK 配置 |
| **errgroup 并行扫描** | GuardDuty 与 Inspector 并发运行；Detective 顺序执行 |
| **异步 SIEM 投递** | 后台 goroutine 投递；永不阻塞扫描完成 |
| **策略即代码** | 20 个 ActionGroup 带类型常量生成 IAM 策略 |
| **幂等角色创建** | CreateRole 失败 → 更新已存在角色的信任策略 |
| **配置层级** | 环境变量 > YAML 文件 > SDK 默认值 |

### 三级审计架构

```
AuditEvent
  ├── 第一级：应用审计 → JSON → stdout → CloudWatch
  ├── 第二级：基础设施审计 → CloudTrail → S3 → Glacier
  └── 第三级：SIEM 转发 → HTTP POST → Splunk/Datadog
```

### 无循环导入

架构通过将跨包依赖注入为闭包参数来避免 Go 循环导入：

```
main → services/aws + services/security     (叶子导入)
services/aws → routes                        (单向)
routes → 仅标准库                             (无内部依赖)
services/security → services/aws             (单向)
```

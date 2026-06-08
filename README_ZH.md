# AWSGateKeeper — AWS 安全审计网关

AWS 安全审计网关，集成 IAM 角色自动化治理、CloudTrail 事件分析、SIEM 转发以及通配符策略实时检测。可部署为 AWS Lambda 函数或独立 HTTP 服务。

---

## 系统架构

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
                          │  │      或本地 :8080      │  │
                          │  └───────────┬───────────┘  │
                          │              │              │
           ┌──────────────┼──────────────┼──────────────┼──────────────┐
           │              │              │              │              │
    ┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
    │ CloudTrail  │ │ IAM 角色  │ │  Cognito    │ │ 通配符    │ │   SIEM    │
    │   事件查询  │ │   构建器  │ │   审计      │ │  监控器   │ │  转发器   │
    └──────┬──────┘ └─────┬─────┘ └──────┬──────┘ └─────┬─────┘ └─────┬─────┘
           │              │              │              │              │
    ┌──────▼──────┐ ┌─────▼─────┐ ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
    │  S3 + 自动  │ │  S3       │ │ CloudWatch  │ │ 审计日志  │ │ Splunk/   │
    │ 转 Glacier  │ │ (角色)    │ │    Logs     │ │ (Stdout)  │ │ Datadog   │
    └─────────────┘ └───────────┘ └─────────────┘ └───────────┘ └───────────┘
```

```
internal/
  model/                    共享领域类型
  preference/               YAML 配置 → 环境变量 桥接层
  routes/                   HTTP 路由处理器
  security/                 凭证加载器、通配符策略监控器
  services/
    aws/                    AWS SDK 封装（IAM、STS、CloudTrail、S3、Lambda）
    governance/             应用层审计日志
    siem/                   SIEM 事件转发器（支持 Splunk / Datadog / 通用）
  utilities/                结构化日志（集成 CloudWatch）
rules/
  projcect.md               审计规则定义（IAM ExternalId、Cognito 外部用户）
```

---

## 审计规则

| 规则 ID | 风险等级 | 描述 |
|---------|----------|------|
| `IAM_VENDOR_EXTERNALID_REQUIRED` | **严重** | 跨账户 IAM 角色必须强制使用唯一 `ExternalId`，防止混淆代理攻击 |
| `COGNITO_PRIVILEGED_EXTERNAL_USERS` | **高** | 非企业邮件域的外部用户不得属于高权限 Cognito 用户组 |

审计引擎每日评估两项规则。严重发现通过 CloudWatch → SIEM 触发即时告警。

---

## 核心功能

### IAM 角色治理
- 8 个预定义权限等级（Root、SOCAnalyst、FrontEndDeveloper、BackEndDeveloper、DeploymentOperation、第三方前端/后端、BillingOnly）
- 自动创建角色，基于 20+ 个 ActionGroup 定义生成最小权限内联策略
- Root 角色附加 `AdministratorAccess` 托管策略；其余角色获得最小权限内联策略
- 幂等操作：已存在的角色将原地更新其信任策略

### 通配符策略监控
- 实时检测 IAM 策略文档中的 `"Resource": "*"` 和 `"Action": "*"`
- 严重级别分类：CRITICAL（双通配符 = 完全管理员权限）、HIGH（单通配符）
- 即时触发审计事件，附带完整上下文（实体名称、ARN、Statement 索引）
- 单行集成点：`RaiseWildcardAlert(operatorID, policyJSON, ...)`

### CloudTrail 集成
- 按事件源（`iam.amazonaws.com`、`cognito-idp.amazonaws.com`）分页查询事件
- 可配置回溯时间窗口（小时）
- 将 SDK 事件类型扁平化为 `EventSummary`（事件 ID、名称、时间、用户 ARN、来源 IP、访问密钥）
- Source IP 从原始 JSON 负载中提取
- S3 生命周期策略自动将跟踪日志转换为 Glacier 归档

### SIEM 转发
- 防火墙式（fire-and-forget）HTTP 投递，支持 Splunk HEC、Datadog、Sumo Logic 及任意 JSON 采集器
- 环境变量开关（`SIEM_ENABLED=true`）
- 5xx 错误自动重试，带退避策略
- Splunk 负载包含 `sourcetype` 和纪元时间戳
- 永不阻塞调用方——审计可用性优于持久性

### 双模 HTTP 服务
- **本地模式**：`net/http` 监听 `0.0.0.0:8080`，支持优雅关闭（SIGINT/SIGTERM）
- **Lambda 模式**：`lambda.Start(HandleAPIGatewayEvent)` — API Gateway 直连处理器
- 路由表：`GET /`（首页）、`GET /health`（健康检查）
- 每次请求记录来源 IP

---

## 快速开始

### 前置条件
- Go 1.26+
- 具备 IAM、STS、CloudTrail、Cognito 和 S3 权限的 AWS 凭证

### 配置

```bash
cp aws-config.example.yaml aws-config.yaml
# 编辑 aws-config.yaml，填入你的 AWS 凭证
```

```yaml
# aws-config.yaml
aws:
  access_key_id:     AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region:            ap-east-1
```

### 本地运行

```bash
go run .
# HTTP 服务启动在 http://localhost:8080
# GET /         → {"message": "Hello from AWSGateKeeper in AWS Lambda!"}
# GET /health   → {"status": "healthy"}
```

### 部署到 Lambda

构建二进制文件后上传至 AWS Lambda（选择 Go 运行环境）。Lambda 执行环境会自动设置 `_LAMBDA_SERVER_PORT` 和 `AWS_LAMBDA_RUNTIME_API` 环境变量。

### SIEM 集成

```bash
export SIEM_ENABLED=true
export SIEM_BACKEND=splunk                          # 或 "generic"
export SIEM_ENDPOINT=https://hec.example.com:8088/services/collector/event
export SIEM_TOKEN=your-hec-token
export SIEM_TIMEOUT_MS=5000
export SIEM_RETRIES=2
```

---

## 环境变量

| 变量 | 是否必须 | 默认值 | 描述 |
|------|----------|--------|------|
| `AWS_ACCESS_KEY_ID` | 是（或 YAML） | — | IAM 访问密钥 |
| `AWS_SECRET_ACCESS_KEY` | 是（或 YAML） | — | IAM 私有密钥 |
| `AWS_REGION` | 是（或 YAML） | `us-east-1` | AWS 区域 |
| `LOG_LEVEL` | 否 | `INFO` | DEBUG / INFO / WARN / ERROR / VVERBOSE |
| `SIEM_ENABLED` | 否 | `false` | 启用 SIEM 转发 |
| `SIEM_BACKEND` | 否 | `generic` | splunk / generic |
| `SIEM_ENDPOINT` | 条件 | — | SIEM HTTP 端点 |
| `SIEM_TOKEN` | 条件 | — | 认证令牌（Splunk HEC 或其他 API Key） |
| `SIEM_TIMEOUT_MS` | 否 | `5000` | 请求超时时间 |
| `SIEM_RETRIES` | 否 | `2` | 5xx 错误重试次数 |
| `AUDIT_S3_BUCKET` | 否 | — | 审计日志归档 S3 桶 |

---

## 依赖项

| 包 | 版本 | 用途 |
|----|------|------|
| `aws-sdk-go-v2` | v1.41 | AWS SDK 核心 |
| `aws-lambda-go` | v1.54 | Lambda 运行时支持 |
| `cloudtrail` | v1.56 | CloudTrail 事件查询 |
| `cognitoidentityprovider` | v1.61 | Cognito 用户池检查 |
| `iam` | v1.54 | IAM 角色/策略管理 |
| `s3` | v1.103 | S3 桶操作 |
| `sts` | v1.43 | STS 身份验证 |
| `google/uuid` | v1.6 | 对象键唯一 ID 生成 |
| `yaml.v3` | v3.0.1 | YAML 配置解析 |

---

## 安全措施

- `aws-config.yaml`（及 `.env`）已通过 `.gitignore` 排除出版本控制
- CloudTrail 和审计 S3 桶默认启用 SSE-S3/AES-256 加密
- IAM 信任策略将 `sts:AssumeRole` 限制为同一账户内主体
- `ASIA...` 前缀的访问密钥为 STS 临时凭证——从不硬编码
- SIEM 转发使用 HTTPS 传输，配合 Bearer/Splunk 令牌认证

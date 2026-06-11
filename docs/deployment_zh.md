# 部署指南

## Lambda 部署

### 容器镜像（推荐）

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap .
zip lambda.zip bootstrap
```

### Lambda 配置

| 设置 | 值 | 备注 |
|---------|-------|-------|
| 运行时 | `provided.al2023` | Go 的仅操作系统运行时 |
| 架构 | `arm64` | Graviton — 成本更低 |
| 内存 | 256–512 MB | GuardDuty + Inspector SDK 调用为 I/O 密集型 |
| 超时 | 30–300 秒 | 首次冷启动较长（DynamoDB 表创建） |
| 预留并发 | 10 | 防止 GuardDuty API 限流（默认 10 req/s） |
| 临时存储 | 512 MB | 默认 |
| 日志保留 | 30 天 | 在 CloudWatch → 日志组 → `/aws/lambda/AWSGateKeeper` 设置 |

### 环境变量

```
IS_PRODUCTION=true
LOG_LEVEL=INFO
GUARDDUTY_DETECTOR_ID=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_REGION=ap-east-1
SECURITY_MESSAGING_URL=https://hooks.slack.com/...
SECURITY_AUDIT_BUCKET=awsgatekeeper-audit
SECURITY_AUDIT_TABLE=awsgatekeeper-findings
EVENTBRIDGE_BUS_NAME=aws-gatekeeper-events
```

### IAM 执行角色

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["guardduty:*"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["inspector2:ListFindings"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["cloudtrail:LookupEvents"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["iam:ListAccessKeys","iam:UpdateAccessKey","iam:PutUserPolicy","iam:PutRolePolicy","iam:DeleteUserPolicy","iam:DeleteRolePolicy"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["s3:PutObject","s3:HeadBucket","s3:CreateBucket"], "Resource": "arn:aws:s3:::awsgatekeeper-*"},
    {"Effect": "Allow", "Action": ["dynamodb:PutItem","dynamodb:DescribeTable","dynamodb:CreateTable"], "Resource": "arn:aws:dynamodb:*:*:table/awsgatekeeper-*"},
    {"Effect": "Allow", "Action": ["events:PutEvents"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["cloudwatch:PutMetricData"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], "Resource": "*"}
  ]
}
```

## CloudWatch 告警

```bash
aws cloudwatch put-metric-alarm \
    --alarm-name AWSGateKeeper-QuarantineExecuted \
    --metric-name QuarantineExecuted \
    --namespace AWSGateKeeper \
    --statistic Sum --period 300 --threshold 0 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1 \
    --alarm-actions arn:aws:sns:REGION:ACCOUNT:security-alerts
```

## 死信队列（DLQ）

```bash
aws lambda create-event-source-mapping \
    --function-name AWSGateKeeper \
    --event-source-arn arn:aws:sqs:REGION:ACCOUNT:AWSGateKeeper-DLQ \
    --maximum-batching-window-in-seconds 60
```

## S3 审计生命周期

部署后配置审计桶生命周期：

```bash
aws s3api put-bucket-lifecycle-configuration \
    --bucket awsgatekeeper-audit \
    --lifecycle-configuration '{"Rules":[{"ID":"retention","Status":"Enabled","Transitions":[{"Days":90,"StorageClass":"GLACIER"}],"Expiration":{"Days":365},"Filter":{"Prefix":"security-reports/"}}]}'
```

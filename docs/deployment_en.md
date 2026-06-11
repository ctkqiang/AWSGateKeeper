# Deployment Guide

## Lambda Deployment

### Container Image (Recommended)

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap .
zip lambda.zip bootstrap
```

### Lambda Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Runtime | `provided.al2023` | OS-only runtime for Go |
| Architecture | `arm64` | Graviton — lower cost |
| Memory | 256–512 MB | GuardDuty + Inspector SDK calls are I/O-bound |
| Timeout | 30–300 s | Longer for first cold start (DynamoDB table creation) |
| Reserved Concurrency | 10 | Prevent GuardDuty API throttle (default 10 req/s) |
| Ephemeral Storage | 512 MB | Default |
| Log Retention | 30 days | Set in CloudWatch → Log Groups → `/aws/lambda/AWSGateKeeper` |

### Environment Variables

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

### IAM Execution Role

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["guardduty:*"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["inspector2:ListFindings"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["cloudtrail:LookupEvents"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["iam:ListAccessKeys","iam:UpdateAccessKey","iam:PutUserPolicy","iam:PutRolePolicy","iam:DeleteUserPolicy","iam:DeleteRolePolicy"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["s3:PutObject","s3:HeadBucket","s3:CreateBucket","s3:PutBucketLifecycleConfiguration"], "Resource": "arn:aws:s3:::awsgatekeeper-*"},
    {"Effect": "Allow", "Action": ["dynamodb:PutItem","dynamodb:DescribeTable","dynamodb:CreateTable"], "Resource": "arn:aws:dynamodb:*:*:table/awsgatekeeper-*"},
    {"Effect": "Allow", "Action": ["events:PutEvents"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["cloudwatch:PutMetricData"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
    {"Effect": "Allow", "Action": ["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"], "Resource": "*"}
  ]
}
```

## CloudWatch Alarms

```bash
aws cloudwatch put-metric-alarm \
    --alarm-name AWSGateKeeper-QuarantineExecuted \
    --metric-name QuarantineExecuted \
    --namespace AWSGateKeeper \
    --statistic Sum --period 300 --threshold 0 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 1 \
    --alarm-actions arn:aws:sns:REGION:ACCOUNT:security-alerts

aws cloudwatch put-metric-alarm \
    --alarm-name AWSGateKeeper-ErrorRate \
    --metric-name Errors \
    --namespace AWSGateKeeper \
    --statistic Sum --period 300 --threshold 5 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2
```

## Dead Letter Queue

```bash
aws lambda create-event-source-mapping \
    --function-name AWSGateKeeper \
    --event-source-arn arn:aws:sqs:REGION:ACCOUNT:AWSGateKeeper-DLQ \
    --maximum-batching-window-in-seconds 60
```

## S3 Audit Lifecycle

After deployment, configure the audit bucket lifecycle:

```bash
aws s3api put-bucket-lifecycle-configuration \
    --bucket awsgatekeeper-audit \
    --lifecycle-configuration '{"Rules":[{"ID":"retention","Status":"Enabled","Transitions":[{"Days":90,"StorageClass":"GLACIER"}],"Expiration":{"Days":365},"Filter":{"Prefix":"security-reports/"}}]}'
```

# 开发指南

## 前置条件

- Go 1.26+
- 具有 IAM、GuardDuty、Inspector、CloudTrail、S3、DynamoDB 权限的 AWS 凭证
- （可选）Docker 用于本地 Lambda 测试

## 本地开发

```bash
# 克隆
git clone https://gitcode.com/ctkqiang_sr/AWSGateKeeper
cd AWSGateKeeper

# 配置
cp aws-config.example.yaml aws-config.yaml
# 填入真实凭证

# 运行
go run .
# HTTP 服务器运行在 :8000
```

## 测试

```bash
# 运行所有测试
go test ./test/... -v -count=1

# 竞态检测
go test -race ./test/...

# 覆盖率
go test -cover ./test/...
```

## 代码质量

```bash
# 格式化
gofmt -w .

# 代码检查
golangci-lint run ./...

# 安全扫描
gosec ./...
```

## 项目结构约定

- 五层架构：传输层 → 编排层 → AWS 客户端层 → 领域层 → 基础设施层
- 所有路由接受注入闭包以避免循环导入
- 包文档注释遵循 `// Package pkg (file.go)` 格式
- 函数文档遵循 `// FuncName verb.\n//\n// @param\n// @return` 格式
- AWS 客户端封装器位于 `internal/services/aws/`
- 编排逻辑位于 `internal/services/security/`
- 领域类型位于 `internal/model/`
- 路由处理器位于 `internal/routes/`

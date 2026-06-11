# Development Guide

## Prerequisites

- Go 1.26+
- AWS credentials with IAM, GuardDuty, Inspector, CloudTrail, S3, DynamoDB permissions
- (Optional) Docker for local Lambda testing

## Local Development

```bash
# Clone
git clone https://gitcode.com/ctkqiang_sr/AWSGateKeeper
cd AWSGateKeeper

# Configure
cp aws-config.example.yaml aws-config.yaml
# Edit with real credentials

# Run
go run .
# HTTP server on :8000
```

## Testing

```bash
# Run all tests
go test ./test/... -v -count=1

# With race detector
go test -race ./test/...

# Coverage
go test -cover ./test/...
```

## Code Quality

```bash
# Format
gofmt -w .

# Lint
golangci-lint run ./...

# Security scan
gosec ./...
```

## Project Structure Conventions

- Five-layer architecture: Transport → Orchestration → AWS Clients → Domain → Infrastructure
- All routes accept injected closures to avoid import cycles
- Package doc comments follow `// Package pkg (file.go)` format
- Function docs follow `// FuncName verb.\n//\n// @param\n// @return` format
- AWS client wrappers live in `internal/services/aws/`
- Orchestration lives in `internal/services/security/`
- Domain types live in `internal/model/`
- Route handlers live in `internal/routes/`

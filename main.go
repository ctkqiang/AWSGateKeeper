package main

import (
	"context"
	"fmt"
	"os"

	"aws_gatekeeper/internal/routes"
	aws_gatekeeper_glob "aws_gatekeeper/internal/services/aws"
	"aws_gatekeeper/internal/services/security"
)

func main() {
	ctx := context.Background()
	if err := aws_gatekeeper_glob.Initialize(ctx); err != nil {
		panic(err)
	}

	cfg := aws_gatekeeper_glob.GetAccount().Config()
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	scanFunc := func(ctx context.Context) (interface{}, error) {
		mcfg, err := security.NewMessagingConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("security config: %w", err)
		}
		return security.ExecuteScanAndDeliver(ctx, mcfg)
	}

	healthFunc := func() map[string]interface{} {
		return security.BuildHealthResponse(cfg)
	}

	gdFactory := func(detectorID string) routes.GuardDutyClient {
		return aws_gatekeeper_glob.NewGuardDutyClient(cfg, region)
	}

	if err := aws_gatekeeper_glob.ServeLambdaEndpoint(scanFunc, healthFunc, gdFactory); err != nil {
		panic(err)
	}
}

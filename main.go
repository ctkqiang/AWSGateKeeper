package main

import (
	"context"
	"fmt"

	aws_gatekeeper_glob "aws_gatekeeper/internal/services/aws"
	"aws_gatekeeper/internal/services/security"
)

func main() {
	ctx := context.Background()
	if err := aws_gatekeeper_glob.Initialize(ctx); err != nil {
		panic(err)
	}

	cfg := aws_gatekeeper_glob.GetAccount().Config()

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

	if err := aws_gatekeeper_glob.ServeLambdaEndpoint(scanFunc, healthFunc); err != nil {
		panic(err)
	}
}

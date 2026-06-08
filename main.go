package main

import (
	"context"

	aws_gatekeeper_glob "aws_gatekeeper/internal/services/aws"
)

func main() {
	ctx := context.Background()
	if err := aws_gatekeeper_glob.Initialize(ctx); err != nil {
		panic(err)
	}

	if err := aws_gatekeeper_glob.ServeLambdaEndpoint(); err != nil {
		panic(err)
	}
}

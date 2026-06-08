package aws

import (
	"aws_gatekeeper/internal/routes"
	"aws_gatekeeper/internal/utilities"
	"fmt"
	"net/http"
	"os"

	aws_lambda_http "github.com/aws/aws-lambda-go/lambda"
	aws_lambda_http_adapter "github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
)

const (
	addr = "0.0.0.0:8080"

	IndexPath  = "/"
	HealthPath = "/health"
)

// ServeLambdaEndpoint starts an HTTP handler that, depending on the execution
// environment, runs as an AWS Lambda handler or as a standard HTTP server.
//
// # Environment Detection
//
// When both _LAMBDA_SERVER_PORT and AWS_LAMBDA_RUNTIME_API are set, the
// function enters Lambda mode via lambda.Start.  Otherwise it falls back to
// a local HTTP server on 0.0.0.0:8080, suitable for local development and
// integration testing.
//
//	@return  error if handler registration fails, adapter creation fails,
//	         or the local HTTP server cannot start
func ServeLambdaEndpoint() error {
	mux := http.NewServeMux()

	mux.HandleFunc(IndexPath, routes.Index)
	mux.HandleFunc(HealthPath, routes.Health)

	adapter := aws_lambda_http_adapter.New(mux)
	if adapter == nil {
		return fmt.Errorf("lambda: failed to create httpadapter")
	}

	if isLambdaRuntime() {
		aws_lambda_http.Start(adapter.ProxyWithContext)
		return nil
	}

	utilities.LogProgress("HTTP", "Starting local HTTP server on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		return fmt.Errorf("local server failed: %w", err)
	}

	return nil
}

// isLambdaRuntime returns true when both Lambda environment variables
// required by the aws-lambda-go runtime are present.
func isLambdaRuntime() bool {
	_, hasPort := os.LookupEnv("_LAMBDA_SERVER_PORT")
	_, hasAPI := os.LookupEnv("AWS_LAMBDA_RUNTIME_API")
	return hasPort && hasAPI
}

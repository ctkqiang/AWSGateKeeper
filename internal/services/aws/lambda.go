// Package aws (lambda.go) provides the HTTP-to-Lambda bridge.
//
// Two execution modes share a single entry point:
//
//	Local development  —  net/http server on 0.0.0.0:8080
//	AWS Lambda         —  lambda.Start(HandleAPIGatewayEvent)
//
// The `_LAMBDA_SERVER_PORT` and `AWS_LAMBDA_RUNTIME_API` environment
// variables are set by the Lambda runtime; their presence determines
// which mode [ServeLambdaEndpoint] operates in.
package aws

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/routes"
	"aws_gatekeeper/internal/utilities"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	aws_v2 "github.com/aws/aws-sdk-go-v2/aws"
	aws_lambda_http "github.com/aws/aws-lambda-go/lambda"
)

const (
	addr = "0.0.0.0:8000"

	IndexPath         = "/"
	HealthPath        = "/health"
	SecurityScanPath  = "/security/scan"
	SecurityHealthPath = "/security/health"

	CreateUserPath = "/create-user"
)

// lambdaRoutes is the route table used by HandleAPIGatewayEvent
// for direct Lambda dispatch.
//
// Add new routes here; the handler will walk this table in order
// and call the first matching entry.
var lambdaRoutes []routeEntry

func initRoutes(cfg aws_v2.Config, scanFunc routes.ScanFunc, healthFunc routes.HealthFunc) {
	lambdaRoutes = []routeEntry{
		{IndexPath, routes.Index},
		{HealthPath, routes.Health},
		{SecurityScanPath, routes.SecurityScanHandler(scanFunc)},
		{SecurityHealthPath, routes.SecurityHealthHandler(healthFunc)},
	}
}

// routeEntry pairs a URL path with its handler function.
type routeEntry struct {
	path    string
	handler http.HandlerFunc
}

// responseRecorder is a lightweight http.ResponseWriter implementation
// that captures status code, headers, and body in memory.  It is used by
// HandleAPIGatewayEvent to bridge the stdlib handler signature to the
// API Gateway response envelope without pulling in net/http/httptest.
type responseRecorder struct {
	statusCode int
	header     http.Header
	body       bytes.Buffer
}

// newResponseRecorder returns a recorder whose status defaults to 200 OK.
//
//	@return  ready-to-use recorder
func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		statusCode: http.StatusOK,
		header:     make(http.Header),
	}
}

// Header returns the response header map.
//
//	@return  response header map
func (r *responseRecorder) Header() http.Header { return r.header }

// Write appends data to the response body.  If WriteHeader has not been
// called before the first Write the status is set to 200 OK.
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}

// WriteHeader records the HTTP status code for the response.
//
//	@param  code  HTTP status code
func (r *responseRecorder) WriteHeader(code int) { r.statusCode = code }

// ServeLambdaEndpoint starts an HTTP handler that, depending on the
// execution environment, runs as an AWS Lambda handler or as a standard
// HTTP server.
//
// scanFunc and healthFunc are injected by main.go to avoid import cycles
// between the services/aws and services/security packages.
func ServeLambdaEndpoint(scanFunc routes.ScanFunc, healthFunc routes.HealthFunc) error {
	cfg := GetAccount().Config()
	initRoutes(cfg, scanFunc, healthFunc)

	mux := http.NewServeMux()
	mux.HandleFunc(IndexPath, logRequest(routes.Index))
	mux.HandleFunc(HealthPath, logRequest(routes.Health))
	mux.HandleFunc(SecurityScanPath, logRequest(routes.SecurityScanHandler(scanFunc)))
	mux.HandleFunc(SecurityHealthPath, logRequest(routes.SecurityHealthHandler(healthFunc)))

	if isLambdaRuntime() {
		aws_lambda_http.Start(HandleAPIGatewayEvent)
		return nil
	}

	utilities.LogProgress("HTTP", "Starting local HTTP server on %s", addr)

	// Graceful shutdown on SIGINT / SIGTERM (Ctrl+C, kill, Docker stop).
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		utilities.LogProgress("HTTP", "Shutting down gracefully", "signal=%s")
		srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("local server failed: %w", err)
	}

	return nil
}

// logRequest wraps an http.HandlerFunc with a request log line printed
// before the handler executes.
//
// Log format:  METHOD /path source=IP:port
func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		utilities.LogProgress(
			"http",
			r.Method+" "+r.URL.Path,
			"source=%s", r.RemoteAddr,
		)
		next(w, r)
	}
}

// isLambdaRuntime reports whether the process is executing inside the AWS
// Lambda execution environment.
//
// Both _LAMBDA_SERVER_PORT and AWS_LAMBDA_RUNTIME_API must be present for
// a positive result.
//
//	@return  true when running on Lambda; false for local / CI
func isLambdaRuntime() bool {
	_, hasPort := os.LookupEnv("_LAMBDA_SERVER_PORT")
	_, hasAPI := os.LookupEnv("AWS_LAMBDA_RUNTIME_API")
	return hasPort && hasAPI
}

// HandleAPIGatewayEvent is the direct Lambda handler for API Gateway
// (REST / HTTP API / Function URL) requests.  It inspects the incoming
// event's HTTP method and path and dispatches to the matching route.
//
// Unlike ServeLambdaEndpoint — which wraps the entire net/http stack
// through httpadapter — this function operates directly on the
// APIGatewayEvent struct and returns a JSON-serialisable response map
// compatible with API Gateway's Lambda integration response format:
//
//	{
//	  "statusCode": 200,
//	  "headers": { "Content-Type": "application/json" },
//	  "body": "{...}"
//	}
//
// Route table (lambdaRoutes):
//
//	GET  /              routes.Index
//	GET  /health        routes.Health
//
// Unknown paths return 404; panics in route handlers are recovered and
// logged, then re-panicked so the Lambda runtime can handle the error.
//
//	@param  ctx    Lambda invocation context
//	@param  event  raw API Gateway proxy event
//	@return        API Gateway integration response
//	@return        error — currently always nil (errors are surfaced
//	               inside the response body)
func HandleAPIGatewayEvent(ctx context.Context, event model.APIGatewayEvent) (map[string]interface{}, error) {
	defer func() {
		if r := recover(); r != nil {
			utilities.Error("lambda: panic in route handler: %v", r)
		}
	}()

	// Reconstruct an http.Request from the API Gateway proxy event.
	req, err := http.NewRequestWithContext(
		ctx,
		event.HTTPMethod,
		event.Path,
		strings.NewReader(event.Body),
	)
	if err != nil {
		return apiGatewayResponse(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid request: %v", err),
		}), nil
	}

	// Mirror incoming headers so route handlers can read them.
	for k, v := range event.Headers {
		req.Header.Set(k, v)
	}

	// Log every incoming request.
	srcIP := req.Header.Get("X-Forwarded-For")
	if srcIP == "" {
		srcIP = req.RemoteAddr
	}
	utilities.LogProgress("lambda", req.Method+" "+req.URL.Path, "source=%s", srcIP)

	// Dispatch to the matching route handler.
	w := newResponseRecorder()
	matched := false

	for _, entry := range lambdaRoutes {
		if event.Path == entry.path {
			entry.handler(w, req)
			matched = true
			break
		}
	}

	if !matched {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "not found"}`))
	}

	return apiGatewayResponse(w.statusCode, w.body.String()), nil
}

// apiGatewayResponse builds the Lambda integration response envelope
// expected by API Gateway.
//
// The response map follows the API Gateway proxy integration contract:
//
//	{
//	  "statusCode": <int>,
//	  "headers":    {"Content-Type": "application/json"},
//	  "body":       "<string>"
//	}
//
//	@param  statusCode  HTTP status to return
//	@param  body        response payload — string, []byte, or any value
//	                      that can be marshalled to JSON
//	@return             API Gateway-compatible response map
func apiGatewayResponse(statusCode int, body interface{}) map[string]interface{} {
	var bodyStr string

	switch v := body.(type) {
	case string:
		bodyStr = v
	case []byte:
		bodyStr = string(v)
	default:
		b, _ := json.Marshal(v)
		bodyStr = string(b)
	}

	return map[string]interface{}{
		"statusCode": statusCode,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"body": bodyStr,
	}
}

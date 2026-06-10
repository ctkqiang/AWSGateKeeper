// Package model (api_gateway.go) defines the API Gateway proxy event
// envelope received by the Lambda handler.
package model

// APIGatewayEvent is the structured proxy event payload delivered by
// API Gateway (REST / HTTP API / Function URL) to the Lambda handler.
type APIGatewayEvent struct {
	HTTPMethod string            `json:"httpMethod"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

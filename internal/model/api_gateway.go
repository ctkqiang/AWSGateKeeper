package model

type APIGatewayEvent struct {
	HTTPMethod string            `json:"httpMethod"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

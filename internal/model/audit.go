// Package model (audit.go) defines the audit event types, the
// AuditLogger, and the Audit struct for the governance pipeline.
package model

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

// Audit holds a pre-configured Cognito client for user-pool inspection.
	CognitoClient *cognitoidentityprovider.Client
}

type AuditEvent struct {
	Timestamp          time.Time   `json:"timestamp"`
	Action             string      `json:"action"`
	UserIdentifier     string      `json:"user_id,omitempty"`
	ResourceIdentifier string      `json:"resource_id,omitempty"`
	CorrelationID      string      `json:"request_id,omitempty"`
	ClientIPAddress    string      `json:"source_ip,omitempty"`
	WasSuccessful      bool        `json:"success"`
	HumanMessage       string      `json:"message,omitempty"`
	AdditionalData     interface{} `json:"metadata,omitempty"`
}

type AuditLogger struct {
	Mutex       sync.Mutex
	JsonEncoder *json.Encoder
}

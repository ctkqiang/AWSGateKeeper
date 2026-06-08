package model

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
)

type Audit struct {
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

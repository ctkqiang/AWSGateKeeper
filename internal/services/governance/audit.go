// Package governance provides audit logging for security-sensitive actions.
//
// Audit events are serialised as newline-delimited JSON and written to the
// configured output destination.  The package supports two deployment modes:
//
//  1. Lambda / CloudWatch (default)
//     Events are written to os.Stdout and captured by the Lambda runtime,
//     which forwards them to CloudWatch Logs.  This is the zero-config
//     path — nothing else is needed.
//
//  2. S3 → Glacier archival (recommended for long-term retention)
//     Events are uploaded to S3 via [S3AuditLogger] in the sibling
//     [aws] package.  An S3 Lifecycle Rule then transitions objects to
//     the GLACIER or DEEP_ARCHIVE storage class after a configurable
//     number of days.  This satisfies compliance requirements
//     (SOC 2, PCI-DSS, HIPAA) that mandate multi-year audit retention
//     at minimal cost.
//
// # S3 Glacier Integration
//
// Audit events flow to Glacier through an S3 Lifecycle Rule — no
// application code touches the Glacier API directly.  Objects are
// uploaded to S3 in the STANDARD tier and automatically transitioned
// to lower-cost storage classes over time.
//
// ## Environment variables
//
//	AUDIT_S3_BUCKET=my-company-audit-logs   # required
//	AUDIT_S3_PREFIX=production/audit        # optional (defaults to "audit-logs")
//	AWS_REGION=ap-east-1                    # optional
//
// ## S3 Lifecycle Policy (JSON)
//
// Apply once via the AWS Console, Terraform, or CloudFormation:
//
//	{
//	  "Rules": [{
//	    "ID": "transition-audit-logs-to-glacier",
//	    "Status": "Enabled",
//	    "Filter": { "Prefix": "production/audit/" },
//	    "Transitions": [
//	      { "Days": 90,  "StorageClass": "GLACIER_IR" },
//	      { "Days": 365, "StorageClass": "DEEP_ARCHIVE" }
//	    ],
//	    "NoncurrentVersionTransitions": [
//	      { "NoncurrentDays": 30, "StorageClass": "GLACIER_IR" }
//	    ],
//	    "Expiration": { "Days": 2555 }
//	  }]
//	}
//
// GLACIER_IR (Instant Retrieval) is preferred for audit logs —
// millisecond retrieval when you need to query historical events.
// DEEP_ARCHIVE suits logs older than one year that must be kept
// but are rarely accessed.
//
// ## Initialisation
//
//	s3Logger, err := aws.NewS3AuditLogger()
//	if err != nil {
//	    log.Fatalf("S3 audit logger: %v", err)
//	}
//
// ## Writing events (dual-write pattern)
//
//	event := model.AuditEvent{
//	    Action:         "AssumeRole",
//	    UserIdentifier: "AIDAUCRXCBPWFRLYNSASR",
//	    WasSuccessful:  true,
//	    HumanMessage:   "Security analyst assumed the SOC role",
//	}
//
//	// Real-time visibility via CloudWatch
//	governance.LogSuccessfulAction(
//	    event.Action, event.UserIdentifier, "",
//	    event.HumanMessage, nil,
//	)
//
//	// Long-term archival via S3 → Glacier
//	if err := s3Logger.WriteAuditEvent(event); err != nil {
//	    log.Printf("S3 audit write failed: %v", err)
//	    // Never fail the caller — CloudWatch already captured the event.
//	}
//
// ## Querying archived events
//
// Objects in Glacier must be restored before reading (minutes for
// GLACIER_IR, hours for DEEP_ARCHIVE).  Query STANDARD-tier objects
// (< 90 days) with Athena; older objects require RestoreObject first.
//
// ## Best Practices
//
//   - Dual-write: stdout for real-time visibility, S3 for durable
//     long-term retention.  Never sacrifice availability for auditing.
//   - Tag S3 objects with account ID and environment for cost allocation.
//   - Enable SSE-S3 or SSE-KMS on the bucket — audit logs carry
//     user identifiers and resource ARNs.
//   - Enable S3 Object Lock in Compliance mode if your regulatory
//     framework requires WORM storage.
package governance

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/utilities"
	"encoding/json"
	"os"
	"time"
)

// defaultAuditLogger is the package-level logger used by the convenience
// wrappers WriteAuditEventUsingDefault, LogSuccessfulAction, and
// LogFailedAction.
var defaultAuditLogger = NewAuditLogger(os.Stdout)

// NewAuditLogger creates an AuditLogger that writes newline-delimited JSON
// audit records to the given file or stream.
//
// In Lambda environments, pass os.Stdout so that logs are captured by
// CloudWatch.  For local development, pass a file opened with os.Create.
//
//	@param  outputFile  destination for audit JSON records
//	@return             initialised AuditLogger ready for use
func NewAuditLogger(outputFile *os.File) *model.AuditLogger {
	return &model.AuditLogger{
		JsonEncoder: json.NewEncoder(outputFile),
	}
}

// WriteAuditEvent serialises a single audit event to JSON and writes it to
// the logger's output stream.  If the caller omits Timestamp, it is set to
// the current UTC time.
//
// This function is safe for concurrent use — the underlying AuditLogger
// protects its encoder with a mutex.
//
//	@param  logger  the audit logger to write to
//	@param  event   the audit record to write
func WriteAuditEvent(logger *model.AuditLogger, event model.AuditEvent) {
	logger.Mutex.Lock()
	defer logger.Mutex.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	if err := logger.JsonEncoder.Encode(event); err != nil {
		utilities.Error("audit: write event failed: %v", err)
	}
}

// WriteAuditEventUsingDefault is a convenience wrapper that writes the
// event through the package-level defaultAuditLogger.
//
//	@param  event  the audit record to write
func WriteAuditEventUsingDefault(event model.AuditEvent) {
	WriteAuditEvent(defaultAuditLogger, event)
}

// LogSuccessfulAction records a successful security-sensitive action in the
// audit log.
//
//	@param  actionName     name of the performed action (e.g. "CreateRole")
//	@param  userID         identifier of the user who performed the action
//	@param  resourceID     ARN or ID of the target resource
//	@param  messageText    human-readable description of what happened
//	@param  extraMetadata  optional arbitrary data attached to the event
func LogSuccessfulAction(actionName, userID, resourceID, messageText string, extraMetadata interface{}) {
	WriteAuditEventUsingDefault(model.AuditEvent{
		Action:             actionName,
		UserIdentifier:     userID,
		ResourceIdentifier: resourceID,
		WasSuccessful:      true,
		HumanMessage:       messageText,
		AdditionalData:     extraMetadata,
	})
}

// LogFailedAction records a failed security-sensitive action in the audit
// log, including an optional error message.
//
//	@param  actionName     name of the failed action
//	@param  userID         identifier of the user who attempted the action
//	@param  resourceID     ARN or ID of the target resource
//	@param  messageText    human-readable description of the failure
//	@param  extraMetadata  optional arbitrary data attached to the event
func LogFailedAction(actionName, userID, resourceID, messageText string, extraMetadata interface{}) {
	WriteAuditEventUsingDefault(model.AuditEvent{
		Action:             actionName,
		UserIdentifier:     userID,
		ResourceIdentifier: resourceID,
		WasSuccessful:      false,
		HumanMessage:       messageText,
		AdditionalData:     extraMetadata,
	})
}

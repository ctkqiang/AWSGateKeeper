// Package governance provides audit logging for security-sensitive
// application-level actions.
//
// Two complementary audit layers exist in this project:
//
//  1. Application audit (this package)
//     Writes structured JSON events to os.Stdout, captured by the Lambda
//     runtime and forwarded to CloudWatch Logs.  If SIEM_ENABLED=true,
//     each event is also forwarded to an external SIEM (Splunk, Datadog,
//     or any JSON-over-HTTP collector) via the [siem] package.  Use
//     LogSuccessfulAction and LogFailedAction for business-level events
//     (role assumption, policy changes, user access decisions).
//
//  2. Infrastructure audit (CloudTrail — automatic)
//     Every AWS API call is captured by CloudTrail without any application
//     code.  IAM role creation, trust-policy updates, Cognito group
//     membership changes — CloudTrail records Who, What, When, and
//     Where for every action.  The [aws.TrailClient] in the sibling
//     [aws] package provides programmatic lookup of CloudTrail events
//     for audit-rule evaluation.
//
//     A CloudTrail trail delivers logs to S3, where a Lifecycle Rule
//     transitions them to Glacier for long-term retention (7 years by
//     default).  This satisfies SOC 2, PCI-DSS, and HIPAA compliance
//     at near-zero operational cost.
//
// # CloudTrail Lookup — Usage
//
// Query IAM events from the last 24 hours:
//
//	client := aws.NewTrailClient(cfg)
//	events, err := client.LookupIAMEvents(ctx, 24)
//	if err != nil {
//	    log.Fatalf("cloudtrail: %v", err)
//	}
//	for _, ev := range events {
//	    fmt.Printf("%s %s %s\n", ev.EventTime, ev.EventName, ev.UserARN)
//	}
//
// Query Cognito events from the last 1 hour:
//
//	events, err := client.LookupCognitoEvents(ctx, 1)
//
// # Best Practices
//
//   - Let CloudTrail own the AWS-level audit trail — never manually log
//     API calls.  The governance logger is for application-level context
//     only.
//   - Keep CloudTrail logs in a dedicated S3 bucket with SSE-KMS
//     encryption and Object Lock (Compliance mode) for WORM storage.
//   - Use CloudTrail Lake for SQL-based queries across months or years
//     of historical data without restoring from Glacier.
package governance

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/services/siem"
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

	// Forward to SIEM (fire-and-forget; no-op when SIEM_ENABLED != "true").
	siem.Send(event)
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

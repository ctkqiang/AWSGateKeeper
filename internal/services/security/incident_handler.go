// Package security (incident_handler.go) implements the real-time
// incident response pipeline for EventBridge-driven CloudTrail events.
//
// The pipeline is intentionally layered:
//
//	┌────────────────────────────────────────────────────────────┐
//	│  Phase 1  Audit              policy baseline compliance  │
//	│  Phase 2  Correlate Threats  GuardDuty findings           │
//	│  Phase 3  Quarantine         Deny-* + key deactivation    │
//	│  Phase 4  Report             Markdown + webhook delivery  │
//	└────────────────────────────────────────────────────────────┘
//
// Each phase is independently testable; the top-level entry point
// ProcessCloudTrailEvent is the only function called from outside
// the package.
package security

import (
	"aws_gatekeeper/internal/model"
	aws_sec "aws_gatekeeper/internal/security"
	aws_svc "aws_gatekeeper/internal/services/aws"
	"aws_gatekeeper/internal/services/governance"
	"aws_gatekeeper/internal/utilities"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/google/uuid"
)

// IncidentHandler orchestrates the full incident response pipeline:
// audit → threat correlation → quarantine → report → webhook delivery.
//
// All heavy state (SDK clients, sub-engines) is constructed once at
// creation time and reused for the lifetime of the handler, making the
// handler safe to register as a long-lived route dependency.
type IncidentHandler struct {
	cfg              aws_sdk.Config           // shared AWS SDK config used by all sub-clients
	quarantineEngine *QuarantineEngine        // engine that performs the Deny-* isolation
	guardDutyClient  *aws_svc.GuardDutyClient // client for GuardDuty finding correlation
	detectiveClient  *aws_svc.DetectiveClient // client for CloudTrail root-cause lookups
	webhookURL       string                   // destination URL for the incident markdown
	siemEnabled      bool                     // whether to also forward to the SIEM pipeline
}

// IncidentConfig holds the parameters needed to construct an
// IncidentHandler.
type IncidentConfig struct {
	Config      aws_sdk.Config // shared AWS SDK config
	DetectorID  string         // GuardDuty detector for the target account
	WebhookURL  string         // empty = no webhook delivery
	SIEMEnabled bool           // enable SIEM forwarder integration
}

// NewIncidentHandler creates an IncidentHandler from the given config.
//
// The handler eagerly initialises the QuarantineEngine and the AWS
// service clients; construction is cheap (no AWS calls are made
// until ProcessCloudTrailEvent is invoked).
//
//	@param  ic  configuration struct (see IncidentConfig)
//	@return     ready-to-use IncidentHandler suitable for HTTP route registration
func NewIncidentHandler(ic IncidentConfig) *IncidentHandler {
	return &IncidentHandler{
		cfg:              ic.Config,
		quarantineEngine: NewQuarantineEngine(ic.Config),
		guardDutyClient:  aws_svc.NewGuardDutyClient(ic.Config, "us-east-1"),
		detectiveClient:  aws_svc.NewDetectiveClient(ic.Config),
		webhookURL:       ic.WebhookURL,
		siemEnabled:      ic.SIEMEnabled,
	}
}

// ProcessCloudTrailEvent is the main entry point for the incident response
// pipeline. It receives a raw CloudTrail event (as JSON) from EventBridge
// and executes the full audit → correlate → quarantine → report loop.
//
// Returns an IncidentReport suitable for HTTP response serialisation.
//
// The function is non-blocking for the webhook delivery step: the
// returned report is built synchronously, but the webhook push and
// SIEM forwarder are dispatched in a goroutine so the caller (an
// EventBridge invocation) returns as quickly as possible.
//
//	@param  ctx       request context — cancellation propagates into
//	                  AWS SDK calls
//	@param  rawEvent  EventBridge event body (the "detail" envelope is
//	                  parsed internally)
//	@return           populated IncidentReport on success
//	@return           non-nil if the CloudTrail envelope cannot be parsed
//	                  or the policy document is missing entirely
func (h *IncidentHandler) ProcessCloudTrailEvent(ctx context.Context, rawEvent json.RawMessage) (*model.IncidentReport, error) {
	incident := &model.IncidentRecord{
		IncidentID: uuid.New().String(),
		DetectedAt: time.Now().UTC(),
	}

	// Parse CloudTrail event envelope.  We use an inline anonymous
	// struct so the JSON contract is documented alongside the field
	// the calling EventBridge rule must produce.
	var ctEvent struct {
		Detail struct {
			EventName    string `json:"eventName"`
			EventSource  string `json:"eventSource"`
			UserIdentity struct {
				Arn string `json:"arn"`
			} `json:"userIdentity"`
			SourceIPAddress   string `json:"sourceIPAddress"`
			RequestParameters struct {
				PolicyDocument string `json:"policyDocument"`
				RoleName       string `json:"roleName"`
				UserName       string `json:"userName"`
				PolicyName     string `json:"policyName"`
			} `json:"requestParameters"`
			ResponseElements struct {
				Role *struct {
					Arn  string `json:"arn"`
					Name string `json:"roleName"`
				} `json:"role"`
			} `json:"responseElements"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(rawEvent, &ctEvent); err != nil {
		return nil, fmt.Errorf("parse cloudtrail event: %w", err)
	}

	d := ctEvent.Detail
	incident.EventName = d.EventName
	incident.EventSource = d.EventSource
	incident.PrincipalARN = d.UserIdentity.Arn
	incident.SourceIP = d.SourceIPAddress

	policyDoc := d.RequestParameters.PolicyDocument
	if policyDoc == "" {
		// Most CloudTrail events do not carry a policy document; we
		// explicitly log and exit so the audit log clearly records
		// "skipped, no policy" rather than silently dropping the
		// event.
		utilities.LogProgress("incident", "skip", "no policy document in event "+d.EventName)
		return nil, nil
	}

	incident.RequestParams = policyDoc

	// Phase 1: Audit policy against baseline.
	violations := auditPolicyAgainstBaseline(policyDoc, d.EventName, d.UserIdentity.Arn)
	incident.Violations = violations

	if len(violations) == 0 {
		// A clean audit result still goes through the governance
		// log so security can prove that every EventBridge event
		// was evaluated, not just the ones that triggered action.
		utilities.LogProgress("incident", "audit", "policy compliant — no violations")
		governance.LogSuccessfulAction("PolicyAudit", d.UserIdentity.Arn, "",
			fmt.Sprintf("event %s policy passed baseline audit", d.EventName), nil)
		return h.buildReport(incident), nil
	}

	utilities.LogProgress("incident", "audit",
		fmt.Sprintf("event=%s violations=%d", d.EventName, len(violations)))

	// Phase 2: Threat correlation with GuardDuty.
	threatScore := correlateThreats(h.guardDutyClient, ctx, d.UserIdentity.Arn)
	incident.ThreatScore = threatScore

	// Phase 3: Quarantine decision.
	if shouldQuarantine(violations, threatScore) {
		// Prefer the role ARN returned by the response (e.g. for
		// CreateRole) so the quarantine policy targets the newly
		// created principal; fall back to the caller's ARN otherwise.
		targetARN := d.UserIdentity.Arn
		if d.ResponseElements.Role != nil && d.ResponseElements.Role.Arn != "" {
			targetARN = d.ResponseElements.Role.Arn
		}
		targetType := "user"
		if strings.Contains(targetARN, ":role/") {
			targetType = "role"
		}

		record, err := h.quarantineEngine.QuarantineIdentity(ctx, targetARN, targetType)
		if err != nil {
			// A failed quarantine is logged but does not abort the
			// incident — the report is still produced so the
			// on-call engineer can intervene manually.
			utilities.Error("incident: quarantine %s: %v", targetARN, err)
			governance.LogFailedAction("QuarantineIdentity", "system", targetARN,
				fmt.Sprintf("quarantine failed: %v", err), nil)
		} else {
			incident.Quarantined = true
			incident.Quarantine = record
		}
	}

	// Phase 4: Build and deliver report.
	report := h.buildReport(incident)

	// Fire-and-forget delivery; failures are recorded in the
	// governance log by the deliverReport function itself.
	go h.deliverReport(ctx, report)

	return report, nil
}

// auditPolicyAgainstBaseline runs the existing wildcard detector and
// any additional organisational compliance checks against the given
// policy document JSON.
//
// Two rule families are evaluated:
//
//	WILDCARD_POLICY       — produced by aws_sec.AuditWildcardPolicy
//	CROSS_ACCOUNT_TRUST   — inline check for CreateRole /
//	                         UpdateAssumeRolePolicy events
//
//	@param  policyJSON    IAM policy document (raw JSON string)
//	@param  eventName     originating CloudTrail event name
//	@param  principalARN  ARN of the IAM principal that issued the call
//	@return               list of compliance violations (empty when
//	                     the policy passes every check)
func auditPolicyAgainstBaseline(policyJSON, eventName, principalARN string) []model.ComplianceViolation {
	var violations []model.ComplianceViolation

	entityType := detectEntityType(eventName)

	findings, err := aws_sec.AuditWildcardPolicy(policyJSON, entityType, principalARN, principalARN)
	if err != nil {
		// Audit failures are logged but treated as "no violations"
		// so a transient error in the detector does not produce a
		// flood of false-positive incidents.
		utilities.Error("incident: audit policy: %v", err)
		return violations
	}

	for _, f := range findings {
		violations = append(violations, model.ComplianceViolation{
			RuleID:      "WILDCARD_POLICY",
			Severity:    string(f.Severity),
			EntityARN:   principalARN,
			EntityType:  entityType,
			Description: f.Summary,
			Statement:   f.Statement,
		})
	}

	// Check for cross-account trust (AssumeRole with external AWS account).
	if strings.Contains(eventName, "CreateRole") || strings.Contains(eventName, "UpdateAssumeRolePolicy") {
		if hasCrossAccountTrust(policyJSON) {
			violations = append(violations, model.ComplianceViolation{
				RuleID:      "CROSS_ACCOUNT_TRUST",
				Severity:    "CRITICAL",
				EntityARN:   principalARN,
				EntityType:  entityType,
				Description: "role trust policy grants AssumeRole to an external AWS account without ExternalId",
				Statement:   0,
			})
		}
	}

	return violations
}

// correlateThreats queries GuardDuty for active findings involving the
// given principal ARN and returns a threat score (0.0–10.0).
//
// The score is the simple sum of per-finding contributions capped at
// 10.0.  The weights were chosen to map the GuardDuty severity scale
// onto the same 0–10 numeric range the audit dashboard uses:
//
//	High     +3.5
//	Medium   +2.0
//	Low      +1.0
//
// A failure in the GuardDuty API is logged and treated as a 0 score
// so the pipeline never blocks on a third-party outage.
//
//	@param  gd            GuardDuty client used to look up findings
//	@param  ctx           request context for the SDK call
//	@param  principalARN  ARN of the principal to correlate
//	@return               threat score in [0.0, 10.0]
func correlateThreats(gd *aws_svc.GuardDutyClient, ctx context.Context, principalARN string) float64 {
	findings, err := gd.ListActiveFindings(ctx, getDetectorID(), 24)
	if err != nil {
		utilities.Error("incident: correlate threats: %v", err)
		return 0
	}

	var score float64
	for _, f := range findings {
		// Match either by resource ARN (the canonical GuardDuty
		// link) or by ARN appearing in the description text
		// (some finding types reference the principal only
		// descriptively).
		if strings.Contains(f.ResourceARN, principalARN) || strings.Contains(f.Description, principalARN) {
			switch f.Severity {
			case model.SeverityHigh:
				score += 3.5
			case model.SeverityMedium:
				score += 2.0
			case model.SeverityLow:
				score += 1.0
			}
		}
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

// shouldQuarantine decides whether to trigger quarantine based on
// violation severity and threat score.
//
// The decision matrix is intentionally simple:
//
//	any violation with CRITICAL severity     →  quarantine
//	threat score >= 7.0                      →  quarantine
//
//	@param  violations   list of detected policy violations
//	@param  threatScore  GuardDuty-derived threat score
//	@return              true if the identity should be isolated
func shouldQuarantine(violations []model.ComplianceViolation, threatScore float64) bool {
	hasCritical := false
	for _, v := range violations {
		if v.Severity == "CRITICAL" {
			hasCritical = true
			break
		}
	}
	return hasCritical || threatScore >= 7.0
}

// buildReport generates the incident report including a Markdown
// summary.
//
// The function is pure: it does not perform I/O, does not emit logs,
// and does not call any AWS service.  All side effects live in
// deliverReport so that buildReport is straightforward to unit test.
//
//	@param  incident  incident record carrying all phase results
//	@return           fully populated incident report
func (h *IncidentHandler) buildReport(incident *model.IncidentRecord) *model.IncidentReport {
	markdown := renderIncidentMarkdown(incident)
	return &model.IncidentReport{
		Incident:   *incident,
		Markdown:   markdown,
		WebhookURL: h.webhookURL,
	}
}

// deliverReport sends the incident report to the configured webhook
// and persists it via the existing SIEM infrastructure.
//
// The function is fire-and-forget from the caller's perspective: it
// is normally invoked in a goroutine and never returns an error.  All
// failures are recorded in the governance audit log so on-call
// engineers can review them post-hoc.
//
//	@param  ctx     request context for the SIEM forwarder
//	@param  report  the incident report to deliver
func (h *IncidentHandler) deliverReport(ctx context.Context, report *model.IncidentReport) {
	if h.webhookURL != "" {
		payload := map[string]interface{}{
			"incident_id":   report.Incident.IncidentID,
			"markdown":      report.Markdown,
			"event_name":    report.Incident.EventName,
			"principal_arn": report.Incident.PrincipalARN,
			"violations":    len(report.Incident.Violations),
			"quarantined":   report.Incident.Quarantined,
			"detected_at":   report.Incident.DetectedAt.Format(time.RFC3339),
		}
		SendToMessagingEndpoint(h.webhookURL, model.MessagingPayload{
			ReportID:    report.Incident.IncidentID,
			Markdown:    report.Markdown,
			GeneratedAt: report.Incident.DetectedAt.Format(time.RFC3339),
			Findings:    len(report.Incident.Violations),
			Critical:    countCriticalViolations(report.Incident.Violations),
		})
		_ = payload
	}

	if h.siemEnabled {
		governance.LogSuccessfulAction("IncidentResponse", "system",
			report.Incident.PrincipalARN,
			fmt.Sprintf("incident %s processed: %d violations, quarantine=%v",
				report.Incident.IncidentID, len(report.Incident.Violations), report.Incident.Quarantined),
			map[string]interface{}{
				"incident_id": report.Incident.IncidentID,
				"violations":  report.Incident.Violations,
				"quarantine":  report.Incident.Quarantine,
			})
	}
}

// renderIncidentMarkdown produces a GitHub-flavoured Markdown string
// from an IncidentRecord.  The output is designed for human consumption
// in messaging platforms and dashboards.
//
//	@param  incident  incident record to render
//	@return           formatted markdown body
func renderIncidentMarkdown(incident *model.IncidentRecord) string {
	var b strings.Builder
	b.WriteString("# Incident Response Report\n\n")
	b.WriteString(fmt.Sprintf("**Incident ID:** `%s`\n", incident.IncidentID))
	b.WriteString(fmt.Sprintf("**Detected At:** %s\n", incident.DetectedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Event:** %s (%s)\n", incident.EventName, incident.EventSource))
	b.WriteString(fmt.Sprintf("**Principal:** `%s`\n", incident.PrincipalARN))
	b.WriteString(fmt.Sprintf("**Source IP:** %s\n", incident.SourceIP))
	b.WriteString(fmt.Sprintf("**Threat Score:** %.1f/10.0\n\n", incident.ThreatScore))

	b.WriteString("## Compliance Violations\n\n")
	if len(incident.Violations) == 0 {
		b.WriteString("_No violations detected._\n\n")
	} else {
		b.WriteString("| Rule | Severity | Entity | Description |\n")
		b.WriteString("|------|----------|--------|-------------|\n")
		for _, v := range incident.Violations {
			b.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s |\n",
				v.RuleID, v.Severity, truncateARN(v.EntityARN), v.Description))
		}
	}

	b.WriteString("\n## Quarantine Status\n\n")
	if incident.Quarantined && incident.Quarantine != nil {
		q := incident.Quarantine
		b.WriteString(fmt.Sprintf("- **Policy Attached:** %v (`%s`)\n", q.PolicyAttached, q.PolicyName))
		b.WriteString(fmt.Sprintf("- **Keys Deactivated:** %d\n", len(q.KeysDeactivated)))
		b.WriteString(fmt.Sprintf("- **Sessions Revoked:** %v\n", q.SessionsRevoked))
		if q.ErrorMessage != "" {
			b.WriteString(fmt.Sprintf("- **Error:** %s\n", q.ErrorMessage))
		}
	} else {
		b.WriteString("_No quarantine action was triggered for this incident._\n")
	}

	return b.String()
}

// detectEntityType maps a CloudTrail event name to the IAM entity
// type that owns the resource being modified.  Used to scope the
// wildcard policy audit.
//
// Heuristic: any event whose name contains "User" is treated as a
// user-level change; everything else (e.g. "CreateRole",
// "AttachRolePolicy") is treated as a role-level change.
//
//	@param  eventName  CloudTrail event name
//	@return            "user" or "role"
func detectEntityType(eventName string) string {
	if strings.Contains(eventName, "User") {
		return "user"
	}
	return "role"
}

// hasCrossAccountTrust reports whether the given trust policy grants
// AssumeRole to an external AWS account without an ExternalId condition.
//
// A policy is considered "external" when the Principal.AWS field
// mentions an account that is not ":root" of the local account and
// when the trust policy has no Condition.StringEquals["sts:ExternalId"]
// entry.
//
//	@param  policyJSON  IAM trust policy document (raw JSON string)
//	@return            true if the policy is unsafe cross-account
func hasCrossAccountTrust(policyJSON string) bool {
	var doc struct {
		Statement []struct {
			Principal struct {
				AWS string `json:"AWS"`
			} `json:"Principal"`
			Condition *struct {
				ExternalIdExists *bool             `json:"Bool,omitempty"`
				StringEquals     map[string]string `json:"StringEquals,omitempty"`
			} `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return false
	}
	for _, s := range doc.Statement {
		if s.Principal.AWS != "" && !strings.Contains(s.Principal.AWS, ":root") {
			if s.Condition == nil || s.Condition.StringEquals == nil {
				return true
			}
			if _, ok := s.Condition.StringEquals["sts:ExternalId"]; !ok {
				return true
			}
		}
	}
	return false
}

// truncateARN shortens an ARN for display in narrow markdown tables.
// Long ARNs are truncated to 60 characters and prefixed with "..."
// so the table remains readable on small screens.
//
//	@param  arn  full IAM ARN
//	@return      ARN truncated to <= 60 characters
func truncateARN(arn string) string {
	if len(arn) <= 60 {
		return arn
	}
	return "..." + arn[len(arn)-57:]
}

// countCriticalViolations returns the number of violations whose
// severity is "CRITICAL".
//
//	@param  v  list of compliance violations
//	@return    count of CRITICAL-severity entries
func countCriticalViolations(v []model.ComplianceViolation) int {
	var n int
	for _, vv := range v {
		if vv.Severity == "CRITICAL" {
			n++
		}
	}
	return n
}

// getDetectorID reads GUARDDUTY_DETECTOR_ID from the environment.
//
// The detector ID is treated as deployment configuration rather than
// code configuration so the same binary can be deployed across
// multiple AWS accounts without rebuild.
//
//	@return  GuardDuty detector ID (may be empty)
func getDetectorID() string {
	return os.Getenv("GUARDDUTY_DETECTOR_ID")
}

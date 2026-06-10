// Package model (security.go) defines the security subsystem domain
// types: findings, investigations, reports, and GuardDuty resource models.
package model

import "time"

// FindingSeverity maps GuardDuty and Inspector severity levels to a
// unified internal scale. Zero value (SeverityUnknown) signals unparsed input.
type FindingSeverity int

const (
	SeverityUnknown    FindingSeverity = iota // unparsed or missing severity
	SeverityInformational                     // GuardDuty: 0.0–3.9, Inspector: INFORMATIONAL
	SeverityLow                               // GuardDuty: 4.0–6.9, Inspector: LOW
	SeverityMedium                            // GuardDuty: 7.0–8.9, Inspector: MEDIUM
	SeverityHigh                              // GuardDuty: 9.0–10.0, Inspector: HIGH
	SeverityCritical                          // Inspector: CRITICAL
)

// GuardDutyFinding holds the subset of a GuardDuty GetFindings response
// that the security subsystem acts on.
type GuardDutyFinding struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Severity    FindingSeverity `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	ResourceARN string          `json:"resource_arn"`
	AccountID   string          `json:"account_id"`
	Region      string          `json:"region"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`

	// ConfirmedCompromised is true when the finding indicates a compromised
	// IAM credential. These findings trigger an automatic IAM disable action.
	ConfirmedCompromised bool `json:"compromised"`

	// NetworkScanAnomaly is true when the finding describes reconnaissance
	// or port-scanning behaviour.
	NetworkScanAnomaly bool `json:"network_scan_anomaly"`

	// Raw JSON preserves the full API response for audit trail replay.
	RawJSON string `json:"raw_json"`
}

// InspectorFinding holds the subset of an Inspector DescribeFindings
// response relevant to container vulnerability tracking.
type InspectorFinding struct {
	ARN             string          `json:"arn"`
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Severity        FindingSeverity `json:"severity"`
	CVE             string          `json:"cve"`
	CVSSScore       float64         `json:"cvss_score"`
	VulnerableImage string          `json:"vulnerable_image"`
	Registry        string          `json:"registry"`
	Repository      string          `json:"repository"`
	PackageName     string          `json:"package_name"`
	InstalledVersion string         `json:"installed_version"`
	FixedVersion    string          `json:"fixed_version"`
	Remediation     string          `json:"remediation"`
	FirstObserved   time.Time       `json:"first_observed"`
	LastObserved    time.Time       `json:"last_observed"`

	// Raw JSON preserves the full API response.
	RawJSON string `json:"raw_json"`
}

// InvestigationResult captures the output of a Detective / CloudTrail
// root-cause investigation triggered by a high-severity finding.
type InvestigationResult struct {
	FindingID   string    `json:"finding_id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`

	// RootCause is the human-readable summary of what caused the finding.
	RootCause string `json:"root_cause"`

	// Timeline lists the CloudTrail events relevant to the investigation
	// in chronological order.
	Timeline []InvestigationEvent `json:"timeline"`

	// AffectedResources lists the ARNs of resources involved.
	AffectedResources []string `json:"affected_resources"`

	// Recommendation is the suggested remediation action.
	Recommendation string `json:"recommendation"`
}

// InvestigationEvent is a single CloudTrail event surfaced during a
// Detective investigation, flattened for display in a security report.
type InvestigationEvent struct {
	EventTime   time.Time `json:"event_time"`
	EventName   string    `json:"event_name"`
	EventSource string    `json:"event_source"`
	UserARN     string    `json:"user_arn"`
	SourceIP    string    `json:"source_ip"`
	Resources   []string  `json:"resources"`
	RawEvent    string    `json:"raw_event"`
}

// SecurityReport is the aggregate output of a security scan cycle,
// combining findings from GuardDuty, Inspector, and Detective.
type SecurityReport struct {
	GeneratedAt        time.Time              `json:"generated_at"`
	ReportID           string                 `json:"report_id"`
	GuardDutyFindings  []GuardDutyFinding     `json:"guardduty_findings"`
	InspectorFindings  []InspectorFinding     `json:"inspector_findings"`
	Investigations     []InvestigationResult  `json:"investigations"`
	ActionsTaken       []string               `json:"actions_taken"`
	Summary            string                 `json:"summary"`
	Markdown           string                 `json:"markdown"`
}

// MessagingPayload is the wire format sent to the placeholder custom
// messaging endpoint after a security scan completes.
type MessagingPayload struct {
	ReportID    string `json:"report_id"`
	Markdown    string `json:"markdown"`
	GeneratedAt string `json:"generated_at"`
	Findings    int    `json:"total_findings"`
	Critical    int    `json:"critical_count"`
}

// FindingStatistics mirrors GuardDuty GetFindingsStatistics output,
// providing aggregate counts by severity level.
type FindingStatistics struct {
	Total          int            `json:"total"`
	BySeverity     map[string]int `json:"by_severity"`
	ByType         map[string]int `json:"by_type"`
	ActiveCount    int            `json:"active"`
	ArchivedCount  int            `json:"archived"`
	GeneratedAt    string         `json:"generated_at"`
}

// ThreatIntelSet represents a custom threat intelligence feed
// (malicious IPs/domains) uploaded to GuardDuty.
type ThreatIntelSet struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Format     string `json:"format"`
	Location   string `json:"location"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
}

// TrustedEntitySet represents an allow-list of known-safe IPs or
// domains used to suppress GuardDuty false positives.
type TrustedEntitySet struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Format     string `json:"format"`
	Location   string `json:"location"`
	Status     string `json:"status"`
	CreatedAt  string `json:"created_at"`
}

// PublishingDestination represents a GuardDuty publishing destination
// (S3, CloudWatch Logs, or Firehose delivery stream).
type PublishingDestination struct {
	DestinationID   string `json:"destination_id"`
	DestinationType string `json:"destination_type"`
	Status          string `json:"status"`
	DestinationARN  string `json:"destination_arn"`
}

// CoverageStats summarizes GuardDuty resource coverage across
// EC2, ECS, EKS, S3, and Lambda.
type CoverageStats struct {
	TotalResources  int            `json:"total_resources"`
	CoveredResources int           `json:"covered_resources"`
	CoveragePercent float64        `json:"coverage_percent"`
	ByResourceType  map[string]int `json:"by_resource_type"`
}

// MemberAccount represents a GuardDuty member account in an
// AWS Organization.
type MemberAccount struct {
	AccountID    string `json:"account_id"`
	Email        string `json:"email"`
	MasterID     string `json:"master_id"`
	Relationship string `json:"relationship"`
	DetectorID   string `json:"detector_id,omitempty"`
	Status       string `json:"status"`
}

// OrganizationStats mirrors GuardDuty GetOrganizationStatistics.
type OrganizationStats struct {
	TotalAccounts    int `json:"total_accounts"`
	ActiveAccounts   int `json:"active_accounts"`
	Members          int `json:"members"`
	EnabledDetectors int `json:"enabled_detectors"`
}

// FeedbackEntry records a GuardDuty finding feedback submission.
type FeedbackEntry struct {
	FindingID string `json:"finding_id"`
	Feedback  string `json:"feedback"` // USEFUL or NOT_USEFUL
	Comment   string `json:"comment,omitempty"`
}


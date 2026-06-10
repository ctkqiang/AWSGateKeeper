// Package model (incident.go) defines types for the incident response
// pipeline: violation records, quarantine records, and incident reports.
package model

import "time"

// ComplianceViolation captures a single security-baseline breach detected
// during a policy or role structure audit.
type ComplianceViolation struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	EntityARN   string `json:"entity_arn"`
	EntityType  string `json:"entity_type"`
	Description string `json:"description"`
	Statement   int    `json:"statement_index"`
}

// IRPhase represents the current stage of the incident response lifecycle.
type IRPhase string

const (
	PhaseDetect      IRPhase = "DETECT"
	PhaseAnalysis    IRPhase = "ANALYSIS"
	PhaseContainment IRPhase = "CONTAINMENT"
	PhaseEradication IRPhase = "ERADICATION"
	PhaseRecovery    IRPhase = "RECOVERY"
)

// IncidentRecord is the top-level record produced when a CloudTrail
// IAM mutation event triggers the incident response pipeline.
type IncidentRecord struct {
	IncidentID    string                `json:"incident_id"`
	EventName     string                `json:"event_name"`
	EventSource   string                `json:"event_source"`
	PrincipalARN  string                `json:"principal_arn"`
	SourceIP      string                `json:"source_ip"`
	RequestParams string                `json:"request_params"`
	Violations    []ComplianceViolation `json:"violations"`
	ThreatScore   float64               `json:"threat_score"`
	Quarantined   bool                  `json:"quarantined"`
	Quarantine    *QuarantineRecord     `json:"quarantine,omitempty"`
	DetectedAt    time.Time             `json:"detected_at"`
	ResolvedAt    *time.Time            `json:"resolved_at,omitempty"`

	// Maturity model fields (AWS Security Orchestration & Ticketing).
	Status         IRPhase           `json:"status"`
	PhaseTimestamps map[IRPhase]time.Time `json:"phase_timestamps"`
	Owner          string            `json:"owner,omitempty"`
	SLADeadline    *time.Time        `json:"sla_deadline,omitempty"`
	IOCs           []string          `json:"iocs,omitempty"`
	EnrichedData   map[string]string `json:"enriched_data,omitempty"`
	SecurityHubARN string            `json:"securityhub_arn,omitempty"`
}

// AdvancePhase transitions the incident to the next IR phase and records
// the timestamp. Returns true if this is the final phase (Recovery).
func (r *IncidentRecord) AdvancePhase(phase IRPhase) bool {
	r.Status = phase
	if r.PhaseTimestamps == nil {
		r.PhaseTimestamps = make(map[IRPhase]time.Time)
	}
	r.PhaseTimestamps[phase] = time.Now().UTC()
	return phase == PhaseRecovery
}

// PhaseDuration returns the elapsed time between two phases.
func (r *IncidentRecord) PhaseDuration(from, to IRPhase) time.Duration {
	if r.PhaseTimestamps == nil {
		return 0
	}
	start, ok := r.PhaseTimestamps[from]
	if !ok {
		return 0
	}
	end, ok := r.PhaseTimestamps[to]
	if !ok {
		return 0
	}
	return end.Sub(start)
}

// QuarantineRecord captures the execution result of a zero-privilege
// isolation loop applied to a compromised identity.
type QuarantineRecord struct {
	TargetARN       string   `json:"target_arn"`
	TargetType      string   `json:"target_type"`
	PolicyName      string   `json:"policy_name"`
	PolicyAttached  bool     `json:"policy_attached"`
	KeysDeactivated []string `json:"keys_deactivated"`
	SessionsRevoked bool     `json:"sessions_revoked"`
	ExecutedAt      time.Time `json:"executed_at"`
	ErrorMessage    string   `json:"error_message,omitempty"`
}

// QuarantinePolicyDocument is the JSON-serialisable inline policy that
// applies an explicit Deny on all actions and resources.
type QuarantinePolicyDocument struct {
	Version   string                     `json:"Version"`
	Statement []QuarantinePolicyStatement `json:"Statement"`
}

// QuarantinePolicyStatement is a single Deny statement.
type QuarantinePolicyStatement struct {
	Sid      string `json:"Sid"`
	Effect   string `json:"Effect"`
	Action   string `json:"Action"`
	Resource string `json:"Resource"`
}

// IncidentReport is the aggregated Markdown report produced after an
// incident is fully processed.
type IncidentReport struct {
	Incident   IncidentRecord `json:"incident"`
	Markdown   string         `json:"markdown"`
	WebhookURL string         `json:"-"`
}

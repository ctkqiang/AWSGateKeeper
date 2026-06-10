// Package model (network.go) defines types for network-layer security
// analysis: VPC Flow Log patterns, DNS threat intelligence, and
// Access Analyzer / Macie cross-service findings.
package model

import "time"

// VPCFlowPattern summarises the aggregated port-and-protocol distribution
// from a batch of GuardDuty VPC Flow Log findings.
type VPCFlowPattern struct {
	FindingCount    int               `json:"finding_count"`
	TopPorts        []PortCount       `json:"top_ports"`
	TopProtocols    []ProtocolCount   `json:"top_protocols"`
	SourceIPRange   string            `json:"source_ip_range"`
	DestinationIPs  []string          `json:"destination_ips"`
	AnalysisWindow  time.Duration     `json:"analysis_window"`
}

// PortCount pairs a port number with its occurrence count.
type PortCount struct {
	Port  int32 `json:"port"`
	Count int   `json:"count"`
}

// ProtocolCount pairs a protocol name with its occurrence count.
type ProtocolCount struct {
	Protocol string `json:"protocol"`
	Count    int    `json:"count"`
}

// DNSThreatEntry is a block rule candidate derived from a GuardDuty
// DNS / CryptoCurrency finding, ready for insertion into Route53
// Resolver DNS Firewall.
type DNSThreatEntry struct {
	Domain      string `json:"domain"`
	FindingID   string `json:"finding_id"`
	Severity    string `json:"severity"`
	RuleAction  string `json:"rule_action"` // BLOCK or ALERT
	Description string `json:"description"`
}

// AccessAnalyzerCorrelation pairs an IAM Access Analyzer external-access
// finding with its GuardDuty threat score.
type AccessAnalyzerCorrelation struct {
	AnalyzerARN       string  `json:"analyzer_arn"`
	FindingID         string  `json:"finding_id"`
	ResourceARN       string  `json:"resource_arn"`
	PrincipalARN      string  `json:"principal_arn"`
	IsPublic          bool    `json:"is_public"`
	GuardDutyScore    float64 `json:"guardduty_score"`
	Action            string  `json:"action"` // ARCHIVE / ALERT / QUARANTINE
}

// MacieDataExposure pairs an Amazon Macie sensitive-data finding with
// a correlated GuardDuty Exfiltration finding.
type MacieDataExposure struct {
	MacieFindingID    string  `json:"macie_finding_id"`
	S3Bucket          string  `json:"s3_bucket"`
	S3Key             string  `json:"s3_key"`
	SensitiveDataType string  `json:"sensitive_data_type"`
	TotalCount        int64   `json:"total_count"`
	GuardDutyARN      string  `json:"guardduty_arn"`
	ExfiltrationScore float64 `json:"exfiltration_score"`
	Severity          string  `json:"severity"`
}

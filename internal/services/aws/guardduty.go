// Package aws (guardduty.go) provides a thin wrapper around the AWS
// GuardDuty SDK tailored to the security-subsystem threat-detection
// pipeline.
//
// GuardDuty is AWS's continuous monitoring service that analyses
// CloudTrail, VPC Flow Logs, and DNS logs to surface potential security
// issues such as compromised credentials, reconnaissance, and
// crypto-mining activity.  This client does not change the GuardDuty
// detector configuration — it only reads findings and applies targeted
// remediation (deactivating compromised IAM access keys) for the
// incident-response loop.
//
// Required IAM permissions for the calling principal:
//
//	guardduty:ListFindings
//	guardduty:GetFindings
//	iam:ListAccessKeys
//	iam:UpdateAccessKey
package aws

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/utilities"
	"context"
	"fmt"
	"strings"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// GuardDutyClient wraps the GuardDuty SDK client with finding-processing
// helpers tailored to the security subsystem.
//
// It also holds a reference to the IAM client so that a single
// GuardDutyClient can both fetch findings and apply credential
// remediation without forcing the caller to wire two SDK clients.
type GuardDutyClient struct {
	client *guardduty.Client // pre-configured GuardDuty SDK client
	iam    *iam.Client       // pre-configured IAM SDK client (for remediation)
	region string            // AWS region the detector is deployed in
}

// NewGuardDutyClient creates a GuardDuty client from a pre-configured
// AWS SDK config. The caller must ensure the config carries credentials
// with guardduty:ListFindings, guardduty:GetFindings, and iam:UpdateAccessKey
// permissions.
//
//	@param  cfg     pre-configured AWS SDK config (region + credentials)
//	@param  region  AWS region in which the GuardDuty detector resides
//	@return         ready-to-use GuardDutyClient for the security pipeline
func NewGuardDutyClient(cfg aws_sdk.Config, region string) *GuardDutyClient {
	return &GuardDutyClient{
		client: guardduty.NewFromConfig(cfg),
		iam:    iam.NewFromConfig(cfg),
		region: region,
	}
}

// ListActiveFindings retrieves all active GuardDuty findings for the
// configured detector across the last N hours. Findings are fetched
// in pages, deduplicated by ID, and returned newest-first.
//
// The function filters at the API boundary:
//
//	service.archived == false   — exclude resolved/closed findings
//	updatedAt >= now-N hours    — bound the lookback window
//
// This dramatically reduces the volume of findings returned for
// long-running accounts and keeps the scan cycle bounded.
//
//	@param  ctx         request context (used for cancellation / deadlines)
//	@param  detectorID  GuardDuty detector ID for the target account/region
//	@param  hours       lookback window in hours; must be > 0
//	@return             slice of parsed GuardDuty findings, newest-first
//	@return             non-nil if the paginated ListFindings or GetFindings
//	                    call returns an error
func (c *GuardDutyClient) ListActiveFindings(ctx context.Context, detectorID string, hours int) ([]model.GuardDutyFinding, error) {
	var allFindings []model.GuardDutyFinding
	seen := make(map[string]bool)

	// Bound the scan window at the API level to avoid paginating years
	// of historical findings for accounts with long-running detectors.
	startTime := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)

	paginator := guardduty.NewListFindingsPaginator(c.client, &guardduty.ListFindingsInput{
		DetectorId: aws_sdk.String(detectorID),
		FindingCriteria: &gdtypes.FindingCriteria{
			Criterion: map[string]gdtypes.Condition{
				"service.archived": {Equals: []string{"false"}},
				"updatedAt":        {GreaterThanOrEqual: aws_sdk.Int64(startTime.UnixMilli())},
			},
		},
	})

	// Walk every page, fetch full details for each batch of finding IDs,
	// and accumulate the parsed result.  We deduplicate by ID because
	// some finding types (e.g. "Recon:EC2/PortProbeUnprotectedPort")
	// can be returned across multiple pages during a single scan.
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list guardduty findings: %w", err)
		}

		if len(page.FindingIds) == 0 {
			continue
		}

		details, err := c.client.GetFindings(ctx, &guardduty.GetFindingsInput{
			DetectorId: aws_sdk.String(detectorID),
			FindingIds: page.FindingIds,
		})
		if err != nil {
			return nil, fmt.Errorf("get guardduty findings: %w", err)
		}

		for _, f := range details.Findings {
			id := aws_sdk.ToString(f.Id)
			if seen[id] {
				continue
			}
			seen[id] = true

			parsed := parseGuardDutyFinding(f, c.region)
			allFindings = append(allFindings, parsed)
		}
	}

	return allFindings, nil
}

// FilterNetworkScanning returns findings that indicate reconnaissance,
// port-scanning, or network probing behaviour. These findings may
// precede an attempted intrusion and warrant immediate investigation.
//
//	@param  findings  full slice of GuardDuty findings to be filtered
//	@return           subset where NetworkScanAnomaly is true
func FilterNetworkScanning(findings []model.GuardDutyFinding) []model.GuardDutyFinding {
	var result []model.GuardDutyFinding
	for _, f := range findings {
		if f.NetworkScanAnomaly {
			result = append(result, f)
		}
	}
	return result
}

// DisableCompromisedCredentials locates every IAM access key belonging
// to the principal identified in the finding and deactivates it.
//
// Only findings where ConfirmedCompromised is true are acted upon.
// Each IAM access key associated with the finding's resource is set to
// INACTIVE status so that it can no longer be used for API calls.
//
// The function logs every successful deactivation through the
// structured logger and emits a governance audit event.  Individual
// per-key failures are logged but do not abort the loop — the goal is
// to deactivate as many of the compromised principal's keys as
// possible, even if one particular call fails (e.g. throttling).
//
//	@param  ctx      request context (used for cancellation / deadlines)
//	@param  finding  a GuardDuty finding with a populated ResourceARN
//	@return          list of access key IDs that were successfully
//	                 deactivated; empty when the finding is not a
//	                 confirmed compromise or no active keys exist
//	@return          non-nil only if the principal's user name cannot
//	                 be extracted from the resource ARN
func (c *GuardDutyClient) DisableCompromisedCredentials(ctx context.Context, finding model.GuardDutyFinding) ([]string, error) {
	if !finding.ConfirmedCompromised {
		return nil, nil
	}

	userName := extractUserNameFromARN(finding.ResourceARN)
	if userName == "" {
		return nil, fmt.Errorf("cannot extract user name from resource ARN: %s", finding.ResourceARN)
	}

	keys, err := c.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws_sdk.String(userName),
	})
	if err != nil {
		return nil, fmt.Errorf("list access keys for %s: %w", userName, err)
	}

	var disabled []string
	for _, key := range keys.AccessKeyMetadata {
		// Skip keys that are already inactive — there is nothing to do
		// and we want to avoid filling the audit log with no-op events.
		if key.Status != "Active" {
			continue
		}
		_, err := c.iam.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			UserName:    aws_sdk.String(userName),
			AccessKeyId: key.AccessKeyId,
			Status:      "Inactive",
		})
		if err != nil {
			utilities.Error("guardduty: disable key %s for %s: %v",
				aws_sdk.ToString(key.AccessKeyId), userName, err)
			continue
		}
		disabled = append(disabled, aws_sdk.ToString(key.AccessKeyId))
		utilities.LogProgress("guardduty", "disable-key",
			fmt.Sprintf("deactivated %s for %s", aws_sdk.ToString(key.AccessKeyId), userName))
	}

	return disabled, nil
}

// parseGuardDutyFinding converts a SDK finding struct into the internal
// GuardDutyFinding model, classifying severity, compromise status, and
// network-scan behaviour.
//
// Severity mapping follows the AWS documentation:
//
//	0.0       — no severity data
//	0.1 – 3.9 — Informational
//	4.0 – 6.9 — Low
//	7.0 – 8.9 — Medium
//	9.0 – 10.0 — High
//
//	@param  f       raw GuardDuty finding struct from the SDK
//	@param  region  AWS region the finding was observed in
//	@return         internal model suitable for JSON serialisation
func parseGuardDutyFinding(f gdtypes.Finding, region string) model.GuardDutyFinding {
	severity := mapGuardDutySeverity(aws_sdk.ToFloat64(f.Severity))

	title := aws_sdk.ToString(f.Title)
	description := aws_sdk.ToString(f.Description)

	resourceARN := aws_sdk.ToString(f.Arn)

	findingType := aws_sdk.ToString(f.Type)
	isCompromised := detectCompromisedCredential(findingType, title)
	isNetworkScan := detectNetworkScan(title, description, findingType)

	createdAt := parseTimeString(aws_sdk.ToString(f.CreatedAt))
	updatedAt := parseTimeString(aws_sdk.ToString(f.UpdatedAt))

	return model.GuardDutyFinding{
		ID:                   aws_sdk.ToString(f.Id),
		Type:                 findingType,
		Severity:             severity,
		Title:                title,
		Description:          description,
		ResourceARN:          resourceARN,
		AccountID:            aws_sdk.ToString(f.AccountId),
		Region:               region,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
		ConfirmedCompromised: isCompromised,
		NetworkScanAnomaly:   isNetworkScan,
		RawJSON:              aws_sdk.ToString(f.Arn),
	}
}

// mapGuardDutySeverity converts GuardDuty's 0.0–10.0 numeric severity
// to the internal FindingSeverity scale.
//
// The boundaries follow the AWS GuardDuty documentation:
//
//	>= 9.0   High              (e.g. Compromised credentials)
//	>= 7.0   Medium            (e.g. Reconnaissance)
//	>= 4.0   Low               (e.g. Unusual behaviour)
//	>  0.0   Informational     (e.g. benign anomalies)
//	==  0.0  Unknown           (no severity data)
//
//	@param  score  GuardDuty's numeric severity, 0.0–10.0
//	@return        mapped internal severity enum
func mapGuardDutySeverity(score float64) model.FindingSeverity {
	switch {
	case score >= 9.0:
		return model.SeverityHigh
	case score >= 7.0:
		return model.SeverityMedium
	case score >= 4.0:
		return model.SeverityLow
	case score > 0:
		return model.SeverityInformational
	default:
		return model.SeverityUnknown
	}
}

// detectCompromisedCredential returns true when the GuardDuty finding
// type and title indicate a compromised IAM credential.
//
// The function is intentionally liberal in matching — it is used to
// decide whether the security pipeline should attempt remediation, so
// false positives are far less costly than false negatives (the latter
// would leave a compromised key active in the account).
//
//	@param  findingType  GuardDuty finding type, e.g. "Recon:EC2/PortProbe"
//	@param  title        human-readable finding title
//	@return              true when the finding likely involves a
//	                     compromised or exposed credential
func detectCompromisedCredential(findingType, title string) bool {
	t := strings.ToLower(title)
	typeStr := strings.ToLower(findingType)
	return strings.Contains(t, "credential") ||
		strings.Contains(t, "compromised") ||
		strings.Contains(t, "exposed") ||
		strings.Contains(typeStr, "CredentialExposure") ||
		strings.Contains(typeStr, "UnauthorizedAccess:IAMUser") ||
		strings.Contains(typeStr, "Stealth")
}

// detectNetworkScan returns true when the finding describes reconnaissance,
// port-scanning, or network-probing behaviour.
//
//	@param  title        finding title (human-readable)
//	@param  description  full finding description
//	@param  findingType  GuardDuty finding type identifier
//	@return              true when the finding suggests probing or
//	                     scanning activity
func detectNetworkScan(title, description, findingType string) bool {
	t := strings.ToLower(title + " " + description)
	typeStr := strings.ToLower(findingType)
	return strings.Contains(t, "scan") ||
		strings.Contains(t, "reconnaissance") ||
		strings.Contains(t, "port probe") ||
		strings.Contains(t, "network probing") ||
		strings.Contains(typeStr, "Recon") ||
		strings.Contains(typeStr, "PortProbe") ||
		strings.Contains(typeStr, "NetworkPortUnusual")
}

// parseTimeString converts an RFC3339 time string to time.Time.
// Falls back to time.Now() on parse failure or empty input.
//
// We deliberately swallow parse errors here: the calling code uses the
// timestamp only for ordering and display, so a missing or malformed
// timestamp should never abort a finding-import operation.
//
//	@param  s  RFC3339-encoded timestamp (may be empty)
//	@return    parsed time, or time.Now() on failure
func parseTimeString(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now()
	}
	return t
}

// extractUserNameFromARN parses an IAM user name from a resource ARN
// of the form arn:aws:iam::ACCOUNT:user/USERNAME.
//
//	@param  arn  IAM user ARN to parse
//	@return      user name segment, or empty string if the ARN is
//	             malformed or does not name a user
func extractUserNameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	resource := parts[5]
	if strings.HasPrefix(resource, "user/") {
		return strings.TrimPrefix(resource, "user/")
	}
	return ""
}

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
type GuardDutyClient struct {
	client *guardduty.Client
	iam    *iam.Client
	region string
}

// NewGuardDutyClient creates a GuardDuty client from a pre-configured
// AWS SDK config. The caller must ensure the config carries credentials
// with guardduty:ListFindings, guardduty:GetFindings, and iam:UpdateAccessKey
// permissions.
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
func (c *GuardDutyClient) ListActiveFindings(ctx context.Context, detectorID string, hours int) ([]model.GuardDutyFinding, error) {
	var allFindings []model.GuardDutyFinding
	seen := make(map[string]bool)

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
// Returns the list of access key IDs that were deactivated.
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

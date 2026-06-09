package aws

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/utilities"
	"context"
	"encoding/json"
	"fmt"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// DetectiveClient uses CloudTrail historical event lookups to
// investigate the root cause of security findings. The name "Detective"
// reflects its investigative role — it does not call the AWS Detective
// API directly (Amazon Detective automates this pattern). This client
// performs the equivalent analysis by querying CloudTrail programmatically.
type DetectiveClient struct {
	client *cloudtrail.Client
}

// NewDetectiveClient creates a Detective client from a pre-configured
// AWS SDK config carrying cloudtrail:LookupEvents permission.
func NewDetectiveClient(cfg aws_sdk.Config) *DetectiveClient {
	return &DetectiveClient{
		client: cloudtrail.NewFromConfig(cfg),
	}
}

// InvestigateFinding traces CloudTrail events related to the given
// resource ARN over the specified lookback window and produces an
// InvestigationResult with a root-cause assessment, event timeline,
// and remediation recommendation.
//
// The investigation:
//   - Queries CloudTrail for events touching the resource ARN.
//   - Flattens them into InvestigationEvent entries.
//   - Identifies anomalous patterns (source IP hop, credential type).
//   - Builds a human-readable root cause summary.
func (c *DetectiveClient) InvestigateFinding(ctx context.Context, findingID, resourceARN string, lookbackHours int) (model.InvestigationResult, error) {
	start := time.Now().UTC()
	startTime := start.Add(-time.Duration(lookbackHours) * time.Hour)

	var timeline []model.InvestigationEvent

	paginator := cloudtrail.NewLookupEventsPaginator(c.client, &cloudtrail.LookupEventsInput{
		LookupAttributes: []cttypes.LookupAttribute{
			{
				AttributeKey:   cttypes.LookupAttributeKeyResourceName,
				AttributeValue: aws_sdk.String(resourceARN),
			},
		},
		StartTime: &startTime,
		EndTime:   &start,
	})

	seen := make(map[string]bool)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return model.InvestigationResult{}, fmt.Errorf("lookup cloudtrail for %s: %w", resourceARN, err)
		}

		for _, ev := range page.Events {
			eventID := aws_sdk.ToString(ev.EventId)
			if seen[eventID] {
				continue
			}
			seen[eventID] = true

			timeline = append(timeline, model.InvestigationEvent{
				EventTime:   aws_sdk.ToTime(ev.EventTime),
				EventName:   aws_sdk.ToString(ev.EventName),
				EventSource: aws_sdk.ToString(ev.EventSource),
				UserARN:     aws_sdk.ToString(ev.Username),
				SourceIP:    extractSourceIP(aws_sdk.ToString(ev.CloudTrailEvent)),
				Resources:   resourceARNs(ev.Resources),
				RawEvent:    aws_sdk.ToString(ev.CloudTrailEvent),
			})
		}
	}

	rootCause := buildRootCause(timeline, resourceARN)
	recommendation := buildRecommendation(timeline, resourceARN)
	affected := extractAffectedResources(timeline, resourceARN)

	utilities.LogProgress("detective", "investigate",
		fmt.Sprintf("finding=%s resource=%s events=%d cause=%s",
			findingID, resourceARN, len(timeline), rootCause))

	return model.InvestigationResult{
		FindingID:         findingID,
		StartedAt:         start,
		CompletedAt:       time.Now().UTC(),
		RootCause:         rootCause,
		Timeline:          timeline,
		AffectedResources: affected,
		Recommendation:    recommendation,
	}, nil
}

// buildRootCause analyses the CloudTrail event timeline and returns a
// single-sentence assessment of the most likely root cause. When the
// timeline is empty the cause is reported as inconclusive.
func buildRootCause(timeline []model.InvestigationEvent, resourceARN string) string {
	if len(timeline) == 0 {
		return fmt.Sprintf("inconclusive — no CloudTrail events found for %s in the lookback window", resourceARN)
	}

	sourceIPs := make(map[string]int)
	eventNames := make(map[string]int)
	for _, ev := range timeline {
		if ev.SourceIP != "" {
			sourceIPs[ev.SourceIP]++
		}
		eventNames[ev.EventName]++
	}

	// Detect IP hop: multiple distinct source IPs from different /16 blocks.
	var uniqueBlocks []string
	for ip := range sourceIPs {
		block := firstTwoOctets(ip)
		found := false
		for _, b := range uniqueBlocks {
			if b == block {
				found = true
				break
			}
		}
		if !found {
			uniqueBlocks = append(uniqueBlocks, block)
		}
	}

	if len(uniqueBlocks) > 1 {
		return fmt.Sprintf(
			"events from %d distinct source IP blocks indicate a potential credential compromise or multi-hop access chain for %s",
			len(uniqueBlocks), resourceARN)
	}

	// Detect unusual API calls.
	sensitiveOps := 0
	for name, count := range eventNames {
		if isSensitiveOperation(name) {
			sensitiveOps += count
		}
	}
	if sensitiveOps > 0 {
		return fmt.Sprintf(
			"%d sensitive API operations detected against %s (e.g. AssumeRole, CreateAccessKey)",
			sensitiveOps, resourceARN)
	}

	return fmt.Sprintf(
		"%d CloudTrail events found for %s — no obvious anomaly pattern detected; manual review recommended",
		len(timeline), resourceARN)
}

// buildRecommendation returns a remediation recommendation string
// based on the investigation timeline.
func buildRecommendation(timeline []model.InvestigationEvent, resourceARN string) string {
	if len(timeline) == 0 {
		return "no events to analyse; verify CloudTrail is enabled and the resource ARN is correct"
	}

	var hasAssumeRole, hasCreateKey bool
	for _, ev := range timeline {
		switch ev.EventName {
		case "AssumeRole":
			hasAssumeRole = true
		case "CreateAccessKey":
			hasCreateKey = true
		}
	}

	if hasCreateKey {
		return "deactivate all newly created access keys immediately; rotate credentials for all IAM users in the chain; enable MFA"
	}
	if hasAssumeRole {
		return "review the trust policy of the assumed role; enforce ExternalId condition for cross-account access; audit all role sessions"
	}
	return "review all listed events for unexpected API calls; consider tightening IAM permissions and enabling GuardDuty anomaly detection"
}

// isSensitiveOperation returns true for IAM API calls that typically
// indicate privilege escalation or persistence attempts.
func isSensitiveOperation(name string) bool {
	switch name {
	case "AssumeRole", "CreateAccessKey", "CreateUser",
		"CreateRole", "AttachRolePolicy", "PutRolePolicy",
		"UpdateAssumeRolePolicy", "CreateLoginProfile":
		return true
	default:
		return false
	}
}

// firstTwoOctets returns the first two octets of an IPv4 address.
func firstTwoOctets(ip string) string {
	parts := make([]byte, 0, 7)
	dots := 0
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' {
			dots++
			if dots == 2 {
				return string(parts) + "."
			}
		}
		if dots < 2 {
			parts = append(parts, ip[i])
		}
	}
	return ip
}

// extractAffectedResources collects unique resource ARNs from the
// investigation timeline.
func extractAffectedResources(timeline []model.InvestigationEvent, primaryARN string) []string {
	seen := map[string]bool{primaryARN: true}
	var result []string

	for _, ev := range timeline {
		for _, r := range ev.Resources {
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			result = append(result, r)
		}
		// Also include the raw CloudTrail event for deeper inspection.
		if ev.RawEvent != "" {
			var raw struct {
				Resources []struct {
					ARN string `json:"arn"`
				} `json:"resources"`
			}
			if json.Unmarshal([]byte(ev.RawEvent), &raw) == nil {
				for _, r := range raw.Resources {
					if r.ARN != "" && !seen[r.ARN] {
						seen[r.ARN] = true
						result = append(result, r.ARN)
					}
				}
			}
		}
	}

	return result
}

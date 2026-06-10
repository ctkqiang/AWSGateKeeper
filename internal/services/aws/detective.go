// Package aws (detective.go) provides a "Detective" client that
// performs root-cause analysis on GuardDuty findings by querying
// CloudTrail for related historical events.
//
// Despite the name, this client does NOT call the AWS Detective API
// directly.  Amazon Detective is a managed investigation service that
// automates exactly this kind of analysis.  This package implements
// the equivalent logic using CloudTrail LookupEvents — a primitive
// available in every account without any Detective subscription.
//
// The trade-off is operational:
//
//	Detective API    richer graph, automated entity resolution,
//	                  requires Detective to be enabled
//	CloudTrail here  self-contained, no extra cost, slightly less
//	                  correlation, works in any account
//
// Required IAM permissions for the calling principal:
//
//	cloudtrail:LookupEvents
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
	client *cloudtrail.Client // pre-configured CloudTrail SDK client
}

// NewDetectiveClient creates a Detective client from a pre-configured
// AWS SDK config carrying cloudtrail:LookupEvents permission.
//
//	@param  cfg  pre-configured AWS SDK config (region + credentials)
//	@return      ready-to-use DetectiveClient for the security pipeline
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
//
// The function is intentionally non-mutating: it never calls
// Update*, Put*, or Delete* — only LookupEvents.  Remediation is
// performed by the QuarantineEngine and GuardDutyClient elsewhere in
// the pipeline.
//
//	@param  ctx            request context (cancellation / deadlines)
//	@param  findingID      originating GuardDuty finding ID (recorded in result)
//	@param  resourceARN    ARN to look up in CloudTrail (must be a valid IAM ARN)
//	@param  lookbackHours  size of the time window to query, in hours
//	@return                populated InvestigationResult; never zero-valued
//	                       on success
//	@return                non-nil if the paginated LookupEvents call fails
func (c *DetectiveClient) InvestigateFinding(ctx context.Context, findingID, resourceARN string, lookbackHours int) (model.InvestigationResult, error) {
	// Pin the start and end of the window at function entry so that
	// every page of CloudTrail events covers the same interval —
	// otherwise a slow query could span the lookback boundary.
	start := time.Now().UTC()
	startTime := start.Add(-time.Duration(lookbackHours) * time.Hour)

	var timeline []model.InvestigationEvent

	// Filter by ResourceName (which accepts any ARN, IAM principal, or
	// object key) rather than EventName so we get every API call that
	// touched the principal in question.
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

	// CloudTrail's LookupEvents is eventually consistent and can
	// occasionally return the same event on consecutive pages, so we
	// deduplicate by EventId before building the timeline.
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
//
// The heuristic inspects two signals in order:
//
//  1. Source IP diversity — events from multiple distinct /16 blocks
//     suggest credential compromise or a multi-hop access chain.
//
//  2. Sensitive API presence — calls like AssumeRole, CreateAccessKey,
//     or AttachRolePolicy indicate privilege escalation attempts.
//
//     @param  timeline     chronological list of CloudTrail events
//     @param  resourceARN  ARN of the resource under investigation (for
//     error messages)
//     @return              human-readable root cause description
func buildRootCause(timeline []model.InvestigationEvent, resourceARN string) string {
	if len(timeline) == 0 {
		return fmt.Sprintf("inconclusive — no CloudTrail events found for %s in the lookback window", resourceARN)
	}

	// Aggregate per-IP and per-API counts so we can decide which
	// anomaly, if any, dominates the timeline.
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
//
// The recommendation ladder, in order of priority:
//
//  1. CreateAccessKey events were seen  →  deactivate new keys + rotate
//
//  2. AssumeRole events were seen        →  audit trust policies + ExternalId
//
//  3. Otherwise                          →  generic tighten-IAM guidance
//
//     @param  timeline     chronological list of CloudTrail events
//     @param  resourceARN  ARN of the resource under investigation (used
//     in the generic fallback message)
//     @return              human-readable remediation guidance
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
//
// This list is intentionally small and conservative: every operation
// here either creates new credentials, grants new permissions, or
// assumes a new identity.  Adding more operations to this list will
// increase the false-positive rate of the SensitiveOps branch in
// buildRootCause.
//
//	@param  name  AWS API operation name (e.g. "AssumeRole")
//	@return       true if the call is a known privilege-escalation
//	              primitive
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
//
// The function is intentionally permissive: any non-IPv4 input
// (including empty strings and IPv6 addresses) is returned unchanged,
// which is harmless because the caller only uses the result for
// de-duplication of source IPs — not for routing or policy decisions.
//
//	@param  ip  IPv4 address string, possibly malformed
//	@return     "<octet1>.<octet2>." for valid IPv4, or the original
//	             string for anything else
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
//
// Two sources are scanned for each event:
//
//  1. The flattened Resources slice returned by CloudTrail (cheap).
//
//  2. The raw CloudTrailEvent JSON, parsed for a "resources" array
//     with "arn" entries (deeper, catches ARNs the SDK omitted).
//
//     @param  timeline     chronological list of CloudTrail events
//     @param  primaryARN   the ARN under investigation; always included
//     implicitly via the dedup set
//     @return              deduplicated, ordered list of affected ARNs
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

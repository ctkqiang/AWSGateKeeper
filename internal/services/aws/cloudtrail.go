// Package aws (cloudtrail.go) provides a CloudTrail client for querying
// historical AWS API activity.  CloudTrail is the authoritative audit log
// for every API call made in the account — it captures Who, What, When,
// and Where without any application code.
//
// This client exposes lookup helpers tailored to the two audit rules
// defined in this project:
//
//	IAM_VENDOR_EXTERNALID_REQUIRED  — cross-account trust-policy checks
//	COGNITO_PRIVILEGED_EXTERNAL_USERS — privileged-group membership checks
//
// CloudTrail automatically records every IAM and Cognito API call, so the
// application never needs to manually log these actions.  The trail itself
// can be configured (via AWS Console / Terraform) to deliver logs to an S3
// bucket with a Lifecycle Rule transitioning to Glacier for long-term
// retention — no application code touches S3 or Glacier directly.
package aws

import (
	"context"
	"fmt"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// TrailClient wraps the CloudTrail SDK client and provides
// audit-rule-specific lookup methods.
//
//	@see rules/projcect.md for the two audit rules this client supports
type TrailClient struct {
	client *cloudtrail.Client
}

// NewTrailClient creates a TrailClient from an existing AWS SDK config.
//
//	@param  cfg  pre-configured AWS SDK config (region + credentials)
//	@return      ready-to-use CloudTrail query client
func NewTrailClient(cfg aws_sdk.Config) *TrailClient {
	return &TrailClient{
		client: cloudtrail.NewFromConfig(cfg),
	}
}

// EventSummary is a flattened representation of a CloudTrail event,
// containing only the fields relevant to audit-rule evaluation.
type EventSummary struct {
	EventID   string    // CloudTrail event ID
	EventName string    // API action, e.g. "CreateRole", "AssumeRole"
	EventTime time.Time // when the event occurred (UTC)
	UserARN   string    // the IAM entity that performed the action
	Resources []string  // ARNs of resources touched by the event
	RawEvent  string    // full CloudTrail event JSON for detailed inspection
}

// LookupIAMEvents retrieves IAM-related CloudTrail events from the
// last N hours.  This directly supports the IAM_VENDOR_EXTERNALID_REQUIRED
// audit rule by surfacing CreateRole, UpdateAssumeRolePolicy, and
// PutRolePolicy calls.
//
//	@param  ctx    cancellation context for the API call
//	@param  hours  lookback window in hours (max 90 days; CloudTrail
//	               retains lookup-able events for 90 days by default)
//	@return        deduplicated list of IAM events, newest first
//	@return        non-nil if the CloudTrail LookupEvents call fails
func (c *TrailClient) LookupIAMEvents(ctx context.Context, hours int) ([]EventSummary, error) {
	return c.lookup(ctx, "iam.amazonaws.com", time.Now().UTC().Add(-time.Duration(hours)*time.Hour))
}

// LookupCognitoEvents retrieves Cognito-related CloudTrail events from
// the last N hours.  This directly supports the
// COGNITO_PRIVILEGED_EXTERNAL_USERS audit rule by surfacing
// AdminAddUserToGroup, AdminRemoveUserFromGroup, and ListUsersInGroup
// calls.
//
//	@param  ctx    cancellation context
//	@param  hours  lookback window in hours
//	@return        deduplicated list of Cognito events, newest first
//	@return        non-nil if the CloudTrail LookupEvents call fails
func (c *TrailClient) LookupCognitoEvents(ctx context.Context, hours int) ([]EventSummary, error) {
	return c.lookup(ctx, "cognito-idp.amazonaws.com", time.Now().UTC().Add(-time.Duration(hours)*time.Hour))
}

// lookup performs a paginated CloudTrail LookupEvents call filtered by
// event source and time range.  Results are deduplicated by EventID.
//
//	@param  ctx        cancellation context
//	@param  src        event source prefix (e.g. "iam.amazonaws.com")
//	@param  startTime  earliest event time to include
//	@return            deduplicated, chronologically ordered event list
//	@return            non-nil if the CloudTrail API call fails
func (c *TrailClient) lookup(ctx context.Context, src string, startTime time.Time) ([]EventSummary, error) {
	var (
		events []EventSummary

		endTime = time.Now().UTC()
		seen    = make(map[string]bool)
	)

	paginator := cloudtrail.NewLookupEventsPaginator(c.client, &cloudtrail.LookupEventsInput{
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyEventSource,
				AttributeValue: aws_sdk.String(src),
			},
		},
		StartTime: &startTime,
		EndTime:   &endTime,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cloudtrail lookup (%s): %w", src, err)
		}

		for _, ev := range page.Events {
			if seen[aws_sdk.ToString(ev.EventId)] {
				continue
			}
			seen[aws_sdk.ToString(ev.EventId)] = true

			events = append(events, EventSummary{
				EventID:   aws_sdk.ToString(ev.EventId),
				EventName: aws_sdk.ToString(ev.EventName),
				EventTime: aws_sdk.ToTime(ev.EventTime),
				UserARN:   aws_sdk.ToString(ev.Username),
				Resources: resourceARNs(ev.Resources),
				RawEvent:  aws_sdk.ToString(ev.CloudTrailEvent),
			})
		}
	}

	return events, nil
}

// resourceARNs extracts ARN strings from a CloudTrail resource list.
func resourceARNs(resources []types.Resource) []string {
	arns := make([]string, 0, len(resources))

	for _, r := range resources {
		if arn := aws_sdk.ToString(r.ResourceName); arn != "" {
			arns = append(arns, arn)
		}
	}

	return arns
}

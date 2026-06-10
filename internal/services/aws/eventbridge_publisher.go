// Package aws (eventbridge_publisher.go) publishes structured security
// events to a custom EventBridge bus for downstream SIEM and automation.
package aws

import (
	"context"
	"encoding/json"
	"fmt"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

// EventPublisher sends structured security events to a custom
// EventBridge bus for downstream consumption (SIEM, audit, automation).
type EventPublisher struct {
	client  *eventbridge.Client
	busName string
	source  string
}

// NewEventPublisher creates an EventBridge publisher from the shared
// SDK config. busName may be empty to use the default bus.
func NewEventPublisher(cfg aws_sdk.Config, busName string) *EventPublisher {
	return &EventPublisher{
		client:  eventbridge.NewFromConfig(cfg),
		busName: busName,
		source:  "aws-gatekeeper",
	}
}

// PublishSecurityEvent sends a single security event to EventBridge.
func (p *EventPublisher) PublishSecurityEvent(ctx context.Context, detailType string, detail interface{}) error {
	body, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("marshal event detail: %w", err)
	}
	input := &eventbridge.PutEventsInput{
		Entries: []ebtypes.PutEventsRequestEntry{
			{
				Source:       aws_sdk.String(p.source),
				DetailType:   aws_sdk.String(detailType),
				Detail:       aws_sdk.String(string(body)),
				EventBusName: busNameOrNil(p.busName),
			},
		},
	}
	result, err := p.client.PutEvents(ctx, input)
	if err != nil {
		return fmt.Errorf("put events: %w", err)
	}
	if result.FailedEntryCount > 0 {
		return fmt.Errorf("%d event entries failed", result.FailedEntryCount)
	}
	return nil
}

// PublishQuarantineEvent emits a quarantine-specific event for
// downstream automation (SIEM alert, Slack notification, CMDB update).
func (p *EventPublisher) PublishQuarantineEvent(ctx context.Context, userARN, policyName string, keysDisabled int) error {
	return p.PublishSecurityEvent(ctx, "aws-gatekeeper.quarantine.executed", map[string]interface{}{
		"user_arn":        userARN,
		"policy_name":     policyName,
		"keys_disabled":   keysDisabled,
		"quarantine_type": "DenyAllInlinePolicy",
	})
}

// PublishScanCompletedEvent emits an event when a full scan cycle
// completes, carrying summary statistics for downstream dashboards.
func (p *EventPublisher) PublishScanCompletedEvent(ctx context.Context, reportID string, gdCount, inspCount, invCount, actionCount int) error {
	return p.PublishSecurityEvent(ctx, "aws-gatekeeper.scan.completed", map[string]interface{}{
		"report_id":          reportID,
		"guardduty_findings": gdCount,
		"inspector_findings": inspCount,
		"investigations":     invCount,
		"actions_taken":      actionCount,
	})
}

func busNameOrNil(name string) *string {
	if name == "" {
		return nil
	}
	return aws_sdk.String(name)
}

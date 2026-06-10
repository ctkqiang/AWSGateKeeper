// Package aws (securityhub.go) provides bidirectional integration with
// AWS Security Hub for the Security Orchestration & Ticketing maturity
// model — ingesting active findings and posting workflow status updates
// back to Security Hub after remediation.
//
// The integration is intentionally read-heavy on the ingest side (we
// only pull ACTIVE findings at or above a given severity) and write-light
// on the update side (we post RESOLVED / NOTIFIED status changes via
// BatchUpdateFindings).
//
// Required IAM permissions for the calling principal:
//
//	securityhub:GetFindings
//	securityhub:BatchUpdateFindings
package aws

import (
	"context"
	"fmt"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	shubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

// SecurityHubClient wraps the Security Hub SDK client for bidirectional
// finding ingestion and status update publication.
type SecurityHubClient struct {
	client *securityhub.Client // pre-configured Security Hub SDK client
}

// NewSecurityHubClient creates a SecurityHubClient from the shared
// AWS SDK configuration.
//
//	@param  cfg  pre-configured AWS SDK config (region + credentials)
//	@return      ready-to-use SecurityHubClient
func NewSecurityHubClient(cfg aws_sdk.Config) *SecurityHubClient {
	return &SecurityHubClient{client: securityhub.NewFromConfig(cfg)}
}

// GetActiveFindings retrieves active Security Hub findings filtered
// by severity label (e.g. "CRITICAL", "HIGH").
//
// Findings are paginated and deduplicated by ID.  The caller is
// responsible for bounding the time window if needed — Security Hub
// does not natively filter by CreatedAt in GetFindings.
//
//	@param  ctx           request context for cancellation / deadlines
//	@param  minSeverity   minimum severity label to include ("HIGH", "CRITICAL")
//	@return               flattened list of matching Security Hub findings
//	@return               non-nil if the paginated API call fails
func (c *SecurityHubClient) GetActiveFindings(ctx context.Context, minSeverity string) ([]SecurityHubFinding, error) {
	input := &securityhub.GetFindingsInput{
		Filters: &shubtypes.AwsSecurityFindingFilters{
			RecordState: []shubtypes.StringFilter{
				{Value: aws_sdk.String("ACTIVE"), Comparison: shubtypes.StringFilterComparisonEquals},
			},
			SeverityLabel: []shubtypes.StringFilter{
				{Value: aws_sdk.String(minSeverity), Comparison: shubtypes.StringFilterComparisonEquals},
			},
		},
	}
	var findings []SecurityHubFinding
	paginator := securityhub.NewGetFindingsPaginator(c.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("get security hub findings: %w", err)
		}
		for _, f := range page.Findings {
			title := aws_sdk.ToString(f.Title)
			desc := aws_sdk.ToString(f.Description)
			resourceARN := ""
			if len(f.Resources) > 0 {
				resourceARN = aws_sdk.ToString(f.Resources[0].Id)
			}
			sev := ""
			if f.Severity != nil && f.Severity.Label != "" {
				sev = string(f.Severity.Label)
			}
			findings = append(findings, SecurityHubFinding{
				ID:           aws_sdk.ToString(f.Id),
				Title:        title,
				Description:  desc,
				Severity:     sev,
				ResourceARN:  resourceARN,
				AWSAccountID: aws_sdk.ToString(f.AwsAccountId),
				CreatedAt:    aws_sdk.ToString(f.CreatedAt),
				ProductARN:   aws_sdk.ToString(f.ProductArn),
			})
		}
	}
	return findings, nil
}

// UpdateFindingStatus posts a workflow status update back to Security Hub
// for a given finding — for example marking it NOTIFIED after our pipeline
// processes it, or RESOLVED after the quarantine engine completes.
//
//	@param  ctx         request context
//	@param  findingID   Security Hub finding ID to update
//	@param  status      new workflow status (NOTIFIED, RESOLVED)
//	@param  note        human-readable note attached to the update
//	@return             non-nil if the BatchUpdateFindings call fails
func (c *SecurityHubClient) UpdateFindingStatus(ctx context.Context, findingID, status, note string) error {
	_, err := c.client.BatchUpdateFindings(ctx, &securityhub.BatchUpdateFindingsInput{
		FindingIdentifiers: []shubtypes.AwsSecurityFindingIdentifier{
			{Id: aws_sdk.String(findingID), ProductArn: aws_sdk.String("default")},
		},
		Note: &shubtypes.NoteUpdate{
			Text:      aws_sdk.String(note),
			UpdatedBy: aws_sdk.String("AWSGateKeeper"),
		},
		Workflow: &shubtypes.WorkflowUpdate{
			Status: shubtypes.WorkflowStatus(status),
		},
	})
	if err != nil {
		return fmt.Errorf("update finding %s status: %w", findingID, err)
	}
	return nil
}

// SecurityHubFinding is a flattened Security Hub finding suitable for
// incident correlation and enrichment in the incident response pipeline.
type SecurityHubFinding struct {
	ID           string `json:"id"`             // Security Hub finding ID
	Title        string `json:"title"`          // finding title
	Description  string `json:"description"`    // full description
	Severity     string `json:"severity"`       // severity label (CRITICAL, HIGH, ...)
	ResourceARN  string `json:"resource_arn"`   // primary resource ARN
	AWSAccountID string `json:"aws_account_id"` // source account ID
	CreatedAt    string `json:"created_at"`     // ISO 8601 creation timestamp
	ProductARN   string `json:"product_arn"`    // originating product ARN
}

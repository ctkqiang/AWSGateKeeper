// Package aws (securityhub.go) provides bidirectional integration with
// AWS Security Hub for the Security Orchestration & Ticketing maturity
// model — ingesting findings and posting status updates back.
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
	client *securityhub.Client
}

// NewSecurityHubClient creates a SecurityHubClient from the shared config.
func NewSecurityHubClient(cfg aws_sdk.Config) *SecurityHubClient {
	return &SecurityHubClient{client: securityhub.NewFromConfig(cfg)}
}

// GetActiveFindings retrieves active Security Hub findings filtered
// by severity label.
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

// UpdateFindingStatus posts a workflow status update back to
// Security Hub.
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

// SecurityHubFinding is a flattened Security Hub finding for incident
// correlation and enrichment.
type SecurityHubFinding struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Severity     string `json:"severity"`
	ResourceARN  string `json:"resource_arn"`
	AWSAccountID string `json:"aws_account_id"`
	CreatedAt    string `json:"created_at"`
	ProductARN   string `json:"product_arn"`
}

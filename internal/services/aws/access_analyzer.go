// Package aws (access_analyzer.go) integrates IAM Access Analyzer with
// the GuardDuty correlation pipeline.  Access Analyzer continuously scans
// resource policies for external access grants; this client surfaces those
// findings and cross-references them with GuardDuty threat scores to
// decide whether to archive, alert, or quarantine.
//
// Required IAM permissions for the calling principal:
//
//	access-analyzer:ListFindings
//	access-analyzer:UpdateFindings
package aws

import (
	"aws_gatekeeper/internal/model"
	"context"
	"fmt"
	"strings"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

// AccessAnalyzerClient wraps the IAM Access Analyzer SDK client for
// external-access finding enumeration and correlation.
type AccessAnalyzerClient struct {
	client *accessanalyzer.Client
}

// NewAccessAnalyzerClient creates an AccessAnalyzerClient from the
// shared AWS SDK configuration.
func NewAccessAnalyzerClient(cfg aws_sdk.Config) *AccessAnalyzerClient {
	return &AccessAnalyzerClient{client: accessanalyzer.NewFromConfig(cfg)}
}

// ListPublicAccessFindings retrieves active Access Analyzer findings
// that indicate external or public access to resources.
func (c *AccessAnalyzerClient) ListPublicAccessFindings(ctx context.Context, analyzerARN string) ([]model.AccessAnalyzerCorrelation, error) {
	input := &accessanalyzer.ListFindingsInput{
		AnalyzerArn: aws_sdk.String(analyzerARN),
		Filter:      map[string]aatypes.Criterion{"status": {Eq: []string{"ACTIVE"}}},
	}
	var correlations []model.AccessAnalyzerCorrelation
	paginator := accessanalyzer.NewListFindingsPaginator(c.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list access analyzer findings: %w", err)
		}
		for _, f := range page.Findings {
			principalARN, isPublic := "", false
			for k, v := range f.Principal {
				if k == "AWS" || k == "CanonicalUser" {
					principalARN, isPublic = v, v == "*"
				}
			}
			correlations = append(correlations, model.AccessAnalyzerCorrelation{
				AnalyzerARN:  analyzerARN,
				FindingID:    aws_sdk.ToString(f.Id),
				ResourceARN:  aws_sdk.ToString(f.Resource),
				PrincipalARN: principalARN,
				IsPublic:     isPublic,
				Action:       "ALERT",
			})
		}
	}
	return correlations, nil
}

// CorrelateAAWithGuardDuty enriches Access Analyzer findings with
// GuardDuty threat scores. Findings with score >= 7 are flagged QUARANTINE.
func CorrelateAAWithGuardDuty(correlations []model.AccessAnalyzerCorrelation, gdFindings []model.GuardDutyFinding) []model.AccessAnalyzerCorrelation {
	for i := range correlations {
		for _, gf := range gdFindings {
			if strings.Contains(correlations[i].PrincipalARN, gf.ResourceARN) ||
				strings.Contains(gf.ResourceARN, correlations[i].PrincipalARN) {
				correlations[i].GuardDutyScore += threatWeight(gf)
			}
		}
		switch {
		case correlations[i].GuardDutyScore >= 7.0:
			correlations[i].Action = "QUARANTINE"
		case correlations[i].GuardDutyScore >= 3.0:
			correlations[i].Action = "ALERT"
		default:
			correlations[i].Action = "ARCHIVE"
		}
	}
	return correlations
}

func threatWeight(f model.GuardDutyFinding) float64 {
	switch f.Severity {
	case model.SeverityHigh:
		if f.ConfirmedCompromised {
			return 5.0
		}
		return 3.0
	case model.SeverityMedium:
		return 2.0
	default:
		return 1.0
	}
}

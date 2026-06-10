// Package aws (macie.go) integrates Amazon Macie with the security
// scan pipeline.  Macie continuously discovers and classifies sensitive
// data in S3 buckets; this client surfaces data-exposure findings and
// cross-references them with GuardDuty Exfiltration anomalies to
// detect potential data breaches.
//
// Required IAM permissions for the calling principal:
//
//	macie2:ListFindings
//	macie2:GetFindings
package aws

import (
	"aws_gatekeeper/internal/model"
	"context"
	"fmt"
	"strings"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
)

// MacieClient wraps the Amazon Macie v2 SDK client for sensitive-data
// discovery and exfiltration correlation.
type MacieClient struct {
	client *macie2.Client
}

// NewMacieClient creates a MacieClient from the shared AWS SDK config.
func NewMacieClient(cfg aws_sdk.Config) *MacieClient {
	return &MacieClient{client: macie2.NewFromConfig(cfg)}
}

// ListSensitiveDataFindings retrieves active Macie findings for
// sensitive data types (PII, credentials, financial data) in S3.
func (c *MacieClient) ListSensitiveDataFindings(ctx context.Context) ([]model.MacieDataExposure, error) {
	input := &macie2.ListFindingsInput{
		FindingCriteria: &macietypes.FindingCriteria{
			Criterion: map[string]macietypes.CriterionAdditionalProperties{
				"classificationDetails.result.sensitiveData.detections.type": {
					Eq: []string{"PII", "CREDENTIALS", "FINANCIAL_INFORMATION"},
				},
			},
		},
	}
	var exposures []model.MacieDataExposure
	paginator := macie2.NewListFindingsPaginator(c.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list macie findings: %w", err)
		}
		if len(page.FindingIds) == 0 {
			continue
		}
		details, err := c.client.GetFindings(ctx, &macie2.GetFindingsInput{
			FindingIds: page.FindingIds,
		})
		if err != nil {
			return nil, fmt.Errorf("get macie finding details: %w", err)
		}
		for _, f := range details.Findings {
			exposures = append(exposures, flattenMacieFinding(f))
		}
	}
	return exposures, nil
}

// CorrelateMacieWithGuardDuty enriches Macie sensitive-data findings
// with GuardDuty exfiltration anomaly scores.
func CorrelateMacieWithGuardDuty(exposures []model.MacieDataExposure, gdFindings []model.GuardDutyFinding) []model.MacieDataExposure {
	for i := range exposures {
		for _, gf := range gdFindings {
			t := strings.ToLower(gf.Type + " " + gf.Title + " " + gf.Description)
			if strings.Contains(t, "exfiltration") {
				exposures[i].ExfiltrationScore += 3.0
				exposures[i].GuardDutyARN = gf.ID
			}
			if strings.Contains(gf.ResourceARN, exposures[i].S3Bucket) {
				exposures[i].ExfiltrationScore += 5.0
			}
		}
		switch {
		case exposures[i].ExfiltrationScore >= 5.0:
			exposures[i].Severity = "CRITICAL"
		case exposures[i].ExfiltrationScore >= 2.0:
			exposures[i].Severity = "HIGH"
		default:
			exposures[i].Severity = "MEDIUM"
		}
	}
	return exposures
}

func flattenMacieFinding(f macietypes.Finding) model.MacieDataExposure {
	e := model.MacieDataExposure{
		MacieFindingID: aws_sdk.ToString(f.Id),
		Severity:       "MEDIUM",
	}
	if f.ClassificationDetails != nil && f.ClassificationDetails.Result != nil {
		r := f.ClassificationDetails.Result
		if r.SensitiveData != nil && len(r.SensitiveData) > 0 {
			for _, d := range r.SensitiveData {
				if e.SensitiveDataType == "" {
					e.SensitiveDataType = string(d.Category)
				}
				for _, det := range d.Detections {
					e.TotalCount += aws_sdk.ToInt64(det.Count)
				}
			}
		}
	}
	return e
}

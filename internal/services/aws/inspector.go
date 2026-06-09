package aws

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/utilities"
	"context"
	"fmt"
	"strings"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// InspectorClient wraps the Inspector v2 SDK client with CVE-logging
// helpers for container workload and registry scanning.
type InspectorClient struct {
	client *inspector2.Client
}

// NewInspectorClient creates an Inspector client from a pre-configured
// AWS SDK config.
func NewInspectorClient(cfg aws_sdk.Config) *InspectorClient {
	return &InspectorClient{
		client: inspector2.NewFromConfig(cfg),
	}
}

// ListContainerFindings retrieves active Inspector findings for container
// images (ECR repositories and running container workloads) across the
// last N hours. Each finding represents a CVE or configuration issue.
func (c *InspectorClient) ListContainerFindings(ctx context.Context, hours int) ([]model.InspectorFinding, error) {
	var allFindings []model.InspectorFinding

	activeStatus := inspector2types.FindingStatusActive
	filter := &inspector2types.FilterCriteria{
		FindingStatus: []inspector2types.StringFilter{
			{Comparison: inspector2types.StringComparisonEquals, Value: aws_sdk.String(string(activeStatus))},
		},
	}

	input := &inspector2.ListFindingsInput{FilterCriteria: filter}
	paginator := inspector2.NewListFindingsPaginator(c.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list inspector findings: %w", err)
		}
		for _, f := range page.Findings {
			parsed := parseInspectorFinding(f)
			if occurredWithin(parsed.FirstObserved, hours) || occurredWithin(parsed.LastObserved, hours) {
				allFindings = append(allFindings, parsed)
			}
		}
	}

	return allFindings, nil
}

// LogCVEs writes every Inspector finding that carries a CVE identifier
// to the structured logger. Returns the total number of CVEs logged.
func LogCVEs(findings []model.InspectorFinding) int {
	var count int
	for _, f := range findings {
		if f.CVE == "" {
			continue
		}
		count++
		utilities.LogProgress("inspector", "cve",
			fmt.Sprintf(
				"CVE=%s CVSS=%.1f Severity=%d Package=%s %s→%s Image=%s",
				f.CVE, f.CVSSScore, f.Severity, f.PackageName,
				f.InstalledVersion, f.FixedVersion, f.VulnerableImage,
			),
		)
	}
	return count
}

// FilterCritical returns findings at SeverityCritical only.
func FilterCritical(findings []model.InspectorFinding) []model.InspectorFinding {
	var result []model.InspectorFinding
	for _, f := range findings {
		if f.Severity == model.SeverityCritical {
			result = append(result, f)
		}
	}
	return result
}

// parseInspectorFinding converts an SDK finding into the internal
// InspectorFinding model, extracting CVE metadata where available.
func parseInspectorFinding(f inspector2types.Finding) model.InspectorFinding {
	severity := mapInspectorSeverity(f.Severity)

	var cve string
	var cvssScore float64
	var pkgName, installedVer, fixedVer string
	if f.PackageVulnerabilityDetails != nil {
		cve = aws_sdk.ToString(f.PackageVulnerabilityDetails.VulnerabilityId)
		for _, score := range f.PackageVulnerabilityDetails.Cvss {
			if score.BaseScore != nil && *score.BaseScore > cvssScore {
				cvssScore = *score.BaseScore
			}
		}
		for _, vulnPkg := range f.PackageVulnerabilityDetails.VulnerablePackages {
			pkgName = aws_sdk.ToString(vulnPkg.Name)
			installedVer = aws_sdk.ToString(vulnPkg.Version)
			if vulnPkg.Remediation != nil {
				fixedVer = aws_sdk.ToString(vulnPkg.Remediation)
			}
		}
	}

	vulnerableImage := ""
	registry := ""
	repository := ""
	if len(f.Resources) > 0 {
		r := f.Resources[0]
		if r.Details != nil && r.Details.AwsEcrContainerImage != nil {
			registry = aws_sdk.ToString(r.Details.AwsEcrContainerImage.Registry)
			repository = aws_sdk.ToString(r.Details.AwsEcrContainerImage.RepositoryName)
			tags := strings.Join(r.Details.AwsEcrContainerImage.ImageTags, ",")
			vulnerableImage = fmt.Sprintf("%s/%s:%s", registry, repository, tags)
		}
	}

	firstObserved := time.Now()
	if f.FirstObservedAt != nil {
		firstObserved = *f.FirstObservedAt
	}
	lastObserved := time.Now()
	if f.LastObservedAt != nil {
		lastObserved = *f.LastObservedAt
	}

	return model.InspectorFinding{
		ARN:              aws_sdk.ToString(f.FindingArn),
		ID:               aws_sdk.ToString(f.FindingArn),
		Title:            aws_sdk.ToString(f.Title),
		Description:      aws_sdk.ToString(f.Description),
		Severity:         severity,
		CVE:              cve,
		CVSSScore:        cvssScore,
		VulnerableImage:  vulnerableImage,
		Registry:         registry,
		Repository:       repository,
		PackageName:      pkgName,
		InstalledVersion: installedVer,
		FixedVersion:     fixedVer,
		Remediation:      remediationText(f.Remediation),
		FirstObserved:    firstObserved,
		LastObserved:     lastObserved,
		RawJSON:          aws_sdk.ToString(f.FindingArn),
	}
}

// mapInspectorSeverity converts the Inspector v2 severity enum to the
// internal FindingSeverity scale.
func mapInspectorSeverity(s inspector2types.Severity) model.FindingSeverity {
	switch s {
	case inspector2types.SeverityCritical:
		return model.SeverityCritical
	case inspector2types.SeverityHigh:
		return model.SeverityHigh
	case inspector2types.SeverityMedium:
		return model.SeverityMedium
	case inspector2types.SeverityLow:
		return model.SeverityLow
	case inspector2types.SeverityInformational:
		return model.SeverityInformational
	default:
		return model.SeverityUnknown
	}
}

// remediationText extracts a human-readable remediation string from
// the Inspector Remediation struct.
func remediationText(r *inspector2types.Remediation) string {
	if r == nil || r.Recommendation == nil {
		return ""
	}
	return aws_sdk.ToString(r.Recommendation.Text)
}

// occurredWithin reports whether t falls within the last N hours.
func occurredWithin(t time.Time, hours int) bool {
	return time.Since(t) <= time.Duration(hours)*time.Hour
}

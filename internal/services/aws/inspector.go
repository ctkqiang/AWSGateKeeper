// Package aws (inspector.go) provides a thin wrapper around the AWS
// Inspector v2 SDK for surfacing container-image vulnerabilities
// (CVE / CVSS metadata) within the security-subsystem scan pipeline.
//
// Inspector v2 continuously scans:
//
//   - Amazon ECR container images
//   - Running Amazon ECS tasks
//   - Running Amazon EKS pods
//
// and produces a unified set of findings keyed by vulnerability.  This
// client does not change the Inspector configuration — it only reads
// active findings and surfaces the CVE/CVSS metadata to the
// orchestrator for inclusion in the security report.
//
// Required IAM permissions for the calling principal:
//
//	inspector2:ListFindings
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
//
// The client is intentionally minimal — it only exposes the read-only
// operations required by the security pipeline.  Mutating Inspector
// configuration (delegated admin, account enablement, etc.) is
// performed by the platform team via IaC and is out of scope here.
type InspectorClient struct {
	client *inspector2.Client // pre-configured Inspector v2 SDK client
}

// NewInspectorClient creates an Inspector client from a pre-configured
// AWS SDK config.
//
//	@param  cfg  pre-configured AWS SDK config (region + credentials)
//	@return      ready-to-use InspectorClient for the security pipeline
func NewInspectorClient(cfg aws_sdk.Config) *InspectorClient {
	return &InspectorClient{
		client: inspector2.NewFromConfig(cfg),
	}
}

// ListContainerFindings retrieves active Inspector findings for container
// images (ECR repositories and running container workloads) across the
// last N hours. Each finding represents a CVE or configuration issue.
//
// Only findings with FindingStatus == ACTIVE are considered.  The
// function performs a post-filter on FirstObservedAt and LastObservedAt
// to bound the result to the lookback window — Inspector's API
// natively supports time filters, but using them adds an additional
// filter rule and we already have the timestamp in the response.
//
//	@param  ctx    request context (cancellation / deadlines)
//	@param  hours  lookback window in hours; findings observed within
//	                this window are retained
//	@return        slice of parsed Inspector findings
//	@return        non-nil if the paginated ListFindings call fails
func (c *InspectorClient) ListContainerFindings(ctx context.Context, hours int) ([]model.InspectorFinding, error) {
	var allFindings []model.InspectorFinding

	activeStatus := inspector2types.FindingStatusActive
	// Inspector supports an extensible filter criteria object; we
	// start with FindingStatus=ACTIVE and let the post-filter
	// (occurredWithin) handle the time window.
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
			// Retain the finding if either FirstObserved or
			// LastObserved falls inside the lookback window — a
			// long-running finding may have its first observation
			// outside the window but still be relevant.
			if occurredWithin(parsed.FirstObserved, hours) || occurredWithin(parsed.LastObserved, hours) {
				allFindings = append(allFindings, parsed)
			}
		}
	}

	return allFindings, nil
}

// LogCVEs writes every Inspector finding that carries a CVE identifier
// to the structured logger. Returns the total number of CVEs logged.
//
// The function emits one log line per CVE with the structured fields
// required by the SIEM pipeline: CVE id, CVSS base score, severity
// rank, package name, installed version, fixed version, and the
// vulnerable image URI.
//
//	@param  findings  full slice of Inspector findings to be processed
//	@return           count of findings that carried a CVE identifier
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
//
//	@param  findings  full slice of Inspector findings
//	@return           subset where Severity == model.SeverityCritical
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
//
// The function defensively handles a nil PackageVulnerabilityDetails
// pointer (Inspector emits this nil for non-package findings such as
// "insecure container configuration") by leaving the CVE/CVSS fields
// at their zero values.
//
//	@param  f  raw Inspector v2 finding struct from the SDK
//	@return    internal model suitable for JSON serialisation
func parseInspectorFinding(f inspector2types.Finding) model.InspectorFinding {
	severity := mapInspectorSeverity(f.Severity)

	var cve string
	var cvssScore float64
	var pkgName, installedVer, fixedVer string
	if f.PackageVulnerabilityDetails != nil {
		cve = aws_sdk.ToString(f.PackageVulnerabilityDetails.VulnerabilityId)
		// CVSS is reported as a list (one entry per scoring vector);
		// we retain the highest base score for headline display.
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
//
// Inspector v2 severity values:
//
//	INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL, UNTRIAGED
//
// We map UNTRIAGED to SeverityUnknown so downstream consumers can
// treat un-triaged findings conservatively (e.g. include them in
// reports but flag them for human review).
//
//	@param  s  Inspector v2 severity enum
//	@return    mapped internal severity enum
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
//
//	@param  r  Inspector Remediation pointer (may be nil)
//	@return    remediation text, or empty string when no
//	           recommendation is available
func remediationText(r *inspector2types.Remediation) string {
	if r == nil || r.Recommendation == nil {
		return ""
	}
	return aws_sdk.ToString(r.Recommendation.Text)
}

// occurredWithin reports whether t falls within the last N hours.
//
// The check is performed against the current wall clock at call time,
// so callers that pin a window with start := time.Now() before a long
// loop may see drift at the tail of the loop.  This is acceptable for
// the security-pipeline use case where N is typically 24h.
//
//	@param  t      timestamp to test
//	@param  hours  lookback window in hours
//	@return        true if t is at most N hours old
func occurredWithin(t time.Time, hours int) bool {
	return time.Since(t) <= time.Duration(hours)*time.Hour
}

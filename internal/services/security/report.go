// Package security (report.go) implements the BuildReport function,
// which aggregates findings into a Markdown report and delivers it via
// S3, DynamoDB, and webhook POST.
package security

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/utilities"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

const messagingTimeout = 10 * time.Second

// BuildReport aggregates findings from GuardDuty, Inspector, and
// Detective into a SecurityReport with a generated Markdown summary.
// timestamps are set to the current UTC time.
func BuildReport(
	gd []model.GuardDutyFinding,
	insp []model.InspectorFinding,
	inv []model.InvestigationResult,
	actions []string,
) *model.SecurityReport {
	now := time.Now().UTC()
	report := &model.SecurityReport{
		GeneratedAt:       now,
		ReportID:          uuid.New().String(),
		GuardDutyFindings: gd,
		InspectorFindings: insp,
		Investigations:    inv,
		ActionsTaken:      actions,
		Summary:           buildSummary(gd, insp, inv, actions),
	}
	report.Markdown = renderMarkdown(report)
	return report
}

// renderMarkdown produces a GitHub-flavoured Markdown string from a
// SecurityReport. The output is designed for human consumption in
// messaging platforms, dashboards, and audit archives.
func renderMarkdown(r *model.SecurityReport) string {
	var b strings.Builder

	b.WriteString("# Security Scan Report\n\n")
	b.WriteString(fmt.Sprintf("**Report ID:** `%s`\n", r.ReportID))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", r.GeneratedAt.Format(time.RFC3339)))
	b.WriteString("---\n\n")

	// Summary.
	b.WriteString("## Summary\n\n")
	b.WriteString(r.Summary)
	b.WriteString("\n\n")

	// GuardDuty.
	b.WriteString("## GuardDuty Findings\n\n")
	if len(r.GuardDutyFindings) == 0 {
		b.WriteString("_No GuardDuty findings in the lookback window._\n\n")
	} else {
		b.WriteString("| Severity | Type | Title | Resource | Compromised |\n")
		b.WriteString("|----------|------|-------|----------|-------------|\n")
		for _, f := range r.GuardDutyFindings {
			comp := ""
			if f.ConfirmedCompromised {
				comp = "YES"
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | `%s` | %s |\n",
				severityLabel(f.Severity), truncate(f.Type, 30),
				truncate(f.Title, 50), truncate(f.ResourceARN, 40), comp))
		}
		b.WriteString("\n")
	}

	// Inspector CVEs.
	b.WriteString("## Inspector Findings (CVEs)\n\n")
	if len(r.InspectorFindings) == 0 {
		b.WriteString("_No Inspector findings in the lookback window._\n\n")
	} else {
		b.WriteString("| Severity | CVE | CVSS | Package | Image |\n")
		b.WriteString("|----------|-----|------|---------|-------|\n")
		for _, f := range r.InspectorFindings {
			b.WriteString(fmt.Sprintf("| %s | %s | %.1f | %s %s→%s | %s |\n",
				severityLabel(f.Severity), f.CVE, f.CVSSScore,
				f.PackageName, f.InstalledVersion, f.FixedVersion,
				truncate(f.VulnerableImage, 40)))
		}
		b.WriteString("\n")
	}

	// Investigations.
	b.WriteString("## Root-Cause Investigations\n\n")
	if len(r.Investigations) == 0 {
		b.WriteString("_No investigations triggered (no findings met the severity threshold)._")
	} else {
		for _, inv := range r.Investigations {
			b.WriteString(fmt.Sprintf("### Finding `%s`\n\n", inv.FindingID))
			b.WriteString(fmt.Sprintf("**Root Cause:** %s\n\n", inv.RootCause))
			b.WriteString(fmt.Sprintf("**Recommendation:** %s\n\n", inv.Recommendation))
			b.WriteString(fmt.Sprintf("**Events analysed:** %d\n\n", len(inv.Timeline)))
		}
	}

	// Actions taken.
	b.WriteString("## Automated Actions\n\n")
	if len(r.ActionsTaken) == 0 {
		b.WriteString("_No automated actions were triggered during this scan cycle._\n")
	} else {
		for _, a := range r.ActionsTaken {
			b.WriteString(fmt.Sprintf("- %s\n", a))
		}
	}

	return b.String()
}

// SendToMessagingEndpoint POSTs a MessagingPayload as JSON to the
// configured URL. This is a best-effort delivery — failures are logged
// but never returned to the caller.
func SendToMessagingEndpoint(url string, payload model.MessagingPayload) {
	body, err := json.Marshal(payload)
	if err != nil {
		utilities.Error("security: marshal messaging payload: %v", err)
		return
	}

	client := &http.Client{Timeout: messagingTimeout}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		utilities.Error("security: POST messaging endpoint %s: %v", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		utilities.Error("security: messaging endpoint returned %d", resp.StatusCode)
		return
	}

	utilities.LogProgress("security", "messaging",
		fmt.Sprintf("report %s sent to %s (%d)", payload.ReportID, url, resp.StatusCode))
}

// SaveReportToS3 uploads the Markdown report as an S3 object under the
// key security-reports/YYYY/MM/DD/{reportID}.md.
func SaveReportToS3(ctx context.Context, cfg aws_sdk.Config, bucket string, report *model.SecurityReport) {
	key := fmt.Sprintf("security-reports/%s/%s.md",
		report.GeneratedAt.Format("2006/01/02"), report.ReportID)

	client := s3.NewFromConfig(cfg)
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws_sdk.String(bucket),
		Key:         aws_sdk.String(key),
		Body:        bytes.NewReader([]byte(report.Markdown)),
		ContentType: aws_sdk.String("text/markdown"),
	})
	if err != nil {
		utilities.Error("security: save report to s3://%s/%s: %v", bucket, key, err)
		return
	}

	utilities.LogProgress("security", "s3-persist",
		fmt.Sprintf("report %s saved to s3://%s/%s", report.ReportID, bucket, key))
}

// SaveReportToDynamoDB writes the SecurityReport metadata to a DynamoDB
// table for structured querying. The full Markdown body is stored as an
// attribute; for large reports prefer S3 storage.
func SaveReportToDynamoDB(ctx context.Context, cfg aws_sdk.Config, table string, report *model.SecurityReport) {
	item := map[string]interface{}{
		"report_id":            report.ReportID,
		"generated_at":         report.GeneratedAt.Format(time.RFC3339),
		"guardduty_count":      len(report.GuardDutyFindings),
		"inspector_count":      len(report.InspectorFindings),
		"investigations_count": len(report.Investigations),
		"actions_taken":        report.ActionsTaken,
		"summary":              report.Summary,
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		utilities.Error("security: marshal dynamodb item: %v", err)
		return
	}

	client := dynamodb.NewFromConfig(cfg)
	_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws_sdk.String(table),
		Item:      av,
	})
	if err != nil {
		utilities.Error("security: put report %s to dynamodb %s: %v", report.ReportID, table, err)
		return
	}

	utilities.LogProgress("security", "ddb-persist",
		fmt.Sprintf("report %s saved to dynamodb/%s", report.ReportID, table))
}

func buildSummary(gd []model.GuardDutyFinding, insp []model.InspectorFinding, inv []model.InvestigationResult, actions []string) string {
	parts := []string{
		fmt.Sprintf("%d GuardDuty findings", len(gd)),
		fmt.Sprintf("%d Inspector findings", len(insp)),
		fmt.Sprintf("%d investigations completed", len(inv)),
		fmt.Sprintf("%d automated actions taken", len(actions)),
	}
	return strings.Join(parts, ", ") + "."
}

func severityLabel(s model.FindingSeverity) string {
	switch s {
	case model.SeverityCritical:
		return "CRITICAL"
	case model.SeverityHigh:
		return "HIGH"
	case model.SeverityMedium:
		return "MEDIUM"
	case model.SeverityLow:
		return "LOW"
	case model.SeverityInformational:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

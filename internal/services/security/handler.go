package security

import (
	"aws_gatekeeper/internal/model"
	aws_svc "aws_gatekeeper/internal/services/aws"
	"aws_gatekeeper/internal/utilities"
	"context"
	"fmt"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/sync/errgroup"
)

// ScanOrchestrator coordinates a full security scan cycle: GuardDuty
// threat detection, Inspector CVE scan, Detective root-cause analysis,
// and report generation + delivery.
type ScanOrchestrator struct {
	cfg             aws_sdk.Config
	region          string
	detectorID      string
	lookbackHours   int
	messagingURL    string
	guardDutyClient *aws_svc.GuardDutyClient
	inspectorClient *aws_svc.InspectorClient
	detectiveClient *aws_svc.DetectiveClient
}

// OrchestratorConfig holds the parameters required to construct a
// ScanOrchestrator. All fields are mandatory except MessagingURL
// (empty = skip sending).
type OrchestratorConfig struct {
	Config        aws_sdk.Config
	Region        string
	DetectorID    string
	LookbackHours int
	MessagingURL  string
}

// NewScanOrchestrator creates a ScanOrchestrator from the given config.
// It initialises the three security service clients (GuardDuty, Inspector,
// Detective) from the shared AWS SDK configuration.
func NewScanOrchestrator(cfg OrchestratorConfig) *ScanOrchestrator {
	return &ScanOrchestrator{
		cfg:             cfg.Config,
		region:          cfg.Region,
		detectorID:      cfg.DetectorID,
		lookbackHours:   cfg.LookbackHours,
		messagingURL:    cfg.MessagingURL,
		guardDutyClient: aws_svc.NewGuardDutyClient(cfg.Config, cfg.Region),
		inspectorClient: aws_svc.NewInspectorClient(cfg.Config),
		detectiveClient: aws_svc.NewDetectiveClient(cfg.Config),
	}
}

// RunFullScan executes all three security scans concurrently, aggregates
// the findings, runs root-cause investigations on high-severity items,
// generates a Markdown report, and persists + transmits it.
//
// Each scan runs in its own goroutine via errgroup. Individual scan
// failures do not abort the cycle — the error is logged and the
// corresponding finding slice remains empty.
func (o *ScanOrchestrator) RunFullScan(ctx context.Context) (*model.SecurityReport, error) {
	utilities.LogProgress("security", "scan", "starting full security scan cycle")

	var (
		gdFindings  []model.GuardDutyFinding
		inspFindings []model.InspectorFinding
		investigations []model.InvestigationResult
		actionsTaken   []string
	)

	g, gCtx := errgroup.WithContext(ctx)

	// GuardDuty scan.
	g.Go(func() error {
		f, err := o.guardDutyClient.ListActiveFindings(gCtx, o.detectorID, o.lookbackHours)
		if err != nil {
			utilities.Error("security: guardduty scan: %v", err)
			return nil // non-fatal
		}
		gdFindings = f

		networkScans := aws_svc.FilterNetworkScanning(f)
		utilities.LogProgress("security", "guardduty",
			fmt.Sprintf("total=%d network_scan=%d compromised=%d",
				len(f), len(networkScans), countCompromised(f)))

		for _, finding := range f {
			if finding.ConfirmedCompromised {
				disabled, err := o.guardDutyClient.DisableCompromisedCredentials(gCtx, finding)
				if err != nil {
					utilities.Error("security: disable credentials for %s: %v", finding.ID, err)
				} else {
					actionsTaken = append(actionsTaken,
						fmt.Sprintf("IAM: deactivated %d access keys for compromised finding %s", len(disabled), finding.ID))
				}
			}
		}
		return nil
	})

	// Inspector scan.
	g.Go(func() error {
		f, err := o.inspectorClient.ListContainerFindings(gCtx, o.lookbackHours)
		if err != nil {
			utilities.Error("security: inspector scan: %v", err)
			return nil
		}
		inspFindings = f

		cveCount := aws_svc.LogCVEs(f)
		criticalCount := len(aws_svc.FilterCritical(f))
		utilities.LogProgress("security", "inspector",
			fmt.Sprintf("total=%d cves=%d critical=%d", len(f), cveCount, criticalCount))
		return nil
	})

	// Wait for both scans before starting investigations.
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("security scan: %w", err)
	}

	// Detective investigations for high-severity GuardDuty findings.
	for _, finding := range gdFindings {
		if finding.Severity < model.SeverityHigh {
			continue
		}
		inv, err := o.detectiveClient.InvestigateFinding(ctx, finding.ID, finding.ResourceARN, o.lookbackHours)
		if err != nil {
			utilities.Error("security: investigate %s: %v", finding.ID, err)
			continue
		}
		investigations = append(investigations, inv)
	}

	report := BuildReport(gdFindings, inspFindings, investigations, actionsTaken)

	o.deliverReport(ctx, report)

	utilities.LogProgress("security", "scan", fmt.Sprintf(
		"cycle complete report=%s gd=%d insp=%d inv=%d actions=%d",
		report.ReportID, len(gdFindings), len(inspFindings), len(investigations), len(actionsTaken)))

	return report, nil
}

// deliverReport persists the report to an S3 audit bucket (if configured)
// and publishes it to the messaging endpoint (if configured).
func (o *ScanOrchestrator) deliverReport(ctx context.Context, report *model.SecurityReport) {
	if o.messagingURL != "" {
		payload := model.MessagingPayload{
			ReportID:    report.ReportID,
			Markdown:    report.Markdown,
			GeneratedAt: report.GeneratedAt.Format(time.RFC3339),
			Findings:    len(report.GuardDutyFindings) + len(report.InspectorFindings),
			Critical:    countCriticalFindings(report),
		}
		go SendToMessagingEndpoint(o.messagingURL, payload)
	}

	if auditBucket := getEnvOrDefault("SECURITY_AUDIT_BUCKET", ""); auditBucket != "" {
		go SaveReportToS3(ctx, o.cfg, auditBucket, report)
	}

	if dynamoTable := getEnvOrDefault("SECURITY_AUDIT_TABLE", ""); dynamoTable != "" {
		go SaveReportToDynamoDB(ctx, o.cfg, dynamoTable, report)
	}
}

func countCompromised(findings []model.GuardDutyFinding) int {
	var n int
	for _, f := range findings {
		if f.ConfirmedCompromised {
			n++
		}
	}
	return n
}

func countCriticalFindings(report *model.SecurityReport) int {
	var n int
	for _, f := range report.GuardDutyFindings {
		if f.Severity >= model.SeverityHigh {
			n++
		}
	}
	for _, f := range report.InspectorFindings {
		if f.Severity >= model.SeverityCritical {
			n++
		}
	}
	return n
}

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
//
// The orchestrator is the top-level entry point of the security
// subsystem's scheduled / on-demand scan path.  It is the only object
// the HTTP layer needs to interact with — all SDK plumbing is hidden
// behind RunFullScan.
type ScanOrchestrator struct {
	cfg             aws_sdk.Config           // shared AWS SDK config
	region          string                   // AWS region for SDK clients
	detectorID      string                   // GuardDuty detector ID
	lookbackHours   int                      // lookback window in hours for all scans
	messagingURL    string                   // optional destination URL for the report
	guardDutyClient *aws_svc.GuardDutyClient // GuardDuty finding fetcher
	inspectorClient *aws_svc.InspectorClient // Inspector CVE fetcher
	detectiveClient *aws_svc.DetectiveClient // Detective / CloudTrail investigator
}

// OrchestratorConfig holds the parameters required to construct a
// ScanOrchestrator. All fields are mandatory except MessagingURL
// (empty = skip sending).
type OrchestratorConfig struct {
	Config        aws_sdk.Config // shared AWS SDK config
	Region        string         // region used to construct SDK clients
	DetectorID    string         // GuardDuty detector for the target account
	LookbackHours int            // lookback window in hours; must be > 0
	MessagingURL  string         // empty = reports are still generated, just not transmitted
}

// NewScanOrchestrator creates a ScanOrchestrator from the given config.
// It initialises the three security service clients (GuardDuty, Inspector,
// Detective) from the shared AWS SDK configuration.
//
//	@param  cfg  orchestrator configuration
//	@return     ready-to-use orchestrator; safe for concurrent use
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
// corresponding finding slice remains empty so a partial degradation
// (e.g. Inspector unavailable) still produces a usable report.
//
//	@param  ctx   request context — cancellation propagates into all
//	              concurrent SDK calls
//	@return       populated SecurityReport on success
//	@return       non-nil only for an irrecoverable error (e.g. context
//	              cancellation while waiting for both scans)
func (o *ScanOrchestrator) RunFullScan(ctx context.Context) (*model.SecurityReport, error) {
	utilities.LogProgress("security", "scan", "starting full security scan cycle")

	var (
		gdFindings     []model.GuardDutyFinding
		inspFindings   []model.InspectorFinding
		investigations []model.InvestigationResult
		actionsTaken   []string
	)

	// errgroup: the first goroutine to return a non-nil error cancels
	// the shared context gCtx; the second scan call short-circuits and
	// we treat the error as non-fatal in the lambda itself.
	g, gCtx := errgroup.WithContext(ctx)

	// GuardDuty scan.
	g.Go(func() error {
		f, err := o.guardDutyClient.ListActiveFindings(gCtx, o.detectorID, o.lookbackHours)
		if err != nil {
			// Non-fatal: log and continue with an empty slice so
			// the rest of the pipeline still produces a report.
			utilities.Error("security: guardduty scan: %v", err)
			return nil
		}
		gdFindings = f

		// Diagnostic counters — useful when triaging a noisy
		// detector or unexplained spike.
		networkScans := aws_svc.FilterNetworkScanning(f)
		utilities.LogProgress("security", "guardduty",
			fmt.Sprintf("total=%d network_scan=%d compromised=%d",
				len(f), len(networkScans), countCompromised(f)))

		// For every ConfirmedCompromised finding, fire the
		// remediation path that deactivates the associated access
		// keys.  Each call is independent so a failure on one
		// finding does not stop the rest.
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
			// Non-fatal: same pattern as GuardDuty.
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
	// Run sequentially because the Detective client paginates
	// CloudTrail by ARN and the ordering keeps investigation
	// context stable for the report.
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

	// Build the report synchronously; delivery is best-effort in a
	// goroutine so the caller can return the report immediately.
	report := BuildReport(gdFindings, inspFindings, investigations, actionsTaken)

	o.deliverReport(ctx, report)

	utilities.LogProgress("security", "scan", fmt.Sprintf(
		"cycle complete report=%s gd=%d insp=%d inv=%d actions=%d",
		report.ReportID, len(gdFindings), len(inspFindings), len(investigations), len(actionsTaken)))

	return report, nil
}

// deliverReport persists the report to an S3 audit bucket (if configured)
// and publishes it to the messaging endpoint (if configured).
//
// All three delivery targets are dispatched in their own goroutine
// so a slow webhook or S3 PUT does not delay the scan cycle result.
//
//	@param  ctx     request context for the persist calls
//	@param  report  the freshly built security report
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

	// Audit bucket persistence is opt-in: when the env var is unset
	// we simply skip the call.  This keeps the same binary usable
	// in CI environments where no bucket exists.
	if auditBucket := getEnvOrDefault("SECURITY_AUDIT_BUCKET", ""); auditBucket != "" {
		go SaveReportToS3(ctx, o.cfg, auditBucket, report)
	}

	if dynamoTable := getEnvOrDefault("SECURITY_AUDIT_TABLE", ""); dynamoTable != "" {
		go SaveReportToDynamoDB(ctx, o.cfg, dynamoTable, report)
	}
}

// countCompromised returns the number of GuardDuty findings whose
// ConfirmedCompromised flag is set.
//
//	@param  findings  slice of GuardDuty findings
//	@return           count of entries marked as compromised
func countCompromised(findings []model.GuardDutyFinding) int {
	var n int
	for _, f := range findings {
		if f.ConfirmedCompromised {
			n++
		}
	}
	return n
}

// countCriticalFindings returns the number of CRITICAL+ findings
// across both GuardDuty and Inspector slices in the report.
//
//	@param  report  the security report
//	@return         total critical (and above) findings across both
//	               data sources
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

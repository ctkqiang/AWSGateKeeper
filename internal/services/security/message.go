// Package security (message.go) provides the MessagingConfig builder
// and the ExecuteScanAndDeliver entry point used by HTTP routes.
package security

import (
	"aws_gatekeeper/internal/model"
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
)

// MessagingConfig holds the parameters required to execute a security
// scan and deliver the resulting report. All fields are read from
// environment variables at construction time so the same binary can
// be deployed across multiple environments without rebuilds.
type MessagingConfig struct {
	Config       aws_sdk.Config // shared AWS SDK config
	Region       string         // region for SDK clients
	DetectorID   string         // GuardDuty detector ID
	LookbackHrs  int            // lookback window in hours
	MessagingURL string         // optional delivery URL
}

// NewMessagingConfig reads security-scan configuration from environment
// variables. Returns an error when GUARDDUTY_DETECTOR_ID is empty.
//
// Environment variables consumed:
//
//	GUARDDUTY_DETECTOR_ID  — required
//	SECURITY_LOOKBACK_HOURS — optional, default 24
//	AWS_REGION             — optional, default us-east-1
//	SECURITY_MESSAGING_URL — optional, empty = no transmission
//
//	@param  cfg  shared AWS SDK config
//	@return      populated MessagingConfig struct
//	@return      non-nil when the mandatory detector ID is unset
func NewMessagingConfig(cfg aws_sdk.Config) (MessagingConfig, error) {
	detectorID := os.Getenv("GUARDDUTY_DETECTOR_ID")
	if detectorID == "" {
		return MessagingConfig{}, fmt.Errorf("GUARDDUTY_DETECTOR_ID must be set")
	}

	lookback := 24
	// SECURITY_LOOKBACK_HOURS lets operators shrink the window during
	// incident response to scope investigations tighter.
	if s := os.Getenv("SECURITY_LOOKBACK_HOURS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			lookback = n
		}
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	return MessagingConfig{
		Config:       cfg,
		Region:       region,
		DetectorID:   detectorID,
		LookbackHrs:  lookback,
		MessagingURL: os.Getenv("SECURITY_MESSAGING_URL"),
	}, nil
}

// ExecuteScanAndDeliver runs a full security scan and delivers the
// report. This is the single entry point called by HTTP routes — it
// constructs the orchestrator, runs the scan, and returns the report.
//
// Returns the generated SecurityReport for the caller to serialise
// as an HTTP response.  Delivery to the messaging endpoint is a
// best-effort side effect of the orchestrator; the returned report
// is always the same regardless of whether delivery succeeded.
//
//	@param  ctx   request context for SDK calls
//	@param  mcfg  messaging config (see NewMessagingConfig)
//	@return       populated SecurityReport
//	@return       non-nil if the scan orchestration itself fails
func ExecuteScanAndDeliver(ctx context.Context, mcfg MessagingConfig) (*model.SecurityReport, error) {
	orch := NewScanOrchestrator(OrchestratorConfig{
		Config:        mcfg.Config,
		Region:        mcfg.Region,
		DetectorID:    mcfg.DetectorID,
		LookbackHours: mcfg.LookbackHrs,
		MessagingURL:  mcfg.MessagingURL,
	})

	report, err := orch.RunFullScan(ctx)
	if err != nil {
		return nil, fmt.Errorf("security scan: %w", err)
	}

	return report, nil
}

// BuildScanResponse converts a SecurityReport into an HTTP-friendly
// map suitable for JSON marshalling by route handlers.
//
// The shape is intentionally flat so dashboards can render
// counts without parsing the full Markdown body.
//
//	@param  report  the report to serialise
//	@return         map of public-facing fields
func BuildScanResponse(report *model.SecurityReport) map[string]interface{} {
	return map[string]interface{}{
		"report_id":          report.ReportID,
		"generated_at":       report.GeneratedAt.Format(time.RFC3339),
		"summary":            report.Summary,
		"guardduty_findings": len(report.GuardDutyFindings),
		"inspector_findings": len(report.InspectorFindings),
		"investigations":     len(report.Investigations),
		"actions_taken":      report.ActionsTaken,
		"markdown":           report.Markdown,
		"status":             "complete",
	}
}

// BuildErrorResponse returns a standardised error map for HTTP error
// responses from security endpoints.
//
//	@param  err  the underlying error
//	@return      map with status="error" and the message
func BuildErrorResponse(err error) map[string]interface{} {
	return map[string]interface{}{
		"status":  "error",
		"message": err.Error(),
	}
}

// BuildHealthResponse returns a simple health-check payload for the
// security subsystem, indicating whether GuardDuty and Inspector
// credentials are configured.
//
// The response is "healthy" only when no issues are present;
// otherwise it is "degraded" with an itemised list of issues so
// the operator can fix them without consulting logs.
//
//	@param  cfg  shared AWS SDK config (currently unused, reserved
//	            for future region-aware checks)
//	@return      map of health-check fields
func BuildHealthResponse(cfg aws_sdk.Config) map[string]interface{} {
	detectorID := os.Getenv("GUARDDUTY_DETECTOR_ID")
	messagingURL := os.Getenv("SECURITY_MESSAGING_URL")

	status := "degraded"
	issues := []string{}

	if detectorID == "" {
		issues = append(issues, "GUARDDUTY_DETECTOR_ID not set")
	}
	if messagingURL == "" {
		// Not strictly a failure (reports are still generated)
		// but a degraded experience — surface it for visibility.
		issues = append(issues, "SECURITY_MESSAGING_URL not set — reports are generated but not transmitted")
	}

	if len(issues) == 0 {
		status = "healthy"
	}

	return map[string]interface{}{
		"status":         status,
		"guardduty":      detectorID != "",
		"messaging_url":  messagingURL != "",
		"issues":         issues,
		"lookback_hours": getLookbackHours(),
	}
}

// getLookbackHours reads SECURITY_LOOKBACK_HOURS from env, defaulting to 24.
//
// Falls back to 24 when the variable is unset or unparseable, which
// matches the dashboard default.
//
//	@return  lookback window in hours (always > 0)
func getLookbackHours() int {
	if s := os.Getenv("SECURITY_LOOKBACK_HOURS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 24
}

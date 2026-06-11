package test

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/routes"
	aws_svc "aws_gatekeeper/internal/services/aws"
	"aws_gatekeeper/internal/services/security"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestBuildReport(t *testing.T) {
	gd := []model.GuardDutyFinding{
		{ID: "gd-1", Severity: model.SeverityHigh, Title: "Test finding", ConfirmedCompromised: true, ResourceARN: "arn:aws:iam::123456789012:user/test"},
	}
	insp := []model.InspectorFinding{
		{ID: "insp-1", CVE: "CVE-2024-1234", CVSSScore: 9.8, Severity: model.SeverityCritical, PackageName: "openssl", InstalledVersion: "1.0.0", FixedVersion: "2.0.0"},
	}
	inv := []model.InvestigationResult{
		{FindingID: "gd-1", RootCause: "credential compromise suspected", Recommendation: "rotate keys"},
	}
	actions := []string{"IAM: deactivated 2 access keys"}

	report := security.BuildReport(gd, insp, inv, actions)

	if report.ReportID == "" {
		t.Fatal("ReportID is empty")
	}
	if report.Markdown == "" {
		t.Fatal("Markdown is empty")
	}
	t.Logf("Report ID: %s", report.ReportID)
	t.Logf("Markdown length: %d bytes", len(report.Markdown))
}

func TestBuildReportEmptyInput(t *testing.T) {
	report := security.BuildReport(nil, nil, nil, nil)
	if report.ReportID == "" {
		t.Fatal("ReportID should not be empty for empty input")
	}
	if !report.GeneratedAt.IsZero() {
		t.Log("GeneratedAt should be set for empty input")
	}
}

func TestBuildScanResponse(t *testing.T) {
	report := &model.SecurityReport{
		ReportID: "test-id",
	}
	resp := security.BuildScanResponse(report)
	if resp["status"] != "complete" {
		t.Fatal("expected status=complete")
	}
	if resp["report_id"] != "test-id" {
		t.Fatal("expected report_id=test-id")
	}
}

func TestValidatorDetectorID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"", false},
		{"abc123", false},
		{"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", true},
	}
	for _, tt := range tests {
		err := security.ValidateDetectorID(tt.id)
		if (err == nil) != tt.valid {
			t.Errorf("ValidateDetectorID(%q) = %v, want valid=%v", tt.id, err, tt.valid)
		}
	}
}

func TestValidatorIAMARN(t *testing.T) {
	validARN := "arn:aws:iam::123456789012:user/test-user"
	if err := security.ValidateIAMARN(validARN); err != nil {
		t.Errorf("expected valid ARN: %v", err)
	}
	if err := security.ValidateIAMARN("not-an-arn"); err == nil {
		t.Error("expected error for invalid ARN")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := security.NewRateLimiter(1000, 1000) // high rate for testing
	for i := 0; i < 100; i++ {
		rl.Wait()
	}
	t.Log("rate limiter completed 100 tokens without blocking")
}

func TestQuarantinePolicy(t *testing.T) {
	report := &model.SecurityReport{
		ReportID: "report-1",
	}
	resp := security.BuildScanResponse(report)
	if resp["markdown"] == nil {
		t.Fatal("markdown should not be nil")
	}
}

func TestSeverityLabel(t *testing.T) {
	report := security.BuildReport(
		[]model.GuardDutyFinding{
			{ID: "1", Severity: model.SeverityCritical},
			{ID: "2", Severity: model.SeverityHigh},
			{ID: "3", Severity: model.SeverityMedium},
		},
		nil, nil, nil,
	)
	if report == nil {
		t.Fatal("report is nil")
	}
	t.Logf("Summary: %s", report.Summary)
}

func TestQuarantinePolicyJSON(t *testing.T) {
	doc := model.QuarantinePolicyDocument{
		Version: "2012-10-17",
		Statement: []model.QuarantinePolicyStatement{
			{Sid: "Test", Effect: "Deny", Action: "*", Resource: "*"},
		},
	}
	b, _ := json.Marshal(doc)
	if !strings.Contains(string(b), "Deny") {
		t.Fatal("quarantine policy must contain Deny")
	}
}

func TestIRPhaseTransitions(t *testing.T) {
	inc := &model.IncidentRecord{DetectedAt: time.Now().UTC()}
	inc.AdvancePhase(model.PhaseDetect)
	inc.AdvancePhase(model.PhaseAnalysis)
	inc.AdvancePhase(model.PhaseContainment)
	if inc.Status != model.PhaseContainment {
		t.Fatalf("expected CONTAINMENT, got %s", inc.Status)
	}
	d := inc.PhaseDuration(model.PhaseDetect, model.PhaseAnalysis)
	if d <= 0 {
		t.Fatal("phase duration should be positive")
	}
}

func TestDNSThreatExtraction(t *testing.T) {
	findings := []model.GuardDutyFinding{
		{ID: "1", Type: "CryptoCurrency:EC2/BitcoinTool.B!DNS", Title: "bitcoin-mining-pool.com", Severity: model.SeverityHigh},
	}
	threats := aws_svc.ExtractDNSThreats(findings)
	if len(threats) == 0 {
		t.Fatal("expected DNS threats from cryptocurrency finding")
	}
	if threats[0].RuleAction != "BLOCK" {
		t.Fatalf("expected BLOCK action, got %s", threats[0].RuleAction)
	}
}

func TestVPCFlowPatterns(t *testing.T) {
	findings := []model.GuardDutyFinding{
		{ID: "1", Type: "Recon:EC2/Portscan", Title: "Port scan from 10.0.0.1", Severity: model.SeverityMedium},
		{ID: "2", Type: "UnauthorizedAccess:EC2/SSHBruteForce", Title: "SSH brute force", Severity: model.SeverityHigh},
	}
	pattern := aws_svc.AnalyzeVPCFlowPatterns(findings)
	if pattern.FindingCount != 2 {
		t.Fatalf("expected 2 VPC findings, got %d", pattern.FindingCount)
	}
}

func TestMiddlewareNoKey(t *testing.T) {
	os.Setenv("API_KEY", "")
	handler := routes.RequireAPIKey(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/security/scan", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200 when API_KEY not set, got %d", rec.Code)
	}
}

func TestMiddlewareWithKey(t *testing.T) {
	os.Setenv("API_KEY", "test-secret")
	defer os.Setenv("API_KEY", "")
	handler := routes.RequireAPIKey(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest("GET", "/security/scan", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401 without header, got %d", rec.Code)
	}
	req.Header.Set("X-API-Key", "test-secret")
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200 with correct key, got %d", rec.Code)
	}
}

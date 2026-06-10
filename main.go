package main

import (
	"context"
	"fmt"
	"os"

	aws_gatekeeper_glob "aws_gatekeeper/internal/services/aws"
	"aws_gatekeeper/internal/routes"
	"aws_gatekeeper/internal/services/security"
)

// gdAdapter wraps the concrete GuardDutyClient to satisfy the
// routes.GuardDutyClient interface, avoiding an import cycle.
type gdAdapter struct {
	client *aws_gatekeeper_glob.GuardDutyClient
}

func (a *gdAdapter) GetFindingsStatistics(ctx context.Context, detectorID string) (interface{}, error) {
	return a.client.GetFindingsStatistics(ctx, detectorID)
}
func (a *gdAdapter) ArchiveFinding(ctx context.Context, detectorID, findingID string) error {
	return a.client.ArchiveFinding(ctx, detectorID, findingID)
}
func (a *gdAdapter) UnarchiveFinding(ctx context.Context, detectorID, findingID string) error {
	return a.client.UnarchiveFinding(ctx, detectorID, findingID)
}
func (a *gdAdapter) ListThreatIntelSets(ctx context.Context, detectorID string) (interface{}, error) {
	return a.client.ListThreatIntelSets(ctx, detectorID)
}
func (a *gdAdapter) ListPublishingDestinations(ctx context.Context, detectorID string) (interface{}, error) {
	return a.client.ListPublishingDestinations(ctx, detectorID)
}
func (a *gdAdapter) GetCoverageStatistics(ctx context.Context, detectorID string) (interface{}, error) {
	return a.client.GetCoverageStatistics(ctx, detectorID)
}
func (a *gdAdapter) ListMembers(ctx context.Context, detectorID string) (interface{}, error) {
	return a.client.ListMembers(ctx, detectorID)
}
func (a *gdAdapter) GetOrganizationStatistics(ctx context.Context) (interface{}, error) {
	return a.client.GetOrganizationStatistics(ctx)
}
func (a *gdAdapter) CreateSampleFindings(ctx context.Context, detectorID string, findingTypes []string) error {
	return a.client.CreateSampleFindings(ctx, detectorID, findingTypes)
}

func main() {
	ctx := context.Background()
	if err := aws_gatekeeper_glob.Initialize(ctx); err != nil {
		panic(err)
	}

	cfg := aws_gatekeeper_glob.GetAccount().Config()
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	scanFunc := func(ctx context.Context) (interface{}, error) {
		mcfg, err := security.NewMessagingConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("security config: %w", err)
		}
		return security.ExecuteScanAndDeliver(ctx, mcfg)
	}

	healthFunc := func() map[string]interface{} {
		return security.BuildHealthResponse(cfg)
	}

	gdFactory := func(detectorID string) routes.GuardDutyClient {
		return &gdAdapter{client: aws_gatekeeper_glob.NewGuardDutyClient(cfg, region)}
	}

	if err := aws_gatekeeper_glob.ServeLambdaEndpoint(scanFunc, healthFunc, gdFactory); err != nil {
		panic(err)
	}
}

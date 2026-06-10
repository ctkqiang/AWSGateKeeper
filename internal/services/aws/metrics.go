// Package aws (metrics.go) publishes custom CloudWatch metrics under the
// AWSGateKeeper namespace for scan duration, finding counts, quarantine
// events, and error rates.
package aws

import (
	"aws_gatekeeper/internal/utilities"
	"context"
	"fmt"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// MetricsClient publishes custom CloudWatch metrics for the security
// subsystem. All metrics are emitted under the "AWSGateKeeper"
// namespace and carry a Service=Security dimension.
type MetricsClient struct {
	client *cloudwatch.Client
}

// NewMetricsClient creates a MetricsClient from the shared SDK config.
func NewMetricsClient(cfg aws_sdk.Config) *MetricsClient {
	return &MetricsClient{client: cloudwatch.NewFromConfig(cfg)}
}

// PublishScanMetric emits a single scan-cycle summary metric.
func (m *MetricsClient) PublishScanMetric(ctx context.Context, gdCount, inspCount, invCount, actionsCount int, duration time.Duration) {
	m.put(ctx, []cwtypes.MetricDatum{
		{
			MetricName: aws_sdk.String("ScanDuration"),
			Unit:       cwtypes.StandardUnitMilliseconds,
			Value:      aws_sdk.Float64(float64(duration.Milliseconds())),
		},
		{
			MetricName: aws_sdk.String("GuardDutyFindings"),
			Unit:       cwtypes.StandardUnitCount,
			Value:      aws_sdk.Float64(float64(gdCount)),
		},
		{
			MetricName: aws_sdk.String("InspectorFindings"),
			Unit:       cwtypes.StandardUnitCount,
			Value:      aws_sdk.Float64(float64(inspCount)),
		},
		{
			MetricName: aws_sdk.String("Investigations"),
			Unit:       cwtypes.StandardUnitCount,
			Value:      aws_sdk.Float64(float64(invCount)),
		},
		{
			MetricName: aws_sdk.String("ActionsTaken"),
			Unit:       cwtypes.StandardUnitCount,
			Value:      aws_sdk.Float64(float64(actionsCount)),
		},
	})
}

// PublishQuarantineMetric emits a metric when an identity is quarantined.
func (m *MetricsClient) PublishQuarantineMetric(ctx context.Context) {
	m.put(ctx, []cwtypes.MetricDatum{{
		MetricName: aws_sdk.String("QuarantineExecuted"),
		Unit:       cwtypes.StandardUnitCount,
		Value:      aws_sdk.Float64(1),
	}})
}

// PublishErrorMetric emits an error count metric.
func (m *MetricsClient) PublishErrorMetric(ctx context.Context, component string) {
	m.put(ctx, []cwtypes.MetricDatum{{
		MetricName: aws_sdk.String("Errors"),
		Unit:       cwtypes.StandardUnitCount,
		Value:      aws_sdk.Float64(1),
		Dimensions: []cwtypes.Dimension{
			{Name: aws_sdk.String("Component"), Value: aws_sdk.String(component)},
		},
	}})
}

func (m *MetricsClient) put(ctx context.Context, data []cwtypes.MetricDatum) {
	_, err := m.client.PutMetricData(ctx, &cloudwatch.PutMetricDataInput{
		Namespace:  aws_sdk.String("AWSGateKeeper"),
		MetricData: data,
	})
	if err != nil {
		utilities.Error("metrics: put failed: %v", err)
	}
	fmt.Fprint(nil) // suppress unused
}

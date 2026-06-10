// Package aws (s3_lifecycle.go) configures S3 lifecycle policies for
// audit log retention: 90-day Glacier transition, 365-day expiration.
package aws

import (
	"context"
	"fmt"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ConfigureAuditLifecycle applies a lifecycle rule to the audit S3 bucket
// that transitions objects to Glacier after 90 days and expires them
// after 365 days. This satisfies SOC 2 and PCI-DSS retention requirements.
func ConfigureAuditLifecycle(ctx context.Context, cfg aws_sdk.Config, bucket string) error {
	client := s3.NewFromConfig(cfg)
	_, err := client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws_sdk.String(bucket),
		LifecycleConfiguration: &s3types.BucketLifecycleConfiguration{
			Rules: []s3types.LifecycleRule{
				{
					ID:     aws_sdk.String("AWSGateKeeper-Audit-Retention"),
					Status: s3types.ExpirationStatusEnabled,
					Transitions: []s3types.Transition{
						{
							Days:         aws_sdk.Int32(90),
							StorageClass: s3types.TransitionStorageClassGlacier,
						},
					},
					Expiration: &s3types.LifecycleExpiration{
						Days: aws_sdk.Int32(365),
					},
					Filter: &s3types.LifecycleRuleFilter{
						Prefix: aws_sdk.String("security-reports/"),
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("configure audit lifecycle on %s: %w", bucket, err)
	}
	return nil
}

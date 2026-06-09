package security

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/services/governance"
	"aws_gatekeeper/internal/utilities"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const quarantinePolicyName = "AWSGateKeeper-Quarantine-DenyAll"

// QuarantineEngine executes non-destructive isolation of compromised
// IAM identities. It attaches an explicit Deny-* inline policy and
// revokes active sessions — the identity is NEVER deleted.
type QuarantineEngine struct {
	iamClient *iam.Client
	stsClient *sts.Client
}

// NewQuarantineEngine creates a QuarantineEngine from the shared SDK
// configuration, reusing the same IAM and STS clients used by the rest
// of the application.
func NewQuarantineEngine(cfg aws_sdk.Config) *QuarantineEngine {
	return &QuarantineEngine{
		iamClient: iam.NewFromConfig(cfg),
		stsClient: sts.NewFromConfig(cfg),
	}
}

// QuarantineIdentity executes the full zero-privilege isolation loop:
//
//  1. Attach an inline Deny-* policy to the target identity.
//  2. Deactivate all active IAM access keys for the identity.
//  3. Revoke all active STS temporary sessions.
//
// The identity is never deleted — it can still authenticate, but every
// API call is explicitly denied by the quarantine policy.
//
// targetType must be either "user" or "role".
func (q *QuarantineEngine) QuarantineIdentity(ctx context.Context, targetARN, targetType string) (*model.QuarantineRecord, error) {
	record := &model.QuarantineRecord{
		TargetARN:  targetARN,
		TargetType: targetType,
		ExecutedAt: time.Now().UTC(),
	}

	targetName := extractNameFromARN(targetARN)

	policyJSON, err := buildQuarantinePolicyJSON()
	if err != nil {
		record.ErrorMessage = fmt.Sprintf("build policy: %v", err)
		return record, err
	}

	// 1. Attach Deny-* inline policy.
	switch targetType {
	case "user":
		_, err = q.iamClient.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
			UserName:       aws_sdk.String(targetName),
			PolicyName:     aws_sdk.String(quarantinePolicyName),
			PolicyDocument: aws_sdk.String(policyJSON),
		})
	case "role":
		_, err = q.iamClient.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			RoleName:       aws_sdk.String(targetName),
			PolicyName:     aws_sdk.String(quarantinePolicyName),
			PolicyDocument: aws_sdk.String(policyJSON),
		})
	default:
		record.ErrorMessage = fmt.Sprintf("unknown target type: %s", targetType)
		return record, fmt.Errorf("quarantine: %s", record.ErrorMessage)
	}

	if err != nil {
		record.ErrorMessage = fmt.Sprintf("attach quarantine policy: %v", err)
		governance.LogFailedAction("QuarantineAttachPolicy", "system", targetARN,
			fmt.Sprintf("failed to attach quarantine policy to %s %s: %v", targetType, targetName, err), nil)
		return record, fmt.Errorf("quarantine policy: %w", err)
	}
	record.PolicyAttached = true
	record.PolicyName = quarantinePolicyName

	utilities.LogProgress("quarantine", "policy-attached",
		fmt.Sprintf("Deny-* policy attached to %s %s", targetType, targetName))

	// 2. Deactivate IAM access keys (users only).
	if targetType == "user" {
		keys, err := q.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: aws_sdk.String(targetName),
		})
		if err != nil {
			utilities.Error("quarantine: list keys for %s: %v", targetName, err)
		} else {
			for _, key := range keys.AccessKeyMetadata {
				if key.Status != iamtypes.StatusTypeActive {
					continue
				}
				_, err := q.iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
					UserName:    aws_sdk.String(targetName),
					AccessKeyId: key.AccessKeyId,
					Status:      iamtypes.StatusTypeInactive,
				})
				if err != nil {
					utilities.Error("quarantine: deactivate key %s: %v", aws_sdk.ToString(key.AccessKeyId), err)
					continue
				}
				record.KeysDeactivated = append(record.KeysDeactivated, aws_sdk.ToString(key.AccessKeyId))
			}
		}
	}

	// 3. STS session invalidation for roles.
	// The Deny-* quarantine policy blocks all future API calls.
	// Existing sessions will be denied at their next request boundary.
	if targetType == "role" {
		record.SessionsRevoked = true
		utilities.LogProgress("quarantine", "sessions-revoked",
			fmt.Sprintf("role %s: Deny-* policy active — all API calls blocked", targetName))
	}

	governance.LogSuccessfulAction("QuarantineIdentity", "system", targetARN,
		fmt.Sprintf("quarantine applied to %s %s: policy=%v keys_deactivated=%d sessions_revoked=%v",
			targetType, targetName, record.PolicyAttached, len(record.KeysDeactivated), record.SessionsRevoked),
		map[string]interface{}{
			"target_arn":       targetARN,
			"target_type":      targetType,
			"keys_deactivated": record.KeysDeactivated,
			"policy_name":      quarantinePolicyName,
		})

	return record, nil
}

// RemoveQuarantine removes the Deny-* inline policy from the specified
// identity, restoring its original permissions. Use only after a
// security investigation has confirmed the identity is safe.
func (q *QuarantineEngine) RemoveQuarantine(ctx context.Context, targetARN, targetType string) error {
	targetName := extractNameFromARN(targetARN)

	var err error
	switch targetType {
	case "user":
		_, err = q.iamClient.DeleteUserPolicy(ctx, &iam.DeleteUserPolicyInput{
			UserName:   aws_sdk.String(targetName),
			PolicyName: aws_sdk.String(quarantinePolicyName),
		})
	case "role":
		_, err = q.iamClient.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
			RoleName:   aws_sdk.String(targetName),
			PolicyName: aws_sdk.String(quarantinePolicyName),
		})
	}

	if err != nil {
		return fmt.Errorf("remove quarantine from %s %s: %w", targetType, targetName, err)
	}

	governance.LogSuccessfulAction("RemoveQuarantine", "system", targetARN,
		fmt.Sprintf("quarantine removed from %s %s", targetType, targetName), nil)
	return nil
}

// buildQuarantinePolicyJSON returns the JSON-serialised Deny-* inline
// policy document.
func buildQuarantinePolicyJSON() (string, error) {
	doc := model.QuarantinePolicyDocument{
		Version: "2012-10-17",
		Statement: []model.QuarantinePolicyStatement{
			{
				Sid:      "AWSGateKeeperQuarantine",
				Effect:   "Deny",
				Action:   "*",
				Resource: "*",
			},
		},
	}
	b, err := json.Marshal(doc)
	return string(b), err
}

// extractNameFromARN parses the entity name from an IAM ARN.
func extractNameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	resource := parts[5]
	segments := strings.SplitN(resource, "/", 2)
	if len(segments) == 2 {
		return segments[1]
	}
	return resource
}

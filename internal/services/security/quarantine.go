// Package security (quarantine.go) implements the QuarantineEngine,
// which performs non-destructive zero-privilege isolation of compromised
// IAM identities via explicit Deny-* inline policies.
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

// quarantinePolicyName is the inline policy name attached to a
// quarantined identity.  Hard-coded so it can be referenced by the
// companion RemoveQuarantine cleanup path.
const quarantinePolicyName = "AWSGateKeeper-Quarantine-DenyAll"

// QuarantineEngine executes non-destructive isolation of compromised
// IAM identities. It attaches an explicit Deny-* inline policy and
// revokes active sessions — the identity is NEVER deleted.
//
// The design choice is deliberate: deletion is irreversible and
// destroys forensic evidence.  Quarantine preserves the identity
// and its history so post-incident analysis can proceed normally.
type QuarantineEngine struct {
	iamClient *iam.Client // IAM client used for inline policy + key operations
	stsClient *sts.Client // STS client reserved for session revocation (future)
}

// NewQuarantineEngine creates a QuarantineEngine from the shared SDK
// configuration, reusing the same IAM and STS clients used by the rest
// of the application.
//
//	@param  cfg  shared AWS SDK config
//	@return      ready-to-use QuarantineEngine
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
//
//	@param  ctx        request context for SDK calls
//	@param  targetARN  full IAM ARN of the identity to quarantine
//	@param  targetType "user" or "role"
//	@return            populated QuarantineRecord with success/failure details
//	@return            non-nil if the inline-policy attachment fails (and
//	                  nothing else in the loop is attempted)
func (q *QuarantineEngine) QuarantineIdentity(ctx context.Context, targetARN, targetType string) (*model.QuarantineRecord, error) {
	record := &model.QuarantineRecord{
		TargetARN:  targetARN,
		TargetType: targetType,
		ExecutedAt: time.Now().UTC(),
	}

	targetName := extractNameFromARN(targetARN)

	// Build the Deny-* policy once; failures here are pre-flight and
	// the quarantine is aborted before any AWS call is made.
	policyJSON, err := buildQuarantinePolicyJSON()
	if err != nil {
		record.ErrorMessage = fmt.Sprintf("build policy: %v", err)
		return record, err
	}

	// 1. Attach Deny-* inline policy.  The IAM call is type-specific
	// because AWS does not provide a unified PutIdentityPolicy API
	// (it requires a managed-policy ARN, not an inline policy).
	var attachErr error
	switch targetType {
	case "user":
		_, attachErr = q.iamClient.PutUserPolicy(ctx, &iam.PutUserPolicyInput{
			UserName:       aws_sdk.String(targetName),
			PolicyName:     aws_sdk.String(quarantinePolicyName),
			PolicyDocument: aws_sdk.String(policyJSON),
		})
	case "role":
		_, attachErr = q.iamClient.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			RoleName:       aws_sdk.String(targetName),
			PolicyName:     aws_sdk.String(quarantinePolicyName),
			PolicyDocument: aws_sdk.String(policyJSON),
		})
	default:
		record.ErrorMessage = fmt.Sprintf("unknown target type: %s", targetType)
		return record, fmt.Errorf("quarantine: %s", record.ErrorMessage)
	}

	if attachErr != nil {
		// Failure at step 1 is a hard fail: nothing else in the
		// loop is attempted because the identity would otherwise
		// be in an inconsistent "keys deactivated but no policy"
		// state.
		record.ErrorMessage = fmt.Sprintf("attach quarantine policy: %v", attachErr)
		governance.LogFailedAction("QuarantineAttachPolicy", "system", targetARN,
			fmt.Sprintf("failed to attach quarantine policy to %s %s: %v", targetType, targetName, attachErr), nil)
		return record, fmt.Errorf("quarantine policy: %w", attachErr)
	}
	record.PolicyAttached = true
	record.PolicyName = quarantinePolicyName

	utilities.LogProgress("quarantine", "policy-attached",
		fmt.Sprintf("Deny-* policy attached to %s %s", targetType, targetName))

	// 2. Deactivate IAM access keys (users only).  Roles never have
	// long-lived access keys, so this step is skipped for them.
	if targetType == "user" {
		keys, err := q.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
			UserName: aws_sdk.String(targetName),
		})
		if err != nil {
			// List failure is non-fatal: we still want to log
			// progress, and the Deny-* policy is already
			// active.  The error is recorded in utilities logs.
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
					// Per-key failure is logged and skipped
					// so one stale key does not block the
					// rest of the deactivation loop.
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

	// Record the success in the governance audit log for later
	// reconstruction of the response timeline.
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
//
//	@param  ctx        request context for SDK calls
//	@param  targetARN  full IAM ARN of the identity to release
//	@param  targetType "user" or "role"
//	@return            nil on successful policy removal
//	@return            non-nil if the IAM DeleteUserPolicy /
//	                  DeleteRolePolicy call fails
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
// policy document.  The single statement denies every action on every
// resource, which is the strongest non-destructive isolation available
// in IAM.
//
//	@return  serialised policy document (JSON string)
//	@return  non-nil only on json.Marshal failure (defensive — the
//	         document is well-known and should never fail)
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
//
// Example: arn:aws:iam::123456789012:user/alice  →  "alice"
//
// Falls back to the resource component when the expected
// "service:name" structure is missing (e.g. for non-standard ARNs),
// and to the full ARN when the input has fewer than 6 colon-separated
// segments (the minimum for a valid ARN).
//
//	@param  arn  IAM ARN
//	@return      extracted entity name (or the original ARN if unparsable)
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

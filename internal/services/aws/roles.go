// Package aws provides IAM role creation and inline policy generation
// based on predefined user privilege levels and action groups.
//
// Role creation maps each UserPriviledge constant declared in the model
// package to an IAM role with a scoped inline policy.  The Root privilege
// receives the AWS-managed AdministratorAccess policy; all other
// privileges receive an inline policy built from the privilege's assigned
// ActionGroup entries (declared in policies.go).
//
// Trust policies restrict sts:AssumeRole to principals within the same
// AWS account, ensuring roles can only be assumed by other IAM entities
// owned by this account.
package aws

import (
	"aws_gatekeeper/internal/model"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// privilegeActionGroups maps each user privilege to the set of AWS
// services (ActionGroups) that the role will have access to.
//
// Empty slices (e.g. Root) are handled specially at policy-build time:
// Root receives AdministratorAccess instead of an inline policy.
//
//	@readonly  populated at init; consumed by BuildInlinePolicy
var privilegeActionGroups = map[model.UserPriviledge][]ActionGroup{
	model.Root: {
		// Root is granted AdministratorAccess managed policy, not an
		// inline policy built from ActionGroups.
	},
	model.SOCAnalyst: {
		Logs,
		CloudWatch,
		CloudTrail,
		GuardDuty,
	},
	model.FrontEndDeveloper: {
		S3,
		CloudFront,
		Lambda,
	},
	model.BackEndDeveloper: {
		DynamoDB,
		APIGateway,
		Lambda,
		SQS,
	},
	model.DeploymentOperation: {
		CodeDeploy,
		CodePipeline,
		CloudFormation,
		ECS,
		ECR,
	},
	model.ThridPartyFrontEndDeveloper: {
		S3, // read-only in practice; policy does not enforce this yet
		CloudFront,
	},
	model.ThridPartyBackEndDeveloper: {
		DynamoDB, // read-only in practice; policy does not enforce this yet
		Lambda,   // invoke-only in practice; policy does not enforce this yet
	},
	model.BillingOnly: {
		Billing,
		CostExplorer,
	},
}

// roleName returns the canonical IAM role name for the given privilege.
//
// Role names follow the pattern "{PrivilegeName}Role" and are used both
// for CreateRole calls and as keys when attaching policies.
//
//	@param  priviledge  the user privilege to resolve
//	@return             the matching IAM role name, or "" if unrecognised
func roleName(priviledge model.UserPriviledge) string {
	names := map[model.UserPriviledge]string{
		model.Root:                        "RootRole",
		model.SOCAnalyst:                  "SOCAnalystRole",
		model.FrontEndDeveloper:           "FrontEndDeveloperRole",
		model.BackEndDeveloper:            "BackEndDeveloperRole",
		model.DeploymentOperation:         "DeploymentOperationRole",
		model.ThridPartyFrontEndDeveloper: "ThirdPartyFrontEndDeveloperRole",
		model.ThridPartyBackEndDeveloper:  "ThirdPartyBackEndDeveloperRole",
		model.BillingOnly:                 "BillingOnlyRole",
	}

	return names[priviledge]
}

// BuildInlinePolicy generates a JSON IAM policy document for a single
// user privilege by collecting the fully qualified action strings from
// every ActionGroup assigned to that privilege.
//
// # Policy Structure
//
// The generated document follows the standard IAM policy schema:
//
//	{
//	  "Version": "2012-10-17",
//	  "Statement": [{
//	    "Effect": "Allow",
//	    "Action": ["s3:GetObject", ...],
//	    "Resource": "*"
//	  }]
//	}
//
// Actions from overlapping groups are deduplicated before serialisation.
// An unrecognised or empty privilege returns a valid but empty policy
// (Statement: []).
//
//	@param  priv  the privilege whose actions should be collected
//	@return       JSON-encoded inline policy document as a string
//	@return       non-nil if JSON marshalling fails
func BuildInlinePolicy(priv model.UserPriviledge) (string, error) {
	groups, ok := privilegeActionGroups[priv]
	if !ok || len(groups) == 0 {
		return `{"Version":"2012-10-17","Statement":[]}`, nil
	}

	// Collect fully qualified action strings from every assigned group.
	var allActions []string
	for _, grp := range groups {
		allActions = append(allActions, GetFullActionsForGroup(grp)...)
	}

	// Deduplicate before building the statement array.
	seen := make(map[string]bool)
	var unique []string
	for _, a := range allActions {
		if !seen[a] {
			seen[a] = true
			unique = append(unique, a)
		}
	}

	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect":   "Allow",
				"Action":   unique,
				"Resource": "*",
			},
		},
	}
	b, err := json.Marshal(policy)
	return string(b), err
}

// ensureRole creates the IAM role if it does not already exist.
// If the role exists, its trust policy is updated in place via
// UpdateAssumeRolePolicy so that subsequent runs are idempotent.
//
//	@param  ctx          cancellation context for the API call(s)
//	@param  client       pre-configured IAM client
//	@param  roleName     name of the role to create or update
//	@param  trustPolicy  JSON trust policy document
//	@param  description  human-readable role description
//	@return              nil on success; the first non-retryable error
//	                     from CreateRole or UpdateAssumeRolePolicy
func ensureRole(ctx context.Context, client *iam.Client, roleName, trustPolicy, description string) error {
	_, err := client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws_sdk.String(roleName),
		AssumeRolePolicyDocument: aws_sdk.String(trustPolicy),
		Description:              aws_sdk.String(description),
	})
	if err == nil {
		return nil
	}

	var existsErr *types.EntityAlreadyExistsException
	if !errors.As(err, &existsErr) {
		return err
	}

	// Role already exists — update the trust policy.
	_, err = client.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
		RoleName:       aws_sdk.String(roleName),
		PolicyDocument: aws_sdk.String(trustPolicy),
	})
	return err
}

// CreateRolesForAllPrivileges ensures every UserPriviledge value has a
// corresponding IAM role.  Roles that do not exist are created; existing
// roles have their trust policy updated (idempotent run).
//
// Policy Assignment Rules
//
//   - Root: receives the AWS-managed AdministratorAccess policy.
//   - All other privileges: receive an inline policy built by
//     BuildInlinePolicy from their assigned ActionGroups.
//
// # Trust Policy
//
// Every role is created with a trust policy that grants sts:AssumeRole
// to any IAM principal within the calling account.
//
//	@param  ctx  tracing / cancellation context for all AWS API calls
//	@param  cfg  pre-configured AWS SDK config used to create IAM and
//	             STS clients
//	@return      nil if every role was created and policies attached;
//	             the first error encountered otherwise
func CreateRolesForAllPrivileges(ctx context.Context, cfg aws_sdk.Config) error {
	iamClient := iam.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)

	// Resolve the caller's account ID for trust-policy ARN construction.
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}
	accountID := aws_sdk.ToString(identity.Account)

	allPrivileges := []model.UserPriviledge{
		model.Root,
		model.SOCAnalyst,
		model.FrontEndDeveloper,
		model.BackEndDeveloper,
		model.DeploymentOperation,
		model.ThridPartyFrontEndDeveloper,
		model.ThridPartyBackEndDeveloper,
		model.BillingOnly,
	}

	for _, priv := range allPrivileges {
		roleName := roleName(priv)

		trustPolicy := fmt.Sprintf(`{
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::%s:root"},
                "Action": "sts:AssumeRole"
            }]
        }`, accountID)

		if err := ensureRole(ctx, iamClient, roleName, trustPolicy,
			fmt.Sprintf("Role for %v", priv)); err != nil {
			return fmt.Errorf("ensure role %s: %w", roleName, err)
		}

		// Root skips inline policy — AdministratorAccess is attached instead.
		if priv == model.Root {
			_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
				RoleName:  aws_sdk.String(roleName),
				PolicyArn: aws_sdk.String("arn:aws:iam::aws:policy/AdministratorAccess"),
			})
			if err != nil {
				return fmt.Errorf("attach admin policy to %s: %w", roleName, err)
			}
			continue
		}

		policyDoc, err := BuildInlinePolicy(priv)
		if err != nil {
			return fmt.Errorf("build policy for %s: %w", roleName, err)
		}

		_, err = iamClient.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			RoleName:       aws_sdk.String(roleName),
			PolicyName:     aws_sdk.String("InlinePolicy"),
			PolicyDocument: aws_sdk.String(policyDoc),
		})
		if err != nil {
			return fmt.Errorf("put policy on %s: %w", roleName, err)
		}
	}
	return nil
}

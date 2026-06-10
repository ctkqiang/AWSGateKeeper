// Package aws (cognito_audit.go) implements the COGNITO_PRIVILEGED_EXTERNAL_USERS
// audit rule by inspecting Cognito user pool groups for external users in
// privileged roles.
package aws

import (
	"context"
	"fmt"
	"strings"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

// CognitoAuditor implements the COGNITO_PRIVILEGED_EXTERNAL_USERS
// audit rule from rules/project.md.
type CognitoAuditor struct {
	client *cognitoidentityprovider.Client
}

// NewCognitoAuditor creates a CognitoAuditor from the shared SDK config.
func NewCognitoAuditor(cfg aws_sdk.Config) *CognitoAuditor {
	return &CognitoAuditor{client: cognitoidentityprovider.NewFromConfig(cfg)}
}

// PrivilegedGroupUsers returns all users who belong to groups whose
// names match the given privileged patterns (e.g. "Admin", "SuperUser").
func (c *CognitoAuditor) PrivilegedGroupUsers(ctx context.Context, userPoolID string, privilegedPatterns []string) ([]PrivilegedUser, error) {
	var results []PrivilegedUser

	paginator := cognitoidentityprovider.NewListGroupsPaginator(c.client, &cognitoidentityprovider.ListGroupsInput{
		UserPoolId: aws_sdk.String(userPoolID),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list groups: %w", err)
		}
		for _, g := range page.Groups {
			groupName := aws_sdk.ToString(g.GroupName)
			if !matchesAnyPattern(groupName, privilegedPatterns) {
				continue
			}
			users, err := c.usersInGroup(ctx, userPoolID, groupName)
			if err != nil {
				continue
			}
			for _, u := range users {
				results = append(results, PrivilegedUser{
					Username:  u,
					GroupName: groupName,
					PoolID:    userPoolID,
				})
			}
		}
	}
	return results, nil
}

// usersInGroup returns all usernames in a given group.
func (c *CognitoAuditor) usersInGroup(ctx context.Context, poolID, groupName string) ([]string, error) {
	var users []string
	paginator := cognitoidentityprovider.NewListUsersInGroupPaginator(c.client, &cognitoidentityprovider.ListUsersInGroupInput{
		UserPoolId: aws_sdk.String(poolID),
		GroupName:  aws_sdk.String(groupName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range page.Users {
			users = append(users, aws_sdk.ToString(u.Username))
		}
	}
	return users, nil
}

// AuditExternalUsers checks whether any user in privileged groups has
// an email domain outside the allowed enterprise domains.
func (c *CognitoAuditor) AuditExternalUsers(ctx context.Context, userPoolID string, privilegedPatterns, allowedDomains []string) ([]ExternalUserViolation, error) {
	privUsers, err := c.PrivilegedGroupUsers(ctx, userPoolID, privilegedPatterns)
	if err != nil {
		return nil, err
	}
	var violations []ExternalUserViolation
	for _, pu := range privUsers {
		detail, err := c.client.AdminGetUser(ctx, &cognitoidentityprovider.AdminGetUserInput{
			UserPoolId: aws_sdk.String(userPoolID),
			Username:   aws_sdk.String(pu.Username),
		})
		if err != nil {
			continue
		}
		email := userAttribute(detail.UserAttributes, "email")
		if email == "" {
			continue
		}
		domain := extractDomain(email)
		if !isAllowedDomain(domain, allowedDomains) {
			violations = append(violations, ExternalUserViolation{
				Username:  pu.Username,
				GroupName: pu.GroupName,
				Email:     email,
				Domain:    domain,
				PoolID:    userPoolID,
			})
		}
	}
	return violations, nil
}

// PrivilegedUser is a user found in a privileged group.
type PrivilegedUser struct {
	Username  string
	GroupName string
	PoolID    string
}

// ExternalUserViolation records a violation of the Cognito external
// user audit rule.
type ExternalUserViolation struct {
	Username  string `json:"username"`
	GroupName string `json:"group_name"`
	Email     string `json:"email"`
	Domain    string `json:"domain"`
	PoolID    string `json:"pool_id"`
}

func matchesAnyPattern(name string, patterns []string) bool {
	for _, p := range patterns {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}

func userAttribute(attrs []cognitotypes.AttributeType, name string) string {
	for _, a := range attrs {
		if aws_sdk.ToString(a.Name) == name {
			return aws_sdk.ToString(a.Value)
		}
	}
	return ""
}

func extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[1])
	}
	return ""
}

func isAllowedDomain(domain string, allowed []string) bool {
	for _, d := range allowed {
		if strings.EqualFold(domain, d) || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

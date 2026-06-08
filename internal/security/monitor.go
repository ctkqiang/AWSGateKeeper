// Package security (monitor.go) provides real-time detection of
// overly permissive IAM policies that contain wildcard ("*") values
// for Resource or Action.
//
// A policy with "Resource": "*" and "Action": "*" effectively grants
// full administrator access — the most dangerous misconfiguration in
// AWS IAM.  This module detects such patterns and raises an immediate
// alert via the audit system, which in turn forwards to CloudWatch,
// SIEM, and any registered alerting callbacks.
package security

import (
	"aws_gatekeeper/internal/services/governance"
	"encoding/json"
	"fmt"
	"strings"
)

// WildcardSeverity classifies how dangerous a detected wildcard grant is.
type WildcardSeverity string

const (
	// SeverityCritical — both Resource AND Action are wildcards.
	// This is equivalent to AdministratorAccess.
	SeverityCritical WildcardSeverity = "CRITICAL"

	// SeverityHigh — Action is "*" but Resource is scoped, or
	// Resource is "*" but Action is scoped.  Still dangerous but less
	// than full admin.
	SeverityHigh WildcardSeverity = "HIGH"

	// SeverityWarn — a wildcard appears in a non-IAM policy statement.
	SeverityWarn WildcardSeverity = "WARN"
)

// PolicyFinding captures a single wildcard violation within an IAM
// policy document.
type PolicyFinding struct {
	Severity   WildcardSeverity `json:"severity"`
	EntityType string           `json:"entity_type"` // role / user / policy / group
	EntityName string           `json:"entity_name"`
	EntityARN  string           `json:"entity_arn,omitempty"`
	Statement  int              `json:"statement_index"` // 0-based index in Statement[]
	Resource   string           `json:"resource"`
	Action     interface{}      `json:"action"` // string or []string
	Summary    string           `json:"summary"`
}

// AuditWildcardPolicy inspects a raw IAM policy JSON document for
// wildcard ("*") values in Resource or Action fields.
//
// Each violating statement produces a PolicyFinding.  An empty result
// means the policy is clean (no wildcards detected).
//
// Call this function immediately after a policy document is created or
// modified — for example, inside a PutRolePolicy / CreatePolicy handler.
//
//	@param  policyJSON   raw IAM policy document as a JSON string
//	@param  entityType   "role", "user", "policy", or "group"
//	@param  entityName   the friendly name of the entity
//	@param  entityARN    optional ARN of the entity
//	@return              list of detected wildcard violations; nil if clean
//	@return              non-nil if the JSON cannot be parsed
func AuditWildcardPolicy(policyJSON, entityType, entityName, entityARN string) ([]PolicyFinding, error) {
	var doc struct {
		Statement []struct {
			Effect   string      `json:"Effect"`
			Action   interface{} `json:"Action"`   // string or []string
			Resource interface{} `json:"Resource"` // string or []string
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return nil, fmt.Errorf("parse policy JSON: %w", err)
	}

	var findings []PolicyFinding

	for i, stmt := range doc.Statement {
		hasResourceWildcard := containsWildcard(stmt.Resource)
		hasActionWildcard := containsWildcard(stmt.Action)

		if !hasResourceWildcard && !hasActionWildcard {
			continue
		}

		sev := classifySeverity(hasActionWildcard, hasResourceWildcard)
		summary := buildSummary(entityType, entityName, hasActionWildcard, hasResourceWildcard)

		findings = append(findings, PolicyFinding{
			Severity:   sev,
			EntityType: entityType,
			EntityName: entityName,
			EntityARN:  entityARN,
			Statement:  i,
			Resource:   fmt.Sprint(stmt.Resource),
			Action:     stmt.Action,
			Summary:    summary,
		})
	}

	return findings, nil
}

// RaiseWildcardAlert inspects a policy and, if any wildcard violation is
// found, immediately writes a CRITICAL audit event and returns the
// findings for the caller to inspect.
//
// This is the one-line integration point — call it after any IAM policy
// mutation.
//
//	@param  operatorID   the IAM user or role ARN who made the change
//	@param  policyJSON   the policy document to inspect
//	@param  entityType   "role", "user", "policy", or "group"
//	@param  entityName   friendly name of the entity
//	@param  entityARN    optional ARN
//	@return              all detected findings; nil if the policy is clean
//	@return              non-nil if the policy cannot be parsed
func RaiseWildcardAlert(operatorID, policyJSON, entityType, entityName, entityARN string) ([]PolicyFinding, error) {
	findings, err := AuditWildcardPolicy(policyJSON, entityType, entityName, entityARN)
	if err != nil {
		governance.LogFailedAction(
			"AuditWildcardPolicy",
			operatorID,
			entityARN,
			fmt.Sprintf("failed to parse policy for %s %s: %v", entityType, entityName, err),
			nil,
		)
		return nil, err
	}

	if len(findings) == 0 {
		return nil, nil
	}

	// Bundle findings into the audit event metadata so the SIEM can
	// display them in context.
	metadata := map[string]interface{}{
		"findings":    findings,
		"entity_type": entityType,
		"entity_name": entityName,
		"entity_arn":  entityARN,
	}

	action := fmt.Sprintf("WildcardPolicyDetected:%s:%s", entityType, entityName)
	message := findings[0].Summary
	if len(findings) > 1 {
		message += fmt.Sprintf(" (+%d more)", len(findings)-1)
	}

	governance.LogFailedAction(
		action,
		operatorID,
		entityARN,
		message,
		metadata,
	)

	return findings, nil
}

// containsWildcard checks whether a policy Action or Resource field
// contains the literal string "*", either as a bare string or inside a
// string slice.
func containsWildcard(val interface{}) bool {
	switch v := val.(type) {
	case string:
		return v == "*"
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

// classifySeverity returns the WildcardSeverity for a given combination.
func classifySeverity(hasActionWildcard, hasResourceWildcard bool) WildcardSeverity {
	if hasActionWildcard && hasResourceWildcard {
		return SeverityCritical
	}
	return SeverityHigh
}

// buildSummary produces a human-readable description of the violation.
func buildSummary(entityType, entityName string, actionStar, resourceStar bool) string {
	var parts []string

	if actionStar {
		parts = append(parts, `Action: "*"`)
	}
	if resourceStar {
		parts = append(parts, `Resource: "*"`)
	}

	desc := strings.Join(parts, " AND ")

	if actionStar && resourceStar {
		return fmt.Sprintf(
			"%s %s grants full administrator access (Action: * on Resource: *) — remediate immediately",
			entityType, entityName,
		)
	}

	return fmt.Sprintf(
		"%s %s contains overly permissive wildcard — %s",
		entityType, entityName, desc,
	)
}

// Package security (validator.go) provides input validation functions
// for ARN format, detector IDs, finding IDs, and IAM policy documents.
package security

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	arnPattern     = regexp.MustCompile(`^arn:aws:[a-z0-9-]+:[0-9]{12}:([a-z0-9-]+/)?[a-zA-Z0-9+=,.@_-]+$`)
	detectorIDPat  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	findingIDPat   = regexp.MustCompile(`^[a-f0-9]{32}$`)
	policyMustHave = regexp.MustCompile(`"Version"\s*:\s*"2012-10-17"`)
)

// ValidateDetectorID checks the GuardDuty detector ID format.
func ValidateDetectorID(id string) error {
	if id == "" {
		return fmt.Errorf("detector_id is required")
	}
	if !detectorIDPat.MatchString(id) {
		return fmt.Errorf("invalid detector_id format: expected 32 hex chars")
	}
	return nil
}

// ValidateFindingID checks a single GuardDuty finding ID.
func ValidateFindingID(id string) error {
	if id == "" {
		return fmt.Errorf("finding_id is required")
	}
	if len(id) > 128 {
		return fmt.Errorf("finding_id too long (max 128)")
	}
	return nil
}

// ValidateIAMARN checks if s looks like a valid IAM ARN.
func ValidateIAMARN(arn string) error {
	if arn == "" {
		return fmt.Errorf("ARN is required")
	}
	if !arnPattern.MatchString(arn) {
		return fmt.Errorf("invalid ARN format: %s", arn)
	}
	if !strings.Contains(arn, ":iam::") {
		return fmt.Errorf("ARN is not an IAM resource: %s", arn)
	}
	return nil
}

// ValidatePolicyDocument performs basic structural validation of an
// IAM policy JSON string before it enters the audit pipeline.
func ValidatePolicyDocument(policyJSON string) error {
	if policyJSON == "" {
		return fmt.Errorf("policy document is required")
	}
	if len(policyJSON) > 10240 {
		return fmt.Errorf("policy document too large (max 10240 bytes)")
	}
	if !policyMustHave.MatchString(policyJSON) {
		return fmt.Errorf("policy document must contain Version: 2012-10-17")
	}
	return nil
}

// ValidateScanRequest validates input to POST /security/scan.
func ValidateScanRequest(detectorID string) error {
	return ValidateDetectorID(detectorID)
}

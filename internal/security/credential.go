// Package security (credential.go) reads and validates AWS credentials
// from environment variables populated by the preference package.
package security

import (
	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/preference"
	"errors"
)

// AWSCredentials reads the three standard AWS credential values from the
// process environment, validates that all are non-empty, and returns them
// as a typed struct.
//
// Validation is performed per-field: each missing value produces a distinct
// error message naming the specific environment variable that was not set.
// On any validation failure the partial struct is returned alongside the
// error so that the caller can still inspect which fields are populated.
//
// Data Flow
//
//	aws-config.yaml  -->  preference.init()  -->  os.Setenv(...)
//	                                                    |
//	AWSCredentials()  <--  preference.GetKey()  <--  os.Getenv(...)
//	         |
//	(model.AWSAuthorisationKeys, error)
//
// Note: this function does NOT verify credentials against AWS STS.  It only
// checks that all three values are non-empty.  STS-level verification must
// be performed separately by the caller if required.
//
//	@return  typed credential struct (partial on error, full on success)
//	@return  non-nil if any of the three required fields is empty, with a
//	         message identifying which variable is missing
func AWSCredentials() (model.AWSAuthorisationKeys, error) {
	credentials := model.AWSAuthorisationKeys{
		AccessKeyID:     preference.GetKey("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: preference.GetKey("AWS_SECRET_ACCESS_KEY"),
		Region:          preference.GetKey("AWS_REGION"),
	}

	if credentials.AccessKeyID == "" {
		return credentials, errors.New("AWS_ACCESS_KEY_ID is not set")
	}

	if credentials.SecretAccessKey == "" {
		return credentials, errors.New("AWS_SECRET_ACCESS_KEY is not set")
	}

	if credentials.Region == "" {
		return credentials, errors.New("AWS_REGION is not set")
	}

	return credentials, nil
}

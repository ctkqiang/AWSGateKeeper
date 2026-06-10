// Package model (aws.go) defines the AWS credential key structure
// shared between the config loader and the authentication singleton.
package model

// AWSAuthorisationKeys holds the three standard AWS credential fields.
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region"`
}

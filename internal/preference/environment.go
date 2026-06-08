// Package preference handles application configuration, loading AWS credentials
// from a YAML file and exposing them through the standard environment variable
// interface expected by the AWS SDK.
//
// # Configuration Loading Flow
//
// At package initialization (init), the package searches upward from the
// current working directory for "aws-config.yaml".  Once found, it unmarshals
// the YAML content into typed structs and populates the corresponding
// environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
// AWS_REGION) unless those variables are already set, in which case the
// existing value takes precedence.
//
// Configuration File Format
//
//	aws:
//	  access_key_id:     AKIAIOSFODNN7EXAMPLE
//	  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
//	  region:            us-east-1
//
// # Security Note
//
// The aws-config.yaml file MUST NOT be committed to version control.
// The .gitignore file excludes it.  For CI/CD environments, prefer injecting
// credentials via the platform's secrets manager rather than relying on a
// local configuration file.
package preference

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AWSConfig is the top-level container for AWS-specific configuration.
//
// It maps directly to the root "aws" key in aws-config.yaml.
type AWSConfig struct {
	// AWS holds the structured credentials and region.
	//
	//	@yaml aws
	AWS AWSCredentials `yaml:"aws"`
}

// AWSCredentials holds the three standard AWS SDK authentication fields.
//
// These fields are mapped to the environment variables that the AWS SDK
// Go v2 configuration chain reads by default, ensuring a smooth transition
// between the YAML file and the SDK's credential resolution.
type AWSCredentials struct {
	// AccessKeyID is the public part of the IAM user/role access key pair.
	//
	//	@yaml access_key_id
	AccessKeyID string `yaml:"access_key_id"`

	// SecretAccessKey is the private part of the IAM user/role access key pair.
	//
	// IMPORTANT: Never log or expose this value.
	//
	//	@yaml secret_access_key
	SecretAccessKey string `yaml:"secret_access_key"`

	// Region specifies the primary AWS region for API calls (e.g. us-east-1).
	//
	//	@yaml region
	Region string `yaml:"region"`
}

// init is the package initializer that triggers the full configuration
// loading pipeline during program startup.
//
// Pipeline Steps
//  1. Locate aws-config.yaml by walking up the directory tree.
//  2. Parse the YAML content into typed structs.
//  3. Export each field as an environment variable (unless already set).
//
// If any step fails, init panics -- the application cannot operate without
// valid AWS credentials.
func init() {
	configPath, err := findConfigFile("aws-config.yaml")
	if err != nil {
		panic(fmt.Errorf("preference: %w", err))
	}

	cfg, err := loadAWSConfig(configPath)
	if err != nil {
		panic(fmt.Errorf("preference: %w", err))
	}

	applyEnvOverrides(cfg)
}

// findConfigFile walks up the directory tree starting from the current
// working directory until it finds the specified file or reaches the
// filesystem root.
//
// # Walking Strategy
//
// The search starts at os.Getwd() and proceeds upward via filepath.Dir.
// On each level the function checks whether the named file exists and is a
// regular file (not a directory).  The first match wins.
//
//	@param  filename  the leaf name of the configuration file to locate
//	@return           the absolute path to the located file
//	@return           an error if the file was not found in any ancestor
//	                  directory up to and including the filesystem root
func findConfigFile(filename string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	for {
		envPath := filepath.Join(cwd, filename)
		if info, err := os.Stat(envPath); err == nil && !info.IsDir() {
			return envPath, nil
		}

		parent := filepath.Dir(cwd)
		if parent == cwd {
			// Reached filesystem root -- stop walking.
			break
		}

		cwd = parent
	}

	return "", fmt.Errorf("config file %s not found (searched up to root directory)", filename)
}

// loadAWSConfig reads and parses an AWS YAML configuration file.
//
// On success it returns a fully populated AWSConfig pointer.  On failure
// it returns a descriptive error that wraps the underlying I/O or YAML
// parsing error for upstream callers to inspect.
//
//	@param  path  absolute path to the aws-config.yaml file
//	@return       parsed configuration struct
//	@return       error if the file cannot be read or the YAML is malformed
func loadAWSConfig(path string) (*AWSConfig, error) {
	var cfg AWSConfig
	data, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return &cfg, nil
}

// applyEnvOverrides exports each AWS credential field as an environment
// variable, but only when the corresponding variable is not already
// present in the process environment.
//
// This ensures that explicit environment settings (e.g. from a CI/CD
// secrets manager) always take precedence over the local YAML file.
//
//	@param  cfg  parsed AWS configuration whose non-empty fields will be
//	            exported if no corresponding environment variable exists
func applyEnvOverrides(cfg *AWSConfig) {
	setIfEmpty("AWS_ACCESS_KEY_ID", cfg.AWS.AccessKeyID)
	setIfEmpty("AWS_SECRET_ACCESS_KEY", cfg.AWS.SecretAccessKey)
	setIfEmpty("AWS_REGION", cfg.AWS.Region)
}

// setIfEmpty is a helper that calls os.Setenv(key, value) only when the
// named environment variable has not already been set AND value is
// non-empty.
//
// This dual check avoids both overwriting explicit user intent and
// polluting the environment with empty strings.
//
//	@param  key    the environment variable name to potentially set
//	@param  value  the candidate value; ignored if empty or if the key
//	               already exists in the process environment
func setIfEmpty(key, value string) {
	if value == "" {
		return
	}

	if _, exists := os.LookupEnv(key); exists {
		return
	}

	os.Setenv(key, value)
}

// GetKey returns the value of the named AWS configuration variable.
//
// After init() completes, the following keys are guaranteed to be available
// (provided they were present in aws-config.yaml):
//
//	"AWS_ACCESS_KEY_ID"
//	"AWS_SECRET_ACCESS_KEY"
//	"AWS_REGION"
//
// An empty string is returned when the key is not found in the environment.
//
//	@param  key   the environment variable name to retrieve
//	@return       the variable value, or "" if not set
func GetKey(key string) string {
	return os.Getenv(key)
}

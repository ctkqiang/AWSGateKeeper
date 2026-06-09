// Package preference handles application configuration, loading AWS credentials
// and webhook channel settings from a YAML file and exposing them through the
// standard environment variable interface.
//
// # Configuration Loading Flow
//
// At package initialization (init), the package searches upward from the
// current working directory for "aws-config.yaml". Once found, it unmarshals
// the YAML content into typed structs and populates the corresponding
// environment variables unless those variables are already set, in which case the
// existing value takes precedence.
//
// Configuration File Format
//
//	aws:
//	  access_key_id:     AKIAIOSFODNN7EXAMPLE
//	  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
//	  region:            us-east-1
//	channel:
//	  platform:          slack
//	  webhook_url:       https://hooks.slack.com/services/T00/B00/X00
//	  secret_key:        optional_sign_secret
//	  keyword:           Security
//
// # Security Note
//
// The aws-config.yaml file MUST NOT be committed to version control.
// The .gitignore file excludes it. For CI/CD environments, prefer injecting
// credentials and webhook URLs via the platform's secrets manager rather than
// relying on a local configuration file.
package preference

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AWSConfig is the top-level container for application configuration.
//
// It maps directly to the root keys in aws-config.yaml.
type AWSConfig struct {
	// AWS holds the structured credentials and region.
	//
	//  @yaml aws
	AWS AWSCredentials `yaml:"aws"`

	// Channel holds the messaging webhook configuration parameters.
	//
	//  @yaml channel
	Channel ChannelCredentials `yaml:"channel"`
}

// AWSCredentials holds the three standard AWS SDK authentication fields.
type AWSCredentials struct {
	// AccessKeyID is the public part of the IAM user/role access key pair.
	AccessKeyID string `yaml:"access_key_id"`

	// SecretAccessKey is the private part of the IAM user/role access key pair.
	SecretAccessKey string `yaml:"secret_access_key"`

	// Region specifies the primary AWS region for API calls (e.g. us-east-1).
	Region string `yaml:"region"`
}

// ChannelCredentials holds configuration fields required by multi-platform webhooks.
type ChannelCredentials struct {
	// Platform specifies the target application ("slack", "teams", "dingtalk", "feishu").
	Platform string `yaml:"platform"`

	// WebhookURL is the complete target HTTP API endpoint endpoint provided by the platform.
	WebhookURL string `yaml:"webhook_url"`

	// SecretKey is optional, used for platforms requiring cryptographic signing (e.g., DingTalk/Feishu).
	SecretKey string `yaml:"secret_key"`

	// Keyword is optional, used for platforms filtering alerts by token phrase matching.
	Keyword string `yaml:"keyword"`
}

// init is the package initializer that triggers the full configuration
// loading pipeline during program startup.
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
			break
		}

		cwd = parent
	}

	return "", fmt.Errorf("config file %s not found (searched up to root directory)", filename)
}

// loadAWSConfig reads and parses an AWS and channel YAML configuration file.
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

// applyEnvOverrides exports each configuration field as an environment
// variable, but only when the corresponding variable is not already
// present in the process environment.
func applyEnvOverrides(cfg *AWSConfig) {
	// AWS credential mapping
	setIfEmpty("AWS_ACCESS_KEY_ID", cfg.AWS.AccessKeyID)
	setIfEmpty("AWS_SECRET_ACCESS_KEY", cfg.AWS.SecretAccessKey)
	setIfEmpty("AWS_REGION", cfg.AWS.Region)

	// Webhook channel mapping
	setIfEmpty("CHANNEL_PLATFORM", cfg.Channel.Platform)
	setIfEmpty("CHANNEL_WEBHOOK_URL", cfg.Channel.WebhookURL)
	setIfEmpty("CHANNEL_SECRET_KEY", cfg.Channel.SecretKey)
	setIfEmpty("CHANNEL_KEYWORD", cfg.Channel.Keyword)
}

// setIfEmpty is a helper that calls os.Setenv(key, value) only when the
// named environment variable has not already been set AND value is non-empty.
func setIfEmpty(key, value string) {
	if value == "" {
		return
	}

	if _, exists := os.LookupEnv(key); exists {
		return
	}

	os.Setenv(key, value)
}

// GetKey returns the value of the named application configuration variable.
//
// Valid Keys:
//
//	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"
//	"CHANNEL_PLATFORM", "CHANNEL_WEBHOOK_URL", "CHANNEL_SECRET_KEY", "CHANNEL_KEYWORD"
func GetKey(key string) string {
	return os.Getenv(key)
}

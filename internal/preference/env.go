package preference

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type AWSConfig struct {
	AWS AWSCredentials `yaml:"aws"`
}

type AWSCredentials struct {
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	Region          string `yaml:"region"`
}

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

func findConfigFile(filename string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("获取工作目录失败: %w", err)
	}

	for {
		envPath := filepath.Join(cwd, filename)
		if info, err := os.Stat(envPath); err == nil && !info.IsDir() {
			return envPath, nil
		}
		parent := filepath.Dir(cwd)
		if parent == cwd {
			break // 已到达文件系统根目录
		}
		cwd = parent
	}

	return "", fmt.Errorf("未找到配置文件 %s（已向上搜索至根目录）", filename)
}

// loadAWSConfig 解析 YAML 配置文件
func loadAWSConfig(path string) (*AWSConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}

	var cfg AWSConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析 YAML 配置失败: %w", err)
	}

	return &cfg, nil
}

// applyEnvOverrides 将配置写入环境变量（仅当对应环境变量尚未设置时覆盖）
func applyEnvOverrides(cfg *AWSConfig) {
	setIfEmpty("AWS_ACCESS_KEY_ID", cfg.AWS.AccessKeyID)
	setIfEmpty("AWS_SECRET_ACCESS_KEY", cfg.AWS.SecretAccessKey)
	setIfEmpty("AWS_REGION", cfg.AWS.Region)
}

func setIfEmpty(key, value string) {
	if value == "" {
		return
	}
	if _, exists := os.LookupEnv(key); exists {
		return // 已存在的环境变量优先
	}
	os.Setenv(key, value)
}

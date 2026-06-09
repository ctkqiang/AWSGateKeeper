package utilities

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Platform defines the supported webhook destinations
type Platform string

const (
	Slack    Platform = "slack"
	DingTalk Platform = "dingtalk"
	Feishu   Platform = "feishu"
	Teams    Platform = "teams"
)

// Shared, thread-safe HTTP client with explicit connection configurations.
// Reusing the client enables TCP connection reuse across multiple invocations.
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 20,
	},
}

// SendWebhook takes a markdown string, a title, and dispatches it to the specified platform URL.
// It accepts optional secrets and keywords for platforms like DingTalk and Feishu that require signatures.
func SendWebhook(ctx context.Context, platform Platform, webhookURL, title, markdownText, secretKey, keyword string) error {
	var (
		payload   []byte
		err       error
		targetURL = webhookURL
	)

	// Inject keyword into title if required by raw structural constraints
	if keyword != "" {
		title = fmt.Sprintf("[%s] %s", keyword, title)
	}

	switch platform {
	case Slack:
		payload, err = json.Marshal(map[string]interface{}{
			"text": fmt.Sprintf("*%s*\n\n%s", title, markdownText),
		})

	case DingTalk:
		// Build payload with signature if a secret key is present
		dingTalkPayload := map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": title,
				"text":  fmt.Sprintf("### %s\n\n%s", title, markdownText),
			},
		}

		if secretKey != "" {
			timestamp := time.Now().UnixNano() / int64(time.Millisecond)
			stringToSign := fmt.Sprintf("%d\n%s", timestamp, secretKey)

			h := hmac.New(sha256.New, []byte(secretKey))
			h.Write([]byte(stringToSign))
			sign := base64.StdEncoding.EncodeToString(h.Sum(nil))

			targetURL = fmt.Sprintf("%s&timestamp=%d&sign=%s", webhookURL, timestamp, sign)
		}
		payload, err = json.Marshal(dingTalkPayload)

	case Feishu:
		feishuPayload := map[string]interface{}{
			"msg_type": "post",
			"content": map[string]interface{}{
				"post": map[string]interface{}{
					"zh_cn": map[string]interface{}{
						"title": title,
						"content": [][]map[string]interface{}{
							{
								{
									"tag":  "markdown",
									"text": markdownText,
								},
							},
						},
					},
				},
			},
		}

		// Feishu signs within the JSON payload root block rather than query parameters
		if secretKey != "" {
			timestamp := time.Now().Unix()
			stringToSign := fmt.Sprintf("%d\n%s", timestamp, secretKey)

			h := hmac.New(sha256.New, []byte(stringToSign))
			sign := base64.StdEncoding.EncodeToString(h.Sum(nil))

			feishuPayload["timestamp"] = fmt.Sprintf("%d", timestamp)
			feishuPayload["sign"] = sign
		}
		payload, err = json.Marshal(feishuPayload)

	case Teams:
		payload, err = json.Marshal(map[string]interface{}{
			"@type":      "MessageCard",
			"@context":   "http://schema.org/extensions",
			"themeColor": "FF0000",
			"summary":    title,
			"title":      title,
			"text":       markdownText,
		})

	default:
		return fmt.Errorf("unsupported platform: %s", platform)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request with context to support cancellations/timeouts upstream gracefully
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to initialize webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read response error payload message from third party body to capture exact configuration rejection errors
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned non-2xx status code: %d, server reply: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

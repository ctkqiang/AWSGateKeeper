// Package utilities (message.go) provides a thin, platform-specific
// webhook dispatcher for the security and governance subsystems.
//
// The function in this file formats a markdown payload for one of four
// supported messaging platforms and POSTs it to a caller-supplied
// webhook URL.  It is intentionally platform-agnostic at the
// call-site: callers pass a Platform enum and the dispatcher takes
// care of the per-platform JSON shape, signature scheme, and content
// type.
//
// Supported platforms:
//
//	Slack     — block-markdown text payload
//	DingTalk  — markdown message with optional HMAC-SHA256 signature
//	Feishu    — post message with optional HMAC-SHA256 signature in body
//	Teams     — Office 365 MessageCard
//
// The dispatcher is read-only with respect to the project source: it
// never persists messages and never reaches out to any platform
// endpoint that is not explicitly provided in the call.
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
	// Slack targets the Slack Incoming Webhook API.
	Slack Platform = "slack"
	// DingTalk targets the DingTalk Custom Robot webhook API.
	DingTalk Platform = "dingtalk"
	// Feishu targets the Feishu/Lark Custom Bot webhook API.
	Feishu Platform = "feishu"
	// Teams targets the Microsoft Teams Office 365 Connector webhook API.
	Teams Platform = "teams"
)

// Shared, thread-safe HTTP client with explicit connection configurations.
// Reusing the client enables TCP connection reuse across multiple invocations.
//
// Tuning notes:
//
//	MaxIdleConns        — global ceiling; sized to absorb a burst of
//	                       concurrent webhook deliveries without
//	                       starving unrelated callers
//	IdleConnTimeout     — keep-alive duration matching typical
//	                       webhook-platform idle windows
//	MaxIdleConnsPerHost — bound per-platform connection reuse so a
//	                       single misbehaving host cannot dominate
//	                       the pool
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
//
// Signature schemes:
//
//	DingTalk  — HMAC-SHA256(timestamp + "\n" + secret); base64-encoded;
//	            appended to the URL as ?timestamp=…&sign=…
//	Feishu    — HMAC-SHA256(timestamp + "\n" + secret); base64-encoded;
//	            included in the JSON body as timestamp + sign
//
// The function returns an error in two situations: a JSON marshalling
// failure, or any non-2xx response from the platform.  Network errors
// are wrapped with the platform URL and the underlying error to ease
// triage.
//
//	@param  ctx           request context — applied to the HTTP call so
//	                      upstream cancellation propagates correctly
//	@param  platform      destination platform identifier
//	@param  webhookURL    full webhook URL (signature is appended for DingTalk)
//	@param  title         message title; prepended with [keyword] when keyword is set
//	@param  markdownText  markdown body of the message
//	@param  secretKey     platform signing secret (empty = no signature)
//	@param  keyword       keyword for DingTalk/Feishu prepended in [brackets]
//	@return               nil on 2xx response from the platform
//	@return               non-nil for marshalling, network, or non-2xx failures
func SendWebhook(ctx context.Context, platform Platform, webhookURL, title, markdownText, secretKey, keyword string) error {
	var (
		payload []byte
		err     error
		// targetURL may be augmented with signature query parameters
		// for DingTalk; the other platforms use the URL verbatim.
		targetURL = webhookURL
	)

	// Inject keyword into title if required by raw structural constraints
	if keyword != "" {
		title = fmt.Sprintf("[%s] %s", keyword, title)
	}

	switch platform {
	case Slack:
		// Slack Incoming Webhook accepts a single "text" field that
		// supports a small subset of markdown (bold via *…*, italic
		// via _…_, code via `…`).  We lead with the title in bold and
		// follow with two newlines + the body, mirroring the layout
		// the security pipeline uses for SIEM-style events.
		payload, err = json.Marshal(map[string]interface{}{
			"text": fmt.Sprintf("*%s*\n\n%s", title, markdownText),
		})

	case DingTalk:
		// DingTalk Custom Robot uses a "markdown" msgtype with a
		// title/text pair.  Signature is computed over the
		// (timestamp, secret) pair and appended to the URL.
		dingTalkPayload := map[string]interface{}{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": title,
				"text":  fmt.Sprintf("### %s\n\n%s", title, markdownText),
			},
		}

		if secretKey != "" {
			// DingTalk requires a millisecond-precision timestamp
			// (not Unix seconds) for its signature scheme.
			timestamp := time.Now().UnixNano() / int64(time.Millisecond)
			stringToSign := fmt.Sprintf("%d\n%s", timestamp, secretKey)

			h := hmac.New(sha256.New, []byte(secretKey))
			h.Write([]byte(stringToSign))
			sign := base64.StdEncoding.EncodeToString(h.Sum(nil))

			targetURL = fmt.Sprintf("%s&timestamp=%d&sign=%s", webhookURL, timestamp, sign)
		}
		payload, err = json.Marshal(dingTalkPayload)

	case Feishu:
		// Feishu uses a "post" msgtype with a locale-keyed
		// ("zh_cn") content array.  The signature is included
		// inside the JSON body rather than as a query parameter.
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
			// Feishu uses Unix-seconds timestamps, not milliseconds.
			timestamp := time.Now().Unix()
			stringToSign := fmt.Sprintf("%d\n%s", timestamp, secretKey)

			h := hmac.New(sha256.New, []byte(stringToSign))
			sign := base64.StdEncoding.EncodeToString(h.Sum(nil))

			feishuPayload["timestamp"] = fmt.Sprintf("%d", timestamp)
			feishuPayload["sign"] = sign
		}
		payload, err = json.Marshal(feishuPayload)

	case Teams:
		// Teams uses the Office 365 MessageCard format.  themeColor
		// is hard-coded to red because every message produced by
		// this dispatcher is a security event — adjust the caller
		// if a non-severity use case emerges.
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
		// Read response error payload message from third party body to capture exact configuration rejection errors.
		// io.ReadAll is bounded only by the platform's response size; in
		// practice webhook error bodies are < 4 KB.
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned non-2xx status code: %d, server reply: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// Package siem forwards audit events to an external SIEM (Security
// Information and Event Management) platform via HTTP.
//
// Supported backends are selected through the SIEM_BACKEND environment
// variable.  The forwarder uses fire-and-forget semantics — delivery
// failures are logged but never block the caller.
//
// Configuration
//
//	SIEM_ENABLED     set to "true" to activate forwarding (default: off)
//	SIEM_BACKEND     "splunk" | "generic"   (default: "generic")
//	SIEM_ENDPOINT    full HTTP endpoint URL (required when enabled)
//	SIEM_TOKEN       authentication token   (required for Splunk HEC)
//	SIEM_TIMEOUT_MS  request timeout in milliseconds (default: 5000)
//	SIEM_RETRIES     number of retries on transient errors (default: 2)
//
// Environment examples
//
//	Splunk Cloud / Enterprise HEC:
//	  SIEM_ENABLED=true
//	  SIEM_BACKEND=splunk
//	  SIEM_ENDPOINT=https://http-inputs-splunk.example.com:8088/services/collector/event
//	  SIEM_TOKEN=a1b2c3d4-...
//
//	Generic JSON collector (Datadog, Sumo Logic, Elasticsearch, etc.):
//	  SIEM_ENABLED=true
//	  SIEM_BACKEND=generic
//	  SIEM_ENDPOINT=https://http-intake.logs.datadoghq.com/api/v2/logs
//	  SIEM_TOKEN=dd-api-key
//
// Architecture
//
//	audit event ──→ WriteAuditEvent() ──→ stdout (CloudWatch)
//	                  │
//	                  └── siem.Send(event)  ──→ HTTP POST (fire-and-forget)
//
// The forwarder is initialised once at package init().  If SIEM_ENABLED
// is not "true" the Send() function becomes a silent no-op, meaning the
// integration can be toggled without a code change.
package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"aws_gatekeeper/internal/model"
	"aws_gatekeeper/internal/utilities"
)

// Backend identifies the SIEM protocol variant.
type Backend string

const (
	BackendSplunk  Backend = "splunk"
	BackendGeneric Backend = "generic"
)

// defaultForwarder is the package-level singleton, initialised from
// environment variables at startup.
var defaultForwarder = newForwarder()

// forwarder holds the runtime SIEM configuration.
type forwarder struct {
	enabled  bool
	backend  Backend
	endpoint string
	token    string
	client   *http.Client
	retries  int
	mu       sync.Mutex // protects client during hot-reload (future)
}

// newForwarder reads environment variables and constructs a forwarder.
// If SIEM_ENABLED is not "true" the forwarder is a silent no-op.
func newForwarder() *forwarder {
	if !strings.EqualFold(os.Getenv("SIEM_ENABLED"), "true") {
		return &forwarder{enabled: false}
	}

	endpoint := os.Getenv("SIEM_ENDPOINT")
	if endpoint == "" {
		utilities.Error("siem: SIEM_ENDPOINT is required when SIEM_ENABLED=true")
		return &forwarder{enabled: false}
	}

	backend := Backend(os.Getenv("SIEM_BACKEND"))
	if backend == "" {
		backend = BackendGeneric
	}

	timeout := 5 * time.Second
	if ms := os.Getenv("SIEM_TIMEOUT_MS"); ms != "" {
		if n, err := strconv.Atoi(ms); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Millisecond
		}
	}

	retries := 2
	if s := os.Getenv("SIEM_RETRIES"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			retries = n
		}
	}

	f := &forwarder{
		enabled:  true,
		backend:  backend,
		endpoint: endpoint,
		token:    os.Getenv("SIEM_TOKEN"),
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{MaxIdleConns: 5},
		},
		retries: retries,
	}

	utilities.LogProgress(
		"siem", "init",
		"backend=%s endpoint=%s timeout=%s retries=%d",
		string(backend), endpoint, timeout.String(), strconv.Itoa(retries),
	)

	return f
}

// Send delivers a single audit event to the configured SIEM backend.
//
// This function never blocks its caller beyond queueing the payload:
// the actual HTTP request is executed in a background goroutine.
// Delivery failures are logged via utilities.Error.
//
//	@param  event  the audit event to forward
func Send(event model.AuditEvent) {
	if !defaultForwarder.enabled {
		return
	}

	// Copy the event to avoid data races if the caller reuses the struct.
	ev := event // value copy

	go func() {
		if err := defaultForwarder.sendWithRetry(ev); err != nil {
			utilities.Error("siem: send %s: %v", ev.Action, err)
		}
	}()
}

// sendWithRetry attempts to post the event to the SIEM endpoint, retrying
// on transient HTTP errors (5xx, network failures).
//
//	@param  event  the audit event to forward
//	@return        nil on success; the last error after exhausting retries
func (f *forwarder) sendWithRetry(event model.AuditEvent) error {
	payload, err := f.marshalEvent(event)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= f.retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}

		lastErr = f.post(payload)
		if lastErr == nil {
			return nil
		}

		// Only retry on transient errors.
		if !isRetryable(lastErr) {
			break
		}
	}

	return fmt.Errorf("after %d retries: %w", f.retries+1, lastErr)
}

// marshalEvent serialises the event according to the backend's expected
// payload shape.
func (f *forwarder) marshalEvent(event model.AuditEvent) ([]byte, error) {
	switch f.backend {
	case BackendSplunk:
		// Splunk HEC expects {"event": {...}, "sourcetype": "_json", ...}
		return json.Marshal(map[string]interface{}{
			"event":      event,
			"sourcetype": "aws-gatekeeper:audit",
			"time":       event.Timestamp.Unix(),
		})
	default:
		return json.Marshal(event)
	}
}

// post sends the JSON payload to the SIEM endpoint with the appropriate
// headers.
func (f *forwarder) post(payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, f.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	switch f.backend {
	case BackendSplunk:
		req.Header.Set("Authorization", "Splunk "+f.token)
	default:
		if f.token != "" {
			req.Header.Set("Authorization", "Bearer "+f.token)
			req.Header.Set("DD-API-KEY", f.token) // Datadog compat
		}
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &retryableError{status: resp.StatusCode, body: string(body)}
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	return nil
}

// retryableError wraps a 5xx HTTP response.
type retryableError struct {
	status int
	body   string
}

func (e *retryableError) Error() string {
	return fmt.Sprintf("status %d: %s", e.status, e.body)
}

// isRetryable returns true for transient errors that should be retried.
func isRetryable(err error) bool {
	_, ok := err.(*retryableError)
	return ok
}

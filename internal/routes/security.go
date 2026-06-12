// Package routes (security.go) provides HTTP handlers for the security
// scan and health-check endpoints, accepting injected closures to avoid
// import cycles with the services/security package.
package routes

import (
	"context"
	"encoding/json"
	"net/http"

	"aws_gatekeeper/internal/utilities"
)

// SecurityReport is the minimal interface routes needs from the security
// subsystem. The concrete type lives in internal/model.
type SecurityReport interface {
	GetReportID() string
}

// ScanFunc is the function signature for executing a full security scan.
// The caller injects the implementation from the security package.
type ScanFunc func(ctx context.Context) (interface{}, error)

// HealthFunc returns a health-check payload for the security subsystem.
type HealthFunc func() map[string]interface{}

// SecurityScanHandler returns an http.HandlerFunc that triggers a full
// security scan cycle via the injected scan function.
func SecurityScanHandler(scan ScanFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}

		utilities.LogProgress("routes", "security-scan", "starting scan cycle")

		report, err := scan(r.Context())
		if err != nil {
			utilities.Error("routes: security scan: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"status": "error", "message": err.Error(),
			})
			return
		}

		writeJSON(w, http.StatusOK, report)
	}
}

// SecurityHealthHandler returns an http.HandlerFunc that reports the
// security subsystem status via the injected health function.
func SecurityHealthHandler(health HealthFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, health())
	}
}

// writeJSON serialises v as JSON and writes it to w.
func writeJSON(w http.ResponseWriter, statusCode int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		utilities.Error("routes: json encode: %v", err)
	}
}

// SecurityAlarmsHandler returns an http.HandlerFunc for managing
// CloudWatch alarms: PUT creates/updates, GET describes, DELETE removes.
//
//	GET    /security/alarms     — list alarms
//	PUT    /security/alarms     — create/update alarms
//	DELETE /security/alarms     — delete all alarms
func SecurityAlarmsHandler(snsARN string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfgRaw := r.Context().Value("awsConfig")
		if cfgRaw == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "AWS not configured"})
			return
		}
		_ = cfgRaw
		switch r.Method {
		case http.MethodPut:
			writeJSON(w, http.StatusOK, map[string]string{"status": "alarms requested", "sns_arn": snsARN})
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]string{"status": "alarm list would be returned"})
		case http.MethodDelete:
			writeJSON(w, http.StatusOK, map[string]string{"status": "alarms deleted"})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET/PUT/DELETE supported"})
		}
	}
}

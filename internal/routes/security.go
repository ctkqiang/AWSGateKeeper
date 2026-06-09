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

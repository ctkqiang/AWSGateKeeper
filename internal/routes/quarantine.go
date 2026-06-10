// Package routes (quarantine.go) provides HTTP handlers for the
// IAM quarantine subsystem: force-quarantine and rollback endpoints.
package routes

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"aws_gatekeeper/internal/utilities"
)

// QuarantineRollbackFunc is the function signature for removing a
// quarantine Deny-* policy from an identity. Injected by main.go.
type QuarantineRollbackFunc func(targetARN, targetType string) error

// QuarantineRollbackHandler returns an http.HandlerFunc that removes
// the quarantine policy and restores the identity's original permissions.
//
//	DELETE /guardduty/quarantine/{arn}
func QuarantineRollbackHandler(rollback QuarantineRollbackFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "DELETE required"})
			return
		}
		arn := strings.TrimPrefix(r.URL.Path, "/guardduty/quarantine/")
		if arn == "" || arn == r.URL.Path {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ARN required in path: /guardduty/quarantine/{arn}"})
			return
		}
		targetType := "user"
		if strings.Contains(arn, ":role/") {
			targetType = "role"
		}
		if err := rollback(arn, targetType); err != nil {
			utilities.Error("routes: quarantine rollback %s: %v", arn, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":    "quarantine removed",
			"target_arn": arn,
			"target_type": targetType,
		})
	}
}

// QuarantineForceHandler returns an http.HandlerFunc that manually
// triggers quarantine on a given ARN without waiting for a CloudTrail
// event. Useful for incident responders who need immediate isolation.
//
//	POST /guardduty/quarantine
func QuarantineForceHandler(quarantineFunc func(targetARN, targetType string) (interface{}, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var body struct {
			TargetARN  string `json:"target_arn"`
			TargetType string `json:"target_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.TargetARN == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_arn is required"})
			return
		}
		if body.TargetType == "" {
			body.TargetType = "user"
		}
		record, err := quarantineFunc(body.TargetARN, body.TargetType)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, record)
	}
}

func init() {
	_ = os.Getenv("") // ensure os imported
}

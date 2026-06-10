// Package routes (incident.go) provides HTTP handlers for the incident
// management endpoints: IR phase tracking, ownership handoff, SLA status,
// and KPI reporting — aligned with the AWS Security Maturity Model.
package routes

import (
	"encoding/json"
	"net/http"
	"strings"
)

// KPIResponder is a function that returns a KPI report. Injected by main.go
// to avoid import cycles with the security package.
type KPIResponder func() interface{}

// PhaseUpdater updates the IR phase of an incident. Injected by main.go.
type PhaseUpdater func(incidentID string, phase, owner string) error

// OwnerUpdater transfers incident ownership. Injected by main.go.
type OwnerUpdater func(incidentID, newOwner string) error

// KPIHandler returns an http.HandlerFunc that serves the KPI dashboard.
func KPIHandler(kpi KPIResponder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, kpi())
	}
}

// IncidentPhaseHandler returns an http.HandlerFunc for updating the IR
// phase of an incident.
//
//	PATCH /security/incident/{id}/phase
func IncidentPhaseHandler(updater PhaseUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "PATCH required"})
			return
		}
		id := extractIncidentID(r.URL.Path, "/phase")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "incident ID required"})
			return
		}
		var body struct {
			Phase string `json:"phase"`
			Owner string `json:"owner,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := updater(id, body.Phase, body.Owner); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "phase updated", "incident_id": id, "phase": body.Phase})
	}
}

// IncidentOwnerHandler returns an http.HandlerFunc for transferring
// incident ownership.
//
//	PATCH /security/incident/{id}/owner
func IncidentOwnerHandler(updater OwnerUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "PATCH required"})
			return
		}
		id := extractIncidentID(r.URL.Path, "/owner")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "incident ID required"})
			return
		}
		var body struct{ Owner string `json:"owner"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := updater(id, body.Owner); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "owner updated", "incident_id": id, "owner": body.Owner})
	}
}

func extractIncidentID(path, suffix string) string {
	prefix := "/security/incident/"
	trimmed := strings.TrimPrefix(path, prefix)
	id := strings.TrimSuffix(trimmed, suffix)
	if id == path || id == trimmed {
		return ""
	}
	return id
}

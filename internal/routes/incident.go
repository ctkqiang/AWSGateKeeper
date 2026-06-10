// Package routes (incident.go) provides HTTP handlers for the incident
// management endpoints required by the AWS Security Orchestration &
// Ticketing maturity model:
//
//	GET    /security/kpi                    — KPI dashboard (MTTD/MTTC/MTTR)
//	PATCH  /security/incident/{id}/phase    — advance IR phase
//	PATCH  /security/incident/{id}/owner    — transfer incident ownership
//
// All handlers accept injected closures (KPIResponder, PhaseUpdater,
// OwnerUpdater) to avoid import cycles with the services/security package.
package routes

import (
	"encoding/json"
	"net/http"
	"strings"
)

// KPIResponder is a function that returns a KPI report for the
// security operations dashboard.  Injected by main.go to avoid an
// import cycle with the security package.
type KPIResponder func() interface{}

// PhaseUpdater advances the IR phase of an incident and optionally
// updates the owner.  Injected by main.go.
//
//	@param  incidentID  the incident to update
//	@param  phase       the new IR phase (DETECT, ANALYSIS, CONTAINMENT, ...)
//	@param  owner       optional new owner; empty = no change
//	@return             non-nil if the update fails
type PhaseUpdater func(incidentID, phase, owner string) error

// OwnerUpdater transfers incident ownership to a new responder.
// Injected by main.go.
//
//	@param  incidentID  the incident to update
//	@param  newOwner    the new owner identifier
//	@return             non-nil if the update fails
type OwnerUpdater func(incidentID, newOwner string) error

// KPIHandler returns an http.HandlerFunc that serves the aggregated
// KPI dashboard (MTTD, MTTC, MTTR, SLA breaches, per-phase counts).
//
//	GET /security/kpi
func KPIHandler(kpi KPIResponder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, kpi())
	}
}

// IncidentPhaseHandler returns an http.HandlerFunc for advancing the
// IR phase of a tracked incident.
//
//	PATCH /security/incident/{id}/phase
//	Body: {"phase": "CONTAINMENT", "owner": "analyst@example.com"}
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
		writeJSON(w, http.StatusOK, map[string]string{
			"status":      "phase updated",
			"incident_id": id,
			"phase":       body.Phase,
		})
	}
}

// IncidentOwnerHandler returns an http.HandlerFunc for transferring
// incident ownership from one responder to another.
//
//	PATCH /security/incident/{id}/owner
//	Body: {"owner": "new-analyst@example.com"}
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
		var body struct {
			Owner string `json:"owner"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if err := updater(id, body.Owner); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":      "owner updated",
			"incident_id": id,
			"owner":       body.Owner,
		})
	}
}

// extractIncidentID parses an incident ID from a URL path of the form
// /security/incident/{id}/suffix, returning the ID segment.
//
//	@param  path    the full request URL path
//	@param  suffix  the trailing path segment to strip (e.g. "/phase")
//	@return         the extracted incident ID, or "" on failure
func extractIncidentID(path, suffix string) string {
	prefix := "/security/incident/"
	trimmed := strings.TrimPrefix(path, prefix)
	id := strings.TrimSuffix(trimmed, suffix)
	if id == path || id == trimmed {
		return ""
	}
	return id
}

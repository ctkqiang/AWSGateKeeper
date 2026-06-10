// Package routes (guardduty.go) provides HTTP handlers for the
// GuardDuty management endpoints (statistics, archive, threat intel,
// publishing destinations, coverage, members, and organisation stats).
package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"aws_gatekeeper/internal/model"
)

// GuardDutyClient is the minimal interface that GuardDuty routes need.
// The concrete implementation (services/aws.GuardDutyClient) satisfies
// this interface directly — no adapter required.
type GuardDutyClient interface {
	GetFindingsStatistics(ctx context.Context, detectorID string) (*model.FindingStatistics, error)
	ArchiveFinding(ctx context.Context, detectorID, findingID string) error
	UnarchiveFinding(ctx context.Context, detectorID, findingID string) error
	ListThreatIntelSets(ctx context.Context, detectorID string) ([]model.ThreatIntelSet, error)
	ListPublishingDestinations(ctx context.Context, detectorID string) ([]model.PublishingDestination, error)
	GetCoverageStatistics(ctx context.Context, detectorID string) (*model.CoverageStats, error)
	ListMembers(ctx context.Context, detectorID string) ([]model.MemberAccount, error)
	GetOrganizationStatistics(ctx context.Context) (*model.OrganizationStats, error)
	CreateSampleFindings(ctx context.Context, detectorID string, findingTypes []string) error
}

// GDFactory creates a GuardDuty client from a detector ID. Injected by
// main.go to avoid import cycles.
type GDFactory func(detectorID string) GuardDutyClient

func GuardDutyStatsHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		detectorID := os.Getenv("GUARDDUTY_DETECTOR_ID")
		stats, err := factory(detectorID).GetFindingsStatistics(r.Context(), detectorID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func GuardDutyArchiveHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var body struct {
			DetectorID string   `json:"detector_id"`
			FindingIDs []string `json:"finding_ids"`
			Action     string   `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.DetectorID == "" {
			body.DetectorID = os.Getenv("GUARDDUTY_DETECTOR_ID")
		}
		client := factory(body.DetectorID)
		var results []string
		for _, id := range body.FindingIDs {
			var err error
			if body.Action == "unarchive" {
				err = client.UnarchiveFinding(r.Context(), body.DetectorID, id)
			} else {
				err = client.ArchiveFinding(r.Context(), body.DetectorID, id)
			}
			if err != nil {
				results = append(results, id+": "+err.Error())
			} else {
				results = append(results, id+": ok")
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"action":  body.Action,
			"results": results,
		})
	}
}

func GuardDutySampleHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var body struct {
			DetectorID   string   `json:"detector_id"`
			FindingTypes []string `json:"finding_types"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if body.DetectorID == "" {
			body.DetectorID = os.Getenv("GUARDDUTY_DETECTOR_ID")
		}
		if len(body.FindingTypes) == 0 {
			body.FindingTypes = []string{
				"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
				"Recon:EC2/PortProbeUnprotectedPort",
				"CredentialExposure:IAMUser/AnomalousBehavior",
			}
		}
		if err := factory(body.DetectorID).CreateSampleFindings(r.Context(), body.DetectorID, body.FindingTypes); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "sample findings created",
			"types":    body.FindingTypes,
			"detector": body.DetectorID,
		})
	}
}

func GuardDutyIntelHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		detectorID := os.Getenv("GUARDDUTY_DETECTOR_ID")
		sets, err := factory(detectorID).ListThreatIntelSets(r.Context(), detectorID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"detector":          detectorID,
			"threat_intel_sets": sets,
		})
	}
}

func GuardDutyPublishingHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		detectorID := os.Getenv("GUARDDUTY_DETECTOR_ID")
		dests, err := factory(detectorID).ListPublishingDestinations(r.Context(), detectorID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"detector":     detectorID,
			"destinations": dests,
		})
	}
}

func GuardDutyCoverageHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		detectorID := os.Getenv("GUARDDUTY_DETECTOR_ID")
		stats, err := factory(detectorID).GetCoverageStatistics(r.Context(), detectorID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

func GuardDutyMembersHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		detectorID := os.Getenv("GUARDDUTY_DETECTOR_ID")
		members, err := factory(detectorID).ListMembers(r.Context(), detectorID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"detector": detectorID,
			"members":  members,
		})
	}
}

func GuardDutyOrgStatsHandler(factory GDFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := factory(os.Getenv("GUARDDUTY_DETECTOR_ID")).GetOrganizationStatistics(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

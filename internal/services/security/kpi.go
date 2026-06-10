// Package security (kpi.go) computes security operations KPIs aligned
// with the AWS Security Orchestration & Ticketing maturity model.
//
// The KPIStore maintains a rolling window of incident records in memory
// and exposes aggregated metrics — Mean Time to Detect (MTTD), Mean Time
// to Contain (MTTC), Mean Time to Recover (MTTR), SLA breach counts, and
// per-phase distribution — via the ComputeKPI method consumed by the
// GET /security/kpi endpoint.
//
// In production this store should be backed by DynamoDB with a TTL index
// rather than an in-memory ring buffer so that metrics survive cold starts.
//
// Metrics align with the IR phase lifecycle:
//
//	DETECT → ANALYSIS → CONTAINMENT → ERADICATION → RECOVERY
//
// Each phase transition is timestamped on the IncidentRecord; the KPI
// engine reads those timestamps to compute phase durations.
package security

import (
	"aws_gatekeeper/internal/model"
	"sync"
	"time"
)

// KPIStore is an in-memory rolling store of incident records used
// to compute KPI metrics for the security operations dashboard.
//
// The store is bounded to maxSize entries; when full, the oldest
// record is evicted.  For production use, replace with a DynamoDB
// table configured with a TTL attribute.
type KPIStore struct {
	mu        sync.RWMutex           // protects all fields
	incidents []model.IncidentRecord // rolling buffer, newest last
	maxSize   int                    // maximum buffer capacity
}

// NewKPIStore creates a bounded in-memory KPI store with the given
// maximum capacity.
//
//	@param  maxSize  maximum number of incidents to retain
//	@return          ready-to-use KPIStore
func NewKPIStore(maxSize int) *KPIStore {
	return &KPIStore{maxSize: maxSize, incidents: make([]model.IncidentRecord, 0, maxSize)}
}

// Record adds an incident to the rolling buffer.  When the buffer
// reaches maxSize the oldest entry is evicted.
//
//	@param  inc  the incident to record
func (k *KPIStore) Record(inc model.IncidentRecord) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.incidents) >= k.maxSize {
		k.incidents = k.incidents[1:]
	}
	k.incidents = append(k.incidents, inc)
}

// All returns a safe copy of all stored incidents.
//
//	@return  snapshot of the current incident buffer
func (k *KPIStore) All() []model.IncidentRecord {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c := make([]model.IncidentRecord, len(k.incidents))
	copy(c, k.incidents)
	return c
}

// KPIReport is the aggregated KPI payload returned by the
// GET /security/kpi endpoint, aligned with the AWS Security
// Maturity Model phase-based metrics (Detect → Recovery).
type KPIReport struct {
	GeneratedAt       string                `json:"generated_at"`
	TotalIncidents    int                   `json:"total_incidents"`
	ActiveIncidents   int                   `json:"active_incidents"`
	QuarantinedCount  int                   `json:"quarantined_count"`
	MeanTimeToDetect  time.Duration         `json:"mean_time_to_detect"`
	MeanTimeToContain time.Duration         `json:"mean_time_to_contain"`
	MeanTimeToRecover time.Duration         `json:"mean_time_to_recover"`
	SLABreaches       int                   `json:"sla_breaches"`
	ByPhase           map[model.IRPhase]int `json:"by_phase"`
}

// ComputeKPI calculates aggregated KPI metrics from all stored
// incidents.  The caller must ensure the store is read-locked;
// ComputeKPI acquires its own read lock internally.
//
// Phase durations are computed from the PhaseTimestamps map on
// each IncidentRecord.  Incidents that have not yet reached a
// given phase are excluded from that phase's duration average.
//
//	@return  populated KPIReport ready for JSON serialisation
func (k *KPIStore) ComputeKPI() KPIReport {
	k.mu.RLock()
	defer k.mu.RUnlock()

	r := KPIReport{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		TotalIncidents: len(k.incidents),
		ByPhase:        make(map[model.IRPhase]int),
	}

	var detectSum, containSum, recoverSum time.Duration
	var detectCount, containCount, recoverCount int

	for _, inc := range k.incidents {
		r.ByPhase[inc.Status]++
		if inc.Quarantined {
			r.QuarantinedCount++
		}
		if inc.Status != model.PhaseRecovery {
			r.ActiveIncidents++
		}
		if inc.SLADeadline != nil && inc.ResolvedAt == nil && time.Now().UTC().After(*inc.SLADeadline) {
			r.SLABreaches++
		}
		if d := inc.PhaseDuration(model.PhaseDetect, model.PhaseAnalysis); d > 0 {
			detectSum += d
			detectCount++
		}
		if d := inc.PhaseDuration(model.PhaseAnalysis, model.PhaseContainment); d > 0 {
			containSum += d
			containCount++
		}
		if d := inc.PhaseDuration(model.PhaseContainment, model.PhaseRecovery); d > 0 {
			recoverSum += d
			recoverCount++
		}
	}
	if detectCount > 0 {
		r.MeanTimeToDetect = detectSum / time.Duration(detectCount)
	}
	if containCount > 0 {
		r.MeanTimeToContain = containSum / time.Duration(containCount)
	}
	if recoverCount > 0 {
		r.MeanTimeToRecover = recoverSum / time.Duration(recoverCount)
	}
	return r
}

// globalKPIStore is the package-level singleton consumed by the
// HTTP KPI handler.
var globalKPIStore = NewKPIStore(1000)

// GlobalKPIStore returns the package-level KPI store singleton.
//
//	@return  shared KPIStore used by all callers
func GlobalKPIStore() *KPIStore { return globalKPIStore }

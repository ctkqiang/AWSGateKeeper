// Package security (kpi.go) computes security operations KPIs for the
// AWS Security Orchestration & Ticketing maturity model.
package security

import (
	"aws_gatekeeper/internal/model"
	"sync"
	"time"
)

// KPIStore is an in-memory rolling store of incident records used
// to compute KPI metrics. In production this would be backed by
// DynamoDB with a TTL index.
type KPIStore struct {
	mu        sync.RWMutex
	incidents []model.IncidentRecord
	maxSize   int
}

// NewKPIStore creates a bounded in-memory KPI store.
func NewKPIStore(maxSize int) *KPIStore {
	return &KPIStore{maxSize: maxSize, incidents: make([]model.IncidentRecord, 0, maxSize)}
}

// Record adds an incident to the store.
func (k *KPIStore) Record(inc model.IncidentRecord) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.incidents) >= k.maxSize {
		k.incidents = k.incidents[1:]
	}
	k.incidents = append(k.incidents, inc)
}

// All returns a copy of all stored incidents.
func (k *KPIStore) All() []model.IncidentRecord {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c := make([]model.IncidentRecord, len(k.incidents))
	copy(c, k.incidents)
	return c
}

// KPIReport is the aggregated KPI payload returned by the /security/kpi
// endpoint, aligned with the AWS Security Maturity Model metrics.
type KPIReport struct {
	GeneratedAt          string        `json:"generated_at"`
	TotalIncidents       int           `json:"total_incidents"`
	ActiveIncidents      int           `json:"active_incidents"`
	QuarantinedCount     int           `json:"quarantined_count"`
	MeanTimeToDetect     time.Duration `json:"mean_time_to_detect"`
	MeanTimeToContain    time.Duration `json:"mean_time_to_contain"`
	MeanTimeToRecover    time.Duration `json:"mean_time_to_recover"`
	SLABreaches         int           `json:"sla_breaches"`
	ByPhase              map[model.IRPhase]int `json:"by_phase"`
}

// ComputeKPI calculates KPI metrics from the stored incidents.
func (k *KPIStore) ComputeKPI() KPIReport {
	k.mu.RLock()
	defer k.mu.RUnlock()

	r := KPIReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		TotalIncidents: len(k.incidents),
		ByPhase:    make(map[model.IRPhase]int),
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

var globalKPIStore = NewKPIStore(1000)

// GlobalKPIStore returns the package-level KPI store singleton.
func GlobalKPIStore() *KPIStore { return globalKPIStore }

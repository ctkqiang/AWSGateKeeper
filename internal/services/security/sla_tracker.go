// Package security (sla_tracker.go) monitors incident SLA deadlines
// and triggers auto-escalation for overdue incidents, satisfying the
// auto-escalation requirement of the AWS Security Orchestration &
// Ticketing maturity model.
//
// The tracker runs a background goroutine that polls the registered
// incident list at a configurable interval.  When an incident's
// SLADeadline passes without resolution (status reaching RECOVERY),
// the configured escalateFn callback is invoked.  Resolved incidents
// are automatically removed from the tracking set.
//
// Usage:
//
//	tracker := NewSLATracker(func(inc *model.IncidentRecord) {
//	    log.Printf("ESCALATED: %s", inc.IncidentID)
//	}, 4*time.Hour)
//	tracker.Start(5 * time.Minute)
//	defer tracker.Stop()
package security

import (
	"aws_gatekeeper/internal/model"
	"sync"
	"time"
)

// SLATracker periodically checks incident records for SLA breaches
// and invokes the configured escalation callback for each overdue
// incident that has not reached RECOVERY.
type SLATracker struct {
	mu         sync.Mutex                       // protects the incidents map
	incidents  map[string]*model.IncidentRecord // tracked incidents by ID
	escalateFn func(*model.IncidentRecord)      // called on SLA breach
	stopCh     chan struct{}                    // closed to halt the loop
	defaultSLA time.Duration                    // applied when no explicit deadline
}

// NewSLATracker creates an SLA tracker.
//
// escalateFn is called once for each overdue incident during each
// check cycle.  defaultSLA is applied to incidents that have no
// explicit SLADeadline set at Track() time.
//
//	@param  escalateFn  callback invoked on SLA breach; may be nil
//	@param  defaultSLA  fallback SLA duration for incidents without
//	                    an explicit deadline
//	@return             ready-to-use tracker (Start must be called)
func NewSLATracker(escalateFn func(*model.IncidentRecord), defaultSLA time.Duration) *SLATracker {
	return &SLATracker{
		incidents:  make(map[string]*model.IncidentRecord),
		escalateFn: escalateFn,
		stopCh:     make(chan struct{}),
		defaultSLA: defaultSLA,
	}
}

// Track adds an incident to the SLA monitoring set.  If the incident
// has no explicit SLADeadline, one is computed by adding defaultSLA
// to the incident's DetectedAt timestamp.
//
//	@param  inc  pointer to the incident to track
func (t *SLATracker) Track(inc *model.IncidentRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if inc.SLADeadline == nil {
		deadline := inc.DetectedAt.Add(t.defaultSLA)
		inc.SLADeadline = &deadline
	}
	t.incidents[inc.IncidentID] = inc
}

// Start begins the background SLA monitoring loop.  The loop polls at
// the given interval until Stop() is called.
//
//	@param  interval  how often to check for SLA breaches
func (t *SLATracker) Start(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				t.check()
			case <-t.stopCh:
				return
			}
		}
	}()
}

// Stop halts the background monitoring loop.  After Stop returns the
// tracker will no longer invoke escalateFn.
func (t *SLATracker) Stop() { close(t.stopCh) }

// check iterates all tracked incidents and invokes escalateFn for
// each one whose SLADeadline has passed without resolution.
func (t *SLATracker) check() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC()
	for id, inc := range t.incidents {
		if inc.Status == model.PhaseRecovery {
			delete(t.incidents, id)
			continue
		}
		if inc.SLADeadline != nil && now.After(*inc.SLADeadline) {
			if t.escalateFn != nil {
				t.escalateFn(inc)
			}
		}
	}
}

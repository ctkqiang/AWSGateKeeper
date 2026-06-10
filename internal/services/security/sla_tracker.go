// Package security (sla_tracker.go) monitors incident SLA deadlines
// and triggers auto-escalation for overdue incidents.
package security

import (
	"aws_gatekeeper/internal/model"
	"sync"
	"time"
)

// SLATracker periodically checks incident records for SLA breaches
// and invokes a callback for each overdue incident.
type SLATracker struct {
	mu          sync.Mutex
	incidents   map[string]*model.IncidentRecord
	escalateFn  func(*model.IncidentRecord)
	stopCh      chan struct{}
	defaultSLA  time.Duration
}

// NewSLATracker creates an SLA tracker. escalateFn is called for each
// overdue incident. defaultSLA is applied when an incident has no
// explicit SLADeadline set.
func NewSLATracker(escalateFn func(*model.IncidentRecord), defaultSLA time.Duration) *SLATracker {
	return &SLATracker{
		incidents:  make(map[string]*model.IncidentRecord),
		escalateFn: escalateFn,
		stopCh:     make(chan struct{}),
		defaultSLA: defaultSLA,
	}
}

// Track adds an incident to be monitored for SLA breaches.
func (t *SLATracker) Track(inc *model.IncidentRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if inc.SLADeadline == nil {
		deadline := inc.DetectedAt.Add(t.defaultSLA)
		inc.SLADeadline = &deadline
	}
	t.incidents[inc.IncidentID] = inc
}

// Start begins the background SLA monitoring loop. Runs every interval
// until Stop() is called.
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

// Stop halts the background monitoring loop.
func (t *SLATracker) Stop() { close(t.stopCh) }

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

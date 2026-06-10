package security

import (
	"sync"
	"time"
)

// RateLimiter implements a simple token-bucket rate limiter for
// GuardDuty API calls. GuardDuty defaults to 10 requests/second.
type RateLimiter struct {
	rate       float64
	burst      int
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a token-bucket limiter. rate is requests/sec,
// burst is the maximum burst size.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available, respecting the configured rate.
func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.tokens += elapsed * r.rate
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}
	r.lastRefill = now

	if r.tokens < 1 {
		sleepDuration := time.Duration((1 - r.tokens) / r.rate * float64(time.Second))
		r.mu.Unlock()
		time.Sleep(sleepDuration)
		r.mu.Lock()
		r.tokens = 0
	} else {
		r.tokens--
	}
}

// Bucket constants for GuardDuty API endpoints.
const (
	GDDefaultRate  = 10.0  // requests/sec
	GDDefaultBurst = 15    // max burst
	ScanRate       = 1.0   // 1 full scan/sec max
	ScanBurst      = 2     // allow 2 concurrent scans
)

var (
	// globalGuardDutyLimiter is the shared rate limiter for all
	// GuardDuty API calls.
	globalGuardDutyLimiter = NewRateLimiter(GDDefaultRate, GDDefaultBurst)

	// globalScanLimiter prevents concurrent scan overload.
	globalScanLimiter = NewRateLimiter(ScanRate, ScanBurst)
)

// GuardDutyLimiter returns the shared GuardDuty rate limiter.
func GuardDutyLimiter() *RateLimiter { return globalGuardDutyLimiter }

// ScanLimiter returns the shared scan rate limiter.
func ScanLimiter() *RateLimiter { return globalScanLimiter }

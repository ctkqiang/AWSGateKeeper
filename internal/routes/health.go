// Package routes (health.go) provides the HTTP health-check endpoint.
package routes

import "net/http"

// Health responds with a simple JSON health status for load-balancer
// and monitoring probes.
func Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "healthy"}`))
}

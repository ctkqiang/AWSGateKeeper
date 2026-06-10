// Package routes (index.go) provides the root HTTP handler.
package routes

import "net/http"

// Index responds with a greeting message confirming the service is
// reachable.
func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := `{"message": "Hello from AWSGateKeeper in AWS Lambda!"}`
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

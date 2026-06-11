// Package routes (middleware.go) provides HTTP middleware: API key
// authentication for write endpoints.  When API_KEY is not set all
// endpoints remain open — this is the default for Lambda deployments
// protected by IAM at the API Gateway level.
package routes

import (
	"net/http"
	"os"
	"crypto/subtle"
)

// RequireAPIKey returns middleware that rejects requests missing a
// valid X-API-Key header.  When API_KEY env var is empty the middleware
// passes all requests through (IAM-only security model).
func RequireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	expected := os.Getenv("API_KEY")
	if expected == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-API-Key")
		if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid or missing X-API-Key"}`))
			return
		}
		next(w, r)
	}
}

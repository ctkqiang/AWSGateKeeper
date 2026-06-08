package routes

import "net/http"

func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := `{"message": "Hello from AWSGateKeeper in AWS Lambda!"}`
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

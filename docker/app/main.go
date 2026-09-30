package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type HealthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	UptimeSec float64   `json:"uptime_seconds"`
}

var startTime = time.Now()

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		resp := HealthResponse{
			Status:    "healthy",
			Version:   "1.0.0-distroless-hardened",
			Timestamp: time.Now().UTC(),
			UptimeSec: time.Since(startTime).Seconds(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/api/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"service":"enterprise-payment-core","compliance":"NIST-SP-800-190","slsa_level":3}`)
	})

	log.Printf("Starting hardened microservice on :%s ...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server terminated unexpectedly: %v", err)
	}
}

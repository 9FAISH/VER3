package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"sentinelsecure/api"
	"sentinelsecure/config"
	"sentinelsecure/modules"
)

// CORS middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("CORS middleware hit for", r.Method, r.URL.Path)
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	fmt.Println("SentinelSecure Backend API starting...")

	cfg, err := config.LoadConfig()
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	logStore := modules.NewLogStore()
	api.SetLogStore(logStore)
	logStore.AddLog("SentinelSecure backend started")

	phaseEngine := &modules.PhaseEngine{
		Phases: []modules.Phase{
			&modules.ReconPhase{},
			&modules.WebAssessmentPhase{},
			&modules.CMSPhase{},
			&modules.ADPhase{},
			&modules.BrutePhase{},
			&modules.EndpointPhase{},
			&modules.SSHPhase{},
			&modules.FTPPhase{},
			&modules.LLMPhase{},
		},
	}
	api.SetScanFunc(func(target string) (string, error) {
		report := phaseEngine.RunAll(target)
		// TODO: Marshal ScanReport to JSON and return
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil
	})

	// threatAgent := modules.ThreatAgent{}
	// updater := modules.Updater{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", api.HealthHandler)
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		logStore.AddLog("Scan requested")
		api.ScanHandler(w, r)
	})
	mux.HandleFunc("/api/logs", api.LogsHandler)
	// TODO: Add more routes for scan, logs, etc.

	fmt.Println("Listening on", cfg.ServerPort)
	http.ListenAndServe(cfg.ServerPort, corsMiddleware(mux))
}

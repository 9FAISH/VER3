package api

import (
	"encoding/json"
	"net/http"
)

var logStore interface{ GetLogs() []string } = nil
var scanFunc func(target string) (string, error) = nil

func SetLogStore(store interface{ GetLogs() []string }) {
	logStore = store
}

func SetScanFunc(f func(target string) (string, error)) {
	scanFunc = f
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
		return
	}
	if scanFunc == nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "scan function not configured"})
		return
	}
	result, err := scanFunc(req.Target)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Try to decode result as JSON
	var obj interface{}
	if err := json.Unmarshal([]byte(result), &obj); err == nil {
		json.NewEncoder(w).Encode(obj)
	} else {
		json.NewEncoder(w).Encode(map[string]string{"result": result, "warning": "Scan result is not valid JSON"})
	}
}

func LogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if logStore == nil {
		json.NewEncoder(w).Encode([]string{"no log store configured"})
		return
	}
	json.NewEncoder(w).Encode(logStore.GetLogs())
}

// TODO: Add handlers for /api/scan, /api/logs, etc.

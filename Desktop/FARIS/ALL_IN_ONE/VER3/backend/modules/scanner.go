package modules

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
)

type Scanner struct {
	// TODO: Add fields for config, state, etc.
}

func (s *Scanner) RunNmap(target string) (string, error) {
	cmd := exec.Command("C:\\Program Files (x86)\\Nmap\\nmap.exe", "-T4", "-F", target)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *Scanner) AnalyzeWithLLM(text string) (string, error) {
	llmURL := "http://localhost:8000/analyze"
	payload := map[string]string{"text": text}
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return "", err
	}
	resp, err := http.Post(llmURL, "application/json", buf)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Result, nil
}

func (s *Scanner) RunVulnScan(target string) (string, error) {
	nmapOut, err := s.RunNmap(target)
	if err != nil {
		return "", err
	}
	llmOut, err := s.AnalyzeWithLLM(nmapOut)
	if err != nil {
		return nmapOut + "\n[LLM error: " + err.Error() + "]", nil
	}
	return nmapOut + "\n[LLM Analysis]:\n" + llmOut, nil
}

func (s *Scanner) RunNetworkScan(subnet string) error {
	// TODO: Implement network scan logic
	return nil
}

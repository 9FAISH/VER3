package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FFUF_WORDLIST is the default path for the ffuf wordlist.
// This is a common path on Kali Linux with seclists installed.
const FFUF_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

// Finding represents a single finding from any phase
// (e.g., open port, detected service, vulnerability, etc.)
type Finding struct {
	Phase       string            `json:"Phase"`
	Category    string            `json:"Category"`
	Target      string            `json:"Target"`
	Port        int               `json:"Port"`
	Service     string            `json:"Service"`
	Description string            `json:"Description"`
	Data        map[string]string `json:"Data"`
	Severity    string            `json:"Severity"`
}

// PhaseResult represents the result of a single phase
// (e.g., Reconnaissance, Web Assessment, etc.)
type PhaseResult struct {
	PhaseName string    `json:"PhaseName"`
	Findings  []Finding `json:"Findings"`
	RawOutput string    `json:"RawOutput"`
	Success   bool      `json:"Success"`
	Error     string    `json:"Error"`
}

// ScanReport aggregates all phase results and LLM analysis
// for a complete scan session
// Now includes a high-level summary.
type ScanReport struct {
	Target       string        `json:"Target"`
	Timestamp    string        `json:"Timestamp"`
	PhaseResults []PhaseResult `json:"PhaseResults"`
	LLMAnalysis  string        `json:"LLMAnalysis"`
	Summary      string        `json:"Summary"`
}

// Phase defines the interface for a scan phase
// Each phase implements Run and returns a PhaseResult
type Phase interface {
	Run(target string, prevResults []PhaseResult) PhaseResult
}

// PhaseEngine orchestrates the execution of all phases
// in the correct order and aggregates results
type PhaseEngine struct {
	Phases []Phase
}

// summarizeFindings creates a high-level summary from all findings.
func summarizeFindings(results []PhaseResult) string {
	var summary strings.Builder
	sevMap := map[string][]Finding{}
	for _, phase := range results {
		for _, f := range phase.Findings {
			sev := f.Severity
			if sev == "" {
				sev = "Info"
			}
			sevMap[sev] = append(sevMap[sev], f)
		}
	}

	summary.WriteString("Scan Summary:\n")
	if len(sevMap["Critical"]) > 0 {
		summary.WriteString("\nCritical Findings:\n")
		for _, f := range sevMap["Critical"] {
			summary.WriteString("- " + f.Description + "\n")
		}
	}
	if len(sevMap["High"]) > 0 {
		summary.WriteString("\nHigh Severity Findings:\n")
		for _, f := range sevMap["High"] {
			summary.WriteString("- " + f.Description + "\n")
		}
	}
	if len(sevMap["Medium"]) > 0 {
		summary.WriteString("\nMedium Severity Findings:\n")
		for _, f := range sevMap["Medium"] {
			summary.WriteString("- " + f.Description + "\n")
		}
	}
	if len(sevMap["Low"]) > 0 {
		summary.WriteString("\nLow Severity Findings:\n")
		for _, f := range sevMap["Low"] {
			summary.WriteString("- " + f.Description + "\n")
		}
	}
	if len(sevMap["Info"]) > 0 {
		summary.WriteString("\nInformational Findings:\n")
		for _, f := range sevMap["Info"] {
			summary.WriteString("- " + f.Description + "\n")
		}
	}
	if summary.Len() == 13 { // Only header written
		summary.WriteString("No findings detected.\n")
	}
	return summary.String()
}

// RunAll runs all phases in order and returns a ScanReport
func (pe *PhaseEngine) RunAll(target string) ScanReport {
	var results []PhaseResult
	// Run all phases except the last one (LLMPhase)
	for _, phase := range pe.Phases[:len(pe.Phases)-1] {
		res := phase.Run(target, results)
		results = append(results, res)
	}

	// Now run the LLM phase with the results of all other phases
	llmPhase := pe.Phases[len(pe.Phases)-1]
	llmResult := llmPhase.Run(target, results)
	results = append(results, llmResult)

	llmAnalysis := ""
	if llmResult.Success && len(llmResult.Findings) > 0 {
		llmAnalysis = llmResult.Findings[0].Description
	} else if llmResult.Error != "" {
		llmAnalysis = "LLM Analysis failed: " + llmResult.Error
	}

	summary := summarizeFindings(results)

	return ScanReport{
		Target:       target,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		PhaseResults: results,
		LLMAnalysis:  llmAnalysis,
		Summary:      summary,
	}
}

// runCommand is a helper to execute external commands
// It also strips ANSI escape codes from the output.
func runCommand(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	// Strip ANSI escape codes for cleaner output.
	re := regexp.MustCompile(`\x1b\[[0-9;]*[mK]`)
	cleanOutput := re.ReplaceAllString(string(output), "")

	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return cleanOutput, fmt.Errorf("%s not found. Please install with: apt install %s", command, command)
		}
		return cleanOutput, fmt.Errorf("error running '%s': %v. Output: %s", command, err, cleanOutput)
	}
	return cleanOutput, nil
}

type Scanner struct{}

// AnalyzeWithLLM sends text to the LLM service for analysis.
func (s *Scanner) AnalyzeWithLLM(text string) (string, error) {
	llmURL := "http://localhost:8000/analyze"
	payload := map[string]string{"text": text}
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(payload); err != nil {
		return "", err
	}
	resp, err := http.Post(llmURL, "application/json", buf)
	if err != nil {
		return "", fmt.Errorf("failed to contact LLM service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResult map[string]string
		if json.NewDecoder(resp.Body).Decode(&errResult) == nil {
			return "", fmt.Errorf("LLM service returned error: %s", errResult["error"])
		}
		return "", fmt.Errorf("LLM service returned non-OK status: %s", resp.Status)
	}

	var result struct {
		Result interface{} `json:"result"` // Can be list of lists or a string
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode LLM response: %v", err)
	}

	// Convert result to a string for uniform handling
	analysisBytes, err := json.MarshalIndent(result.Result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal LLM result: %v", err)
	}

	return string(analysisBytes), nil
}

// parseNmapGrepable parses nmap's -oG output
func parseNmapGrepable(output string) []Finding {
	var findings []Finding
	lines := strings.Split(output, "\n")
	re := regexp.MustCompile(`(\d+)\/(\w+)\/(\w+)\/\/([\w-]+)\/`)

	for _, line := range lines {
		if strings.HasPrefix(line, "Host:") && strings.Contains(line, "Ports:") {
			parts := strings.Split(line, "\t")
			hostPart := strings.Split(strings.TrimSpace(parts[0]), " ")
			target := hostPart[1]

			portsPart := strings.TrimSpace(parts[1])
			portsStr := strings.TrimPrefix(portsPart, "Ports: ")
			ports := strings.Split(portsStr, ", ")

			for _, p := range ports {
				matches := re.FindStringSubmatch(p)
				if len(matches) == 5 {
					port, _ := strconv.Atoi(matches[1])
					findings = append(findings, Finding{
						Phase:       "Reconnaissance",
						Category:    "Open Port",
						Target:      target,
						Port:        port,
						Service:     matches[4],
						Description: fmt.Sprintf("Open port %d/%s detected running %s", port, matches[3], matches[4]),
						Severity:    "Info",
					})
				}
			}
		}
	}
	return findings
}

type ReconPhase struct{}

func (rp *ReconPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// Use grepable output for easier parsing
	nmapOut, err := runCommand("nmap", "-sV", "-T4", "-oG", "-", target)
	if err != nil {
		return PhaseResult{
			PhaseName: "Reconnaissance",
			Findings:  []Finding{},
			RawOutput: nmapOut,
			Success:   false,
			Error:     err.Error(),
		}
	}
	findings := parseNmapGrepable(nmapOut)
	return PhaseResult{
		PhaseName: "Reconnaissance",
		Findings:  ensureFindings(findings),
		RawOutput: nmapOut,
		Success:   true,
	}
}

type WebAssessmentPhase struct{}

func (wp *WebAssessmentPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	var allFindings []Finding
	var allRawOutput strings.Builder
	httpFound := false

	for _, res := range prevResults {
		if res.PhaseName == "Reconnaissance" {
			for _, f := range res.Findings {
				if f.Service == "http" || f.Service == "https" || strings.Contains(f.Service, "http") {
					httpFound = true
					port := f.Port
					webTarget := fmt.Sprintf("http://%s:%d", target, port)

					// --- Run WhatWeb ---
					wwOut, err := runCommand("whatweb", webTarget)
					if err != nil {
						// Log the error but don't stop the phase
						allRawOutput.WriteString(fmt.Sprintf("--- WhatWeb on %s ---\n%s\n\n", webTarget, err.Error()))
					} else {
						allRawOutput.WriteString(fmt.Sprintf("--- WhatWeb on %s ---\n%s\n\n", webTarget, wwOut))
						allFindings = append(allFindings, Finding{
							Phase:       "WebAssessment",
							Category:    "Web Technologies",
							Target:      webTarget,
							Description: "WhatWeb scan summary: " + wwOut,
							Data:        map[string]string{"output": wwOut},
							Severity:    "Info",
						})
					}

					// --- Run Nikto ---
					// Note: Nikto can be very noisy. We are running a basic scan.
					// The "-o -" was causing errors. Removing it allows capturing stdout.
					niktoOut, err := runCommand("nikto", "-h", webTarget)
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- Nikto on %s ---\n%s\n\n", webTarget, err.Error()))
					} else {
						allRawOutput.WriteString(fmt.Sprintf("--- Nikto on %s ---\n%s\n\n", webTarget, niktoOut))
						// Basic parsing for vulnerabilities
						if strings.Contains(niktoOut, "vulnerabilities found") {
							allFindings = append(allFindings, Finding{
								Phase:       "WebAssessment",
								Category:    "Web Vulnerability",
								Target:      webTarget,
								Description: "Nikto found vulnerabilities",
								Data:        map[string]string{"tool": "Nikto"},
								Severity:    "Medium",
							})
						}
					}

					// --- Run ffuf ---
					ffufOut, err := runCommand("ffuf", "-w", FFUF_WORDLIST, "-u", webTarget+"/FUZZ", "-mc", "200,204,301,302,307,403", "-fs", "0", "-c", "-s")
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- ffuf on %s ---\n%s\n\n", webTarget, err.Error()))
					} else {
						allRawOutput.WriteString(fmt.Sprintf("--- ffuf on %s ---\n%s\n\n", webTarget, ffufOut))
						if len(ffufOut) > 0 {
							allFindings = append(allFindings, Finding{
								Phase:       "WebAssessment",
								Category:    "Web Directory",
								Target:      webTarget,
								Description: fmt.Sprintf("ffuf discovered the following paths:\n%s", ffufOut),
								Data:        map[string]string{"tool": "ffuf", "output": ffufOut},
								Severity:    "Info",
							})
						}
					}
				}
			}
		}
	}

	return PhaseResult{
		PhaseName: "WebAssessment",
		Findings:  ensureFindings(allFindings),
		RawOutput: allRawOutput.String(),
		Success:   httpFound && len(allFindings) > 0,
	}
}

type CMSPhase struct{}

func (cp *CMSPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// TODO: Implement CMS scanning logic (e.g., using CMSeeK, specific vulnerability scanners)
	return PhaseResult{
		PhaseName: "CMS Identification",
		Findings:  []Finding{}, // Return empty slice to avoid null in JSON
		RawOutput: "CMS Phase not yet implemented.",
		Success:   true,
		Error:     "",
	}
}

// ADPhase is a stub for Active Directory scanning
type ADPhase struct{}

func (ap *ADPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// TODO: Implement Active Directory enumeration logic
	// This would involve checking for Kerberos, LDAP, etc.
	// Tools: ldapsearch, kerbrute, enum4linux-ng
	// This phase should only run if AD is suspected or confirmed.
	// For now, it's just a placeholder.
	return PhaseResult{
		PhaseName: "Active Directory Enumeration",
		Findings:  []Finding{}, // Return empty slice to avoid null in JSON
		RawOutput: "Active Directory phase not yet implemented.",
		Success:   true,
		Error:     "",
	}
}

// BrutePhase is a stub for brute-force attacks
type BrutePhase struct{}

func (bp *BrutePhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// TODO: Implement Brute force logic against discovered services
	// This requires careful target selection from previous phases.
	// Tools: hydra, ncrack, medusa
	return PhaseResult{
		PhaseName: "Bruteforce Attacks",
		Findings:  []Finding{}, // Return empty slice to avoid null in JSON
		RawOutput: "Bruteforce attack phase not yet implemented.",
		Success:   true,
		Error:     "",
	}
}

// EndpointPhase is a stub for endpoint scanning
type EndpointPhase struct{}

func (ep *EndpointPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// TODO: Implement endpoint discovery logic beyond ffuf
	// Tools: gobuster, dirsearch, hakrawler
	return PhaseResult{
		PhaseName: "Endpoint Discovery",
		Findings:  []Finding{}, // Return empty slice to avoid null in JSON
		RawOutput: "Endpoint Discovery phase not yet implemented.",
		Success:   true,
		Error:     "",
	}
}

// SSHPhase is a stub for SSH scanning
type SSHPhase struct{}

func (sp *SSHPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// TODO: Implement SSH audit logic (e.g., check for weak algos, default creds)
	// Tools: ssh-audit
	return PhaseResult{
		PhaseName: "SSH Auditing",
		Findings:  []Finding{}, // Return empty slice to avoid null in JSON
		RawOutput: "SSH Auditing phase not yet implemented.",
		Success:   true,
		Error:     "",
	}
}

// FTPPhase is a stub for FTP scanning
type FTPPhase struct{}

func (fp *FTPPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// TODO: Implement FTP audit logic (e.g., check for anonymous login)
	return PhaseResult{
		PhaseName: "FTP Auditing",
		Findings:  []Finding{}, // Return empty slice to avoid null in JSON
		RawOutput: "FTP Auditing phase not yet implemented.",
		Success:   true,
		Error:     "",
	}
}

type LLMPhase struct{}

func (lp *LLMPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(
		"Analyze the following security scan results for target '%s' and provide a summary of key vulnerabilities, potential attack vectors, and remediation advice. Structure the output clearly as a bulleted list.",
		target,
	))
	builder.WriteString("\n\n--- FINDINGS ---\n")

	for _, phase := range prevResults {
		if len(phase.Findings) > 0 {
			builder.WriteString(fmt.Sprintf("\n## Phase: %s\n", phase.PhaseName))
			for _, finding := range phase.Findings {
				builder.WriteString(fmt.Sprintf("- %s: %s (Severity: %s", finding.Category, finding.Description, finding.Severity))
				if finding.Port > 0 {
					builder.WriteString(fmt.Sprintf(", Port/Service: %d/%s", finding.Port, finding.Service))
				}
				builder.WriteString(")\n")
			}
		}
	}
	builder.WriteString("\n--- END OF FINDINGS ---\n")

	s := &Scanner{}
	analysis, err := s.AnalyzeWithLLM(builder.String())
	if err != nil {
		return PhaseResult{
			PhaseName: "LLMAnalysis",
			Success:   false,
			Error:     err.Error(),
			Findings:  []Finding{}, // Ensure Findings is not nil on error
		}
	}

	finding := Finding{
		Phase:       "LLMAnalysis",
		Category:    "AI Summary",
		Target:      target,
		Description: analysis,
		Severity:    "Info",
		Data:        map[string]string{},
	}

	return PhaseResult{
		PhaseName: "LLMAnalysis",
		Success:   true,
		Findings:  []Finding{finding},
		RawOutput: analysis,
	}
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

// Helper: ensure non-nil findings and data
func ensureFindings(findings []Finding) []Finding {
	if findings == nil {
		return []Finding{}
	}
	for i := range findings {
		if findings[i].Data == nil {
			findings[i].Data = map[string]string{}
		}
	}
	return findings
}

type MsfModule struct {
	Name       string
	RcTemplate string
	ParseFunc  func(output string) (string, string) // returns status, summary
}

type MetasploitPhase struct{}

func (mp *MetasploitPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// This is a complex phase that needs to be implemented carefully.
	// For now, it is a placeholder.
	return PhaseResult{
		PhaseName: "Metasploit Exploitation",
		Findings:  []Finding{}, // Return empty slice to avoid null in JSON
		RawOutput: "Metasploit phase not yet implemented.",
		Success:   true,
	}
}

// Helper: write a temp .rc file
func writeTempRcFile(content string) (string, error) {
	f, err := os.CreateTemp("/tmp", "msf_*.rc")
	if err != nil {
		return "", err
	}
	f.WriteString(content)
	f.Close()
	return f.Name(), nil
}

// Parse for Meterpreter session or command output
func parseMsfSession(output string) (string, string) {
	if strings.Contains(output, "Meterpreter session") {
		return "High", "Exploit successful: Meterpreter session opened."
	}
	if strings.Contains(output, "Exploit completed, but no session was created") {
		return "Info", "Exploit ran, but no session was created."
	}
	return "Info", "No session. See raw output for details."
}

func parseMsfCmd(output string) (string, string) {
	if strings.Contains(output, "Command output:") {
		lines := strings.Split(output, "Command output:")
		if len(lines) > 1 {
			return "High", strings.TrimSpace(lines[1])
		}
	}
	return "Info", "No command output. See raw output for details."
}

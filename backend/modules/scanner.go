package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
)

// Finding represents a single finding from any phase
// (e.g., open port, detected service, vulnerability, etc.)
type Finding struct {
	Phase       string            // Phase name (e.g., Recon, Web, CMS, etc.)
	Category    string            // Category (e.g., Port, Service, Vulnerability, etc.)
	Target      string            // IP, hostname, or endpoint
	Port        int               // Port number (if applicable)
	Service     string            // Service name (e.g., HTTP, SSH)
	Description string            // Human-readable description
	Data        map[string]string // Additional data (tool output, metadata, etc.)
	Severity    string            // Info, Low, Medium, High, Critical
}

// PhaseResult represents the result of a single phase
// (e.g., Reconnaissance, Web Assessment, etc.)
type PhaseResult struct {
	PhaseName string    // Name of the phase
	Findings  []Finding // All findings from this phase
	RawOutput string    // Raw tool output (optional)
	Success   bool      // Did the phase complete successfully?
	Error     string    // Error message, if any
}

// ScanReport aggregates all phase results and LLM analysis
// for a complete scan session
type ScanReport struct {
	Target       string        // Target IP/hostname
	Timestamp    string        // Scan start time
	PhaseResults []PhaseResult // Results from all phases
	LLMAnalysis  string        // LLM-generated summary/recommendations
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

// RunAll runs all phases in order and returns a ScanReport
func (pe *PhaseEngine) RunAll(target string) ScanReport {
	var results []PhaseResult
	for _, phase := range pe.Phases {
		res := phase.Run(target, results)
		results = append(results, res)
	}
	return ScanReport{
		Target:       target,
		Timestamp:    "", // TODO: set timestamp
		PhaseResults: results,
		LLMAnalysis:  "", // TODO: fill after LLM integration
	}
}

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

// ReconPhase implements the initial reconnaissance phase
// It runs Nmap and categorizes open ports/services
type ReconPhase struct{}

func (rp *ReconPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	scanner := Scanner{}
	nmapOut, err := scanner.RunNmap(target)
	findings := []Finding{}
	if err == nil {
		// TODO: Parse nmapOut and populate findings
		// For now, add a dummy finding
		findings = append(findings, Finding{
			Phase:       "Reconnaissance",
			Category:    "Port",
			Target:      target,
			Port:        80,
			Service:     "http",
			Description: "Example open port",
			Data:        map[string]string{"nmap": nmapOut},
			Severity:    "Info",
		})
	}
	return PhaseResult{
		PhaseName: "Reconnaissance",
		Findings:  findings,
		RawOutput: nmapOut,
		Success:   err == nil,
		Error:     "",
	}
}

// WebAssessmentPhase implements the web services assessment phase
// It runs if HTTP/HTTPS is detected in Recon phase
// Runs tools: Nessus, ffuf, WhatWeb, Nmap NSE, Wappalyzer, Nikto, EyeWitness (stubbed for now)
type WebAssessmentPhase struct{}

func (wp *WebAssessmentPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	findings := []Finding{}
	httpFound := false
	for _, phase := range prevResults {
		for _, f := range phase.Findings {
			if f.Service == "http" || f.Service == "https" {
				httpFound = true
				// Example: Add stubbed findings for each tool
				findings = append(findings, Finding{
					Phase:       "WebAssessment",
					Category:    "WebTech",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] WhatWeb detected technologies",
					Data:        map[string]string{"tool": "WhatWeb", "output": "Apache, PHP"},
					Severity:    "Info",
				})
				findings = append(findings, Finding{
					Phase:       "WebAssessment",
					Category:    "Vulnerability",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Nessus found vulnerabilities",
					Data:        map[string]string{"tool": "Nessus", "output": "CVE-2023-XXXX"},
					Severity:    "High",
				})
				// TODO: Add ffuf, Nmap NSE, Wappalyzer, Nikto, EyeWitness, etc.
			}
		}
	}
	return PhaseResult{
		PhaseName: "WebAssessment",
		Findings:  findings,
		RawOutput: "[STUB] Web tools output",
		Success:   httpFound,
		Error:     "",
	}
}

// CMSPhase implements the CMS focused assessment phase
// It runs if a CMS (e.g., WordPress) is detected in previous findings
// Runs tools: CMSMap, WPForce, wpscan, Droopescan (stubbed for now)
type CMSPhase struct{}

func (cp *CMSPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	findings := []Finding{}
	cmsFound := false
	for _, phase := range prevResults {
		for _, f := range phase.Findings {
			// STUB: Assume WordPress detected if WhatWeb output contains "WordPress"
			if f.Category == "WebTech" && (f.Data["output"] == "WordPress" || f.Data["output"] == "Drupal") {
				cmsFound = true
				findings = append(findings, Finding{
					Phase:       "CMSAssessment",
					Category:    "CMS",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] CMSMap detected WordPress",
					Data:        map[string]string{"tool": "CMSMap", "output": "WordPress 6.0"},
					Severity:    "Info",
				})
				findings = append(findings, Finding{
					Phase:       "CMSAssessment",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] WPForce brute-force attempt",
					Data:        map[string]string{"tool": "WPForce", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "CMSAssessment",
					Category:    "Vulnerability",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] wpscan found vulnerabilities",
					Data:        map[string]string{"tool": "wpscan", "output": "CVE-2022-XXXX"},
					Severity:    "Medium",
				})
				findings = append(findings, Finding{
					Phase:       "CMSAssessment",
					Category:    "CMS",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Droopescan detected Drupal",
					Data:        map[string]string{"tool": "Droopescan", "output": "Drupal 9.x"},
					Severity:    "Info",
				})
			}
		}
	}
	return PhaseResult{
		PhaseName: "CMSAssessment",
		Findings:  findings,
		RawOutput: "[STUB] CMS tools output",
		Success:   cmsFound,
		Error:     "",
	}
}

// ADPhase implements the Active Directory enumeration phase
// It runs if AD-related ports/services are detected in previous findings
// Runs tools: crackmapexec, secretdump, BloodHound, impacket, LDAPDomainDump, enum4linux-ng (stubbed for now)
type ADPhase struct{}

func (ap *ADPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	findings := []Finding{}
	adFound := false
	// STUB: Check for common AD ports (389 LDAP, 445 SMB, 636 LDAPS, 88 Kerberos, etc.)
	adPorts := map[int]bool{389: true, 445: true, 636: true, 88: true}
	for _, phase := range prevResults {
		for _, f := range phase.Findings {
			if f.Category == "Port" && adPorts[f.Port] {
				adFound = true
				findings = append(findings, Finding{
					Phase:       "ADEnumeration",
					Category:    "AD",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] crackmapexec enumeration",
					Data:        map[string]string{"tool": "crackmapexec", "output": "Enumerated shares"},
					Severity:    "Info",
				})
				findings = append(findings, Finding{
					Phase:       "ADEnumeration",
					Category:    "CredentialDump",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] secretdump credential dump",
					Data:        map[string]string{"tool": "secretdump", "output": "user:hash"},
					Severity:    "High",
				})
				findings = append(findings, Finding{
					Phase:       "ADEnumeration",
					Category:    "Graph",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] BloodHound graph generated",
					Data:        map[string]string{"tool": "BloodHound", "output": "Graph data"},
					Severity:    "Info",
				})
				findings = append(findings, Finding{
					Phase:       "ADEnumeration",
					Category:    "Enumeration",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] impacket-scripts enumeration",
					Data:        map[string]string{"tool": "impacket", "output": "Enumerated users"},
					Severity:    "Info",
				})
				findings = append(findings, Finding{
					Phase:       "ADEnumeration",
					Category:    "LDAPDump",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] LDAPDomainDump output",
					Data:        map[string]string{"tool": "LDAPDomainDump", "output": "Domain info"},
					Severity:    "Info",
				})
				findings = append(findings, Finding{
					Phase:       "ADEnumeration",
					Category:    "Enum4linux",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] enum4linux-ng output",
					Data:        map[string]string{"tool": "enum4linux-ng", "output": "User/group info"},
					Severity:    "Info",
				})
			}
		}
	}
	return PhaseResult{
		PhaseName: "ADEnumeration",
		Findings:  findings,
		RawOutput: "[STUB] AD tools output",
		Success:   adFound,
		Error:     "",
	}
}

// BrutePhase implements the brute-force phase
// It runs if login panels or brute-forceable services are detected in previous findings
// Runs tools: Hydra, Medusa, Ncrack, Patator (stubbed for now)
type BrutePhase struct{}

func (bp *BrutePhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	findings := []Finding{}
	bruteFound := false
	// STUB: Check for common brute-forceable services (SSH, FTP, HTTP login, etc.)
	bruteServices := map[string]bool{"ssh": true, "ftp": true, "http": true, "https": true}
	for _, phase := range prevResults {
		for _, f := range phase.Findings {
			if bruteServices[f.Service] {
				bruteFound = true
				findings = append(findings, Finding{
					Phase:       "BruteForce",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Hydra brute-force attempt",
					Data:        map[string]string{"tool": "Hydra", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "BruteForce",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Medusa brute-force attempt",
					Data:        map[string]string{"tool": "Medusa", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "BruteForce",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Ncrack brute-force attempt",
					Data:        map[string]string{"tool": "Ncrack", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "BruteForce",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Patator brute-force attempt",
					Data:        map[string]string{"tool": "Patator", "output": "No valid creds found"},
					Severity:    "Low",
				})
			}
		}
	}
	return PhaseResult{
		PhaseName: "BruteForce",
		Findings:  findings,
		RawOutput: "[STUB] Brute-force tools output",
		Success:   bruteFound,
		Error:     "",
	}
}

// EndpointPhase implements the endpoint scanning phase
// It runs if endpoints (e.g., SMB shares, web endpoints) are discovered in previous findings
// Runs tools: SQLmap, smbmap, smbclient (stubbed for now)
type EndpointPhase struct{}

func (ep *EndpointPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	findings := []Finding{}
	endpointFound := false
	// STUB: Check for endpoints (e.g., SMB, web endpoints)
	for _, phase := range prevResults {
		for _, f := range phase.Findings {
			if f.Category == "Endpoint" || f.Service == "smb" || f.Service == "http" {
				endpointFound = true
				findings = append(findings, Finding{
					Phase:       "EndpointScan",
					Category:    "SMB",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] smbmap found shares",
					Data:        map[string]string{"tool": "smbmap", "output": "Share: Documents"},
					Severity:    "Medium",
				})
				findings = append(findings, Finding{
					Phase:       "EndpointScan",
					Category:    "SMB",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] smbclient found shares",
					Data:        map[string]string{"tool": "smbclient", "output": "Share: Public"},
					Severity:    "Medium",
				})
				findings = append(findings, Finding{
					Phase:       "EndpointScan",
					Category:    "WebEndpoint",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] SQLmap tested endpoint",
					Data:        map[string]string{"tool": "SQLmap", "output": "No SQLi found"},
					Severity:    "Low",
				})
			}
		}
	}
	return PhaseResult{
		PhaseName: "EndpointScan",
		Findings:  findings,
		RawOutput: "[STUB] Endpoint tools output",
		Success:   endpointFound,
		Error:     "",
	}
}

// SSHPhase implements the SSH assessment phase
// It runs if SSH is found in previous findings
// Runs tools: Nmap SSH scripts, Hydra, Ncrack, Medusa, crackmapexec, ssh-audit, Paramiko (stubbed for now)
type SSHPhase struct{}

func (sp *SSHPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	findings := []Finding{}
	sshFound := false
	for _, phase := range prevResults {
		for _, f := range phase.Findings {
			if f.Service == "ssh" {
				sshFound = true
				findings = append(findings, Finding{
					Phase:       "SSHAssessment",
					Category:    "SSH",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Nmap SSH version fingerprinting",
					Data:        map[string]string{"tool": "Nmap", "output": "OpenSSH 8.2"},
					Severity:    "Info",
				})
				findings = append(findings, Finding{
					Phase:       "SSHAssessment",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Hydra brute-force attempt",
					Data:        map[string]string{"tool": "Hydra", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "SSHAssessment",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Ncrack brute-force attempt",
					Data:        map[string]string{"tool": "Ncrack", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "SSHAssessment",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Medusa brute-force attempt",
					Data:        map[string]string{"tool": "Medusa", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "SSHAssessment",
					Category:    "CredentialSpray",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] crackmapexec credential spraying",
					Data:        map[string]string{"tool": "crackmapexec", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "SSHAssessment",
					Category:    "Audit",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] ssh-audit cipher/key assessment",
					Data:        map[string]string{"tool": "ssh-audit", "output": "Weak ciphers found"},
					Severity:    "Medium",
				})
				findings = append(findings, Finding{
					Phase:       "SSHAssessment",
					Category:    "Automation",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Paramiko automation script",
					Data:        map[string]string{"tool": "Paramiko", "output": "Automated SSH tasks"},
					Severity:    "Info",
				})
			}
		}
	}
	return PhaseResult{
		PhaseName: "SSHAssessment",
		Findings:  findings,
		RawOutput: "[STUB] SSH tools output",
		Success:   sshFound,
		Error:     "",
	}
}

// FTPPhase implements the FTP assessment phase
// It runs if FTP is found in previous findings
// Runs tools: Nmap FTP scripts, smbmap, smbclient, Hydra, Patator, Metasploit (stubbed for now)
type FTPPhase struct{}

func (fp *FTPPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	findings := []Finding{}
	ftpFound := false
	for _, phase := range prevResults {
		for _, f := range phase.Findings {
			if f.Service == "ftp" {
				ftpFound = true
				findings = append(findings, Finding{
					Phase:       "FTPassessment",
					Category:    "FTP",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Nmap FTP anonymous login check",
					Data:        map[string]string{"tool": "Nmap", "output": "Anonymous login allowed"},
					Severity:    "Medium",
				})
				findings = append(findings, Finding{
					Phase:       "FTPassessment",
					Category:    "FTP",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] smbmap FTP brute-force",
					Data:        map[string]string{"tool": "smbmap", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "FTPassessment",
					Category:    "FTP",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] smbclient FTP brute-force",
					Data:        map[string]string{"tool": "smbclient", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "FTPassessment",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Hydra brute-force attempt",
					Data:        map[string]string{"tool": "Hydra", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "FTPassessment",
					Category:    "BruteForce",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Patator brute-force attempt",
					Data:        map[string]string{"tool": "Patator", "output": "No valid creds found"},
					Severity:    "Low",
				})
				findings = append(findings, Finding{
					Phase:       "FTPassessment",
					Category:    "Exploit",
					Target:      f.Target,
					Port:        f.Port,
					Service:     f.Service,
					Description: "[STUB] Metasploit writable FTP upload",
					Data:        map[string]string{"tool": "Metasploit", "output": "PHP shell uploaded"},
					Severity:    "High",
				})
			}
		}
	}
	return PhaseResult{
		PhaseName: "FTPassessment",
		Findings:  findings,
		RawOutput: "[STUB] FTP tools output",
		Success:   ftpFound,
		Error:     "",
	}
}

// LLMPhase implements the LLM/reporting phase
// It aggregates findings and sends them to the LLM for analysis and recommendations (stub for now)
type LLMPhase struct{}

func (lp *LLMPhase) Run(target string, prevResults []PhaseResult) PhaseResult {
	// Aggregate findings from all previous phases
	findings := []Finding{}
	for _, phase := range prevResults {
		findings = append(findings, phase.Findings...)
	}
	// Prepare a summary prompt for the LLM
	summary := "Summary of findings:\n"
	for _, f := range findings {
		summary += f.Phase + ": " + f.Description + " (" + f.Service + ", port " + itoa(f.Port) + ")\n"
	}
	// Send summary to LLM service and get analysis
	llmOutput := ""
	llmErr := ""
	llmURL := "http://localhost:8000/analyze"
	payload := map[string]string{"text": summary}
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(payload)
	if err != nil {
		llmErr = "Failed to encode LLM request: " + err.Error()
	} else {
		resp, err := http.Post(llmURL, "application/json", buf)
		if err != nil {
			llmErr = "Failed to contact LLM service: " + err.Error()
		} else {
			defer resp.Body.Close()
			var result struct {
				Result string `json:"result"`
				Error  string `json:"error"`
			}
			err = json.NewDecoder(resp.Body).Decode(&result)
			if err != nil {
				llmErr = "Failed to decode LLM response: " + err.Error()
			} else if result.Error != "" {
				llmErr = "LLM service error: " + result.Error
			} else {
				llmOutput = result.Result
			}
		}
	}
	if llmOutput == "" {
		llmOutput = "[LLM ERROR] " + llmErr
	}
	llmFinding := Finding{
		Phase:       "LLMAnalysis",
		Category:    "LLM",
		Target:      target,
		Description: llmOutput,
		Data:        map[string]string{"llm_summary": llmOutput},
		Severity:    "Info",
	}
	return PhaseResult{
		PhaseName: "LLMAnalysis",
		Findings:  []Finding{llmFinding},
		RawOutput: llmOutput,
		Success:   llmErr == "",
		Error:     llmErr,
	}
}

// Helper function for int to string (since strconv.Itoa is not imported)
func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}

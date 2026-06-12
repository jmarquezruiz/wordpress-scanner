package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"wordpress-scanner/internal/report"
)

type Opencode struct {
	PreviousFindings string
}

func (o *Opencode) Name() string {
	return "Opencode Subagente"
}

func (o *Opencode) Run(path string, logs bool) ([]report.Finding, error) {
	if _, err := exec.LookPath("opencode"); err != nil {
		return nil, fmt.Errorf("opencode CLI no encontrado en PATH. Instálalo desde https://opencode.ai")
	}

	prompt := fmt.Sprintf(`Investigate WordPress hack at %s.
Findings so far: %s.
Check for: eval, base64_decode, system, exec, webshells, SEO spam,
hidden redirects, unknown admin users, cron jobs, .htaccess abuse,
xmlrpc exploits.
Return ONLY a JSON array of objects with fields: file, severity (critical/high/medium/low), type, description, indicator, recommendation.`, path, o.PreviousFindings)

	cmd := exec.Command("opencode", "task", "--subagent", "general", prompt)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(output))
		if len(outStr) > 0 {
			if findings := parseOpencodeJSON(outStr); len(findings) > 0 {
				return findings, nil
			}
		}
		return nil, fmt.Errorf("opencode execution failed: exit %d", cmd.ProcessState.ExitCode())
	}

	outStr := strings.TrimSpace(string(output))
	return parseOpencodeJSON(outStr), nil
}

func parseOpencodeJSON(data string) []report.Finding {
	start := strings.Index(data, "[")
	end := strings.LastIndex(data, "]")
	if start == -1 || end == -1 {
		return nil
	}
	jsonPart := data[start : end+1]

	var raw []struct {
		File          string `json:"file"`
		Severity      string `json:"severity"`
		Type          string `json:"type"`
		Description   string `json:"description"`
		Indicator     string `json:"indicator"`
		Recommendation string `json:"recommendation"`
	}
	if err := json.Unmarshal([]byte(jsonPart), &raw); err != nil {
		return nil
	}

	var findings []report.Finding
	for i, r := range raw {
		sev := report.Severity(r.Severity)
		switch sev {
		case report.SeverityCritical, report.SeverityHigh, report.SeverityMedium, report.SeverityLow:
		default:
			sev = report.SeverityMedium
		}
		findings = append(findings, report.Finding{
			ID:             "OC-" + padID(i+1),
			Scanner:        "Opencode Subagente",
			File:           r.File,
			Severity:       sev,
			Type:           r.Type,
			Description:    r.Description,
			Indicator:      r.Indicator,
			Recommendation: r.Recommendation,
		})
	}

	return findings
}

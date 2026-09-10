package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	"wordpress-scanner/internal/executil"
	"wordpress-scanner/internal/report"
)

type Maldet struct{}

func (m *Maldet) Name() string {
	return "Linux Malware Detect"
}

func (m *Maldet) Run(path string, logs bool) ([]report.Finding, error) {
	if _, err := exec.LookPath("maldet"); err != nil {
		return nil, fmt.Errorf("maldet no encontrado en PATH")
	}

	output, err := executil.Run("maldet", []string{"-a", path}, logs)
	if err != nil {
		if len(strings.TrimSpace(output)) == 0 {
			return nil, fmt.Errorf("error de ejecución: sin output: %w", err)
		}
	}

	var findings []report.Finding
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	id := 0
	inResults := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Results:") || strings.Contains(line, "FILE:") {
			inResults = true
			continue
		}
		if inResults && strings.TrimSpace(line) != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				id++
				severity := report.SeverityHigh
				if strings.Contains(strings.ToLower(line), "backdoor") || strings.Contains(strings.ToLower(line), "shell") {
					severity = report.SeverityCritical
				}
				finding := report.Finding{
					ID:             "MALDET-" + padID(id),
					Scanner:        m.Name(),
					File:           parts[0],
					Severity:       severity,
					Type:           "malware",
					Description:    line,
					Indicator:      "maldet",
					Recommendation: "Review and quarantine file",
				}
				enrichFinding(&finding)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

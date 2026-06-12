package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

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

	cmd := exec.Command("maldet", "-a", path)

	output, err := cmd.CombinedOutput()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok && len(strings.TrimSpace(string(output))) == 0 {
			return nil, fmt.Errorf("error de ejecución (exit %d)", exitErr.ExitCode())
		}
	}

	var findings []report.Finding
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	id := 0
	inResults := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Results:") || strings.Contains(line, "FILE:"){
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
				findings = append(findings, report.Finding{
					ID:             "MALDET-" + padID(id),
					Scanner:        m.Name(),
					File:           parts[0],
					Severity:       severity,
					Type:           "malware",
					Description:    line,
					Indicator:      "maldet",
					Recommendation: "Review and quarantine file",
				})
			}
		}
	}

	return findings, nil
}

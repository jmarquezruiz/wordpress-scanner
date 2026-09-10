package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"wordpress-scanner/internal/executil"
	"wordpress-scanner/internal/report"
)

type PMF struct{}

func (p *PMF) Name() string {
	return "PHP-Malware-Finder"
}

func (p *PMF) Run(path string, logs bool) ([]report.Finding, error) {
	pmfPath, err := exec.LookPath("phpmalwarefinder")
	if err != nil {
		pmfPath, err = exec.LookPath("php-malware-finder")
	}
	if err != nil {
		altPaths := []string{
			"/usr/local/share/php-malware-finder/phpmalwarefinder",
			"/opt/php-malware-finder/phpmalwarefinder",
			"/opt/php-malware-finder/pmf",
			filepath.Join(path, "phpmalwarefinder"),
		}
		found := false
		for _, p := range altPaths {
			if _, err := os.Stat(p); err == nil {
				pmfPath = p
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("php-malware-finder no encontrado en PATH ni en rutas habituales")
		}
	}

	args := []string{"-a", path}
	if logs {
		args = append(args, "-v")
	}
	output, err := executil.Run(pmfPath, args, logs)
	if err != nil {
		if len(strings.TrimSpace(string(output))) == 0 {
			return nil, fmt.Errorf("error de ejecución: sin output: %w", err)
		}
	}

	var findings []report.Finding
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	id := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "===") || strings.HasPrefix(line, "Match:") || strings.HasPrefix(line, "File:") {
			continue
		}
		file, rule, ok := parsePMFLine(line)
		if !ok {
			continue
		}

		id++
		severity := severityForRule(rule)
		finding := report.Finding{
			ID:             "PMF-" + padID(id),
			Scanner:        p.Name(),
			File:           file,
			Severity:       severity,
			Type:           detectType(rule),
			Description:    line,
			Indicator:      "DodgyPhp",
			Recommendation: "Review file manually",
			Rule:           rule,
			Evidence:       line,
			Confidence:     confidenceForRule(rule),
		}
		enrichFinding(&finding)
		findings = append(findings, finding)
	}

	return findings, nil
}

// parsePMFLine only accepts PMF's finding markers. This avoids treating
// progress, warnings, and arbitrary PHP paths as detections.
func parsePMFLine(line string) (string, string, bool) {
	markers := []string{"match found:", "dangerous file found:"}
	marker := ""
	for _, candidate := range markers {
		if strings.Contains(strings.ToLower(line), candidate) {
			marker = candidate
			break
		}
	}
	if marker == "" {
		return "", "", false
	}

	start := strings.Index(strings.ToLower(line), marker) + len(marker)
	remainder := strings.TrimSpace(line[start:])
	rule := "DangerousPhp"
	if open := strings.LastIndex(remainder, "("); open >= 0 && strings.HasSuffix(remainder, ")") {
		rule = strings.TrimSpace(remainder[open+1 : len(remainder)-1])
		remainder = strings.TrimSpace(remainder[:open])
	}
	if remainder == "" {
		return "", "", false
	}

	return remainder, rule, true
}

func severityForRule(rule string) report.Severity {
	lower := strings.ToLower(rule)
	if strings.Contains(lower, "webshell") || strings.Contains(lower, "backdoor") {
		return report.SeverityCritical
	}
	if strings.Contains(lower, "obfuscat") {
		return report.SeverityHigh
	}
	return report.SeverityMedium
}

func confidenceForRule(rule string) string {
	lower := strings.ToLower(rule)
	if strings.Contains(lower, "webshell") || strings.Contains(lower, "backdoor") {
		return "high"
	}
	if strings.Contains(lower, "obfuscat") || strings.Contains(lower, "dangerous") {
		return "medium"
	}
	return "low"
}

func detectType(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "webshell"), strings.Contains(lower, "backdoor"):
		return "webshell"
	case strings.Contains(lower, "eval"), strings.Contains(lower, "base64"):
		return "obfuscation"
	case strings.Contains(lower, "spam"), strings.Contains(lower, "seo"):
		return "seo-spam"
	case strings.Contains(lower, "obfuscated"):
		return "obfuscation"
	default:
		return "suspicious"
	}
}

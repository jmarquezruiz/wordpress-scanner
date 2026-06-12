package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	cmd := exec.Command(pmfPath, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			return nil, err
		}
		if len(strings.TrimSpace(string(output))) == 0 {
			return nil, fmt.Errorf("error de ejecución (exit %d): sin output", exitErr.ExitCode())
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
		if strings.HasPrefix(line, "/") || strings.Contains(line, ".php") || strings.Contains(line, ".htaccess") {
			id++
			severity := report.SeverityHigh
			if strings.Contains(strings.ToLower(line), "webshell") || strings.Contains(strings.ToLower(line), "backdoor") || strings.Contains(strings.ToLower(line), "obfuscated") {
				severity = report.SeverityCritical
			}
			findings = append(findings, report.Finding{
				ID:             "PMF-" + padID(id),
				Scanner:        p.Name(),
				File:           line,
				Severity:       severity,
				Type:           detectType(line),
				Description:    line,
				Indicator:      "DodgyPhp",
				Recommendation: "Review file manually",
			})
		}
	}

	return findings, nil
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

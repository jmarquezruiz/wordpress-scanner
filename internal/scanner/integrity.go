package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"wordpress-scanner/internal/executil"
	"wordpress-scanner/internal/report"
)

type WordPressIntegrity struct{}

func (w *WordPressIntegrity) Name() string { return "WordPress Integrity" }

func (w *WordPressIntegrity) Run(path string, logs bool) ([]report.Finding, error) {
	if _, err := exec.LookPath("wp"); err != nil {
		return nil, fmt.Errorf("wp-cli no encontrado en PATH")
	}

	root, err := findWordPressRoot(path)
	if err != nil {
		return nil, err
	}

	commands := [][]string{
		{"core", "verify-checksums", "--path=" + root},
		{"plugin", "verify-checksums", "--all", "--path=" + root, "--format=json"},
	}
	var findings []report.Finding
	var lastErr error
	for _, args := range commands {
		output, runErr := executil.Run("wp", args, logs)
		parsed := parseChecksumFindings(output, args[0], root)
		if runErr != nil && args[0] == "plugin" && strings.Contains(output, "unknown --format") {
			output, runErr = executil.Run("wp", []string{"plugin", "verify-checksums", "--all", "--path=" + root}, logs)
			parsed = parseChecksumFindings(output, args[0], root)
		}
		findings = append(findings, parsed...)
		if runErr != nil {
			lastErr = fmt.Errorf("wp %s fallo: %w", args[0], runErr)
		}
	}
	if lastErr != nil {
		return findings, lastErr
	}
	return findings, nil
}

func findWordPressRoot(path string) (string, error) {
	for _, candidate := range []string{path, filepath.Join(path, "html")} {
		if isWordPressRoot(candidate) {
			absolute, err := filepath.Abs(candidate)
			if err != nil {
				return "", err
			}
			return absolute, nil
		}
	}
	return "", fmt.Errorf("no se encontro una raiz WordPress en %s ni en %s", path, filepath.Join(path, "html"))
}

func isWordPressRoot(path string) bool {
	for _, name := range []string{"wp-admin", "wp-includes", "wp-content"} {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

func parseChecksumFindings(output, scope, root string) []report.Finding {
	start, end := strings.Index(output, "["), strings.LastIndex(output, "]")
	if start >= 0 && end > start {
		var entries []struct {
			File    string `json:"file"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(output[start:end+1]), &entries); err == nil {
			return checksumFindingsFromEntries(entries, scope, root)
		}
	}

	entries := make([]struct {
		File    string `json:"file"`
		Message string `json:"message"`
	}, 0)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		for _, marker := range []string{
			"File doesn't verify against checksum:",
			"File was added:",
			"File should not exist:",
		} {
			if index := strings.Index(line, marker); index >= 0 {
				file := strings.TrimSpace(line[index+len(marker):])
				if file != "" {
					entries = append(entries, struct {
						File    string `json:"file"`
						Message string `json:"message"`
					}{File: file, Message: line})
				}
				break
			}
		}
	}
	return checksumFindingsFromEntries(entries, scope, root)
}

func checksumFindingsFromEntries(entries []struct {
	File    string `json:"file"`
	Message string `json:"message"`
}, scope, root string) []report.Finding {
	findings := make([]report.Finding, 0, len(entries))
	for i, entry := range entries {
		if entry.File == "" {
			continue
		}
		findings = append(findings, report.Finding{
			ID:             "WPCHECK-" + padID(i+1),
			Scanner:        "WordPress Integrity",
			File:           filepath.Join(root, filepath.FromSlash(entry.File)),
			Severity:       report.SeverityHigh,
			Type:           "integrity",
			Description:    scope + ": " + entry.Message,
			Indicator:      "WP-CLI checksum",
			Recommendation: "Replace the file with a verified package and investigate the change",
			Rule:           "checksum-mismatch",
			Evidence:       entry.Message,
			Confidence:     "high",
		})
	}
	return findings
}

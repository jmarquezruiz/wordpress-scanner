package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wordpress-scanner/internal/report"
)

type AnomalousPHP struct{}

func (a *AnomalousPHP) Name() string { return "Anomalous PHP locations" }

func (a *AnomalousPHP) Run(path string, logs bool) ([]report.Finding, error) {
	var findings []report.Finding
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(filePath)) != ".php" {
			return nil
		}

		relative, err := filepath.Rel(path, filePath)
		if err != nil {
			return nil
		}
		normalized := filepath.ToSlash(relative)
		location := anomalousLocation(normalized)
		if location == "" {
			return nil
		}

		finding := report.Finding{
			ID:             "ANOM-" + padID(len(findings)+1),
			Scanner:        a.Name(),
			File:           filePath,
			Severity:       report.SeverityHigh,
			Type:           "anomalous-file",
			Description:    fmt.Sprintf("PHP file in high-risk location: %s", location),
			Indicator:      "Unexpected PHP location",
			Recommendation: "Review the file and compare it with the official or project package",
			Rule:           "unexpected-php-location",
			Confidence:     "medium",
		}
		enrichFinding(&finding)
		findings = append(findings, finding)
		return nil
	})
	return findings, err
}

func anomalousLocation(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/wp-content/uploads/") || strings.HasPrefix(lower, "wp-content/uploads/"):
		return "wp-content/uploads"
	case strings.Contains(lower, "/wp-admin/css/colors/") || strings.HasPrefix(lower, "wp-admin/css/colors/"):
		return "wp-admin/css/colors"
	case strings.Contains(lower, "/wp-includes/php-ai-client/") || strings.HasPrefix(lower, "wp-includes/php-ai-client/"):
		return "wp-includes/php-ai-client"
	default:
		return ""
	}
}

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func outputDir() string {
	now := time.Now()
	return filepath.Join("wpscanner-output", now.Format("20060102-150405"))
}

func EnsureOutputDir() (string, error) {
	dir := outputDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("error creating output directory: %w", err)
	}
	return dir, nil
}

func GenerateJSONReport(r Report, dir string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling report: %w", err)
	}
	path := filepath.Join(dir, "wpscanner-report.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing report: %w", err)
	}
	return nil
}

func GenerateMDReport(r Report, dir string) error {
	path := filepath.Join(dir, "wpscanner-report.md")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# WordPress Scanner Report\n\n")
	fmt.Fprintf(f, "**Tool:** %s v%s\n", r.Meta.Tool, r.Meta.Version)
	fmt.Fprintf(f, "**Scan date:** %s\n", r.Meta.ScanDate)
	fmt.Fprintf(f, "**Target:** %s\n", r.Meta.TargetPath)
	if r.Meta.TargetDomain != "" {
		fmt.Fprintf(f, "**Domain:** %s\n", r.Meta.TargetDomain)
	}
	fmt.Fprintf(f, "**Elapsed:** %ds\n\n", r.Meta.ElapsedSeconds)

	fmt.Fprintf(f, "## Summary\n\n")
	fmt.Fprintf(f, "| Severity | Count |\n")
	fmt.Fprintf(f, "|----------|-------|\n")
	fmt.Fprintf(f, "| Critical | %d |\n", r.Summary.Critical)
	fmt.Fprintf(f, "| High | %d |\n", r.Summary.High)
	fmt.Fprintf(f, "| Medium | %d |\n", r.Summary.Medium)
	fmt.Fprintf(f, "| Low | %d |\n", r.Summary.Low)
	fmt.Fprintf(f, "| **Total** | **%d** |\n", r.Summary.TotalFindings+r.Summary.DBFindings)
	fmt.Fprintln(f)

	if len(r.Findings) > 0 {
		fmt.Fprintf(f, "## File Findings\n\n")
		fmt.Fprintf(f, "| ID | Scanner | File | Severity | Type | Description |\n")
		fmt.Fprintf(f, "|----|---------|------|----------|------|-------------|\n")
		for _, fi := range r.Findings {
			fmt.Fprintf(f, "| %s | %s | %s | %s | %s | %s |\n",
				fi.ID, fi.Scanner, fi.File, fi.Severity, fi.Type, fi.Description)
		}
		fmt.Fprintln(f)
	}

	if len(r.DBFindings) > 0 {
		fmt.Fprintf(f, "## Database Findings\n\n")
		fmt.Fprintf(f, "| ID | Category | Check | Severity | Rows | Sample |\n")
		fmt.Fprintf(f, "|----|----------|-------|----------|------|--------|\n")
		for _, d := range r.DBFindings {
			fmt.Fprintf(f, "| %s | %s | %s | %s | %d | %s |\n",
				d.ID, d.Category, d.Check, d.Severity, d.RowsAffected, d.Sample)
		}
		fmt.Fprintln(f)
	}

	return nil
}

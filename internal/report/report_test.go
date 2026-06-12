package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureOutputDir(t *testing.T) {
	dir, err := EnsureOutputDir()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer os.RemoveAll(filepath.Dir(dir))

	if dir == "" {
		t.Fatal("expected non-empty directory")
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("expected directory to exist")
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	r := Report{
		Meta: Meta{
			Tool:    "wordpress-scanner",
			Version: "1.0.3",
		},
		Findings: []Finding{
			{
				ID:       "TEST-001",
				Scanner:  "test",
				File:     "test.php",
				Severity: SeverityCritical,
				Type:     "malware",
			},
		},
		Summary: Summary{
			TotalFindings: 1,
			Critical:      1,
		},
	}

	tmpDir := t.TempDir()

	if err := GenerateJSONReport(r, tmpDir); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	path := filepath.Join(tmpDir, "wpscanner-report.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected report file to exist")
	}

	loaded, err := LoadReport(path)
	if err != nil {
		t.Fatalf("expected no error loading report, got %v", err)
	}

	if loaded.Meta.Version != "1.0.3" {
		t.Errorf("expected version 1.0.3, got %s", loaded.Meta.Version)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(loaded.Findings))
	}
}

func TestSummaryCounters(t *testing.T) {
	r := Report{
		Findings: []Finding{
			{Severity: SeverityCritical, Type: "webshell"},
			{Severity: SeverityCritical, Type: "backdoor"},
			{Severity: SeverityHigh, Type: "seo-spam"},
			{Severity: SeverityMedium, Type: "suspicious"},
			{Severity: SeverityLow, Type: "info"},
		},
	}

	for _, f := range r.Findings {
		r.Summary.TotalFindings++
		switch f.Severity {
		case SeverityCritical:
			r.Summary.Critical++
		case SeverityHigh:
			r.Summary.High++
		case SeverityMedium:
			r.Summary.Medium++
		case SeverityLow:
			r.Summary.Low++
		}
		if f.Type == "webshell" || f.Type == "backdoor" {
			r.Summary.Backdoors++
		}
	}

	if r.Summary.TotalFindings != 5 {
		t.Errorf("expected 5 total, got %d", r.Summary.TotalFindings)
	}
	if r.Summary.Critical != 2 {
		t.Errorf("expected 2 critical, got %d", r.Summary.Critical)
	}
	if r.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", r.Summary.High)
	}
	if r.Summary.Backdoors != 2 {
		t.Errorf("expected 2 backdoors, got %d", r.Summary.Backdoors)
	}
}

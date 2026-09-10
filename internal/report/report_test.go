package report

import (
	"os"
	"path/filepath"
	"strings"
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
			Version: "1.4.0",
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

	if loaded.Meta.Version != "1.4.0" {
		t.Errorf("expected version 1.4.0, got %s", loaded.Meta.Version)
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

func TestDeduplicateFindingsPreservesOccurrences(t *testing.T) {
	findings := []Finding{
		{Scanner: "pmf", File: "consultzone.php", Rule: "ObfuscatedPhp", Evidence: "first"},
		{Scanner: "pmf", File: "consultzone.php", Rule: "ObfuscatedPhp", Evidence: "second"},
		{Scanner: "pmf", File: "consultzone.php", Rule: "DangerousPhp", Evidence: "third"},
	}

	got := DeduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 grouped findings, got %d", len(got))
	}
	if got[0].Occurrences != 2 {
		t.Fatalf("expected 2 occurrences, got %d", got[0].Occurrences)
	}
	if got[0].Evidence != "first\nsecond" {
		t.Fatalf("unexpected evidence: %q", got[0].Evidence)
	}
}

func TestGenerateHTMLReport(t *testing.T) {
	r := Report{
		Meta: Meta{TargetPath: "/tmp/site"},
		Findings: []Finding{{
			ID:          "TEST-001",
			Scanner:     "test",
			File:        "<payload.php>",
			Severity:    SeverityHigh,
			Description: "<script>alert(1)</script>",
		}},
		Summary: Summary{High: 1, TotalFindings: 1, UniqueFiles: 1, EvidenceCount: 1},
	}

	dir := t.TempDir()
	if err := GenerateHTMLReport(r, dir); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "wpscanner-report.html"))
	if err != nil {
		t.Fatalf("expected HTML report, got %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "WordPress Scanner") {
		t.Error("expected report title")
	}
	if strings.Contains(content, "<script>alert(1)</script>") {
		t.Error("unescaped finding content found in HTML")
	}
}

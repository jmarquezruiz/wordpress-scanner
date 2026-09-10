package scanner

import (
	"testing"
)

func TestPadID(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{1, "001"},
		{10, "010"},
		{100, "100"},
		{999, "999"},
		{0, "000"},
	}

	for _, tt := range tests {
		got := padID(tt.input)
		if got != tt.want {
			t.Errorf("padID(%d) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestDetectType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"found webshell in file", "webshell"},
		{"backdoor detected", "webshell"},
		{"eval function usage", "obfuscation"},
		{"base64 encoded content", "obfuscation"},
		{"SEO spam detected", "seo-spam"},
		{"unknown pattern", "suspicious"},
	}

	for _, tt := range tests {
		got := detectType(tt.input)
		if got != tt.want {
			t.Errorf("detectType(%q) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestParsePMFLine(t *testing.T) {
	file, rule, ok := parsePMFLine("2026/09/10 09:41:22 [WARNING] match found: /tmp/consultzone.php (ObfuscatedPhp)")
	if !ok {
		t.Fatal("expected PMF finding to be parsed")
	}
	if file != "/tmp/consultzone.php" {
		t.Fatalf("unexpected file: %s", file)
	}
	if rule != "ObfuscatedPhp" {
		t.Fatalf("unexpected rule: %s", rule)
	}
}

func TestParsePMFLineIgnoresNonFindings(t *testing.T) {
	lines := []string{
		"Scanning /var/www/html/wp-includes/functions.php",
		"2026/09/10 [INFO] scanned 100 PHP files",
		"File: /var/www/html/index.php",
	}
	for _, line := range lines {
		if _, _, ok := parsePMFLine(line); ok {
			t.Errorf("line was incorrectly parsed as finding: %s", line)
		}
	}
}

func TestSeverityForPMFRule(t *testing.T) {
	if got := severityForRule("ObfuscatedPhp"); got != "high" {
		t.Fatalf("expected obfuscation to be high, got %s", got)
	}
	if got := severityForRule("WebShell"); got != "critical" {
		t.Fatalf("expected webshell to be critical, got %s", got)
	}
}

func TestAnomalousLocation(t *testing.T) {
	if got := anomalousLocation("wp-content/uploads/cache.php"); got == "" {
		t.Fatal("expected uploads PHP to be anomalous")
	}
	if got := anomalousLocation("wp-admin/includes/template.php"); got != "" {
		t.Fatalf("did not expect normal core location to be anomalous: %s", got)
	}
}

func TestParseChecksumFindings(t *testing.T) {
	findings := parseChecksumFindings(`Warning: File doesn't verify against checksum: wp-includes/functions.php`, "core", "/tmp/site")
	if len(findings) != 1 {
		t.Fatalf("expected one checksum finding, got %d", len(findings))
	}
	if findings[0].Type != "integrity" || findings[0].Confidence != "high" {
		t.Fatalf("unexpected checksum finding: %+v", findings[0])
	}
}

func TestParseExtraCoreFiles(t *testing.T) {
	findings := parseChecksumFindings(`Warning: File should not exist: wp-admin/css/colors/ectoplasm/witnessquarter.php`, "core", "/tmp/site")
	if len(findings) != 1 {
		t.Fatalf("expected one extra-file finding, got %d", len(findings))
	}
	if findings[0].File != "/tmp/site/wp-admin/css/colors/ectoplasm/witnessquarter.php" {
		t.Fatalf("unexpected absolute path: %s", findings[0].File)
	}
}

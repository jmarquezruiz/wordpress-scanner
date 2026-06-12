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

package executil

import (
	"strings"
	"testing"
)

func TestRunCapturesStdoutAndStderr(t *testing.T) {
	output, err := Run("sh", []string{"-c", "printf out; printf err >&2"}, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(output, "out") || !strings.Contains(output, "err") {
		t.Fatalf("expected both streams in output, got %q", output)
	}
}

func TestRunReturnsExitErrorWithOutput(t *testing.T) {
	output, err := Run("sh", []string{"-c", "printf failure; exit 7"}, false)
	if err == nil {
		t.Fatal("expected process error")
	}
	if !strings.Contains(output, "failure") {
		t.Fatalf("expected captured output, got %q", output)
	}
}

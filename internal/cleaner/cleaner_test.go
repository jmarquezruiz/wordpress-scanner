package cleaner

import (
	"strings"
	"testing"

	"wordpress-scanner/internal/report"
)

func TestGenerateCleanupSQL(t *testing.T) {
	dbFindings := []report.DBFinding{
		{
			ID:       "DB-001",
			Check:    "Usuarios admin no originales",
			CleanupSQL: "DELETE FROM wp_users WHERE ID NOT IN (1)",
		},
		{
			ID:       "DB-002",
			Check:    "Posts con SEO spam",
			CleanupSQL: "DELETE FROM wp_posts WHERE post_content LIKE '%casino%'",
		},
	}

	statements := GenerateCleanupSQL(dbFindings)
	if len(statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(statements))
	}

	if !strings.Contains(statements[0], "DB-001") {
		t.Error("expected statement 0 to contain DB-001")
	}
	if !strings.Contains(statements[0], "DELETE FROM wp_users") {
		t.Error("expected statement 0 to contain DELETE sql")
	}
}

func TestGenerateCleanupSQLNoFindings(t *testing.T) {
	statements := GenerateCleanupSQL(nil)
	if len(statements) != 1 {
		t.Fatalf("expected 1 statement (noop), got %d", len(statements))
	}
}

func TestGenerateCleanupHeader(t *testing.T) {
	header := GenerateCleanupHeader()
	if !strings.Contains(header, "START TRANSACTION") {
		t.Error("expected header to contain START TRANSACTION")
	}
}

func TestGenerateCleanupFooter(t *testing.T) {
	footer := GenerateCleanupFooter()
	if !strings.Contains(footer, "COMMIT") {
		t.Error("expected footer to contain COMMIT")
	}
	if !strings.Contains(footer, "ROLLBACK") {
		t.Error("expected footer to contain ROLLBACK")
	}
}

package dbscanner

import (
	"testing"
)

func TestDefaultQueries(t *testing.T) {
	catalog := DefaultQueries("wp_")

	if len(catalog.Checks) != 10 {
		t.Fatalf("expected 10 default queries, got %d", len(catalog.Checks))
	}

	expectedIDs := []string{
		"DB-001", "DB-002", "DB-003", "DB-004", "DB-005",
		"DB-006", "DB-007", "DB-008", "DB-009", "DB-010",
	}

	for i, id := range expectedIDs {
		if catalog.Checks[i].ID != id {
			t.Errorf("expected check %d to have ID %s, got %s", i, id, catalog.Checks[i].ID)
		}
	}
}

func TestDefaultQueriesCustomPrefix(t *testing.T) {
	catalog := DefaultQueries("custom_")

	if catalog.Checks[0].Query != "SELECT ID, user_login, user_email FROM custom_users WHERE ID NOT IN (1)" {
		t.Errorf("query did not use custom prefix: %s", catalog.Checks[0].Query)
	}
}

func TestIsSocketPath(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"/var/run/mysqld/mysqld.sock", true},
		{"./var/mysql.sock", true},
		{"../socket/mysql.sock", true},
		{"localhost", false},
		{"127.0.0.1", false},
		{"192.168.1.1", false},
	}

	for _, tt := range tests {
		got := isSocketPath(tt.host)
		if got != tt.want {
			t.Errorf("isSocketPath(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestIsDomain(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"db.example.com", true},
		{"localhost", false},
		{"127.0.0.1", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		got := isDomain(tt.host)
		if got != tt.want {
			t.Errorf("isDomain(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

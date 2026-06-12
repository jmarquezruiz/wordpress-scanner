package dbscanner

import "wordpress-scanner/internal/ui"

type DBScanner interface {
	Connect(creds *ui.DBCredentials) error
	Close() error
	RunAllChecks() ([]DBScanResult, error)
}

type DBScanResult struct {
	Category string
	Findings []DBFinding
	Error    error
}

type DBFinding struct {
	ID           string `json:"id"`
	Check        string `json:"check"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	RowsAffected int    `json:"rows_affected"`
	Sample       string `json:"sample"`
	CleanupSQL   string `json:"cleanup_sql"`
	Cleaned      bool   `json:"cleaned"`
}

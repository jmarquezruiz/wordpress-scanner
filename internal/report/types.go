package report

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Finding struct {
	ID             string   `json:"id"`
	Scanner        string   `json:"scanner"`
	File           string   `json:"file"`
	Severity       Severity `json:"severity"`
	Type           string   `json:"type"`
	Description    string   `json:"description"`
	Indicator      string   `json:"indicator"`
	Recommendation string   `json:"recommendation"`
	Cleaned        bool     `json:"cleaned"`
	Rule           string   `json:"rule,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	SHA256         string   `json:"sha256,omitempty"`
	Size           int64    `json:"size,omitempty"`
	ModifiedAt     string   `json:"modified_at,omitempty"`
	Occurrences    int      `json:"occurrences,omitempty"`
}

type DBFinding struct {
	ID           string   `json:"id"`
	Check        string   `json:"check"`
	Category     string   `json:"category"`
	Severity     Severity `json:"severity"`
	RowsAffected int      `json:"rows_affected"`
	Sample       string   `json:"sample"`
	CleanupSQL   string   `json:"cleanup_sql"`
	Cleaned      bool     `json:"cleaned"`
}

type Summary struct {
	TotalFindings     int  `json:"total_findings"`
	EvidenceCount     int  `json:"evidence_count,omitempty"`
	UniqueFiles       int  `json:"unique_files,omitempty"`
	DuplicateFindings int  `json:"duplicate_findings,omitempty"`
	Critical          int  `json:"critical"`
	High              int  `json:"high"`
	Medium            int  `json:"medium"`
	Low               int  `json:"low"`
	Backdoors         int  `json:"backdoors"`
	Injections        int  `json:"injecctions"`
	DBFindings        int  `json:"db_findings"`
	Cleaned           bool `json:"cleaned"`
}

type Meta struct {
	Tool           string `json:"tool"`
	Version        string `json:"version"`
	ScanDate       string `json:"scan_date"`
	TargetPath     string `json:"target_path"`
	TargetDomain   string `json:"target_domain,omitempty"`
	ElapsedSeconds int    `json:"elapsed_seconds"`
}

type Report struct {
	Meta        Meta              `json:"meta"`
	Findings    []Finding         `json:"findings"`
	DBFindings  []DBFinding       `json:"db_findings,omitempty"`
	Summary     Summary           `json:"summary"`
	CleanHashes map[string]string `json:"clean_hashes,omitempty"`
}

type ScannerResult struct {
	ScannerName string
	Findings    []Finding
	Duration    time.Duration
	Error       error
}

type DBScanResult struct {
	Findings []DBFinding
	Duration time.Duration
	Error    error
}

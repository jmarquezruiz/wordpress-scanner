package scanner

import "wordpress-scanner/internal/report"

type Scanner interface {
	Name() string
	Run(path string, logs bool) ([]report.Finding, error)
}

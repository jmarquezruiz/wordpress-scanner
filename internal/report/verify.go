package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"wordpress-scanner/internal/ui"
)

func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading report file: %w", err)
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("error parsing report: %w", err)
	}
	return &r, nil
}

func VerifyFileHashes(r *Report) ([]string, []string, []string) {
	var cleaned, removed, stillInfected []string

	for _, f := range r.Findings {
		hash, exists := r.CleanHashes[f.File]
		if !exists {
			continue
		}

		fullPath := filepath.Join(r.Meta.TargetPath, f.File)
		currentHash := sha256File(fullPath)

		if currentHash == "" {
			removed = append(removed, f.File)
			f.Cleaned = true
		} else if currentHash != hash {
			info, err := os.Stat(fullPath)
			if err == nil && info.Size() == 0 {
				removed = append(removed, f.File)
				f.Cleaned = true
			} else {
				cleaned = append(cleaned, f.File)
				f.Cleaned = true
			}
		} else {
			stillInfected = append(stillInfected, f.File)
		}
	}

	return cleaned, removed, stillInfected
}

func sha256File(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func PrintVerificationResults(cleaned, removed, stillInfected []string) {
	ui.Section("Verificando archivos")
	for _, f := range cleaned {
		ui.CheckOK(f + " → Limpiado ✓")
	}
	for _, f := range removed {
		ui.CheckOK(f + " → Eliminado ✓")
	}
	for _, f := range stillInfected {
		ui.CheckFail(f + " → Hash sin cambios (aún infectado)")
	}
}

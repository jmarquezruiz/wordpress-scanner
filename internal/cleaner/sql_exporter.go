package cleaner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func ExportSQL(statements []string, outputDir string) (string, error) {
	now := time.Now()
	filename := fmt.Sprintf("cleanup-%s.sql", now.Format("20060102-150405"))
	path := filepath.Join(outputDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("error creating SQL file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(GenerateCleanupHeader()); err != nil {
		return "", err
	}

	for _, stmt := range statements {
		if _, err := f.WriteString(stmt + "\n"); err != nil {
			return "", err
		}
	}

	if _, err := f.WriteString(GenerateCleanupFooter()); err != nil {
		return "", err
	}

	return path, nil
}

package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"wordpress-scanner/internal/report"
)

type Scanner interface {
	Name() string
	Run(path string, logs bool) ([]report.Finding, error)
}

func enrichFinding(f *report.Finding) {
	info, err := os.Stat(f.File)
	if err != nil || !info.Mode().IsRegular() {
		return
	}

	f.Size = info.Size()
	f.ModifiedAt = info.ModTime().UTC().Format("2006-01-02T15:04:05Z07:00")

	file, err := os.Open(f.File)
	if err != nil {
		return
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err == nil {
		f.SHA256 = hex.EncodeToString(hash.Sum(nil))
	}
}

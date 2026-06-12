package scanner

import (
	"bufio"
	"os/exec"
	"strings"

	"wordpress-scanner/internal/report"
)

type ClamAV struct{}

func (c *ClamAV) Name() string {
	return "ClamAV"
}

func (c *ClamAV) Run(path string, logs bool) ([]report.Finding, error) {
	args := []string{"-ri", "--no-summary", path}
	cmd := exec.Command("clamscan", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var findings []report.Finding
	scanner := bufio.NewScanner(stdout)
	id := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "---") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				filePath := strings.TrimSpace(parts[0])
				description := strings.TrimSpace(parts[1])
				id++
				findings = append(findings, report.Finding{
					ID:             "CLAM-" + padID(id),
					Scanner:        c.Name(),
					File:           filePath,
					Severity:       report.SeverityCritical,
					Type:           "malware",
					Description:    description,
					Indicator:      "ClamAV",
					Recommendation: "Review and delete file",
				})
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return findings, nil
			}
		}
		return findings, err
	}

	return findings, nil
}

func padID(n int) string {
	if n == 0 {
		return "000"
	}
	if n < 10 {
		return "00" + itoa(n)
	} else if n < 100 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

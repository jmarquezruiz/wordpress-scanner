package executil

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// Run streams both process output streams while retaining the complete output
// for parsers. The output is only printed when liveLogs is enabled.
func Run(binary string, args []string, liveLogs bool) (string, error) {
	cmd := exec.Command(binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}

	var output bytes.Buffer
	var mu sync.Mutex
	read := func(stream io.Reader, label string) {
		scanner := bufio.NewScanner(stream)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			output.WriteString(line)
			output.WriteByte('\n')
			mu.Unlock()
			if liveLogs {
				if label == "stderr" {
					fmt.Fprintf(os.Stdout, "[stderr] %s\n", line)
				} else {
					fmt.Fprintln(os.Stdout, line)
				}
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); read(stdout, "stdout") }()
	go func() { defer wg.Done(); read(stderr, "stderr") }()
	wg.Wait()

	err = cmd.Wait()
	return output.String(), err
}

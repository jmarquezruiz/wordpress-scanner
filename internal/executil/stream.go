package executil

import (
	"bufio"
	"bytes"
	"io"
	"os/exec"
	"sync"
)

// Run streams both process output streams while retaining the complete output
// for parsers. Presentation of live progress is handled by the UI.
func Run(binary string, args []string, _ bool) (string, error) {
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
	read := func(stream io.Reader) {
		scanner := bufio.NewScanner(stream)
		for scanner.Scan() {
			line := scanner.Text()
			mu.Lock()
			output.WriteString(line)
			output.WriteByte('\n')
			mu.Unlock()
			// Keep command output available to the parser. The live view is
			// rendered by the UI instead of printing every scanner line.
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); read(stdout) }()
	go func() { defer wg.Done(); read(stderr) }()
	wg.Wait()

	err = cmd.Wait()
	return output.String(), err
}

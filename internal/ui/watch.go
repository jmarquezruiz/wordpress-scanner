package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type watchEntry struct {
	name     string
	state    string
	started  time.Time
	finished time.Time
}

// LiveWatch renders scanner progress without flooding the terminal with the
// raw output produced by each external scanner.
type LiveWatch struct {
	mu       sync.Mutex
	entries  []*watchEntry
	done     chan struct{}
	closed   chan struct{}
	stopOnce sync.Once
}

func NewLiveWatch(names []string, includeDB bool) *LiveWatch {
	w := &LiveWatch{done: make(chan struct{}), closed: make(chan struct{})}
	for _, name := range names {
		w.entries = append(w.entries, &watchEntry{name: name, state: "Pendiente"})
	}
	if includeDB {
		w.entries = append(w.entries, &watchEntry{name: "Base de datos", state: "Pendiente"})
	}
	return w
}

func (w *LiveWatch) Start() {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer close(w.closed)
		w.render()
		for {
			select {
			case <-ticker.C:
				w.render()
			case <-w.done:
				return
			}
		}
	}()
}

func (w *LiveWatch) StartItem(name string) {
	w.update(name, func(entry *watchEntry) {
		entry.state = "Escaneando"
		entry.started = time.Now()
	})
}

func (w *LiveWatch) FinishItem(name string, findings int, err error) {
	w.update(name, func(entry *watchEntry) {
		entry.finished = time.Now()
		if err != nil {
			entry.state = fmt.Sprintf("Error: %s", err)
		} else {
			entry.state = fmt.Sprintf("Completado (%d hallazgos)", findings)
		}
	})
}

func (w *LiveWatch) Stop() {
	w.stopOnce.Do(func() {
		close(w.done)
		<-w.closed
		w.render()
		fmt.Println()
	})
}

func (w *LiveWatch) update(name string, update func(*watchEntry)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, entry := range w.entries {
		if entry.name == name {
			update(entry)
			return
		}
	}
}

func (w *LiveWatch) render() {
	w.mu.Lock()
	defer w.mu.Unlock()

	var out strings.Builder
	out.WriteString("\033[H\033[2J")
	out.WriteString(Cyan("── Escaneo en vivo ─────────────────────────────────────────\n"))
	out.WriteString("Actualizado: " + time.Now().Format("15:04:05") + "\n\n")
	for _, entry := range w.entries {
		elapsed := "-"
		if !entry.started.IsZero() {
			end := time.Now()
			if !entry.finished.IsZero() {
				end = entry.finished
			}
			elapsed = end.Sub(entry.started).Round(time.Second).String()
		}
		out.WriteString(fmt.Sprintf("  %-28s %-32s %s\n", entry.name, entry.state, elapsed))
	}
	out.WriteString("\nPulsa Ctrl+C para cancelar el escaneo.\n")
	fmt.Fprint(os.Stdout, out.String())
}

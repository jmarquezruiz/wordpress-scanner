package ui

import (
	"fmt"
	"os"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/schollz/progressbar/v3"
)

var (
	Green  = color.New(color.FgGreen).SprintFunc()
	Red    = color.New(color.FgRed).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	Blue   = color.New(color.FgBlue).SprintFunc()
	Cyan   = color.New(color.FgCyan).SprintFunc()
	Gray   = color.New(color.FgHiBlack).SprintFunc()
	Bold   = color.New(color.Bold).SprintFunc()
)

func ColorSeverity(s string) string {
	switch s {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint(s)
	case "high":
		return Red(s)
	case "medium":
		return Yellow(s)
	case "low":
		return Blue(s)
	default:
		return Gray(s)
	}
}

func NewSpinner(suffix string) *spinner.Spinner {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	s.Suffix = " " + suffix
	s.Writer = os.Stderr
	return s
}

func NewProgressBar(max int, description string) *progressbar.ProgressBar {
	bar := progressbar.NewOptions(max,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() { fmt.Fprint(os.Stderr, "\n") }),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "█",
			SaucerHead:    "█",
			SaucerPadding: "░",
			BarStart:      "|",
			BarEnd:        "|",
		}),
	)
	return bar
}

func Section(title string) {
	fmt.Println()
	fmt.Println(Cyan("── " + Bold(title) + " ───────────────────────────────"))
}

func CheckOK(text string) {
	fmt.Printf("  %s %s\n", Green("✓"), text)
}

func CheckFail(text string) {
	fmt.Printf("  %s %s\n", Red("✗"), text)
}

func CheckWarn(text string) {
	fmt.Printf("  %s %s\n", Yellow("⚠"), text)
}

func PrintFindingsTable(rows []TableRow) {
	if len(rows) == 0 {
		CheckOK("No se encontraron hallazgos")
		return
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"ID", "Scanner", "Archivo", "Severidad", "Tipo", "Descripción"})
	for _, r := range rows {
		t.AppendRow(table.Row{r.ID, r.Scanner, r.File, ColorSeverity(r.Severity), r.Type, r.Description})
	}
	t.Render()
}

func PrintDBFindingsTable(rows []DBTableRow) {
	if len(rows) == 0 {
		CheckOK("No se encontraron hallazgos en DB")
		return
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.AppendHeader(table.Row{"ID", "Categoría", "Check", "Severidad", "Filas", "Muestra"})
	for _, r := range rows {
		t.AppendRow(table.Row{r.ID, r.Category, r.Check, ColorSeverity(r.Severity), r.RowsAffected, r.Sample})
	}
	t.Render()
}

type TableRow struct {
	ID          string
	Scanner     string
	File        string
	Severity    string
	Type        string
	Description string
}

type DBTableRow struct {
	ID           string
	Category     string
	Check        string
	Severity     string
	RowsAffected int
	Sample       string
}

func PrintSummary(critical, high, medium, low, totalFindings, dbFindings int, cleaned bool) {
	fmt.Println()
	fmt.Println(Cyan("┌─ " + Bold("RESUMEN") + " ───────────────────────────────────────────┐"))
	fmt.Printf("│  %s: %d   %s: %d   %s: %d   %s: %d    │\n",
		Red("Critical"), critical,
		Red("High"), high,
		Yellow("Medium"), medium,
		Blue("Low"), low)
	fmt.Printf("│  Archivos infectados: %d                              │\n", totalFindings)
	if dbFindings > 0 {
		fmt.Printf("│  Hallazgos en DB: %d                                 │\n", dbFindings)
	}
	if cleaned {
		fmt.Printf("│  %s                                              │\n", Green("LIMPIO ✓"))
	} else {
		fmt.Printf("│  %s                                        │\n", Red("PENDIENTE DE LIMPIEZA"))
	}
	fmt.Println(Cyan("└──────────────────────────────────────────────────────────────┘"))
}

func PrintResultBox(title string, lines []string, colorFn func(...interface{}) string) {
	fmt.Println()
	fmt.Println(colorFn("┌─ " + Bold(title) + " ───────────────────────────┐"))
	for _, l := range lines {
		fmt.Printf("│  %s\n", colorFn(l))
	}
	fmt.Println(colorFn("└──────────────────────────────────────────────────┘"))
}

func PrintBanner() {
	banner := `
__          __ _____     _____                                        
\ \        / /|  __ \   / ____|                                       
 \ \  /\  / / | |__) | | (___    ___   __ _  _ __   _ __    ___  _ __ 
  \ \/  \/ /  |  ___/   \___ \  / __| / _` + "`" + ` | '_ \ | '_ \  / _ \| '__|
   \  /\  /   | |       ____) || (__ | (_| || | | || | | ||  __/| |   
    \/  \/    |_|      |_____/  \___| \__,_||_| |_||_| |_| \___||_|   

                         jmarquez.dev
`
	fmt.Print(Cyan(banner))
	fmt.Printf("  %s v1.4.0\n", Bold("WordPress Scanner"))
	fmt.Println()
}

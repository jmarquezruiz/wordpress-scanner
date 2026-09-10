package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"wordpress-scanner/internal/nextSteps"
	"wordpress-scanner/internal/report"
	"wordpress-scanner/internal/ui"
)

var reportCmd = &cobra.Command{
	Use:   "report --report report.json",
	Short: "Genera informe formal para el cliente",
	Long: `A partir de un reporte de escaneo, genera:
- INFORME_CLIENTE.md (informe formal para enviar al cliente)
- SIGUIENTES_PASOS.md (guía de acciones post-limpieza)`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().String("report", "", "Ruta al reporte JSON (requerido)")
	reportCmd.MarkFlagRequired("report")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	reportPath, _ := cmd.Flags().GetString("report")

	r, err := report.LoadReport(reportPath)
	if err != nil {
		return fmt.Errorf("error loading report: %w", err)
	}

	dir := filepath.Dir(reportPath)

	ui.Section("Generando informe para el cliente")

	clientReportPath, err := report.GenerateClientReport(*r, dir)
	if err != nil {
		return fmt.Errorf("error generating client report: %w", err)
	}
	ui.CheckOK(fmt.Sprintf("Informe cliente: %s", clientReportPath))

	nextStepsPath, err := nextSteps.GenerateNextSteps(r, dir)
	if err != nil {
		return fmt.Errorf("error generating next steps: %w", err)
	}
	ui.CheckOK(fmt.Sprintf("Siguientes pasos: %s", nextStepsPath))

	htmlPath := filepath.Join(dir, "wpscanner-report.html")
	if err := report.GenerateHTMLReport(*r, dir); err != nil {
		return fmt.Errorf("error generating HTML report: %w", err)
	}
	ui.CheckOK(fmt.Sprintf("Informe HTML: %s", htmlPath))

	ui.PrintResultBox("ARCHIVOS GENERADOS",
		[]string{
			clientReportPath,
			nextStepsPath,
			htmlPath,
		}, ui.Cyan)

	return nil
}

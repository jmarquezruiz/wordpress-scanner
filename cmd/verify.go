package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"wordpress-scanner/internal/report"
	"wordpress-scanner/internal/ui"
)

var verifyCmd = &cobra.Command{
	Use:   "verify --report report.json",
	Short: "Verifica limpieza post-cleanup",
	Long: `Carga un reporte previo, re-escanea los archivos afectados y determina
si la limpieza fue exitosa o si quedan hallazgos sin resolver.`,
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().String("report", "", "Ruta al reporte JSON (requerido)")
	verifyCmd.MarkFlagRequired("report")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	reportPath, _ := cmd.Flags().GetString("report")

	r, err := report.LoadReport(reportPath)
	if err != nil {
		return fmt.Errorf("error loading report: %w", err)
	}

	cleaned, removed, stillInfected := report.VerifyFileHashes(r)

	report.PrintVerificationResults(cleaned, removed, stillInfected)

	if len(stillInfected) > 0 {
		ui.PrintResultBox("CONCLUSIÓN",
			[]string{
				fmt.Sprintf("✗ Quedan %d hallazgos sin resolver", len(stillInfected)),
				"Ejecuta 'wpscanner clean' de nuevo para limpiarlos",
			}, ui.Red)
	} else if len(cleaned)+len(removed) > 0 {
		ui.PrintResultBox("CONCLUSIÓN",
			[]string{
				"✓ Todo limpio",
				fmt.Sprintf("(%d archivos limpiados, %d eliminados)", len(cleaned), len(removed)),
			}, ui.Green)
	} else {
		ui.CheckOK("No se encontraron cambios respecto al reporte previo")
	}

	return nil
}

package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"wordpress-scanner/internal/dbscanner"
	"wordpress-scanner/internal/report"
	"wordpress-scanner/internal/ui"
)

var cleanCmd = &cobra.Command{
	Use:   "clean --report report.json",
	Short: "Limpia la base de datos local basándose en el reporte",
	Long: `Carga un reporte previo, genera las sentencias SQL de limpieza y las ejecuta
en la base de datos local. Nunca toca producción directamente.`,
	RunE: runClean,
}

func init() {
	cleanCmd.Flags().String("report", "", "Ruta al reporte JSON (requerido)")
	cleanCmd.MarkFlagRequired("report")
	rootCmd.AddCommand(cleanCmd)
}

func runClean(cmd *cobra.Command, args []string) error {
	reportPath, _ := cmd.Flags().GetString("report")

	r, err := report.LoadReport(reportPath)
	if err != nil {
		return fmt.Errorf("error loading report: %w", err)
	}

	if len(r.DBFindings) == 0 {
		ui.CheckOK("No hay hallazgos en DB para limpiar")
		return nil
	}

	creds, err := ui.AskDBCredentials()
	if err != nil {
		return err
	}

	ui.Section("Conectando a base de datos local")
	conn := &dbscanner.MySQLConnector{}
	if err := conn.Connect(creds); err != nil {
		return fmt.Errorf("error connecting to local DB: %w", err)
	}
	defer conn.Close()
	ui.CheckOK("Conexión exitosa")

	dir := filepath.Dir(reportPath)
	return runCleanLocal(conn, r.DBFindings, dir)
}

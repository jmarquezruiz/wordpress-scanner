package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"wordpress-scanner/internal/dbscanner"
	"wordpress-scanner/internal/report"
	"wordpress-scanner/internal/ui"
)

var scanDBCmd = &cobra.Command{
	Use:   "scan-db",
	Short: "Escanea la base de datos WordPress",
	Long:  `Conecta a la base de datos MySQL y ejecuta queries de detección de malware en tablas de WordPress.`,
	RunE:  runScanDB,
}

func init() {
	rootCmd.AddCommand(scanDBCmd)
}

func runScanDB(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	creds, err := ui.AskDBCredentials()
	if err != nil {
		return err
	}

	ui.Section("Conectando a base de datos")
	conn := &dbscanner.MySQLConnector{}
	if err := conn.Connect(creds); err != nil {
		ui.CheckFail("Error: " + err.Error())
		return err
	}
	defer conn.Close()
	ui.CheckOK("Conexión exitosa")

	ui.Section("Ejecutando scans de base de datos")

	var allDBFindings []report.DBFinding
	sp := ui.NewSpinner("Ejecutando queries de detección...")
	sp.Start()
	results, err := conn.RunAllChecks()
	sp.Stop()
	if err != nil {
		ui.CheckFail("Error en escaneo: " + err.Error())
		return err
	}

	for _, res := range results {
		for _, f := range res.Findings {
			allDBFindings = append(allDBFindings, report.DBFinding{
				ID:           f.ID,
				Check:        f.Check,
				Category:     f.Category,
				Severity:     report.Severity(f.Severity),
				RowsAffected: f.RowsAffected,
				Sample:       f.Sample,
				CleanupSQL:   f.CleanupSQL,
			})
		}
		if len(res.Findings) > 0 {
			ui.CheckWarn(fmt.Sprintf("%s: %d hallazgos", res.Category, len(res.Findings)))
		} else {
			ui.CheckOK(fmt.Sprintf("%s: Sin hallazgos", res.Category))
		}
	}

	ui.Section("Generando reportes")

	dir, err := report.EnsureOutputDir()
	if err != nil {
		return err
	}

	elapsed := int(time.Since(startTime).Seconds())
	r := report.Report{
		Meta: report.Meta{
			Tool:           "wordpress-scanner",
			Version:        "1.4.0",
			ScanDate:       time.Now().Format(time.RFC3339),
			TargetPath:     creds.Host + "/" + creds.Database,
			ElapsedSeconds: elapsed,
		},
		DBFindings: allDBFindings,
		Summary: report.Summary{
			DBFindings: len(allDBFindings),
		},
	}

	if err := report.GenerateJSONReport(r, dir); err != nil {
		return err
	}
	ui.CheckOK("Reporte JSON generado")

	if err := report.GenerateMDReport(r, dir); err != nil {
		return err
	}
	ui.CheckOK("Reporte MD generado")

	ui.PrintDBFindingsTable(dbFindingsToRows(allDBFindings))

	proceed, err := ui.AskProceedClean()
	if err != nil {
		return err
	}

	if proceed {
		if err := runCleanLocal(conn, allDBFindings, dir); err != nil {
			return err
		}
	}

	return nil
}

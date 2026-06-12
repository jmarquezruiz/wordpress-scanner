package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"wordpress-scanner/internal/cleaner"
	"wordpress-scanner/internal/dbscanner"
	"wordpress-scanner/internal/report"
	"wordpress-scanner/internal/scanner"
	"wordpress-scanner/internal/ui"
	"wordpress-scanner/internal/updater"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Escanea archivos WordPress en busca de malware",
	Long:  `Ejecuta múltiples scanners sobre la ruta especificada para detectar malware, webshells y amenazas de seguridad.`,
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().Bool("db", false, "Escanea también la base de datos")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	scanDB, _ := cmd.Flags().GetBool("db")

	startTime := time.Now()

	config := &ui.ScanConfig{}
	var err error

	if len(args) > 0 {
		config.Path = args[0]
	} else {
		config.Path, err = ui.AskPath(".")
		if err != nil {
			return err
		}
	}

	scannerNames, err := ui.AskScanners()
	if err != nil {
		return err
	}

	config.UpdateDBs, err = ui.AskConfirmUpdate()
	if err != nil {
		return err
	}

	config.ShowLogs, err = ui.AskShowLogs()
	if err != nil {
		return err
	}

	if !scanDB {
		config.ScanDB, err = ui.AskScanDB()
		if err != nil {
			return err
		}
	} else {
		config.ScanDB = true
	}

	var dbCreds *ui.DBCredentials
	if config.ScanDB {
		dbCreds, err = ui.AskDBCredentials()
		if err != nil {
			return err
		}
	}

	if config.UpdateDBs {
		if err := updater.UpdateAll(config.ShowLogs); err != nil {
			ui.CheckWarn(err.Error())
		}
	}

	ui.Section("Escaneando archivos")
	var allFindings []report.Finding
	for _, name := range scannerNames {
		var s scanner.Scanner
		switch name {
		case "ClamAV (clamscan -ri)":
			s = &scanner.ClamAV{}
		case "PHP-Malware-Finder (YARA)":
			s = &scanner.PMF{}
		case "Linux Malware Detect (maldet -a)":
			s = &scanner.Maldet{}
		case "Opencode Subagente (deep analysis)":
			s = &scanner.Opencode{PreviousFindings: formatFindings(allFindings)}
		default:
			continue
		}

		sp := ui.NewSpinner(s.Name())
		sp.Start()
		findings, scanErr := s.Run(config.Path, config.ShowLogs)
		sp.Stop()
		allFindings = append(allFindings, findings...)
		if scanErr != nil && len(findings) == 0 {
			ui.CheckWarn(s.Name() + ": " + scanErr.Error())
		} else if scanErr != nil {
			ui.CheckOK(fmt.Sprintf("%s  %d hallazgos encontrados", s.Name(), len(findings)))
			ui.CheckWarn(s.Name() + " terminó con advertencia: " + scanErr.Error())
		} else if len(findings) > 0 {
			ui.CheckOK(fmt.Sprintf("%s  %d hallazgos encontrados", s.Name(), len(findings)))
		} else {
			ui.CheckOK(fmt.Sprintf("%s  Sin hallazgos", s.Name()))
		}
	}

	var dbFindings []report.DBFinding
	if config.ScanDB && dbCreds != nil {
		ui.Section("Escaneando base de datos")
		conn := &dbscanner.MySQLConnector{}
		if err := conn.Connect(dbCreds); err != nil {
			ui.CheckFail("Error conectando a MySQL: " + err.Error())
		} else {
			defer conn.Close()
			sp := ui.NewSpinner("Ejecutando queries de detección...")
			sp.Start()
			results, err := conn.RunAllChecks()
			sp.Stop()
			if err != nil {
				ui.CheckFail("Error en escaneo DB: " + err.Error())
			} else {
				for _, res := range results {
					for _, f := range res.Findings {
						dbFindings = append(dbFindings, report.DBFinding{
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
			}
		}
	}

	ui.Section("Generando reportes")

	dir, err := report.EnsureOutputDir()
	if err != nil {
		return err
	}

	elapsed := int(time.Since(startTime).Seconds())
	r := buildReport(config.Path, dbCreds, allFindings, dbFindings, elapsed)

	if err := report.GenerateJSONReport(r, dir); err != nil {
		return err
	}
	ui.CheckOK(fmt.Sprintf("wpscanner-report.json generado en %s", dir))

	if err := report.GenerateMDReport(r, dir); err != nil {
		return err
	}
	ui.CheckOK(fmt.Sprintf("wpscanner-report.md generado en %s", dir))

	ui.PrintSummary(r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.TotalFindings, r.Summary.DBFindings, r.Summary.Cleaned)
	ui.PrintFindingsTable(findingsToRows(allFindings))
	ui.PrintDBFindingsTable(dbFindingsToRows(dbFindings))

	proceed, err := ui.AskProceedClean()
	if err != nil {
		return err
	}

	if proceed && config.ScanDB && dbCreds != nil {
		conn := &dbscanner.MySQLConnector{}
		if err := conn.Connect(dbCreds); err != nil {
			return fmt.Errorf("error connecting to local DB for clean: %w", err)
		}
		defer conn.Close()

		if err := runCleanLocal(conn, dbFindings, dir); err != nil {
			return err
		}
	}

	return nil
}

func findingsToRows(findings []report.Finding) []ui.TableRow {
	rows := make([]ui.TableRow, len(findings))
	for i, f := range findings {
		rows[i] = ui.TableRow{
			ID:          f.ID,
			Scanner:     f.Scanner,
			File:        f.File,
			Severity:    string(f.Severity),
			Type:        f.Type,
			Description: f.Description,
		}
	}
	return rows
}

func dbFindingsToRows(findings []report.DBFinding) []ui.DBTableRow {
	rows := make([]ui.DBTableRow, len(findings))
	for i, f := range findings {
		rows[i] = ui.DBTableRow{
			ID:           f.ID,
			Category:     f.Category,
			Check:        f.Check,
			Severity:     string(f.Severity),
			RowsAffected: f.RowsAffected,
			Sample:       f.Sample,
		}
	}
	return rows
}

func buildReport(path string, creds *ui.DBCredentials, findings []report.Finding, dbFindings []report.DBFinding, elapsed int) report.Report {
	summary := report.Summary{}
	for _, f := range findings {
		summary.TotalFindings++
		switch f.Severity {
		case report.SeverityCritical:
			summary.Critical++
		case report.SeverityHigh:
			summary.High++
		case report.SeverityMedium:
			summary.Medium++
		case report.SeverityLow:
			summary.Low++
		}
		if f.Type == "webshell" || f.Type == "backdoor" {
			summary.Backdoors++
		}
		if f.Type == "obfuscation" || f.Type == "injection" {
			summary.Injections++
		}
	}
	summary.DBFindings = len(dbFindings)

	domain := ""
	if creds != nil {
		domain = creds.Host
	}

	return report.Report{
		Meta: report.Meta{
			Tool:           "wordpress-scanner",
			Version:        "1.0.3",
			ScanDate:       time.Now().Format(time.RFC3339),
			TargetPath:     path,
			TargetDomain:   domain,
			ElapsedSeconds: elapsed,
		},
		Findings:   findings,
		DBFindings: dbFindings,
		Summary:    summary,
		CleanHashes: make(map[string]string),
	}
}

func formatFindings(findings []report.Finding) string {
	if len(findings) == 0 {
		return "No findings yet"
	}
	result := ""
	for i, f := range findings {
		if i > 5 {
			result += fmt.Sprintf("... and %d more", len(findings)-5)
			break
		}
		result += fmt.Sprintf("- %s: %s (%s)\n", f.File, f.Description, f.Severity)
	}
	return result
}

func runCleanLocal(conn *dbscanner.MySQLConnector, dbFindings []report.DBFinding, dir string) error {
	cl := cleaner.NewCleaner(conn)
	ops := cl.GenerateOperations(dbFindings)

	if len(ops) == 0 {
		ui.CheckOK("No hay operaciones de limpieza que ejecutar")
		return nil
	}

	cl.PreviewOperations(ops)

	confirm, err := ui.AskConfirmClean("limpieza completa", len(ops))
	if err != nil {
		return err
	}

	if !confirm {
		ui.CheckWarn("Limpieza cancelada")
		return nil
	}

	runner := cleaner.NewSQLRunner(conn.DB)
	results := runner.RunAllOperations(ops)

	for i, res := range results {
		if res.Error != nil {
			ui.CheckFail(fmt.Sprintf("[%d] %s → Error: %s", i+1, res.Operation, res.Error))
		} else {
			ui.CheckOK(fmt.Sprintf("[%d] %s → %d filas afectadas", i+1, res.Operation, res.RowsAffected))
		}
	}

	export, err := ui.AskExportSQL()
	if err != nil {
		return err
	}

	if export {
		statements := cleaner.GenerateCleanupSQL(dbFindings)
		sqlPath, err := cleaner.ExportSQL(statements, dir)
		if err != nil {
			return err
		}
		ui.CheckOK(fmt.Sprintf("SQL exportado: %s", sqlPath))
	}

	return nil
}

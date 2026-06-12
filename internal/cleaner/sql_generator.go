package cleaner

import (
	"fmt"

	"wordpress-scanner/internal/report"
)

func GenerateCleanupSQL(dbFindings []report.DBFinding) []string {
	var statements []string
	for _, f := range dbFindings {
		if f.CleanupSQL != "" {
			statements = append(statements, fmt.Sprintf("-- %s (%s)\n%s;\n", f.ID, f.Check, f.CleanupSQL))
		}
	}
	if len(statements) == 0 {
		statements = append(statements, "-- No se generaron sentencias de limpieza\n")
	}
	return statements
}

func GenerateCleanupHeader() string {
	return `-- ==========================================
-- WordPress Scanner - Cleanup SQL
-- Generado automáticamente
-- ==========================================
-- IMPORTANTE: Hacer backup antes de ejecutar
-- ==========================================

START TRANSACTION;

`
}

func GenerateCleanupFooter() string {
	return `
-- ==========================================
-- Revisar antes de hacer COMMIT
-- ==========================================
-- Si todo está correcto:  COMMIT;
-- Si hay errores:         ROLLBACK;
-- ==========================================
`
}

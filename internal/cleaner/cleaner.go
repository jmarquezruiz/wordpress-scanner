package cleaner

import (
	"fmt"

	"wordpress-scanner/internal/dbscanner"
	"wordpress-scanner/internal/report"
	"wordpress-scanner/internal/ui"
)

type Cleaner struct {
	Connector *dbscanner.MySQLConnector
}

type CleanOperation struct {
	Description string
	SQL         string
	RowsAffected int64
	Executed    bool
}

func NewCleaner(conn *dbscanner.MySQLConnector) *Cleaner {
	return &Cleaner{Connector: conn}
}

func (c *Cleaner) GenerateOperations(dbFindings []report.DBFinding) []CleanOperation {
	var ops []CleanOperation
	for _, f := range dbFindings {
		if f.CleanupSQL != "" {
			ops = append(ops, CleanOperation{
				Description:  fmt.Sprintf("%s: %s", f.ID, f.Check),
				SQL:          f.CleanupSQL,
				RowsAffected: int64(f.RowsAffected),
			})
		}
	}
	return ops
}

func (c *Cleaner) PreviewOperations(ops []CleanOperation) {
	ui.Section("Operaciones de limpieza")
	for i, op := range ops {
		fmt.Printf("  [%d] %s (%d filas)\n", i+1, op.Description, op.RowsAffected)
		fmt.Printf("       SQL: %s\n", op.SQL)
	}
}

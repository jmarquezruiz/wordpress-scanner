package cleaner

import (
	"database/sql"
	"fmt"
)

type SQLRunner struct {
	DB *sql.DB
}

type RunResult struct {
	Operation string
	RowsAffected int64
	Error      error
}

func NewSQLRunner(db *sql.DB) *SQLRunner {
	return &SQLRunner{DB: db}
}

func (r *SQLRunner) RunOperation(op CleanOperation) RunResult {
	result := RunResult{Operation: op.Description}

	tx, err := r.DB.Begin()
	if err != nil {
		result.Error = fmt.Errorf("error starting transaction: %w", err)
		return result
	}
	defer tx.Rollback()

	res, err := tx.Exec(op.SQL)
	if err != nil {
		result.Error = fmt.Errorf("error executing SQL: %w", err)
		return result
	}

	rows, _ := res.RowsAffected()
	result.RowsAffected = rows

	if err := tx.Commit(); err != nil {
		result.Error = fmt.Errorf("error committing transaction: %w", err)
		return result
	}

	return result
}

func (r *SQLRunner) RunAllOperations(ops []CleanOperation) []RunResult {
	var results []RunResult
	for _, op := range ops {
		result := r.RunOperation(op)
		results = append(results, result)
	}
	return results
}

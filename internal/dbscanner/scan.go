package dbscanner

import (
	"database/sql"
	"fmt"
	"strings"
)

func (m *MySQLConnector) ScanUsers() ([]DBFinding, error) {
	prefix := m.Creds.Prefix
	queries := []QueryCheck{
		DefaultQueries(prefix).Checks[0],
		DefaultQueries(prefix).Checks[4],
	}
	return m.executeQueries(queries)
}

func (m *MySQLConnector) ScanPosts() ([]DBFinding, error) {
	prefix := m.Creds.Prefix
	queries := []QueryCheck{
		DefaultQueries(prefix).Checks[1],
	}
	return m.executeQueries(queries)
}

func (m *MySQLConnector) ScanComments() ([]DBFinding, error) {
	prefix := m.Creds.Prefix
	queries := []QueryCheck{
		DefaultQueries(prefix).Checks[3],
		DefaultQueries(prefix).Checks[6],
	}
	return m.executeQueries(queries)
}

func (m *MySQLConnector) ScanOptions() ([]DBFinding, error) {
	prefix := m.Creds.Prefix
	queries := []QueryCheck{
		DefaultQueries(prefix).Checks[2],
		DefaultQueries(prefix).Checks[7],
		DefaultQueries(prefix).Checks[8],
		DefaultQueries(prefix).Checks[9],
	}
	return m.executeQueries(queries)
}

func (m *MySQLConnector) ScanPostmeta() ([]DBFinding, error) {
	prefix := m.Creds.Prefix
	queries := []QueryCheck{
		DefaultQueries(prefix).Checks[5],
	}
	return m.executeQueries(queries)
}

func (m *MySQLConnector) executeQueries(checks []QueryCheck) ([]DBFinding, error) {
	var findings []DBFinding
	for _, check := range checks {
		finding, err := m.executeQuery(check)
		if err != nil {
			return findings, err
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings, nil
}

func (m *MySQLConnector) executeQuery(check QueryCheck) (*DBFinding, error) {
	rows, err := m.DB.Query(check.Query)
	if err != nil {
		return nil, fmt.Errorf("query %s error: %w", check.ID, err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	count := 0
	var sample string
	var ids []string
	values := make([]sql.NullString, len(columns))
	scanArgs := make([]interface{}, len(columns))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	for rows.Next() {
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, err
		}
		if count == 0 {
			parts := make([]string, 0, len(columns))
			for i, v := range values {
				if v.Valid {
					val := v.String
					if len(val) > 80 {
						val = val[:80] + "..."
					}
					parts = append(parts, fmt.Sprintf("%s: %s", columns[i], val))
				}
			}
			sample = joinStrings(parts, ", ")
		}
		if check.PKColumn != "" && values[0].Valid {
			ids = append(ids, values[0].String)
		}
		count++
	}

	if count == 0 {
		return nil, nil
	}

	finding := &DBFinding{
		ID:           check.ID,
		Check:        check.Name,
		Category:     check.Category,
		Severity:     check.Severity,
		RowsAffected: count,
		Sample:       sample,
	}

	if check.TableName != "" && check.PKColumn != "" && len(ids) > 0 {
		prefix := m.Creds.Prefix
		finding.CleanupSQL = fmt.Sprintf("DELETE FROM %s%s WHERE %s IN (%s)",
			prefix, check.TableName, check.PKColumn, joinSQLIDs(ids))
	}

	return finding, nil
}

func joinSQLIDs(ids []string) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(id, "'", "\\'"))
	}
	return strings.Join(quoted, ",")
}

func joinStrings(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	result := elems[0]
	for _, e := range elems[1:] {
		result += sep + e
	}
	return result
}

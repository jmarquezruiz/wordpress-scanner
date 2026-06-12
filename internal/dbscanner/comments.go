package dbscanner

func (m *MySQLConnector) ScanCommentsFindings() ([]DBFinding, error) {
	return m.ScanComments()
}

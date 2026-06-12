package dbscanner

func (m *MySQLConnector) ScanOptionsFindings() ([]DBFinding, error) {
	return m.ScanOptions()
}

package dbscanner

func (m *MySQLConnector) ScanPostmetaFindings() ([]DBFinding, error) {
	return m.ScanPostmeta()
}

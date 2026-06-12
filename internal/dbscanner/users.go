package dbscanner

func (m *MySQLConnector) ScanUsersFindings() ([]DBFinding, error) {
	return m.ScanUsers()
}

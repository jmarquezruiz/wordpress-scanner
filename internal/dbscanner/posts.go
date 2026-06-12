package dbscanner

func (m *MySQLConnector) ScanPostsFindings() ([]DBFinding, error) {
	return m.ScanPosts()
}

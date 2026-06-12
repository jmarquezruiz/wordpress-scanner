package dbscanner

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"wordpress-scanner/internal/ui"
)

type MySQLConnector struct {
	DB   *sql.DB
	Creds *ui.DBCredentials
}

func (m *MySQLConnector) Connect(creds *ui.DBCredentials) error {
	m.Creds = creds
	dsn, err := buildDSN(creds)
	if err != nil {
		return fmt.Errorf("error building DSN: %w", err)
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("error opening connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("error connecting to MySQL: %w", err)
	}

	m.DB = db
	return nil
}

func (m *MySQLConnector) Close() error {
	if m.DB != nil {
		return m.DB.Close()
	}
	return nil
}

func (m *MySQLConnector) RunAllChecks() ([]DBScanResult, error) {
	var results []DBScanResult

	categories := []struct {
		name string
		fn   func() ([]DBFinding, error)
	}{
		{"users", m.ScanUsers},
		{"posts", m.ScanPosts},
		{"comments", m.ScanComments},
		{"options", m.ScanOptions},
		{"postmeta", m.ScanPostmeta},
	}

	for _, cat := range categories {
		findings, err := cat.fn()
		res := DBScanResult{
			Category: cat.name,
			Findings: findings,
			Error:    err,
		}
		results = append(results, res)
	}

	return results, nil
}

func buildDSN(creds *ui.DBCredentials) (string, error) {
	host := creds.Host
	port := creds.Port

	if host == "" {
		host = "localhost"
	}

	if port == "" {
		port = "3306"
	}

	userPass := creds.User
	if creds.Password != "" {
		userPass = creds.User + ":" + creds.Password
	}

	if isSocketPath(host) {
		return fmt.Sprintf("%s@unix(%s)/%s?charset=utf8mb4", userPass, host, creds.Database), nil
	}

	if host == "localhost" && port == "3306" {
		socketPaths := []string{
			"/var/run/mysqld/mysqld.sock",
			"/tmp/mysql.sock",
			"/opt/lampp/var/mysql/mysql.sock",
			"/Applications/MAMP/tmp/mysql/mysql.sock",
		}
		for _, sp := range socketPaths {
			if _, err := os.Stat(sp); err == nil {
				return fmt.Sprintf("%s@unix(%s)/%s?charset=utf8mb4", userPass, sp, creds.Database), nil
			}
		}
	}

	if host == "localhost" {
		host = "127.0.0.1"
	}

	if net.ParseIP(host) != nil || isDomain(host) {
		addr := host
		if port != "" {
			addr = host + ":" + port
		}
		return fmt.Sprintf("%s@tcp(%s)/%s?charset=utf8mb4", userPass, addr, creds.Database), nil
	}

	return fmt.Sprintf("%s@tcp(%s:%s)/%s?charset=utf8mb4", userPass, host, port, creds.Database), nil
}

func isSocketPath(host string) bool {
	return strings.HasPrefix(host, "/") || strings.HasPrefix(host, "./") || strings.HasPrefix(host, "../")
}

func isDomain(host string) bool {
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.Contains(host, ".")
}

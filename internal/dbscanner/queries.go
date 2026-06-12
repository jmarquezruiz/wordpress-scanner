package dbscanner

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type QueryCheck struct {
	ID           string `yaml:"id"`
	Name         string `yaml:"name"`
	Category     string `yaml:"category"`
	Query        string `yaml:"query"`
	Severity     string `yaml:"severity"`
	TableName    string `yaml:"table,omitempty"`
	PKColumn     string `yaml:"pk,omitempty"`
}

type QueryCatalog struct {
	Checks []QueryCheck `yaml:"checks"`
}

func DefaultQueries(prefix string) QueryCatalog {
	return QueryCatalog{
		Checks: []QueryCheck{
			{
				ID: "DB-001", Name: "Usuarios admin no originales", Category: "users",
				Query:    fmt.Sprintf("SELECT ID, user_login, user_email FROM %susers WHERE ID NOT IN (1)", prefix),
				Severity: "high", TableName: "users", PKColumn: "ID",
			},
			{
				ID: "DB-002", Name: "Posts con SEO spam de casino", Category: "posts",
				Query:    fmt.Sprintf("SELECT ID, post_title, LEFT(post_content,200) FROM %sposts WHERE post_content LIKE '%%casino%%' OR post_content LIKE '%%gambling%%' OR post_content LIKE '%%poker%%'", prefix),
				Severity: "critical", TableName: "posts", PKColumn: "ID",
			},
			{
				ID: "DB-003", Name: "Opciones con eval/base64", Category: "options",
				Query:    fmt.Sprintf("SELECT option_id, option_name, LEFT(option_value,100) FROM %soptions WHERE option_value LIKE '%%eval(%%' OR option_value LIKE '%%base64_decode(%%'", prefix),
				Severity: "critical", TableName: "options", PKColumn: "option_id",
			},
			{
				ID: "DB-004", Name: "Comentarios spam aprobados con links", Category: "comments",
				Query:    fmt.Sprintf("SELECT comment_ID, comment_author, LEFT(comment_content,100) FROM %scomments WHERE comment_approved = '1' AND comment_content LIKE '%%<a href%%'", prefix),
				Severity: "medium", TableName: "comments", PKColumn: "comment_ID",
			},
			{
				ID: "DB-005", Name: "Usuarios con capacidades de admin", Category: "users",
				Query:    fmt.Sprintf("SELECT u.ID, u.user_login FROM %susermeta um JOIN %susers u ON u.ID = um.user_id WHERE um.meta_key = '%scapabilities' AND um.meta_value LIKE '%%administrator%%'", prefix, prefix, prefix),
				Severity: "high",
			},
			{
				ID: "DB-006", Name: "Post meta con payloads ofuscados", Category: "postmeta",
				Query:    fmt.Sprintf("SELECT meta_id, post_id, meta_key, LEFT(meta_value,100) FROM %spostmeta WHERE meta_value LIKE '%%eval(%%' OR meta_value LIKE '%%base64%%' OR meta_value LIKE '%%gamblers%%'", prefix),
				Severity: "critical", TableName: "postmeta", PKColumn: "meta_id",
			},
			{
				ID: "DB-007", Name: "Trackbacks y pingbacks", Category: "comments",
				Query:    fmt.Sprintf("SELECT comment_ID, comment_post_ID, comment_author FROM %scomments WHERE comment_type IN ('trackback','pingback')", prefix),
				Severity: "low", TableName: "comments", PKColumn: "comment_ID",
			},
			{
				ID: "DB-008", Name: "Opciones críticas del sitio", Category: "options",
				Query:    fmt.Sprintf("SELECT option_name, LEFT(option_value,200) FROM %soptions WHERE option_name IN ('siteurl','home','admin_email','users_can_register','default_role','active_plugins','template','stylesheet')", prefix),
				Severity: "info",
			},
			{
				ID: "DB-009", Name: "Cron con tareas sospechosas", Category: "options",
				Query:    fmt.Sprintf("SELECT option_id, option_name, LEFT(option_value,500) FROM %soptions WHERE option_name = 'cron'", prefix),
				Severity: "medium",
			},
			{
				ID: "DB-010", Name: "Redirecciones y front page inyectadas", Category: "options",
				Query:    fmt.Sprintf("SELECT option_id, option_name, LEFT(option_value,200) FROM %soptions WHERE option_name LIKE '%%redirect%%' OR option_name = 'page_on_front' OR option_name = 'page_for_posts'", prefix),
				Severity: "medium", TableName: "options", PKColumn: "option_id",
			},
		},
	}
}

func LoadCustomQueries() (QueryCatalog, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return QueryCatalog{}, nil
	}
	customPath := filepath.Join(home, ".wordpress-scanner", "custom-queries.yaml")
	data, err := os.ReadFile(customPath)
	if err != nil {
		return QueryCatalog{}, nil
	}
	var catalog QueryCatalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return QueryCatalog{}, fmt.Errorf("error parsing custom queries: %w", err)
	}
	return catalog, nil
}

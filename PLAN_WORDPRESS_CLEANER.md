# wpscanner — WordPress Security Scanner CLI

Herramienta CLI en Go para escaneo, análisis, reporte y verificación de malware en WordPress.

---

## Concepto

Pipeline de hardening: **escanea → analiza → reporta → verifica**

```
wpscanner scan [path]              # Escanea archivos y genera reporte
wpscanner scan-db                  # Escanea base de datos (pide credenciales)
wpscanner scan --db                # Escanea archivos + base de datos
wpscanner verify --report.json     # Verifica que todo esté limpio tras limpiar
```

---

## 1. Estructura del proyecto

```
wpscanner/
├── main.go                      # Entry point
├── go.mod / go.sum
├── cmd/
│   ├── root.go                  # Comando raíz, flags globales
│   ├── scan.go                  # wpscanner scan [path]
│   └── verify.go                # wpscanner verify --report report.json
├── internal/
│   ├── scanner/
│   │   ├── scanner.go           # Interface Scanner { Name(), Run(path, logs) ([]Result, error) }
│   │   ├── clamav.go            # clamscan -ri + parseo output
│   │   ├── pmf.go               # php-malware-finder (YARA) + parseo
│   │   ├── maldet.go            # maldet -a + parseo
│   │   └── opencode.go          # Subagente opencode para deep analysis
│   ├── dbscanner/
│   │   ├── dbscanner.go         # Interface DBScanner { Connect(creds) error; Run(queries) ([]DBFinding, error) }
│   │   ├── connector.go         # Conexión MySQL: soporta TCP (localhost, 127.0.0.1, IPs), socket Unix (/var/run/mysqld/mysqld.sock), puertos personalizados
│   │   ├── queries.go           # Catálogo de queries de detección (extensible con JSON externo)
│   │   ├── users.go             # Usuarios extra, admins, capabilities
│   │   ├── posts.go             # Posts con SEO spam, eval, base64, iframes ocultos
│   │   ├── comments.go          # Spam, trackbacks, pingbacks, aprobados con links
│   │   ├── options.go           # Cron malicioso, widgets, redirecciones, opciones críticas
│   │   └── postmeta.go          # Post meta con payloads ofuscados
│   ├── updater/
│   │   └── updater.go           # freshclam, maldet -u, etc.
│   ├── report/
│   │   ├── types.go             # Structs compartidos
│   │   ├── generate.go          # Genera .json + .md
│   │   └── verify.go            # Verifica limpieza post-cleanup
│   └── ui/
│       └── prompts.go           # Menú interactivo (gum / survey)
```

---

## 2. Flujo de ejecución

```
$ wpscanner scan

  1. Pide ruta del proyecto
  2. Pide scanners a usar (checkbox):
     [x] ClamAV (clamscan -ri)
     [x] PHP-Malware-Finder (YARA)
     [x] Linux Malware Detect (maldet -a)
     [x] Opencode Subagente (deep analysis)
  3. Pide si actualizar DBs antes
  4. Pide si mostrar logs en vivo
  5. Ejecuta cada scanner secuencialmente
  6. Si opencode marcado → genera prompt con hallazgos previos → subagente
  7. Genera reportes:
     ├── wpscanner-report-YYYYMMDD-HHMMSS.json  (máquina)
     └── wpscanner-report-YYYYMMDD-HHMMSS.md    (humano)
  8. Muestra resumen en terminal
```

```
$ wpscanner scan-db

  1. Pide credenciales MySQL:
     ┌─ Host ─────────────────────────┐
     │  localhost / 127.0.0.1 / IP    │ ← detecta automáticamente TCP vs socket
     ├─ Puerto ───────────────────────┤     (socket Unix si host está vacío o "localhost" sin TCP)
     │  (opcional, default 3306)      │
     ├─ Usuario ──────────────────────┤
     │  root / wp_user                │
     ├─ Contraseña ───────────────────┤
     │  ****                           │
     ├─ Base de datos ────────────────┤
     │  wordpress / wp_database       │
     └─ Prefijo tablas ───────────────┘
       (opcional, default wp_)

  2. Conexión: detecta tipo de host
     - "localhost" sin puerto → prueba socket Unix (/var/run/mysqld/mysqld.sock, /tmp/mysql.sock)
     - "localhost:3306" o "127.0.0.1" → TCP
     - IP externa → TCP con timeout configurable
     - Pipe / socket personalizado → soporte para Docker, MAMP, XAMPP

  3. Ejecuta queries de detección organizadas en categorías:
     [x] Usuarios y roles
     [x] Posts y contenido
     [x] Comentarios
     [x] Opciones (cron, widgets, redirecciones)
     [x] Post meta
     [x] Opciones críticas
  4. Muestra resultados en tabla por categoría
  5. Genera reporte igual que scan (JSON + MD)
  6. Pregunta si quiere generar queries de limpieza (opcional)
```

---

## 3. Formato del reporte JSON

```json
{
  "meta": {
    "tool": "wpscanner",
    "version": "1.0.0",
    "scan_date": "2026-06-12T17:30:00+02:00",
    "target_path": "/home/user/target",
    "elapsed_seconds": 342
  },
  "findings": [
    {
      "id": "BAK-001",
      "scanner": "pmf",
      "file": "wp-includes/template-loader-edit.php",
      "severity": "critical",
      "type": "webshell",
      "description": "Webshell via HTTP header B033B35",
      "indicator": "DodgyPhp",
      "recommendation": "Delete file"
    }
  ],
  "summary": {
    "total_findings": 6,
    "critical": 4,
    "high": 1,
    "medium": 1,
    "low": 0,
    "backdoors": 4,
    "injections": 2
  },
  "clean_hashes": {
    "wp-blog-header.php": "sha256:abc123..."
  }
}
```

---

## 4. Flujo de verificación

```
$ wpscanner verify --report wpscanner-report-20260612-173000.json

  1. Carga findings del reporte previo
  2. Para cada finding:
     → SHA256 actual del archivo
     → Si cambió el hash → "revisar manual"
     → Si no existe → "eliminado ✓"
     → Si mismo hash → "aún infectado ✗"
  3. Re-ejecuta scanners solo sobre archivos afectados
  4. Compara resultados
  5. Conclusión: "Limpio ✓" o "Quedan N hallazgos ✗"
```

---

## 5. Conexión a base de datos

### 5.1 Detección automática de conexión

El connector prueba en orden hasta encontrar conexión:

| Entrada usuario | Comportamiento |
|----------------|----------------|
| `localhost` | Prueba socket Unix (`/var/run/mysqld/mysqld.sock`, `/tmp/mysql.sock`, `/opt/lampp/var/mysql/mysql.sock`, etc.) |
| `localhost:3306` | TCP forzado |
| `127.0.0.1` | TCP |
| `192.168.x.x` o dominio | TCP |
| `./var/mysql.sock` | Socket personalizado |

### 5.2 Driver

```go
import _ "github.com/go-sql-driver/mysql"
// Conexión socket:
// "user:pass@unix(/var/run/mysqld/mysqld.sock)/dbname"
// Conexión TCP:
// "user:pass@tcp(localhost:3306)/dbname"
```

### 5.3 Catálogo de queries (extensible)

Las queries se definen en YAML/JSON externo para poder añadir nuevas sin recompilar:

```yaml
checks:
  - id: "DB-001"
    name: "Usuarios admin no originales"
    category: "users"
    query: "SELECT ID, user_login, user_email FROM wp_users WHERE ID NOT IN (1)"
    severity: "high"

  - id: "DB-002"
    name: "Posts con SEO spam de casino"
    category: "posts"
    query: "SELECT ID, post_title, LEFT(post_content,200) FROM wp_posts WHERE post_content LIKE '%casino%' OR post_content LIKE '%gambling%'"
    severity: "critical"

  - id: "DB-003"
    name: "Opciones con eval/base64"
    category: "options"
    query: "SELECT option_id, option_name FROM wp_options WHERE option_value LIKE '%eval(%' OR option_value LIKE '%base64_decode(%'"
    severity: "critical"

  - id: "DB-004"
    name: "Comentarios spam aprobados con links"
    category: "comments"
    query: "SELECT comment_ID, comment_author FROM wp_comments WHERE comment_approved = '1' AND comment_content LIKE '%<a href%'"
    severity: "medium"

  - id: "DB-005"
    name: "Usuarios con capacidades de admin"
    category: "users"
    query: "SELECT u.ID, u.user_login FROM wp_usermeta um JOIN wp_users u ON u.ID = um.user_id WHERE um.meta_key = 'wp_capabilities' AND um.meta_value LIKE '%administrator%'"
    severity: "high"

  - id: "DB-006"
    name: "Post meta con payloads ofuscados"
    category: "postmeta"
    query: "SELECT meta_id, post_id, meta_key FROM wp_postmeta WHERE meta_value LIKE '%eval(%' OR meta_value LIKE '%base64%' OR meta_value LIKE '%gamblers%'"
    severity: "critical"

  - id: "DB-007"
    name: "Trackbacks y pingbacks"
    category: "comments"
    query: "SELECT comment_ID, comment_post_ID FROM wp_comments WHERE comment_type IN ('trackback','pingback')"
    severity: "low"

  - id: "DB-008"
    name: "Opciones críticas del sitio"
    category: "options"
    query: "SELECT option_name, option_value FROM wp_options WHERE option_name IN ('siteurl','home','admin_email','users_can_register','default_role','active_plugins','template','stylesheet')"
    severity: "info"

  - id: "DB-009"
    name: "Cron con tareas sospechosas"
    category: "options"
    query: "SELECT option_name, LEFT(option_value,500) FROM wp_options WHERE option_name = 'cron' OR option_name LIKE '%cron%'"
    severity: "medium"

  - id: "DB-010"
    name: "Redirecciones y front page inyectadas"
    category: "options"
    query: "SELECT option_id, option_name FROM wp_options WHERE option_name LIKE '%redirect%' OR option_name LIKE '%page_on_front%' OR option_name LIKE '%page_for_posts%'"
    severity: "medium"
```

El usuario puede añadir sus propias queries en `~/.wpscanner/custom-queries.yaml`.

### 5.4 Generación de queries de limpieza

Al detectar hallazgos, la herramienta ofrece generar automáticamente las sentencias DELETE/UPDATE correspondientes y guardarlas en un `.sql`.

---

## 6. Integración con opencode

```go
func (o *OpencodeScanner) Run(path string, logs bool) ([]Result, error) {
    prompt := fmt.Sprintf(`Investigate WordPress hack at %s.
Findings so far: %s.
Check for: eval, base64_decode, system, exec, webshells, SEO spam,
hidden redirects, unknown admin users, cron jobs, .htaccess abuse,
xmlrpc exploits. Return structured JSON list of findings.`,
        path, previousFindings)

    cmd := exec.Command("opencode", "task", "--subagent", "general", prompt)
    // parse output
}

// Variante DB: recibe findings de DB y los añade al prompt
func (o *OpencodeScanner) RunWithDB(path string, dbFindings []DBFinding, logs bool) ([]Result, error) {
    prompt := fmt.Sprintf(`Investigate WordPress hack at %s.
File findings: %s.
Database findings: %s.`,
        path, fileFindings, dbFindings)
    // ...
}
```

---

## 7. Librerías Go

| Propósito | Librería |
|-----------|----------|
| CLI framework | `github.com/spf13/cobra` |
| Menús interactivos | `github.com/AlecAivazis/survey/v2` |
| Colores | `github.com/fatih/color` |
| Spinner | `github.com/briandowns/spinner` |
| YARA (extra) | `github.com/hillu/go-yara/v4` |
| MySQL driver | `github.com/go-sql-driver/mysql` |
| SQL conn pool | `database/sql` (stdlib) |

---

## 8. Roadmap

| Fase | Tarea | Est. |
|------|-------|------|
| 1 | Estructura base + cobra | 30 min |
| 2 | Interfaz Scanner + tipos | 20 min |
| 3 | Scanner ClamAV | 45 min |
| 4 | Scanner PMF (YARA) | 30 min |
| 5 | Scanner Maldet | 45 min |
| 6 | Scanner Opencode (subagente) | 1 h |
| 7 | Updater DBs | 30 min |
| 8 | Generar reportes JSON + MD | 45 min |
| 9 | Verificación post-cleanup | 30 min |
| 10 | Menú interactivo UI | 45 min |
| 11 | Comandos scan + verify | 30 min |
| 12 | Módulo dbscanner — connector MySQL | 30 min |
| 13 | Módulo dbscanner — catálogo queries base | 45 min |
| 14 | Módulo dbscanner — generación queries limpieza | 30 min |
| 15 | Integración scan + scan-db (reporte unificado) | 30 min |
| 16 | Tests con WordPress real | 1 h |

**Total estimado: ~10-11 horas**

---

## 9. Diagrama

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────────────────┐
│  wpscanner scan │────→│  UI prompts      │────→│  Update DBs (si marcado)     │
│  [path]     │     │  + elegir scanners│    └──────────────┬───────────────┘
└─────────────┘     └──────────────────┘                    │
                                                            ▼
                                            ┌──────────────────────────────┐
                                            │  Ejecutar scanners archivos  │
                                            │  clamscan → pmf → maldet    │
                                            │  └─ opencode (subagente)    │
                                            └──────────────┬───────────────┘
                                                            │
                                                            ▼
┌─────────────┐     ┌──────────────────┐     ┌──────────────────────────────┐
│ wpscanner scan-db│───→│  Pedir credenciales│──→│  Detectar tipo conexión     │
│             │     │  MySQL host/user/ │   │  socket / TCP / IP externa   │
│             │     │  pass/db/prefix   │   └──────────────┬───────────────┘
└─────────────┘     └──────────────────┘                   │
                                                            ▼
                                            ┌──────────────────────────────┐
                                            │  Ejecutar catálogo queries   │
                                            │  users → posts → comments    │
                                            │  options → postmeta → cron   │
                                            └──────────────┬───────────────┘
                                                            │
                                                            ▼
                                            ┌──────────────────────────────┐
                                            │  Generar reportes            │
                                            │  ├── .json (máquina)        │
                                            │  └── .md (humano)           │
                                            │  └── .sql (limpieza) opcional│
                                            └──────────────┬───────────────┘
                                                            │
                                                            ▼
                                            ┌──────────────────────────────┐
                                            │  Resumen en terminal         │
                                            └──────────────────────────────┘

┌─────────────┐     ┌──────────────────┐     ┌──────────────────────────────┐
│ wpscanner verify│────→│  Cargar reporte  │────→│  Re-scanear (files + DB)    │
│ --report X  │     │  previo .json    │     │  → "Limpio" o "Quedan N"    │
└─────────────┘     └──────────────────┘     └──────────────────────────────┘
```

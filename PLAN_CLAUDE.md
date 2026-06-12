# WordPress Scanner — CLI de Seguridad WordPress

Herramienta CLI en Go para escaneo, análisis, limpieza y reporte de malware en WordPress.
Automatiza el proceso completo: detección → limpieza en local → informe para cliente → guía de pasos finales manuales.

---

## Banner de arranque

Al ejecutar cualquier subcomando, lo primero que aparece:

```
__          __ _____     _____                                        
\ \        / /|  __ \   / ____|                                       
 \ \  /\  / / | |__) | | (___    ___   __ _  _ __   _ __    ___  _ __ 
  \ \/  \/ /  |  ___/   \___ \  / __| / _` || '_ \ | '_ \  / _ \| '__|
   \  /\  /   | |       ____) || (__ | (_| || | | || | | ||  __/| |   
    \/  \/    |_|      |_____/  \___| \__,_||_| |_||_| |_| \___||_|   

                         jmarquez.dev
```

Seguido de la versión y fecha de inicio del scan.

---

## Concepto

Pipeline completo: **escanea → analiza → limpia (en local) → verifica → reporta → guía pasos manuales**

```
wpscanner scan [path]              # Escanea archivos y genera reporte
wpscanner scan-db                  # Escanea base de datos (pide credenciales)
wpscanner scan --db                # Escanea archivos + base de datos (recomendado)
wpscanner clean --report X.json    # Aplica limpieza sobre DB local basándose en el reporte
wpscanner verify --report X.json   # Verifica limpieza post-cleanup
wpscanner report --report X.json   # Genera informe formal en PDF/MD para el cliente
```

---

## 1. Estructura del proyecto

```
wordpress-scanner/
├── main.go
├── go.mod / go.sum
├── cmd/
│   ├── root.go                  # Cobra root, banner, flags globales
│   ├── scan.go                  # wpscanner scan [path]
│   ├── scandb.go                # wpscanner scan-db
│   ├── clean.go                 # wpscanner clean --report X.json
│   ├── verify.go                # wpscanner verify --report X.json
│   └── report.go                # wpscanner report --report X.json (genera INFORME_CLIENTE.md)
├── internal/
│   ├── scanner/
│   │   ├── scanner.go           # Interface Scanner { Name(), Run(path, logs) ([]Result, error) }
│   │   ├── clamav.go            # clamscan -ri + parseo output
│   │   ├── pmf.go               # php-malware-finder (YARA) + parseo
│   │   ├── maldet.go            # maldet -a + parseo
│   │   └── opencode.go          # Subagente opencode para deep analysis
│   ├── dbscanner/
│   │   ├── dbscanner.go         # Interface DBScanner
│   │   ├── connector.go         # Conexión MySQL: TCP / socket Unix / Docker
│   │   ├── queries.go           # Catálogo de queries de detección (YAML extensible)
│   │   ├── users.go             # Usuarios extra, admins, capabilities
│   │   ├── posts.go             # Posts con SEO spam, eval, base64, iframes ocultos
│   │   ├── comments.go          # Spam, trackbacks, pingbacks
│   │   ├── options.go           # Cron malicioso, widgets, redirecciones
│   │   └── postmeta.go          # Post meta con payloads ofuscados
│   ├── cleaner/
│   │   ├── cleaner.go           # Orquesta el proceso de limpieza en local
│   │   ├── sql_generator.go     # Genera sentencias DELETE/UPDATE a partir de findings
│   │   ├── sql_runner.go        # Ejecuta SQL en DB local con confirmación + rollback
│   │   └── sql_exporter.go      # Exporta el .sql final validado para ejecutar en producción
│   ├── report/
│   │   ├── types.go             # Structs compartidos (Finding, DBFinding, Summary, etc.)
│   │   ├── generate.go          # Genera .json + .md internos
│   │   ├── client_report.go     # Genera INFORME_CLIENTE_YYYYMMDD.md (formal, para enviar)
│   │   └── verify.go            # Lógica de verificación post-cleanup
│   ├── nextSteps/
│   │   └── generator.go         # Genera SIGUIENTES_PASOS.md personalizado
│   ├── updater/
│   │   └── updater.go           # freshclam, maldet -u, etc.
│   └── ui/
│       ├── prompts.go           # Menús interactivos (survey/v2)
│       └── progress.go          # Spinners, barras de progreso, tablas, colores en CLI
```

---

## 2. Flujo de ejecución completo

### 2.1 `wpscanner scan --db`

```
[Banner ASCII]

  ┌─ WordPress Scanner ──────────────────────────────────┐
  │  Ruta del proyecto WordPress: /var/www/misite        │
  │  Base de datos: localhost / user / pass / wp_db      │
  │  Prefijo tablas: wp_                                  │
  └──────────────────────────────────────────────────────┘

  Scanners a usar:
  [x] ClamAV (clamscan -ri)
  [x] PHP-Malware-Finder (YARA)
  [x] Linux Malware Detect (maldet -a)
  [x] Opencode Subagente (deep analysis)

  ¿Actualizar bases de datos de firmas antes? [s/N]
  ¿Mostrar logs en vivo? [s/N]

  ── Escaneando archivos ────────────────────────────────
  ⠸ ClamAV        ████████████░░░░  67%  wp-content/plugins/...
  ✓ ClamAV        3 hallazgos críticos
  ⠸ PMF (YARA)    ████████████████  100%
  ✓ PMF           1 hallazgo crítico
  ⠸ Maldet        ████░░░░░░░░░░░░  25%
  ...

  ── Escaneando base de datos ───────────────────────────
  ✓ Usuarios y roles        2 hallazgos (high)
  ✓ Posts y contenido       5 hallazgos (critical)
  ✓ Comentarios             12 hallazgos (low)
  ✓ Opciones                1 hallazgo (critical)
  ✓ Post meta               0 hallazgos

  ── Análisis profundo con Opencode ────────────────────
  ⠸ Analizando hallazgos previos...
  ✓ Opencode      2 hallazgos adicionales detectados

  ── Generando reportes ────────────────────────────────
  ✓ wpscanner-report-20260612-153000.json
  ✓ wpscanner-report-20260612-153000.md

  ┌─ RESUMEN ────────────────────────────────────────────┐
  │  Critical: 8   High: 3   Medium: 2   Low: 12        │
  │  Archivos infectados: 5                              │
  │  Hallazgos en DB: 20                                 │
  └──────────────────────────────────────────────────────┘

  ¿Proceder con limpieza en local? [s/N]   ← si sí, lanza clean automáticamente
```

---

### 2.2 `wpscanner clean --report X.json`

El proceso de limpieza se ejecuta **exclusivamente en local** (DB local que el usuario ha importado).
Nunca toca producción directamente.

```
  ── Limpieza en base de datos local ──────────────────
  Base de datos local: localhost / user / pass / wp_db_local

  Se van a ejecutar 8 operaciones:
  ┌─────────────────────────────────────────────────────┐
  │  [1] DELETE usuarios admin no originales (2 filas) │
  │  [2] DELETE posts con SEO spam (5 filas)           │
  │  [3] UPDATE opciones con eval() (1 fila)           │
  │  [4] DELETE comentarios trackback/pingback (12)    │
  │  ...                                                │
  └─────────────────────────────────────────────────────┘

  ¿Ejecutar limpieza? (se puede revertir con rollback) [s/N]

  ✓ [1] Ejecutado — 2 filas eliminadas
  ✓ [2] Ejecutado — 5 filas eliminadas
  ✓ [3] Ejecutado — 1 fila actualizada
  ✓ [4] Ejecutado — 12 filas eliminadas

  ── Verificación post-limpieza ────────────────────────
  Re-ejecutando queries de detección...
  ✓ Usuarios y roles        0 hallazgos ✓
  ✓ Posts y contenido       0 hallazgos ✓
  ✓ Opciones                0 hallazgos ✓

  ┌─ RESULTADO ──────────────────────────────────────────┐
  │  Base de datos: LIMPIA ✓                            │
  │  Todas las queries de detección pasan               │
  └──────────────────────────────────────────────────────┘

  ¿Exportar .sql final para ejecutar en producción? [s/N]
  ✓ cleanup-20260612-153000.sql generado
```

El flujo permite ejecutar `clean` múltiples veces hasta que todas las verificaciones pasen.
Solo entonces se exporta el `.sql` final.

---

### 2.3 Archivos de salida por sesión

Todos los archivos se guardan en `./wpscanner-output/YYYYMMDD-HHMMSS/`:

```
wpscanner-output/
└── 20260612-153000/
    ├── wpscanner-report.json              # Reporte máquina (interno)
    ├── wpscanner-report.md                # Reporte legible (interno)
    ├── cleanup.sql                        # SQL final para ejecutar en producción
    ├── INFORME_CLIENTE_20260612.md        # Informe formal para enviar al cliente
    └── SIGUIENTES_PASOS.md               # Guía manual para completar el trabajo
```

---

## 3. Informe para el cliente (`INFORME_CLIENTE_YYYYMMDD.md`)

Generado con `wpscanner report` o automáticamente al finalizar el scan.

Estructura del informe:

```markdown
# Informe de Seguridad WordPress
**Cliente:** [nombre del sitio / dominio]
**Fecha del análisis:** 12 de junio de 2026
**Analista:** jmarquez.dev

---

## Resumen ejecutivo
Descripción en lenguaje no técnico del estado del sitio y las amenazas encontradas.

## Hallazgos críticos
| ID | Tipo | Descripción | Ruta/Tabla | Acción tomada |
|----|------|-------------|------------|---------------|
| BAK-001 | Webshell | Puerta trasera via HTTP header | wp-includes/template-loader-edit.php | Eliminado |
...

## Hallazgos en base de datos
| ID | Categoría | Descripción | Registros afectados | Acción |
...

## Acciones realizadas
Lista de limpieza ejecutada.

## Estado final
✓ Sitio limpio tras la intervención.

## Recomendaciones
- Actualizar WordPress, plugins y tema
- Cambiar todas las contraseñas y salts
- Activar autenticación en dos factores
- Contratar plan de mantenimiento mensual
```

El informe está pensado para ser enviado directamente al cliente, con lenguaje accesible.

---

## 4. Siguientes pasos manuales (`SIGUIENTES_PASOS.md`)

Generado automáticamente al finalizar, personalizado según los hallazgos del scan.

Contenido base (siempre incluido):

```markdown
# Siguientes Pasos — Post-limpieza

## 1. Ejecutar cleanup.sql en producción
Antes de nada, hacer backup completo de la BD de producción.
Luego ejecutar: `mysql -u user -p database < cleanup.sql`

## 2. Cambiar contraseñas
- [ ] Contraseña del admin de WordPress
- [ ] Contraseña de la base de datos
- [ ] Contraseña FTP/SFTP
- [ ] Contraseña del panel de hosting

## 3. Regenerar salts y keys de wp-config.php
Ir a: https://api.wordpress.org/secret-key/1.1/salt/
Reemplazar el bloque completo en wp-config.php

## 4. Actualizar WordPress core
Dashboard → Actualizaciones → Actualizar WordPress

## 5. Actualizar plugins
Dashboard → Actualizaciones → Plugins

## 6. Actualizar tema
Dashboard → Actualizaciones → Temas
⚠️  Si el tema tiene modificaciones personales, revisar antes de actualizar

## 7. Revisar usuarios administradores
Usuarios → Todos los usuarios → revisar que solo existen los legítimos

## 8. Revisar plugins instalados
Plugins → Eliminar cualquier plugin no reconocido o desactivado sin uso

## 9. Configurar permisos de archivos
chmod 644 wp-config.php
chmod 755 wp-content/uploads

## 10. Verificar .htaccess
Revisar que no contenga redirecciones no autorizadas.
Regenerar desde: Ajustes → Enlaces permanentes → Guardar

## 11. Activar plugin de seguridad
Instalar Wordfence o iThemes Security y configurar alertas por email
```

Secciones adicionales se añaden automáticamente según los hallazgos:
- Si se detectaron webshells → instrucciones específicas de revisión de permisos
- Si hubo spam SEO en posts → instrucciones para revisar indexación en Google Search Console
- Si se encontraron usuarios admin extra → recordatorio de revisar también en wp-cli
- Si hay plugins desactualizados → lista de plugins a actualizar con sus versiones

---

## 5. Formato del reporte JSON

```json
{
  "meta": {
    "tool": "wordpress-scanner",
    "version": "1.0.0",
    "scan_date": "2026-06-12T15:30:00+02:00",
    "target_path": "/home/user/target",
    "target_domain": "example.com",
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
      "recommendation": "Delete file",
      "cleaned": false
    }
  ],
  "db_findings": [
    {
      "id": "DB-002",
      "check": "Posts con SEO spam de casino",
      "category": "posts",
      "severity": "critical",
      "rows_affected": 5,
      "sample": "ID 423: 'Best casino online 2026...'",
      "cleanup_sql": "DELETE FROM wp_posts WHERE ...",
      "cleaned": false
    }
  ],
  "summary": {
    "total_findings": 6,
    "critical": 4,
    "high": 1,
    "medium": 1,
    "low": 0,
    "backdoors": 4,
    "injections": 2,
    "db_findings": 20,
    "cleaned": false
  },
  "clean_hashes": {
    "wp-blog-header.php": "sha256:abc123..."
  }
}
```

---

## 6. Verificación post-cleanup (`wpscanner verify`)

```
$ wpscanner verify --report wpscanner-output/20260612-153000/wpscanner-report.json

  ── Verificando archivos ──────────────────────────────
  ✓ wp-includes/template-loader-edit.php → Eliminado ✓
  ✓ wp-content/plugins/bad-plugin/shell.php → Eliminado ✓
  ✗ wp-content/uploads/2026/image.php → Hash sin cambios (aún infectado)

  ── Re-escaneando DB ──────────────────────────────────
  ✓ Usuarios y roles        0 hallazgos ✓
  ✓ Posts y contenido       0 hallazgos ✓
  ✗ Opciones                1 hallazgo (cron sospechoso)

  ┌─ CONCLUSIÓN ─────────────────────────────────────────┐
  │  ✗ Quedan 2 hallazgos sin resolver                  │
  │  Ejecuta wpscanner clean de nuevo para limpiarlos   │
  └──────────────────────────────────────────────────────┘
```

---

## 7. Conexión a base de datos

### 7.1 Detección automática de conexión

| Entrada usuario | Comportamiento |
|----------------|----------------|
| `localhost` | Prueba socket Unix (`/var/run/mysqld/mysqld.sock`, `/tmp/mysql.sock`, `/opt/lampp/var/mysql/mysql.sock`) |
| `localhost:3306` | TCP forzado |
| `127.0.0.1` | TCP |
| `192.168.x.x` o dominio | TCP |
| `./var/mysql.sock` | Socket personalizado |

### 7.2 Driver

```go
import _ "github.com/go-sql-driver/mysql"
// Conexión socket:  "user:pass@unix(/var/run/mysqld/mysqld.sock)/dbname"
// Conexión TCP:     "user:pass@tcp(localhost:3306)/dbname"
```

### 7.3 Catálogo de queries (extensible con YAML externo)

Las queries se definen en `~/.wordpress-scanner/custom-queries.yaml` y se pueden añadir sin recompilar.

Queries base incluidas (DB-001 a DB-010):
- DB-001: Usuarios admin no originales
- DB-002: Posts con SEO spam de casino
- DB-003: Opciones con eval/base64
- DB-004: Comentarios spam aprobados con links
- DB-005: Usuarios con capacidades de admin
- DB-006: Post meta con payloads ofuscados
- DB-007: Trackbacks y pingbacks
- DB-008: Opciones críticas del sitio (info)
- DB-009: Cron con tareas sospechosas
- DB-010: Redirecciones y front page inyectadas

Ver definición completa en el PLAN original.

---

## 8. Integración con Opencode

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

func (o *OpencodeScanner) RunWithDB(path string, dbFindings []DBFinding, logs bool) ([]Result, error) {
    prompt := fmt.Sprintf(`Investigate WordPress hack at %s.
File findings: %s.
Database findings: %s.
Generate cleanup SQL statements for each DB finding.`,
        path, fileFindings, dbFindings)
    // ...
}
```

---

## 9. UI en CLI — Principios de diseño

Todo el output en CLI debe ser claro, bonito y útil en tiempo real. Principios:

- **Banner** siempre primero, con versión
- **Secciones** separadas con líneas `──` y título
- **Spinners** con `briandowns/spinner` mientras escanea, mostrando el archivo actual
- **Barras de progreso** por cada scanner (porcentaje + archivo en curso)
- **Tablas** para mostrar hallazgos agrupados por categoría con colores por severidad:
  - `critical` → rojo brillante
  - `high` → rojo
  - `medium` → amarillo
  - `low` → azul
  - `info` → gris
- **Checkmarks** `✓` en verde para acciones completadas
- **Cruces** `✗` en rojo para hallazgos sin resolver
- **Resumen final** en caja con bordes ASCII
- Todas las confirmaciones de limpieza con preview de las filas afectadas antes de ejecutar

---

## 10. Librerías Go

| Propósito | Librería |
|-----------|----------|
| CLI framework | `github.com/spf13/cobra` |
| Menús interactivos | `github.com/AlecAivazis/survey/v2` |
| Colores | `github.com/fatih/color` |
| Spinner | `github.com/briandowns/spinner` |
| Tablas CLI | `github.com/jedib0t/go-pretty/v6/table` |
| Barras de progreso | `github.com/schollz/progressbar/v3` |
| YARA (extra) | `github.com/hillu/go-yara/v4` |
| MySQL driver | `github.com/go-sql-driver/mysql` |
| SQL conn pool | `database/sql` (stdlib) |
| Markdown render CLI | `github.com/charmbracelet/glamour` (para preview del informe en terminal) |

---

## 11. Roadmap

| Fase | Tarea | Est. |
|------|-------|------|
| 1 | Estructura base + cobra + banner ASCII | 30 min |
| 2 | Interfaz Scanner + tipos compartidos | 20 min |
| 3 | UI: spinners, colores, tablas, progress bars | 45 min |
| 4 | Scanner ClamAV | 45 min |
| 5 | Scanner PMF (YARA) | 30 min |
| 6 | Scanner Maldet | 45 min |
| 7 | Scanner Opencode (subagente) | 1 h |
| 8 | Updater DBs | 30 min |
| 9 | Módulo dbscanner — connector MySQL | 30 min |
| 10 | Módulo dbscanner — catálogo queries base | 45 min |
| 11 | Módulo dbscanner — generación queries limpieza | 30 min |
| 12 | Módulo cleaner — sql_generator | 30 min |
| 13 | Módulo cleaner — sql_runner (con rollback) | 45 min |
| 14 | Módulo cleaner — sql_exporter (.sql final) | 20 min |
| 15 | Generar reporte JSON + MD interno | 45 min |
| 16 | Generar INFORME_CLIENTE.md (formal) | 1 h |
| 17 | Generar SIGUIENTES_PASOS.md (personalizado) | 45 min |
| 18 | Verificación post-cleanup | 30 min |
| 19 | Integración scan + scan-db + clean (pipeline completo) | 45 min |
| 20 | Tests con WordPress real (varios casos) | 1.5 h |

**Total estimado: ~13-14 horas**

---

## 12. Diagrama de flujo completo

```
┌──────────────────┐
│  wpscanner scan  │
│  [--db] [path]   │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────┐
│  Banner ASCII + config prompts   │
│  (ruta, DB creds, scanners, etc.)│
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  Update DBs de firmas (opcional) │
└────────┬─────────────────────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐  ┌──────────────────────┐
│ Scan   │  │ Scan DB              │
│ files  │  │ users→posts→comments │
│ clamav │  │ options→postmeta     │
│ pmf    │  └──────────┬───────────┘
│ maldet │             │
└───┬────┘             │
    └────────┬──────────┘
             │
             ▼
┌──────────────────────────────────┐
│  Opencode subagente              │
│  (análisis profundo + SQL extra) │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  Generar reporte JSON + MD       │
│  Mostrar resumen en terminal     │
└────────┬─────────────────────────┘
         │
         ▼ ¿Limpiar ahora?
┌──────────────────────────────────┐
│  wpscanner clean                 │
│  Preview filas → confirmar →     │
│  ejecutar en DB local            │
└────────┬─────────────────────────┘
         │
         ▼ (puede repetirse hasta pasar)
┌──────────────────────────────────┐
│  Verificación post-limpieza      │
│  Re-ejecuta queries de detección │
└────────┬─────────────────────────┘
         │ ✓ Todo limpio
         ▼
┌──────────────────────────────────┐
│  Exportar cleanup.sql final      │
│  (para ejecutar en producción)   │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│  Generar INFORME_CLIENTE.md      │
│  Generar SIGUIENTES_PASOS.md     │
└──────────────────────────────────┘
```

---

## 13. Notas para OpenCode al implementar

- El nombre del binario es `wpscanner`
- El módulo Go se llamará `wordpress-scanner`
- El banner ASCII ya está definido arriba, usar exactamente ese
- Los archivos de salida van siempre en `./wpscanner-output/YYYYMMDD-HHMMSS/` relativo al directorio de trabajo
- La limpieza **nunca** se ejecuta en producción directamente; el flujo es: local → verificar → exportar .sql → el usuario lo ejecuta a mano en producción
- El `SIGUIENTES_PASOS.md` incluye siempre el bloque base pero añade secciones específicas según los findings detectados en el scan
- El `INFORME_CLIENTE.md` debe ser formal y entendible por alguien no técnico
- Usar `go-pretty` para las tablas de hallazgos en CLI con colores por severidad
- El spinner debe mostrar el archivo/query en curso, no solo girar en vacío

# Por dónde vamos — WordPress Scanner

Estado actual del proyecto tras la sesión del 12/06/2026.

!!!!!IMPORTANTE!!!!!!
  ⚠ PHP-Malware-Finder: exit status 255
  ⚠ Linux Malware Detect: exit status 1
  ⚠ Opencode Subagente: opencode execution failed: exit status 1

---

## Resumen

Proyecto funcional compilado en `./wpscanner` (v1.0.3). Pipeline completo: escanea → analiza → reporta → limpia (DB local) → exporta SQL → genera informe cliente + siguientes pasos.

## Commands

| Comando | Estado | Notas |
|---------|--------|-------|
| `wpscanner scan [--db]` | ✅ Funcional | Escanea archivos + DB (si --db) |
| `wpscanner scan-db` | ✅ Funcional | Solo DB |
| `wpscanner clean --report X.json` | ✅ Funcional | Limpia DB local con preview |
| `wpscanner verify --report X.json` | ✅ Funcional | Verifica hashes post-cleanup |
| `wpscanner report --report X.json` | ✅ Funcional | Genera INFORME_CLIENTE + SIGUIENTES_PASOS |

## Scanners

| Scanner | Estado | Resultado real en tests |
|---------|--------|------------------------|
| **ClamAV** (`clamscan -ri`) | ✅ Funcional | Detecta malware real |
| **PHP-Malware-Finder** (`phpmalwarefinder -a`) | ✅ Funcional | Se corrigió búsqueda del binario (antes buscaba `php-malware-finder`, ahora también `phpmalwarefinder`). Usa `CombinedOutput()` para capturar stdout+stderr. No falla en exit 255 si hay output. |
| **Linux Malware Detect** (`maldet -a`) | ⚠ No verificado en producción | Usa `CombinedOutput()`. El usuario no tiene maldet instalado (exit 1). |
| **Opencode Subagente** | ⚠ No verificado | El usuario no tiene `opencode` CLI. Ahora mensaje claro si no está instalado. |

## Bugs corregidos

| Versión | Bug | Fix |
|---------|-----|-----|
| 1.0.0→1.0.1 | Spinner infinito (nunca se llamaba `Stop()`) | `sp.Stop()` después de cada scan |
| 1.0.0→1.0.1 | Doble banner en `wpscanner` sin args | Banner solo en `Execute()`, eliminado de `rootCmd.Run` |
| 1.0.1→1.0.2 | CleanupSQL vacío → "No hay operaciones" | Recolección dinámica de IDs + generación de `DELETE FROM tabla WHERE pk IN (...)` |
| 1.0.2→1.0.3 | PMF no encontraba `phpmalwarefinder` (solo buscaba `php-malware-finder`) | Añadido `phpmalwarefinder` como primera opción |
| 1.0.2→1.0.3 | PMF fallaba en exit 255 y descartaba findings | `CombinedOutput()` + no descartar findings cuando hay error con output |
| 1.0.2→1.0.3 | Scanners con findings+error se descartaban (continue en scan loop) | Ya no hace continue, muestra findings + advertencia |
| 1.0.2→1.0.3 | SIGUIENTES_PASOS no listaba archivos infectados | Nueva sección con tabla de archivos + comandos rm |
| 1.0.2→1.0.3 | Numeración harcodeada en SIGUIENTES_PASOS | Numeración dinámica según findings |
| 1.0.2→1.0.3 | cleanup.sql aparecía aunque no hubiera DB findings | Condicional, solo si hay DB findings con cleanup |

## Bugs conocidos / Pendientes

- **Maldet**: No verificado. El usuario no lo tiene instalado. Si se instala, probar.
- **Opencode**: No verificado. Requiere instalación de `opencode` CLI.
- **PMF parsing**: El parseo del output depende del formato de PMF. Si cambia entre versiones, puede no detectar findings correctamente.
- **verify**: Solo verifica hashes de archivos si existen en `CleanHashes` del reporte. Actualmente `CleanHashes` está vacío porque no se genera durante el scan (solo estructurado). Habría que poblar `CleanHashes` con los hashes de archivos limpios conocidos de WordPress core.
- **clean**: Solo limpia DB (no elimina archivos infectados). Las instrucciones para archivos van a SIGUIENTES_PASOS.
- **Reporte JSON**: No incluye `CleanHashes` poblado. Hay que decidir si generar hashes de archivos core conocidos.
- **Sin flag `--db`**: El flag existe en `scan` pero no está bien documentado en CLI help.

## Output de ejemplo real (12/06/2026)

Proyecto real: `lamillorcocadesantjoan.cat`

1. Scan encontró:
   - ClamAV: `wp-blog-header.php` infectado con base64 inject (critical)
   - DB: 6226 posts con spam casino (eliminados vía clean), 3 opciones redirect (eliminadas)
   - PMF + Maldet + Opencode: no disponibles en ese momento

2. Clean aplicado: DELETE 6226 posts, DELETE 3 options
3. SQL exportado: `cleanup-20260612-184556.sql`
4. Reporte generado: INFORME_CLIENTE + SIGUIENTES_PASOS

## Estructura del proyecto

```
wordpress-scanner/
├── main.go
├── go.mod / go.sum
├── wpscanner              ← binario compilado
├── cmd/
│   ├── root.go            ← Cobra root + banner
│   ├── scan.go            ← scan [--db]
│   ├── scandb.go          ← scan-db
│   ├── clean.go           ← clean --report
│   ├── verify.go          ← verify --report
│   └── report.go          ← report --report
├── internal/
│   ├── scanner/
│   │   ├── scanner.go     ← interface
│   │   ├── clamav.go
│   │   ├── pmf.go         ← corregido: phpmalwarefinder + CombinedOutput
│   │   ├── maldet.go      ← corregido: CombinedOutput
│   │   ├── opencode.go    ← corregido: parseo JSON aunque exit != 0
│   │   └── scanner_test.go
│   ├── dbscanner/
│   │   ├── dbscanner.go   ← interface
│   │   ├── connector.go   ← MySQL: TCP/socket autodetect
│   │   ├── queries.go     ← DB-001 a DB-010 + cleanup por IDs
│   │   ├── scan.go        ← executeQuery con recolección de IDs
│   │   ├── {users,posts,comments,options,postmeta}.go
│   │   └── dbscanner_test.go
│   ├── cleaner/
│   │   ├── cleaner.go
│   │   ├── sql_generator.go
│   │   ├── sql_runner.go
│   │   └── sql_exporter.go
│   ├── report/
│   │   ├── types.go
│   │   ├── generate.go
│   │   ├── client_report.go
│   │   ├── verify.go
│   │   └── report_test.go
│   ├── nextSteps/
│   │   └── generator.go   ← corregido: lista archivos + num dinámico
│   ├── updater/
│   │   └── updater.go
│   └── ui/
│       ├── progress.go    ← spinners, tablas, colores, banner
│       └── prompts.go     ← survey menus
```

## Próximas mejoras sugeridas

- [ ] Poblar `CleanHashes` con hashes SHA256 de WordPress core para verify
- [ ] Añadir modo "solo archivos" sin preguntar DB
- [ ] Mejorar documentación `--help` de los flags
- [ ] Tests de integración con WordPress real
- [ ] Soporte para escanear archivos comprimidos (.zip, .gz)
- [ ] Parallel scanner execution (actualmente secuencial)

---

*Documento generado manualmente tras sesión de desarrollo. Última actualización: 12/06/2026.*

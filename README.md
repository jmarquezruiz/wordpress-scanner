<div align="center">
  <br/>
  <pre>
┌────────────────────────────────┐
│      wordpress-scanner         │
└────────────────────────────────┘
  </pre>
  <p><strong>Scanner de seguridad para instalaciones WordPress</strong></p>
  <p>
    <a href="#características">Características</a> •
    <a href="#requisitos">Requisitos</a> •
    <a href="#instalación">Instalación</a> •
    <a href="#uso">Uso</a> •
    <a href="#flujo-ftp">Flujo FTP</a> •
    <a href="#estructura">Estructura</a>
  </p>
  <br/>
</div>

## 🔍 ¿Qué es wordpress-scanner?

**wordpress-scanner** es una herramienta CLI escrita en Go para analizar instalaciones WordPress en busca de malware, webshells, backdoors, ofuscación, inyecciones y contenido sospechoso.

El proyecto combina varios motores de análisis, revisiones específicas de la base de datos MySQL y generación de informes en JSON y Markdown. Su flujo está pensado para trabajar de forma controlada:

```text
escanea → analiza → reporta → revisa → limpia → verifica
```

> ⚠️ El scanner trabaja sobre rutas locales. Para analizar un WordPress accesible únicamente por FTP/SFTP, descarga primero una copia y escanéala localmente.

## ✨ Características

- **Escaneo de archivos WordPress** mediante varios motores de seguridad.
- **ClamAV** para detección de malware conocido.
- **PHP-Malware-Finder** para analizar código PHP sospechoso.
- **Linux Malware Detect** como motor adicional de análisis.
- **Integridad de WordPress** mediante WP-CLI y checksums oficiales.
- **Detección de ubicaciones PHP anómalas** en uploads y rutas sensibles.
- **Escaneo MySQL** con comprobaciones sobre posts, comentarios, usuarios, opciones y metadatos.
- **Informes JSON, Markdown y HTML** generados automáticamente por cada ejecución.
- **Informe para cliente** y guía de siguientes pasos.
- **Limpieza de base de datos con confirmación**, vista previa y exportación SQL.
- **Interfaz interactiva** con selección de scanners, spinners, tablas y confirmaciones.

## 🧰 Requisitos

| Herramienta | Uso |
|---|---|
| [Go](https://go.dev/) | Compilar el proyecto |
| ClamAV | Scanner `clamscan` |
| PHP-Malware-Finder | Análisis de PHP/YARA |
| Linux Malware Detect | Scanner `maldet` |
| WP-CLI | Checksums de core y plugins |
| MySQL/MariaDB | Escaneo opcional de base de datos |

Los scanners externos son opcionales. Si uno no está instalado, el programa muestra una advertencia y continúa con los demás.

## ⚙️ Instalación

### Compilar desde el código fuente

```bash
git clone https://github.com/tu-usuario/wordpress-scanner.git
cd wordpress-scanner

go mod download
go build -o wpscanner .
```

Ejecutar el binario compilado:

```bash
./wpscanner --help
```

También puedes instalarlo en una ruta incluida en tu `PATH`:

```bash
go install .
```

## 🚀 Uso

### Escanear archivos

```bash
./wpscanner scan /var/www/wordpress
```

Si no indicas una ruta, el programa la solicitará de forma interactiva:

```bash
./wpscanner scan
```

Durante el proceso podrás elegir los scanners, actualizar sus bases de firmas, mostrar logs y decidir si quieres consultar también la base de datos.

### Escanear archivos y base de datos

```bash
./wpscanner scan --db /var/www/wordpress
```

El programa solicitará las credenciales de MySQL y ejecutará las comprobaciones de archivos y base de datos.

### Escanear únicamente la base de datos

```bash
./wpscanner scan-db
```

Este comando conecta con MySQL, ejecuta las comprobaciones disponibles y genera el mismo tipo de reporte.

### Generar informe para cliente

Después de un escaneo, utiliza el reporte JSON generado:

```bash
./wpscanner report --report wpscanner-output/20260612-184556/wpscanner-report.json
```

Se crearán:

- `INFORME_CLIENTE.md`
- `SIGUIENTES_PASOS.md`

### Limpiar la base de datos

La limpieza solo afecta a la base de datos a la que te conectes y siempre solicita confirmación:

```bash
./wpscanner clean --report wpscanner-output/20260612-184556/wpscanner-report.json
```

El proyecto muestra las operaciones antes de ejecutarlas y puede exportar un archivo SQL para revisión o ejecución posterior.

### Verificar un reporte

```bash
./wpscanner verify --report wpscanner-output/20260612-184556/wpscanner-report.json
```

## 📁 Flujo FTP/SFTP

El scanner no analiza directamente una URL `ftp://` o `sftp://`. Las herramientas de análisis necesitan una ruta local del sistema.

La forma recomendada es descargar una copia completa del WordPress y escanearla sin modificar producción.

### FTP con `lftp`

```bash
mkdir -p /tmp/wp-scan
lftp ftp://servidor
```

Dentro de `lftp`:

```text
user usuario
mirror --verbose /ruta/remota /tmp/wp-scan
quit
```

Después:

```bash
./wpscanner scan /tmp/wp-scan
```

### SFTP con `rsync`

```bash
mkdir -p /tmp/wp-scan
rsync -a --info=progress2 usuario@servidor:/ruta/remota/ /tmp/wp-scan/
./wpscanner scan /tmp/wp-scan
```

No es necesario comprimir el proyecto. Descargar la estructura de archivos tal cual facilita conservar rutas, extensiones y contexto. Además, el soporte para analizar archivos comprimidos no está incluido actualmente.

La base de datos debe analizarse por separado mediante acceso MySQL o mediante una copia/dump de la base de datos. El acceso FTP por sí solo no proporciona acceso a MySQL.

## 📄 Archivos generados

Cada ejecución crea un directorio con fecha dentro de `wpscanner-output/`:

```text
wpscanner-output/
└── 20260612-184556/
    ├── wpscanner-report.json
    ├── wpscanner-report.md
    ├── wpscanner-report.html
    ├── INFORME_CLIENTE.md
    ├── SIGUIENTES_PASOS.md
    └── cleanup-*.sql
```

Los últimos archivos solo se generan cuando corresponde: por ejemplo, el SQL de limpieza requiere hallazgos en la base de datos y confirmación del usuario.

## 🏗️ Estructura del proyecto

```text
wordpress-scanner/
├── main.go
├── cmd/
│   ├── root.go          # Comando principal
│   ├── scan.go          # Escaneo de archivos y DB
│   ├── scandb.go        # Escaneo exclusivo de DB
│   ├── clean.go         # Limpieza de DB
│   ├── verify.go        # Verificación
│   └── report.go        # Informes para cliente
├── internal/
│   ├── scanner/         # ClamAV, PMF, Maldet, integridad y anomalías
│   ├── dbscanner/       # Conexión y queries MySQL
│   ├── cleaner/         # Operaciones y exportación SQL
│   ├── report/          # Modelos y generación de informes
│   ├── nextSteps/       # Guía de acciones posteriores
│   ├── updater/         # Actualización de firmas
│   └── ui/              # Prompts, tablas y progreso
├── go.mod
└── wpscanner
```

## 🧪 Tests

Ejecutar todos los tests:

```bash
go test ./...
```

Ejecutar los tests con más detalle:

```bash
go test -v ./...
```

## ⚠️ Limitaciones

- El análisis de archivos es local; no existe soporte FTP remoto nativo.
- La limpieza automática se limita actualmente a la base de datos.
- Los archivos detectados deben revisarse, reemplazarse o eliminarse manualmente.
- Los scanners externos deben instalarse aparte.
- El acceso FTP no permite analizar la base de datos MySQL.
- No se ejecuta todavía un análisis recursivo especializado de ZIP/TAR/GZ.

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Puedes abrir un issue para reportar un problema o proponer una mejora, o enviar un pull request con cambios y tests cuando sea posible.

## 📄 Licencia

La licencia del proyecto se definirá en el repositorio.

---

<div align="center">
  <sub>Hecho con ❤️ por jmarquez.dev</sub>
</div>

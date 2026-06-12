package nextSteps

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"wordpress-scanner/internal/report"
)

func GenerateNextSteps(r *report.Report, dir string) (string, error) {
	now := time.Now()
	filename := fmt.Sprintf("SIGUIENTES_PASOS_%s.md", now.Format("20060102"))
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmt.Fprintf(f, "# Siguientes Pasos — Post-limpieza\n\n")
	fmt.Fprintf(f, "Generado el %s\n\n", now.Format("2 de enero de 2006"))
	fmt.Fprintf(f, "---\n\n")

	step := 1

	hasFiles := len(r.Findings) > 0
	hasDBWithCleanup := false
	for _, d := range r.DBFindings {
		if d.CleanupSQL != "" {
			hasDBWithCleanup = true
			break
		}
	}

	if hasDBWithCleanup {
		fmt.Fprintf(f, "## %d. Ejecutar cleanup.sql en producción\n\n", step)
		step++
		fmt.Fprintf(f, "Antes de nada, hacer **backup completo** de la BD de producción.\n\n")
		fmt.Fprintf(f, "Luego ejecutar:\n")
		fmt.Fprintf(f, "```bash\nmysql -u usuario -p basededatos < cleanup.sql\n```\n\n")
	}

	if hasFiles {
		fmt.Fprintf(f, "## %d. Revisar y eliminar archivos infectados\n\n", step)
		step++
		fmt.Fprintf(f, "Los siguientes archivos fueron detectados como maliciosos. Acción recomendada:\n\n")
		fmt.Fprintf(f, "| # | Archivo | Severidad | Tipo | Acción |\n")
		fmt.Fprintf(f, "|---|---------|-----------|------|--------|\n")
		for i, fi := range r.Findings {
			fmt.Fprintf(f, "| %d | `%s` | %s | %s | Revisar y eliminar |\n", i+1, fi.File, fi.Severity, fi.Type)
		}
		fmt.Fprintf(f, "\n")
		fmt.Fprintf(f, "```bash\n")
		for _, fi := range r.Findings {
			fmt.Fprintf(f, "rm -f \"%s\"\n", fi.File)
		}
		fmt.Fprintf(f, "```\n\n")
		fmt.Fprintf(f, "⚠ Verificar que el archivo no sea legítimo antes de eliminarlo.\n\n")
	}

	fmt.Fprintf(f, "## %d. Cambiar contraseñas\n\n", step)
	step++
	fmt.Fprintf(f, "- [ ] Contraseña del admin de WordPress\n")
	fmt.Fprintf(f, "- [ ] Contraseña de la base de datos\n")
	fmt.Fprintf(f, "- [ ] Contraseña FTP/SFTP\n")
	fmt.Fprintf(f, "- [ ] Contraseña del panel de hosting\n\n")

	fmt.Fprintf(f, "## %d. Regenerar salts y keys de wp-config.php\n\n", step)
	step++
	fmt.Fprintf(f, "Ir a: https://api.wordpress.org/secret-key/1.1/salt/\n")
	fmt.Fprintf(f, "Reemplazar el bloque completo en wp-config.php\n\n")

	fmt.Fprintf(f, "## %d. Actualizar WordPress core\n\n", step)
	step++
	fmt.Fprintf(f, "Dashboard → Actualizaciones → Actualizar WordPress\n\n")

	fmt.Fprintf(f, "## %d. Actualizar plugins\n\n", step)
	step++
	fmt.Fprintf(f, "Dashboard → Actualizaciones → Plugins\n\n")

	fmt.Fprintf(f, "## %d. Actualizar tema\n\n", step)
	step++
	fmt.Fprintf(f, "Dashboard → Actualizaciones → Temas\n")
	fmt.Fprintf(f, "⚠ Si el tema tiene modificaciones personales, revisar antes de actualizar\n\n")

	fmt.Fprintf(f, "## %d. Revisar usuarios administradores\n\n", step)
	step++
	fmt.Fprintf(f, "Usuarios → Todos los usuarios → revisar que solo existen los legítimos\n\n")

	fmt.Fprintf(f, "## %d. Revisar plugins instalados\n\n", step)
	step++
	fmt.Fprintf(f, "Plugins → Eliminar cualquier plugin no reconocido o desactivado sin uso\n\n")

	fmt.Fprintf(f, "## %d. Configurar permisos de archivos\n\n", step)
	step++
	fmt.Fprintf(f, "```bash\n")
	fmt.Fprintf(f, "chmod 644 wp-config.php\n")
	fmt.Fprintf(f, "chmod 755 wp-content/uploads\n")
	fmt.Fprintf(f, "find wp-content -type f -name '*.php' -exec chmod 644 {} \\;\n")
	fmt.Fprintf(f, "```\n\n")

	fmt.Fprintf(f, "## %d. Verificar .htaccess\n\n", step)
	step++
	fmt.Fprintf(f, "Revisar que no contenga redirecciones no autorizadas.\n")
	fmt.Fprintf(f, "Regenerar desde: Ajustes → Enlaces permanentes → Guardar\n\n")

	fmt.Fprintf(f, "## %d. Activar plugin de seguridad\n\n", step)
	step++
	fmt.Fprintf(f, "Instalar Wordfence o iThemes Security y configurar alertas por email\n\n")

	hasWebshells := false
	hasSEOSpam := false
	hasExtraAdmins := false
	hasBackdoors := false

	for _, f := range r.Findings {
		if f.Type == "webshell" || f.Type == "backdoor" {
			hasWebshells = true
		}
		if f.Severity == report.SeverityCritical {
			hasBackdoors = true
		}
	}
	for _, d := range r.DBFindings {
		if d.Category == "posts" || d.Category == "postmeta" {
			hasSEOSpam = true
		}
		if d.Category == "users" {
			hasExtraAdmins = true
		}
	}

	if hasBackdoors {
		fmt.Fprintf(f, "## %d. Buscar más archivos maliciosos ocultos\n\n", step)
		step++
		fmt.Fprintf(f, "Los atacantes suelen esconder webshells en ubicaciones como:\n")
		fmt.Fprintf(f, "- `wp-content/uploads/` — archivos PHP camuflados como imágenes\n")
		fmt.Fprintf(f, "- `wp-content/plugins/` — plugins falsos o modificados\n")
		fmt.Fprintf(f, "- `wp-includes/` — archivos del core con backdoors\n")
		fmt.Fprintf(f, "- `.htaccess` — redirecciones encubiertas\n")
		fmt.Fprintf(f, "\nEjecutar:\n")
		fmt.Fprintf(f, "```bash\n")
		fmt.Fprintf(f, "find . -name '*.php' -newer wp-config.php -type f\n")
		fmt.Fprintf(f, "find wp-content/uploads -name '*.php' -type f\n")
		fmt.Fprintf(f, "find . -name '*.ico' -o -name '*.txt' | xargs file | grep PHP\n")
		fmt.Fprintf(f, "```\n\n")
	}

	if hasWebshells {
		fmt.Fprintf(f, "## %d. Revisión de permisos por webshells\n\n", step)
		step++
		fmt.Fprintf(f, "Se detectaron webshells. Revisar permisos de archivos en wp-content:\n")
		fmt.Fprintf(f, "```bash\n")
		fmt.Fprintf(f, "find wp-content -type f -perm 777\n")
		fmt.Fprintf(f, "find wp-content -name '*.php' -type f\n")
		fmt.Fprintf(f, "```\n\n")
	}

	if hasSEOSpam {
		fmt.Fprintf(f, "## %d. Revisar indexación en Google Search Console\n\n", step)
		step++
		fmt.Fprintf(f, "Si hubo spam SEO en posts, es posible que Google haya indexado contenido malicioso.\n")
		fmt.Fprintf(f, "Solicitar revisión en Google Search Console → Inspección de URL\n\n")
	}

	if hasExtraAdmins {
		fmt.Fprintf(f, "## %d. Verificar usuarios con wp-cli\n\n", step)
		step++
		fmt.Fprintf(f, "```bash\n")
		fmt.Fprintf(f, "wp user list\n")
		fmt.Fprintf(f, "wp user list --role=administrator\n")
		fmt.Fprintf(f, "```\n\n")
	}

	return path, nil
}

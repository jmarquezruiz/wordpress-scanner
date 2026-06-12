package report

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func GenerateClientReport(r Report, dir string) (string, error) {
	now := time.Now()
	filename := fmt.Sprintf("INFORME_CLIENTE_%s.md", now.Format("20060102"))
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fmt.Fprintf(f, "# Informe de Seguridad WordPress\n\n")
	fmt.Fprintf(f, "**Cliente:** %s\n", r.Meta.TargetDomain)
	fmt.Fprintf(f, "**Fecha del análisis:** %s\n", formatDate(r.Meta.ScanDate))
	fmt.Fprintf(f, "**Analista:** jmarquez.dev\n\n")
	fmt.Fprintf(f, "---\n\n")

	fmt.Fprintf(f, "## Resumen ejecutivo\n\n")
	fmt.Fprintf(f, "Se ha realizado un análisis de seguridad exhaustivo del sitio web. ")
	if r.Summary.TotalFindings+r.Summary.DBFindings > 0 {
		fmt.Fprintf(f, "Se detectaron un total de **%d hallazgos** de seguridad, ", r.Summary.TotalFindings+r.Summary.DBFindings)
		fmt.Fprintf(f, "de los cuales **%d** son de severidad crítica. ", r.Summary.Critical)
		fmt.Fprintf(f, "Estos hallazgos incluyen archivos maliciosos, contenido modificado y configuraciones de riesgo.")
	} else {
		fmt.Fprintf(f, "No se detectaron amenazas significativas durante el análisis.")
	}
	fmt.Fprintf(f, "\n\n")

	fmt.Fprintf(f, "## Hallazgos críticos\n\n")
	fmt.Fprintf(f, "| ID | Tipo | Descripción | Ruta/Tabla | Acción tomada |\n")
	fmt.Fprintf(f, "|----|------|-------------|-------------|---------------|\n")
	criticalCount := 0
	for _, fi := range r.Findings {
		if fi.Severity == SeverityCritical {
			criticalCount++
			action := "Pendiente"
			if fi.Cleaned {
				action = "Eliminado"
			}
			fmt.Fprintf(f, "| %s | %s | %s | %s | %s |\n", fi.ID, fi.Type, fi.Description, fi.File, action)
		}
	}
	for _, d := range r.DBFindings {
		if d.Severity == "critical" {
			criticalCount++
			action := "Pendiente"
			if d.Cleaned {
				action = "Limpieza aplicada"
			}
			fmt.Fprintf(f, "| %s | %s | %s | %s | %s |\n", d.ID, d.Category, d.Check, d.Category, action)
		}
	}
	if criticalCount == 0 {
		fmt.Fprintf(f, "| - | - | No se encontraron hallazgos críticos | - | - |\n")
	}
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "## Hallazgos en base de datos\n\n")
	fmt.Fprintf(f, "| ID | Categoría | Descripción | Registros afectados | Acción |\n")
	fmt.Fprintf(f, "|----|-----------|-------------|--------------------|--------|\n")
	for _, d := range r.DBFindings {
		action := "Pendiente"
		if d.Cleaned {
			action = "Limpieza aplicada"
		}
		fmt.Fprintf(f, "| %s | %s | %s | %d | %s |\n", d.ID, d.Category, d.Check, d.RowsAffected, action)
	}
	if len(r.DBFindings) == 0 {
		fmt.Fprintf(f, "| - | - | No se realizó escaneo de base de datos | - | - |\n")
	}
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "## Acciones realizadas\n\n")
	if r.Summary.Cleaned {
		fmt.Fprintf(f, "- Limpieza de base de datos aplicada\n")
		fmt.Fprintf(f, "- Verificación post-limpieza completada\n")
	} else {
		fmt.Fprintf(f, "- Escaneo de archivos completado\n")
		fmt.Fprintf(f, "- Escaneo de base de datos completado\n")
		fmt.Fprintf(f, "- Pendiente de limpieza\n")
	}
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "## Estado final\n\n")
	if r.Summary.Cleaned {
		fmt.Fprintf(f, "✓ Sitio limpio tras la intervención.\n")
	} else {
		fmt.Fprintf(f, "⚠ Pendiente de limpieza.\n")
	}
	fmt.Fprintf(f, "\n")

	fmt.Fprintf(f, "## Recomendaciones\n\n")
	fmt.Fprintf(f, "- Actualizar WordPress, plugins y tema a sus últimas versiones\n")
	fmt.Fprintf(f, "- Cambiar todas las contraseñas (admin, FTP, hosting, DB)\n")
	fmt.Fprintf(f, "- Regenerar salts y keys de wp-config.php\n")
	fmt.Fprintf(f, "- Activar autenticación en dos factores\n")
	fmt.Fprintf(f, "- Contratar plan de mantenimiento mensual\n")

	return path, nil
}

func formatDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}
	return t.Format("2 de enero de 2006")
}

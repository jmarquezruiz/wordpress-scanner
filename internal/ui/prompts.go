package ui

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
)

type DBCredentials struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
	Prefix   string
}

type ScanConfig struct {
	Path         string
	Scanners     []string
	UpdateDBs    bool
	ShowLogs     bool
	ScanDB       bool
	ProceedClean bool
}

func AskPath(defaultPath string) (string, error) {
	var path string
	prompt := &survey.Input{
		Message: "Ruta del proyecto WordPress:",
		Default: defaultPath,
	}
	err := survey.AskOne(prompt, &path, survey.WithValidator(survey.Required))
	return path, err
}

func AskScanners() ([]string, error) {
	options := []string{
		"ClamAV (clamscan -ri)",
		"PHP-Malware-Finder (YARA)",
		"Linux Malware Detect (maldet -a)",
		"WordPress Integrity (WP-CLI checksums)",
		"Anomalous PHP locations",
	}
	selected := []string{}
	prompt := &survey.MultiSelect{
		Message: "Scanners a usar:",
		Options: options,
		Default: options,
	}
	err := survey.AskOne(prompt, &selected)
	return selected, err
}

func AskConfirmUpdate() (bool, error) {
	confirm := false
	prompt := &survey.Confirm{
		Message: "¿Actualizar bases de datos de firmas antes?",
		Default: false,
	}
	err := survey.AskOne(prompt, &confirm)
	return confirm, err
}

func AskShowLogs() (bool, error) {
	show := false
	prompt := &survey.Confirm{
		Message: "¿Mostrar logs en vivo?",
		Default: false,
	}
	err := survey.AskOne(prompt, &show)
	return show, err
}

func AskScanDB() (bool, error) {
	scan := false
	prompt := &survey.Confirm{
		Message: "¿Escane también la base de datos?",
		Default: true,
	}
	err := survey.AskOne(prompt, &scan)
	return scan, err
}

func AskDBCredentials() (*DBCredentials, error) {
	creds := &DBCredentials{}
	qs := []*survey.Question{
		{
			Name: "host",
			Prompt: &survey.Input{
				Message: "Host MySQL:",
				Default: "localhost",
				Help:    "localhost, 127.0.0.1, IP, o ruta a socket Unix",
			},
		},
		{
			Name: "port",
			Prompt: &survey.Input{
				Message: "Puerto (opcional, default 3306):",
				Default: "",
				Help:    "Dejar vacío para default 3306 o socket Unix",
			},
		},
		{
			Name: "user",
			Prompt: &survey.Input{
				Message: "Usuario MySQL:",
				Default: "root",
			},
			Validate: survey.Required,
		},
		{
			Name: "password",
			Prompt: &survey.Password{
				Message: "Contraseña MySQL:",
			},
		},
		{
			Name: "database",
			Prompt: &survey.Input{
				Message: "Base de datos:",
			},
			Validate: survey.Required,
		},
		{
			Name: "prefix",
			Prompt: &survey.Input{
				Message: "Prefijo de tablas (opcional, default wp_):",
				Default: "wp_",
			},
		},
	}
	err := survey.Ask(qs, creds)
	if err != nil {
		return nil, err
	}
	return creds, nil
}

func AskProceedClean() (bool, error) {
	proceed := false
	prompt := &survey.Confirm{
		Message: "¿Proceder con limpieza en local?",
		Default: false,
	}
	err := survey.AskOne(prompt, &proceed)
	return proceed, err
}

func AskConfirmClean(description string, rows int) (bool, error) {
	confirm := false
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("%s (%d filas afectadas). ¿Ejecutar?", description, rows),
		Default: false,
	}
	err := survey.AskOne(prompt, &confirm)
	return confirm, err
}

func AskExportSQL() (bool, error) {
	export := false
	prompt := &survey.Confirm{
		Message: "¿Exportar .sql final para ejecutar en producción?",
		Default: false,
	}
	err := survey.AskOne(prompt, &export)
	return export, err
}

func AskReportPath() (string, error) {
	path := ""
	prompt := &survey.Input{
		Message: "Ruta del reporte JSON:",
	}
	err := survey.AskOne(prompt, &path, survey.WithValidator(survey.Required))
	return path, err
}

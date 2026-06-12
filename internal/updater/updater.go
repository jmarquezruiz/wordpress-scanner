package updater

import (
	"fmt"
	"os/exec"

	"wordpress-scanner/internal/ui"
)

func UpdateAll(logs bool) error {
	ui.Section("Actualizando bases de datos de firmas")

	if err := updateClamAV(logs); err != nil {
		ui.CheckWarn("ClamAV update: " + err.Error())
	}
	if err := updateMaldet(logs); err != nil {
		ui.CheckWarn("Maldet update: " + err.Error())
	}

	ui.CheckOK("Actualización completada")
	return nil
}

func updateClamAV(logs bool) error {
	if _, err := exec.LookPath("freshclam"); err != nil {
		return fmt.Errorf("freshclam no encontrado, saltando")
	}
	cmd := exec.Command("freshclam")
	if logs {
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("freshclam error: %s", string(out))
		}
		fmt.Println(string(out))
	} else {
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	ui.CheckOK("ClamAV actualizado")
	return nil
}

func updateMaldet(logs bool) error {
	if _, err := exec.LookPath("maldet"); err != nil {
		return fmt.Errorf("maldet no encontrado, saltando")
	}
	cmd := exec.Command("maldet", "-u")
	if logs {
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("maldet update error: %s", string(out))
		}
		fmt.Println(string(out))
	} else {
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	ui.CheckOK("Maldet actualizado")
	return nil
}

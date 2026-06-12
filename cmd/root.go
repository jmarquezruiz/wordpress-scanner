package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"wordpress-scanner/internal/ui"
)

var rootCmd = &cobra.Command{
	Use:   "wpscanner",
	Short: "WordPress Security Scanner CLI",
	Long: `Herramienta CLI para escaneo, análisis, limpieza y reporte de malware en WordPress.
Pipeline completo: escanea → analiza → limpia → verifica → reporta.

Documentación: https://jmarquez.dev`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Usa --help para ver los comandos disponibles.")
	},
}

func Execute() {
	ui.PrintBanner()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolP("version", "v", false, "Muestra la versión")
}

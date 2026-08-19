package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kushardogra/docker-misconfig-scanner/internal/report"
	"github.com/kushardogra/docker-misconfig-scanner/internal/scanner"
)

func main() {
	var outputFormat string

	rootCmd := &cobra.Command{
		Use:   "dmscan [path]",
		Short: "Docker Misconfiguration Scanner",
		Long:  `dmscan statically analyzes Dockerfiles and docker-compose files for security misconfigurations.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := scanner.Scan(args[0])
			if err != nil {
				return err
			}
			switch outputFormat {
			case "json":
				return report.PrintJSON(findings)
			default:
				report.PrintTable(findings)
			}
			return nil
		},
	}

	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

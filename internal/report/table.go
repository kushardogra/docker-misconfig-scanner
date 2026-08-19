package report

import (
	"fmt"
	"strings"

	"github.com/kushardogra/docker-misconfig-scanner/internal/types"
)

func PrintTable(findings []types.Finding) {
	if len(findings) == 0 {
		fmt.Println("✅ No misconfigurations found.")
		return
	}

	fmt.Printf("\n%-13s %-10s %-45s %s\n", "RULE ID", "SEVERITY", "TITLE", "FILE")
	fmt.Println(strings.Repeat("─", 110))
	for _, f := range findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Printf("%-13s %-10s %-45s %s\n", f.RuleID, f.Severity, f.Title, loc)
	}
	fmt.Printf("\n%d finding(s) detected.\n\n", len(findings))
}

package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kushardogra/docker-misconfig-scanner/internal/types"
)

func PrintJSON(findings []types.Finding) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("JSON encoding error: %w", err)
	}
	return nil
}

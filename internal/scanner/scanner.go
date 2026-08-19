package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kushardogra/docker-misconfig-scanner/internal/parser"
	"github.com/kushardogra/docker-misconfig-scanner/internal/rules"
	"github.com/kushardogra/docker-misconfig-scanner/internal/types"
)

func Scan(target string) ([]types.Finding, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", target, err)
	}

	var findings []types.Finding

	if info.IsDir() {
		err = filepath.Walk(target, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			f, err := scanFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
				return nil
			}
			findings = append(findings, f...)
			return nil
		})
	} else {
		findings, err = scanFile(target)
	}

	return findings, err
}

func scanFile(path string) ([]types.Finding, error) {
	base := filepath.Base(path)
	lower := strings.ToLower(base)

	ctx := &types.ParseContext{FilePath: path}

	switch {
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."):
		directives, err := parser.ParseDockerfile(path)
		if err != nil {
			return nil, err
		}
		ctx.Directives = directives

	case lower == "docker-compose.yml" || lower == "docker-compose.yaml":
		compose, err := parser.ParseCompose(path)
		if err != nil {
			return nil, err
		}
		ctx.ComposeData = compose

	default:
		return nil, nil
	}

	var findings []types.Finding
	for _, rule := range rules.Registry {
		findings = append(findings, rule.Check(ctx)...)
	}
	return findings, nil
}

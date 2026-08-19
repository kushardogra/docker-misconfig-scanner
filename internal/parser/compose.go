package parser

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/kushardogra/docker-misconfig-scanner/internal/types"
)

type rawCompose struct {
	Services map[string]types.ComposeService `yaml:"services"`
}

func ParseCompose(path string) (*types.ComposeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw rawCompose
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return &types.ComposeFile{Services: raw.Services}, nil
}

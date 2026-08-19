package rules

import "github.com/kushardogra/docker-misconfig-scanner/internal/types"

type Rule struct {
	ID          string
	Severity    string
	Title       string
	Description string
	Remediation string
	Check       func(ctx *types.ParseContext) []types.Finding
}

var Registry []Rule

func Register(r Rule) {
	Registry = append(Registry, r)
}

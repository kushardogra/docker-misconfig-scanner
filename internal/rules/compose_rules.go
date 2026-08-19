package rules

import (
	"strings"

	"github.com/kushardogra/docker-misconfig-scanner/internal/types"
)

func init() {
	Register(Rule{
		ID:          "COMPOSE-001",
		Severity:    types.SeverityCritical,
		Title:       "Docker socket mounted into container",
		Description: "/var/run/docker.sock bind-mounted — full host Docker control possible.",
		Remediation: "Remove the Docker socket mount or use a restricted proxy.",
		Check:       checkDockerSocketMount,
	})

	Register(Rule{
		ID:          "COMPOSE-002",
		Severity:    types.SeverityCritical,
		Title:       "Container running in privileged mode",
		Description: "privileged: true grants full host capabilities.",
		Remediation: "Remove privileged: true. Use cap_add for specific capabilities only.",
		Check:       checkPrivilegedMode,
	})

	Register(Rule{
		ID:          "COMPOSE-003",
		Severity:    types.SeverityHigh,
		Title:       "Container using host network mode",
		Description: "network_mode: host bypasses Docker network isolation.",
		Remediation: "Use a custom bridge network instead.",
		Check:       checkHostNetwork,
	})
}

func checkDockerSocketMount(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		for _, vol := range svc.Volumes {
			if strings.Contains(vol, "/var/run/docker.sock") {
				findings = append(findings, types.Finding{
					RuleID:      "COMPOSE-001",
					Severity:    types.SeverityCritical,
					Title:       "Docker socket mounted into container",
					Description: "Service '" + name + "' mounts /var/run/docker.sock.",
					Remediation: "Remove the Docker socket mount.",
					File:        ctx.FilePath,
				})
			}
		}
	}
	return findings
}

func checkPrivilegedMode(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		if svc.Privileged {
			findings = append(findings, types.Finding{
				RuleID:      "COMPOSE-002",
				Severity:    types.SeverityCritical,
				Title:       "Privileged container",
				Description: "Service '" + name + "' runs with privileged: true.",
				Remediation: "Remove privileged: true.",
				File:        ctx.FilePath,
			})
		}
	}
	return findings
}

func checkHostNetwork(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		if strings.ToLower(svc.NetworkMode) == "host" {
			findings = append(findings, types.Finding{
				RuleID:      "COMPOSE-003",
				Severity:    types.SeverityHigh,
				Title:       "Host network mode",
				Description: "Service '" + name + "' uses network_mode: host.",
				Remediation: "Use a custom bridge network.",
				File:        ctx.FilePath,
			})
		}
	}
	return findings
}

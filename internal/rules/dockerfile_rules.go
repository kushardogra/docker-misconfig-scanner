package rules

import (
	"strings"

	"github.com/kushardogra/docker-misconfig-scanner/internal/types"
)

func init() {
	Register(Rule{
		ID:          "DOCKER-001",
		Severity:    types.SeverityHigh,
		Title:       "Container runs as root (missing USER directive)",
		Description: "No USER directive found. Container will run as root by default.",
		Remediation: "Add a non-root USER directive, e.g., USER 1001.",
		Check:       checkMissingUser,
	})

	Register(Rule{
		ID:          "DOCKER-002",
		Severity:    types.SeverityMedium,
		Title:       "Base image unpinned (latest tag or no tag)",
		Description: "FROM uses 'latest' or no tag — non-reproducible builds.",
		Remediation: "Pin to a specific version, e.g., FROM ubuntu:22.04.",
		Check:       checkUnpinnedBaseImage,
	})

	Register(Rule{
		ID:          "DOCKER-003",
		Severity:    types.SeverityCritical,
		Title:       "Potential secret in ENV or ARG instruction",
		Description: "ENV/ARG appears to contain a password, token, or key.",
		Remediation: "Use Docker secrets or runtime environment injection.",
		Check:       checkSecretsInEnv,
	})
}

func checkMissingUser(ctx *types.ParseContext) []types.Finding {
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) == "USER" {
			return nil
		}
	}
	if len(ctx.Directives) == 0 {
		return nil
	}
	return []types.Finding{{
		RuleID:      "DOCKER-001",
		Severity:    types.SeverityHigh,
		Title:       "Container runs as root (missing USER directive)",
		Description: "No USER directive found. Container will run as root.",
		Remediation: "Add a non-root USER directive, e.g., USER 1001.",
		File:        ctx.FilePath,
	}}
}

func checkUnpinnedBaseImage(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) != "FROM" {
			continue
		}
		image := strings.Fields(d.Args)[0]
		if image == "scratch" {
			continue
		}
		if !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest") {
			findings = append(findings, types.Finding{
				RuleID:      "DOCKER-002",
				Severity:    types.SeverityMedium,
				Title:       "Unpinned base image",
				Description: "FROM " + image + " uses no tag or 'latest'.",
				Remediation: "Pin to a specific version, e.g., FROM ubuntu:22.04.",
				File:        ctx.FilePath,
				Line:        d.Line,
			})
		}
	}
	return findings
}

var secretKeywords = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"auth", "private_key", "access_key", "aws_secret", "credentials",
}

func checkSecretsInEnv(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		instr := strings.ToUpper(d.Instruction)
		if instr != "ENV" && instr != "ARG" {
			continue
		}
		lower := strings.ToLower(d.Args)
		for _, kw := range secretKeywords {
			if strings.Contains(lower, kw) {
				findings = append(findings, types.Finding{
					RuleID:      "DOCKER-003",
					Severity:    types.SeverityCritical,
					Title:       "Potential secret in " + d.Instruction,
					Description: "Possible secret detected: " + d.Instruction + " " + d.Args,
					Remediation: "Use Docker secrets or runtime environment injection.",
					File:        ctx.FilePath,
					Line:        d.Line,
				})
				break
			}
		}
	}
	return findings
}

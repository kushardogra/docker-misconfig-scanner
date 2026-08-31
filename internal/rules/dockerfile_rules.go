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

	Register(Rule{
		ID:          "DOCKER-004",
		Severity:    types.SeverityMedium,
		Title:       "ADD used instead of COPY",
		Description: "ADD can fetch remote URLs and auto-extract archives, increasing supply chain risk.",
		Remediation: "Use COPY instead of ADD unless remote URL or archive extraction is required.",
		Check:       checkAddInstruction,
	})

	Register(Rule{
		ID:          "DOCKER-005",
		Severity:    types.SeverityLow,
		Title:       "Missing HEALTHCHECK instruction",
		Description: "No HEALTHCHECK defined. Docker cannot detect if the container is unhealthy.",
		Remediation: "Add a HEALTHCHECK, e.g. HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
		Check:       checkMissingHealthcheck,
	})

	Register(Rule{
		ID:          "DOCKER-006",
		Severity:    types.SeverityMedium,
		Title:       "Development environment variable detected",
		Description: "ENV contains a development/debug flag unsafe for production images.",
		Remediation: "Remove debug flags from the image. Inject environment-specific values at runtime.",
		Check:       checkDevEnvVars,
	})

	Register(Rule{
		ID:          "DOCKER-007",
		Severity:    types.SeverityCritical,
		Title:       "Explicit USER root in Dockerfile",
		Description: "USER root explicitly sets the container user to root.",
		Remediation: "Remove USER root and use a non-root user instead.",
		Check:       checkExplicitRoot,
	})

	Register(Rule{
		ID:          "DOCKER-008",
		Severity:    types.SeverityCritical,
		Title:       "curl or wget piped to shell",
		Description: "RUN instruction pipes a remote download directly to bash or sh — a supply chain attack vector.",
		Remediation: "Download files separately, verify checksums, then execute.",
		Check:       checkCurlPipeToShell,
	})

	Register(Rule{
		ID:          "DOCKER-009",
		Severity:    types.SeverityMedium,
		Title:       "Overly broad COPY (copying entire build context)",
		Description: "COPY . . copies the entire build context including .git, .env, and other sensitive files.",
		Remediation: "Use a .dockerignore file and copy only required files explicitly.",
		Check:       checkBroadCopy,
	})

	Register(Rule{
		ID:          "DOCKER-010",
		Severity:    types.SeverityHigh,
		Title:       "SSH private key copied into image",
		Description: "A file matching an SSH private key pattern is copied into the image.",
		Remediation: "Never copy SSH keys into images. Use ssh-agent forwarding or secrets at runtime.",
		Check:       checkSshKeyCopied,
	})
}

// ── DOCKER-001 ──────────────────────────────────────────────────────────────

func checkMissingUser(ctx *types.ParseContext) []types.Finding {
	if len(ctx.Directives) == 0 {
		return nil
	}
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) == "USER" {
			return nil
		}
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

// ── DOCKER-002 ──────────────────────────────────────────────────────────────

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

// ── DOCKER-003 ──────────────────────────────────────────────────────────────

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

// ── DOCKER-004 ──────────────────────────────────────────────────────────────

func checkAddInstruction(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) == "ADD" {
			findings = append(findings, types.Finding{
				RuleID:      "DOCKER-004",
				Severity:    types.SeverityMedium,
				Title:       "ADD used instead of COPY",
				Description: "ADD instruction found — prefer COPY for predictable behavior.",
				Remediation: "Replace ADD with COPY unless remote URL or archive extraction is required.",
				File:        ctx.FilePath,
				Line:        d.Line,
			})
		}
	}
	return findings
}

// ── DOCKER-005 ──────────────────────────────────────────────────────────────

func checkMissingHealthcheck(ctx *types.ParseContext) []types.Finding {
	if len(ctx.Directives) == 0 {
		return nil
	}
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) == "HEALTHCHECK" {
			return nil
		}
	}
	return []types.Finding{{
		RuleID:      "DOCKER-005",
		Severity:    types.SeverityLow,
		Title:       "Missing HEALTHCHECK instruction",
		Description: "No HEALTHCHECK found. Docker cannot detect container health.",
		Remediation: "Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
		File:        ctx.FilePath,
	}}
}

// ── DOCKER-006 ──────────────────────────────────────────────────────────────

var devEnvKeywords = []string{
	"debug=true", "node_env=development", "flask_env=development",
	"django_debug=true", "app_env=dev", "rails_env=development",
}

func checkDevEnvVars(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) != "ENV" {
			continue
		}
		lower := strings.ToLower(d.Args)
		for _, kw := range devEnvKeywords {
			if strings.Contains(lower, kw) {
				findings = append(findings, types.Finding{
					RuleID:      "DOCKER-006",
					Severity:    types.SeverityMedium,
					Title:       "Development environment variable detected",
					Description: "Development flag found in ENV: " + d.Args,
					Remediation: "Remove debug flags from the image. Inject at runtime instead.",
					File:        ctx.FilePath,
					Line:        d.Line,
				})
				break
			}
		}
	}
	return findings
}

// ── DOCKER-007 ──────────────────────────────────────────────────────────────

func checkExplicitRoot(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) == "USER" &&
			strings.TrimSpace(strings.ToLower(d.Args)) == "root" {
			findings = append(findings, types.Finding{
				RuleID:      "DOCKER-007",
				Severity:    types.SeverityCritical,
				Title:       "Explicit USER root in Dockerfile",
				Description: "USER root found — container runs with full root privileges.",
				Remediation: "Use a non-root user, e.g. USER 1001.",
				File:        ctx.FilePath,
				Line:        d.Line,
			})
		}
	}
	return findings
}

// ── DOCKER-008 ──────────────────────────────────────────────────────────────

var shellPipePatterns = []string{
	"| bash", "| sh", "| ash", "| zsh",
	"|bash", "|sh", "|ash", "|zsh",
}

func checkCurlPipeToShell(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) != "RUN" {
			continue
		}
		lower := strings.ToLower(d.Args)
		hasFetch := strings.Contains(lower, "curl") || strings.Contains(lower, "wget")
		if !hasFetch {
			continue
		}
		for _, pattern := range shellPipePatterns {
			if strings.Contains(lower, pattern) {
				findings = append(findings, types.Finding{
					RuleID:      "DOCKER-008",
					Severity:    types.SeverityCritical,
					Title:       "curl/wget piped to shell",
					Description: "Remote content piped directly to shell: " + d.Args,
					Remediation: "Download separately, verify checksum, then execute.",
					File:        ctx.FilePath,
					Line:        d.Line,
				})
				break
			}
		}
	}
	return findings
}

// ── DOCKER-009 ──────────────────────────────────────────────────────────────

func checkBroadCopy(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		if strings.ToUpper(d.Instruction) != "COPY" {
			continue
		}
		args := strings.TrimSpace(d.Args)
		if args == ". ." || args == "./ ." || args == ". ./" || args == "./ ./" {
			findings = append(findings, types.Finding{
				RuleID:      "DOCKER-009",
				Severity:    types.SeverityMedium,
				Title:       "Overly broad COPY",
				Description: "COPY . . copies entire build context including sensitive files.",
				Remediation: "Add a .dockerignore and copy only required files.",
				File:        ctx.FilePath,
				Line:        d.Line,
			})
		}
	}
	return findings
}

// ── DOCKER-010 ──────────────────────────────────────────────────────────────

var sshKeyPatterns = []string{
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	".pem", ".key", ".p12", ".pfx",
}

func checkSshKeyCopied(ctx *types.ParseContext) []types.Finding {
	var findings []types.Finding
	for _, d := range ctx.Directives {
		instr := strings.ToUpper(d.Instruction)
		if instr != "COPY" && instr != "ADD" {
			continue
		}
		lower := strings.ToLower(d.Args)
		for _, pattern := range sshKeyPatterns {
			if strings.Contains(lower, pattern) {
				findings = append(findings, types.Finding{
					RuleID:      "DOCKER-010",
					Severity:    types.SeverityHigh,
					Title:       "SSH private key copied into image",
					Description: "Possible private key in: " + d.Instruction + " " + d.Args,
					Remediation: "Use runtime secrets or ssh-agent forwarding instead.",
					File:        ctx.FilePath,
					Line:        d.Line,
				})
				break
			}
		}
	}
	return findings
}

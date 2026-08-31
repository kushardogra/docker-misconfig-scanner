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

	Register(Rule{
		ID:          "COMPOSE-004",
		Severity:    types.SeverityMedium,
		Title:       "No resource limits defined",
		Description: "Service has no memory or CPU limits. A runaway container can exhaust host resources.",
		Remediation: "Add mem_limit and cpus values to the service definition.",
		Check:       checkNoResourceLimits,
	})

	Register(Rule{
		ID:          "COMPOSE-005",
		Severity:    types.SeverityHigh,
		Title:       "Port bound to all interfaces (0.0.0.0)",
		Description: "A port is explicitly bound to 0.0.0.0, exposing it on all network interfaces.",
		Remediation: "Bind to a specific interface, e.g. 127.0.0.1:8080:8080 for local-only access.",
		Check:       checkPortBoundToAll,
	})

	Register(Rule{
		ID:          "COMPOSE-006",
		Severity:    types.SeverityHigh,
		Title:       "Hardcoded secret in environment block",
		Description: "The environment block contains what appears to be a hardcoded password, token, or key.",
		Remediation: "Use Docker secrets or reference variables from a .env file instead.",
		Check:       checkComposeSecrets,
	})

	Register(Rule{
		ID:          "COMPOSE-007",
		Severity:    types.SeverityCritical,
		Title:       "Container shares host PID namespace",
		Description: "pid: host allows the container to see and signal all host processes.",
		Remediation: "Remove pid: host unless absolutely required.",
		Check:       checkHostPid,
	})

	Register(Rule{
		ID:          "COMPOSE-008",
		Severity:    types.SeverityHigh,
		Title:       "Container shares host IPC namespace",
		Description: "ipc: host shares the host's inter-process communication namespace.",
		Remediation: "Remove ipc: host to maintain isolation.",
		Check:       checkHostIpc,
	})

	Register(Rule{
		ID:          "COMPOSE-009",
		Severity:    types.SeverityMedium,
		Title:       "no-new-privileges not set",
		Description: "security_opt does not include no-new-privileges, allowing privilege escalation via setuid binaries.",
		Remediation: "Add security_opt: [no-new-privileges:true] to the service.",
		Check:       checkNoNewPrivileges,
	})

	Register(Rule{
		ID:          "COMPOSE-010",
		Severity:    types.SeverityHigh,
		Title:       "Unpinned image tag in compose service",
		Description: "Service uses 'latest' tag or no tag — non-deterministic deployments.",
		Remediation: "Pin the image to a specific version tag, e.g. nginx:1.25.3",
		Check:       checkUnpinnedComposeImage,
	})
}

// ── COMPOSE-001 ─────────────────────────────────────────────────────────────

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

// ── COMPOSE-002 ─────────────────────────────────────────────────────────────

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

// ── COMPOSE-003 ─────────────────────────────────────────────────────────────

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

// ── COMPOSE-004 ─────────────────────────────────────────────────────────────

func checkNoResourceLimits(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		if svc.MemLimit == "" && svc.CPUs == "" {
			findings = append(findings, types.Finding{
				RuleID:      "COMPOSE-004",
				Severity:    types.SeverityMedium,
				Title:       "No resource limits defined",
				Description: "Service '" + name + "' has no memory or CPU limits.",
				Remediation: "Set mem_limit and cpus in the service definition.",
				File:        ctx.FilePath,
			})
		}
	}
	return findings
}

// ── COMPOSE-005 ─────────────────────────────────────────────────────────────

func checkPortBoundToAll(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		for _, port := range svc.Ports {
			if strings.HasPrefix(port, "0.0.0.0:") {
				findings = append(findings, types.Finding{
					RuleID:      "COMPOSE-005",
					Severity:    types.SeverityHigh,
					Title:       "Port bound to all interfaces",
					Description: "Service '" + name + "' binds port to 0.0.0.0: " + port,
					Remediation: "Bind to 127.0.0.1 for local-only access.",
					File:        ctx.FilePath,
				})
			}
		}
	}
	return findings
}

// ── COMPOSE-006 ─────────────────────────────────────────────────────────────

var composeSecretKeywords = []string{
	"password", "passwd", "secret", "token", "api_key",
	"apikey", "private_key", "access_key", "aws_secret",
}

func checkComposeSecrets(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		for _, env := range svc.Environment {
			lower := strings.ToLower(env)
			for _, kw := range composeSecretKeywords {
				if strings.Contains(lower, kw) && strings.Contains(env, "=") {
					findings = append(findings, types.Finding{
						RuleID:      "COMPOSE-006",
						Severity:    types.SeverityHigh,
						Title:       "Hardcoded secret in environment block",
						Description: "Service '" + name + "' has a potential secret in environment: " + env,
						Remediation: "Use Docker secrets or a .env file reference instead.",
						File:        ctx.FilePath,
					})
					break
				}
			}
		}
	}
	return findings
}

// ── COMPOSE-007 ─────────────────────────────────────────────────────────────

func checkHostPid(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		if strings.ToLower(svc.Pid) == "host" {
			findings = append(findings, types.Finding{
				RuleID:      "COMPOSE-007",
				Severity:    types.SeverityCritical,
				Title:       "Container shares host PID namespace",
				Description: "Service '" + name + "' uses pid: host.",
				Remediation: "Remove pid: host.",
				File:        ctx.FilePath,
			})
		}
	}
	return findings
}

// ── COMPOSE-008 ─────────────────────────────────────────────────────────────

func checkHostIpc(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		if strings.ToLower(svc.Ipc) == "host" {
			findings = append(findings, types.Finding{
				RuleID:      "COMPOSE-008",
				Severity:    types.SeverityHigh,
				Title:       "Container shares host IPC namespace",
				Description: "Service '" + name + "' uses ipc: host.",
				Remediation: "Remove ipc: host.",
				File:        ctx.FilePath,
			})
		}
	}
	return findings
}

// ── COMPOSE-009 ─────────────────────────────────────────────────────────────

func checkNoNewPrivileges(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		hasFlag := false
		for _, opt := range svc.SecurityOpt {
			if strings.Contains(strings.ToLower(opt), "no-new-privileges") {
				hasFlag = true
				break
			}
		}
		if !hasFlag {
			findings = append(findings, types.Finding{
				RuleID:      "COMPOSE-009",
				Severity:    types.SeverityMedium,
				Title:       "no-new-privileges not set",
				Description: "Service '" + name + "' does not set no-new-privileges.",
				Remediation: "Add security_opt: [no-new-privileges:true]",
				File:        ctx.FilePath,
			})
		}
	}
	return findings
}

// ── COMPOSE-010 ─────────────────────────────────────────────────────────────

func checkUnpinnedComposeImage(ctx *types.ParseContext) []types.Finding {
	if ctx.ComposeData == nil {
		return nil
	}
	var findings []types.Finding
	for name, svc := range ctx.ComposeData.Services {
		if svc.Image == "" {
			continue
		}
		if !strings.Contains(svc.Image, ":") ||
			strings.HasSuffix(svc.Image, ":latest") {
			findings = append(findings, types.Finding{
				RuleID:      "COMPOSE-010",
				Severity:    types.SeverityHigh,
				Title:       "Unpinned image tag in compose service",
				Description: "Service '" + name + "' uses unpinned image: " + svc.Image,
				Remediation: "Pin to a specific version, e.g. nginx:1.25.3",
				File:        ctx.FilePath,
			})
		}
	}
	return findings
}

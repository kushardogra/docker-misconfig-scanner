# 🐳 docker-misconfig-scanner

A fast, lightweight static analysis CLI tool that detects security misconfigurations in Dockerfiles and docker-compose files — before they reach production.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](go.mod)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()

---

## The Problem

Docker's default behavior is insecure. Containers run as root, base images go unpinned, secrets get baked into layers, and the Docker daemon silently bypasses host firewall rules (UFW, firewalld) by manipulating iptables directly. These aren't edge cases — they're the default.

`docker-misconfig-scanner` catches these issues at the source, before deployment.

---

## Features

- 🔍 Static analysis of `Dockerfile` and `docker-compose.yml` files
- 📁 Scan a single file or an entire directory recursively
- 🧩 Typed rule IDs (e.g. `DOCKER-001`, `COMPOSE-002`) for traceability
- 📊 Human-readable table output or machine-readable JSON
- ⚡ Written in Go — fast, single binary, no runtime dependencies

---

## Detected Misconfigurations

| Rule ID      | Severity | Target         | Description                                      |
|--------------|----------|----------------|--------------------------------------------------|
| DOCKER-001   | HIGH     | Dockerfile     | Missing USER directive — container runs as root  |
| DOCKER-002   | MEDIUM   | Dockerfile     | Unpinned base image (latest tag or no tag)       |
| DOCKER-003   | CRITICAL | Dockerfile     | Potential secret in ENV or ARG instruction       |
| COMPOSE-001  | CRITICAL | docker-compose | Docker socket mounted into container             |
| COMPOSE-002  | CRITICAL | docker-compose | Container running in privileged mode             |
| COMPOSE-003  | HIGH     | docker-compose | Host network mode bypasses network isolation     |

---

## Installation

**Requires Go 1.21+**

```bash
git clone https://github.com/kushardogra/docker-misconfig-scanner.git
cd docker-misconfig-scanner
go build ./cmd/scan/
```

---

## Usage

**Scan a directory:**
```bash
./scan ./your-project/
```

**Scan a single file:**
```bash
./scan ./Dockerfile
```

**JSON output (for pipelines and scripts):**
```bash
./scan ./your-project/ -o json
```

---

## Example Output

```
RULE ID       SEVERITY   TITLE                                          FILE
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
DOCKER-001    HIGH       Container runs as root (missing USER)          Dockerfile
DOCKER-002    MEDIUM     Unpinned base image                            Dockerfile:1
DOCKER-003    CRITICAL   Potential secret in ENV                        Dockerfile:4
COMPOSE-001   CRITICAL   Docker socket mounted into container           docker-compose.yml
COMPOSE-002   CRITICAL   Privileged container                           docker-compose.yml
COMPOSE-003   HIGH       Host network mode                              docker-compose.yml

7 finding(s) detected.
```

---

## Project Structure

```
docker-misconfig-scanner/
├── cmd/scan/            # CLI entrypoint
├── internal/
│   ├── types/           # Shared types (Finding, Directive, ComposeFile)
│   ├── parser/          # Dockerfile and docker-compose parsers
│   ├── rules/           # Detection rule engine and rule registry
│   ├── scanner/         # Orchestrates parsing and rule evaluation
│   └── report/          # Table and JSON output formatters
└── testdata/vulnerable/ # Sample misconfigured files for testing
```

---

## Background

This tool grew out of a real-world incident: a ransomware breach caused by Docker containers silently bypassing UFW firewall rules via the `DOCKER` iptables chain, combined with weak credential defaults. The scanner's detection logic forms the basis of an ongoing empirical study of Docker misconfiguration prevalence across public GitHub repositories.

---

## Contributing

Contributions welcome — especially new detection rules. Each rule follows the pattern in `internal/rules/dockerfile_rules.go` and `compose_rules.go`. Open an issue first to discuss before submitting a PR.

---

## License

MIT © [Kushar Dogra](https://github.com/kushardogra)

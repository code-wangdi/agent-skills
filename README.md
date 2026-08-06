# Agent Skills

[![Security](https://github.com/code-wangdi/agent-skills/actions/workflows/security.yml/badge.svg)](https://github.com/code-wangdi/agent-skills/actions/workflows/security.yml)

Portable, security-conscious Agent Skills for Pi, Claude Code, Codex, OpenCode, and other [Agent Skills](https://agentskills.io/) compatible clients.

## Goals

- Keep reusable workflows in standards-compliant `SKILL.md` packages.
- Share one Skill core across multiple coding agents.
- Put client-specific model routing in thin adapters rather than portable Skill metadata.
- Prevent personal URLs, credentials, private paths, and other sensitive data from entering public Git history.

The first planned package is a guarded `commit-and-push` workflow that delegates analysis to a low-cost model while deterministic tooling owns Git mutations.

## Repository layout

```text
skills/<skill-name>/
├── SKILL.md
├── scripts/
├── references/
└── assets/
```

Each Skill should follow the open Agent Skills specification and keep client-specific launchers outside the portable core.

## Security-first setup

This public repository has GitHub Secret Scanning and Push Protection enabled. Local hooks and CI add checks for private endpoints, credential-bearing URLs, personal paths, non-example file and Git-metadata emails, credential files, and secret patterns.

Install [Gitleaks](https://github.com/gitleaks/gitleaks), then enable repository hooks:

```bash
scripts/install-hooks.sh
```

Run all checks manually:

```bash
scripts/security-scan.sh --all
```

Use placeholders in examples:

```text
https://api.example.com
${SERVICE_BASE_URL}
${API_TOKEN}
/Users/<username>/project
user@example.com
```

See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before publishing a Skill.

## Supported clients

The portable Skill core targets any Agent Skills-compatible client. Client-specific adapters may be provided for:

- Pi
- Claude Code
- Codex
- OpenCode

## License

[MIT](LICENSE)

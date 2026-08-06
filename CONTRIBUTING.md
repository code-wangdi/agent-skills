# Contributing

## Local setup

Requirements:

- Python 3.10 or newer
- Gitleaks 8.30.1 or newer

Install Gitleaks using your operating system's package manager or the official releases. Configure a privacy-safe GitHub noreply identity, then enable the tracked hooks:

```bash
git config --local user.name "${GITHUB_LOGIN}"
git config --local user.email "${GITHUB_ID}+${GITHUB_LOGIN}@users.noreply.github.com"
scripts/install-hooks.sh
```

The scanner checks pending author/committer identities and identities already stored in commit and annotated-tag metadata.

Confirm the setup:

```bash
python3 -m unittest discover -s tests -v
scripts/security-scan.sh --all
```

## Safe examples

Use portable placeholders in every Skill, reference, test, and script:

| Avoid | Use instead |
|---|---|
| A personal API hostname | `https://api.example.com` or `${SERVICE_BASE_URL}` |
| A literal key or token | `${API_TOKEN}` or `<token>` |
| A personal home path | `/Users/<username>/project` or a relative path |
| A personal email address | `user@example.com` |
| A checked-in environment file | `.env.example` with placeholder values |

## Before committing

1. Review `git status --short` and `git diff --cached`.
2. Stage only intentional files.
3. Run `scripts/security-scan.sh --staged`.
4. Do not use `--no-verify`.

Before pushing, run `scripts/security-scan.sh --history` and confirm GitHub Actions passes.

If a check fails, replace the value with a placeholder. Do not add `gitleaks:allow`, `.gitleaksignore`, a broad allowlist, or a weakened detection rule merely to land a change.

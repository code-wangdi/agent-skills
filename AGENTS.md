# Repository instructions

## Security is a release gate

Before every commit, run:

```bash
scripts/security-scan.sh --staged
```

Before every push, run:

```bash
scripts/security-scan.sh --history
```

Non-negotiable rules:

- Never commit API keys, tokens, passwords, cookies, private keys, credential files, or real webhook values.
- Never publish personal absolute paths, non-example email addresses, localhost/private-network endpoints, or internal-only hostnames.
- Git author, committer, and tagger identities must use a GitHub noreply address; checks include Git metadata, not only file contents.
- Use placeholders such as `${API_TOKEN}`, `${SERVICE_BASE_URL}`, `https://api.example.com`, and `/Users/<username>/project`.
- Do not use `--no-verify`, `gitleaks:allow`, or `.gitleaksignore`, and do not weaken scanners or hooks to make a change pass.
- If a scanner reports a false positive, rewrite the example with a clear placeholder. Security-control changes require explicit owner review.
- If a secret may have entered Git history, stop immediately. Revoke or rotate it before attempting history cleanup.

# Security policy

## Sensitive-data policy

This is a public repository. Contributions must not contain:

- API keys, access tokens, passwords, session cookies, private keys, signing material, or credential files
- Web, database, cache, queue, or file-transfer URLs with embedded credentials or literal credential-like query parameters
- localhost, private-network, reserved-IP, single-label, or internal-only service endpoints
- personal absolute home-directory paths or non-example email addresses in files, commits, or annotated tags

Use public examples and environment-variable placeholders instead:

```text
https://api.example.com
${SERVICE_BASE_URL}
${API_TOKEN}
/Users/<username>/project
user@example.com
```

Normal public documentation URLs are allowed. Automated checks cannot infer whether every public-looking domain belongs to an individual, so contributors must still review staged content manually.

## Enforcement layers

1. GitHub Secret Scanning and Push Protection block supported token formats server-side.
2. Tracked Git hooks run the custom sensitive-data policy and Gitleaks before commit and push.
3. GitHub Actions scan reachable Git blobs plus commit/annotated-tag messages and identity metadata, with redacted output.
4. Sensitive filenames and credential directories are excluded through `.gitignore` and rejected if force-added.
5. Inline `gitleaks:allow` directives and repository-wide `.gitleaksignore` files are forbidden.
6. Security-control files are listed in `CODEOWNERS` for explicit review in pull requests.

Install local hooks with:

```bash
scripts/install-hooks.sh
```

Hooks are defense in depth, not a substitute for reviewing `git diff --cached`. Git author, committer, and tagger emails must use GitHub noreply addresses.

## Reporting a vulnerability

Use GitHub private vulnerability reporting rather than opening a public issue:

https://github.com/code-wangdi/agent-skills/security/advisories/new

Do not include a live secret in the report. Describe the affected path and secret type with the value redacted.

## If sensitive data is exposed

1. Revoke or rotate the credential immediately. Deleting a Git commit does not invalidate a secret.
2. Stop further pushes.
3. Remove the value from the working tree and rewrite affected Git history if necessary.
4. Re-run both policy and Gitleaks history scans.
5. Treat forks, caches, action logs, and clones as potentially containing the old value.

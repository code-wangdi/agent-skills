#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "hook installation must run inside a Git repository" >&2
  exit 2
}
cd "$root"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks is required before enabling hooks." >&2
  echo "Install it from https://github.com/gitleaks/gitleaks, then rerun this script." >&2
  exit 2
fi

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push scripts/security-scan.sh scripts/check_sensitive_data.py

echo "Installed repository hooks via core.hooksPath=.githooks"
echo "Commits scan Git identity and the staged snapshot; pushes scan reachable history."

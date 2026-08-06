#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/security-scan.sh [--staged|--working-tree|--history|--all]

  --staged       Scan exactly what is staged. Used by the pre-commit hook.
  --working-tree Scan tracked and non-ignored working files.
  --history      Scan every reachable Git blob and the full Git history.
  --all          Run working-tree and history scans (default).
EOF
}

mode="${1:---all}"
case "$mode" in
  --staged|--working-tree|--history|--all) ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "security scan must run inside a Git repository" >&2
  exit 2
}
cd "$root"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the sensitive-data policy scan" >&2
  exit 2
fi
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks is required. Install v8.30.1 or newer: https://github.com/gitleaks/gitleaks" >&2
  exit 2
fi

run_gitleaks_staged() {
  gitleaks git --pre-commit --staged --redact --no-banner --ignore-gitleaks-allow --config .gitleaks.toml .
}

run_gitleaks_history() {
  gitleaks git --redact --no-banner --ignore-gitleaks-allow --config .gitleaks.toml .
}

run_gitleaks_working_tree() {
  gitleaks dir --redact --no-banner --ignore-gitleaks-allow --config .gitleaks.toml .
}

# Fail before Git creates an object if the pending identity contains a personal email.
python3 scripts/check_sensitive_data.py --identity

case "$mode" in
  --staged)
    python3 scripts/check_sensitive_data.py --staged
    run_gitleaks_staged
    ;;
  --working-tree)
    python3 scripts/check_sensitive_data.py --all
    run_gitleaks_working_tree
    ;;
  --history)
    python3 scripts/check_sensitive_data.py --history
    run_gitleaks_history
    ;;
  --all)
    python3 scripts/check_sensitive_data.py --all
    python3 scripts/check_sensitive_data.py --history
    run_gitleaks_working_tree
    run_gitleaks_history
    ;;
esac

echo "security scan passed ($mode)"

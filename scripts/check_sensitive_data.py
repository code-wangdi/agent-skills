#!/usr/bin/env python3
"""Detect secrets, private endpoints, and personal data without printing values."""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable
from urllib.parse import parse_qsl, urlsplit

MAX_TEXT_BYTES = 5 * 1024 * 1024

GENERIC_IDENTITIES = {
    "example",
    "placeholder",
    "runner",
    "user",
    "username",
    "your-name",
    "your_name",
}

EXAMPLE_DOMAINS = {
    "example.com",
    "example.net",
    "example.org",
    "noreply.github.com",
    "users.noreply.github.com",
}

EXAMPLE_EMAILS = {
    "noreply@github.com",
}

INTERNAL_SUFFIXES = (
    ".corp",
    ".home",
    ".internal",
    ".intranet",
    ".lan",
    ".local",
    ".private",
    ".svc",
)

SENSITIVE_QUERY_KEYS = {
    "apikey",
    "accesstoken",
    "auth",
    "authorization",
    "authtoken",
    "clientsecret",
    "credential",
    "googaccessid",
    "idtoken",
    "key",
    "oauthcode",
    "oauthverifier",
    "code",
    "codeverifier",
    "password",
    "passwd",
    "refreshtoken",
    "secret",
    "sharedaccesssignature",
    "sig",
    "signature",
    "token",
    "webhook",
    "xamzcredential",
    "xamzsecuritytoken",
    "xamzsignature",
    "xgoogcredential",
    "xgoogsignature",
}

SENSITIVE_QUERY_SUFFIXES = (
    "apikey",
    "credential",
    "pass",
    "password",
    "secret",
    "secretkey",
    "signature",
    "token",
    "verifier",
)

SENSITIVE_FILE_NAMES = {
    ".dockercfg",
    ".git-credentials",
    ".gitleaksignore",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".secrets",
    "application_default_credentials.json",
    "auth.json",
    "client_secret.json",
    "credentials",
    "credentials.json",
    "credentials.yaml",
    "credentials.yml",
    "id_ed25519",
    "id_rsa",
    "kubeconfig",
    "secrets",
    "secrets.json",
    "service-account.json",
    "token.json",
}

SENSITIVE_DIRECTORY_MARKERS = {
    ".aws",
    ".azure",
    ".docker",
    ".gnupg",
    ".kube",
    ".ssh",
}

SENSITIVE_PATH_FRAGMENTS = (
    "/.config/gcloud/",
    "/.config/gh/",
    "/.config/glab/",
    "/.config/op/",
)

SENSITIVE_FILE_SUFFIXES = (
    ".jks",
    ".key",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".pem",
    ".pfx",
    ".tfstate",
    ".tfstate.backup",
)

SAFE_ENV_FILE_NAMES = {".env.example", ".env.sample", ".env.template"}

SENSITIVE_ASSIGNMENT_SUFFIXES = (
    "accesskey",
    "accesstoken",
    "apikey",
    "authtoken",
    "bearertoken",
    "clientsecret",
    "connectionstring",
    "credential",
    "credentials",
    "dsn",
    "idtoken",
    "jwtsecret",
    "jwttoken",
    "pass",
    "password",
    "passwd",
    "privatekey",
    "refreshtoken",
    "secret",
    "secretaccesskey",
    "secretkey",
    "signingkey",
    "token",
    "webhooktoken",
    "webhookurl",
)

URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,31}://[^\s<>\"'`]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
GIT_IDENTITY_EMAIL_RE = re.compile(r"<([^<>\r\n]+)>")
GITHUB_NOREPLY_EMAIL_RE = re.compile(
    r"(?:noreply@github\.com|[A-Z0-9._%+\[\]-]+@users\.noreply\.github\.com)",
    re.IGNORECASE,
)
POSIX_HOME_RE = re.compile(
    r"""(?x)(?<![A-Za-z0-9_.-])/(?:Users|home)/([A-Za-z0-9][A-Za-z0-9_.-]*)(?=/|[\s"'`),;:]|$)"""
)
WINDOWS_HOME_RE = re.compile(
    r"""(?ix)\b[A-Z]:\\Users\\([A-Za-z0-9][A-Za-z0-9_.-]*)(?=\\|[\s"'`),;:]|$)"""
)
ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?<![a-z0-9_.-])
    (?P<quote>["']?)
    (?P<key>[a-z][a-z0-9_.-]{0,127})
    (?P=quote)
    \s*(?:=|:)\s*
    (?P<value>
        "(?:[^"\\]|\\.)*"(?=\s*(?:[,;#}\]&)]|$)) |
        '(?:[^'\\]|\\.)*'(?=\s*(?:[,;#}\]&)]|$)) |
        [^\r\n,;#&]+
    )
    """
)

ENV_REFERENCE_RE = re.compile(r"\$(?:\{[A-Z_][A-Z0-9_]*\}|[A-Z_][A-Z0-9_]*)")
GITHUB_REFERENCE_RE = re.compile(r"\$\{\{\s*(?:secrets|env|vars)\.[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}")
TEMPLATE_REFERENCE_RE = re.compile(r"\{\{\s*[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}")
ANGLE_PLACEHOLDER_RE = re.compile(r"<[A-Za-z_][A-Za-z0-9_.-]*>")
CODE_REFERENCE_RE = re.compile(
    r"""(?ix)
    (?:
        (?:os\.)?getenv\(\s*["'][A-Z_][A-Z0-9_]*["']\s*\) |
        os\.environ\[\s*["'][A-Z_][A-Z0-9_]*["']\s*\] |
        os\.environ\.get\(\s*["'][A-Z_][A-Z0-9_]*["']\s*\) |
        process\.env\.[A-Z_][A-Z0-9_]*
    )
    """
)

PRIVATE_KEY_BEGIN = "-----BEGIN "
PRIVATE_KEY_END = " PRIVATE KEY-----"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str
    source: str


def git(args: list[str], *, text: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )
    return result.stdout


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def is_sensitive_assignment_key(key: str) -> bool:
    normalized = normalized_key(key)
    return normalized.endswith(SENSITIVE_ASSIGNMENT_SUFFIXES)


def is_placeholder(value: str) -> bool:
    candidate = value.strip().strip("\"'").strip()
    lower = candidate.lower()
    if not candidate:
        return True
    if any(
        pattern.fullmatch(candidate)
        for pattern in (
            ENV_REFERENCE_RE,
            GITHUB_REFERENCE_RE,
            TEMPLATE_REFERENCE_RE,
            ANGLE_PLACEHOLDER_RE,
            CODE_REFERENCE_RE,
        )
    ):
        return True
    if lower in {
        "changeme",
        "example",
        "false",
        "none",
        "null",
        "placeholder",
        "redacted",
        "replace-me",
        "replace_me",
        "secret",
        "token",
        "your-value",
        "your_value",
    }:
        return True
    if lower.startswith(("example_", "placeholder_", "redacted_", "your_")):
        return True
    if set(candidate) <= {"*", "x", "X", "-", "_"}:
        return True
    return False


def sensitive_path_reason(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    pure = PurePosixPath(normalized)
    base = pure.name.lower()
    parts = {part.lower() for part in pure.parts}
    padded_path = f"/{normalized.strip('/').lower()}/"

    if base.startswith(".env") and base not in SAFE_ENV_FILE_NAMES:
        return "environment file may contain credentials"
    if base == ".gitleaksignore":
        return "repository-wide Gitleaks ignore files are forbidden"
    if base in SENSITIVE_FILE_NAMES:
        return "credential file must not be tracked"
    if base.endswith(SENSITIVE_FILE_SUFFIXES):
        return "private key or credential container must not be tracked"
    if base.startswith(("id_ed25519", "id_rsa")):
        return "SSH private key must not be tracked"
    if parts.intersection(SENSITIVE_DIRECTORY_MARKERS):
        return "personal credential directory must not be tracked"
    if any(fragment in padded_path for fragment in SENSITIVE_PATH_FRAGMENTS):
        return "personal credential directory must not be tracked"
    if base.startswith("service-account") and base.endswith((".json", ".yaml", ".yml")):
        return "service-account credential file must not be tracked"
    if base.startswith("credentials") and base.endswith((".json", ".yaml", ".yml")):
        return "credential file must not be tracked"
    if base.startswith("secrets.") and not base.endswith((".example", ".sample", ".template")):
        return "secret data file must not be tracked"
    return None


def private_host_reason(hostname: str | None) -> str | None:
    if not hostname:
        return None
    host = hostname.rstrip(".").lower()
    if any(marker in host for marker in ("$", "{", "}", "<", ">")):
        return None
    if host == "localhost":
        return "localhost URL is machine-specific; use a placeholder or configurable variable"
    if host.endswith(INTERNAL_SUFFIXES):
        return "internal-only hostname must not be published"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            address = ipaddress.ip_address(socket.inet_aton(host))
        except OSError:
            if "." not in host:
                return "single-label hostname is likely an internal-only endpoint"
            return None
    if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
        return "private, loopback, link-local, or reserved IP URL must not be published"
    return None


def is_sensitive_query_key(key: str) -> bool:
    normalized = normalized_key(key)
    return normalized in SENSITIVE_QUERY_KEYS or normalized.endswith(SENSITIVE_QUERY_SUFFIXES)


def inspect_url(url: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    cleaned = url.rstrip(".,);]")
    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return [("malformed-url", "URL cannot be parsed safely")]

    if parsed.username is not None or parsed.password is not None:
        findings.append(("credentialed-url", "URL contains embedded user information or a password"))

    host_reason = private_host_reason(parsed.hostname)
    if host_reason:
        findings.append(("private-url", host_reason))

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if is_sensitive_query_key(key) and not is_placeholder(value):
            findings.append(("sensitive-url-parameter", "URL contains a literal credential-like query parameter"))
            break
    return findings


def scan_text(path: str, text: str, *, source: str) -> list[Finding]:
    findings: list[Finding] = []
    path_reason = sensitive_path_reason(path)
    if path_reason:
        findings.append(Finding(path, 0, "sensitive-file", path_reason, source))

    git_identity = path.startswith(".git-metadata/") and path.endswith(".identity")
    for line_number, line in enumerate(text.splitlines(), 1):
        if git_identity:
            identity_emails = GIT_IDENTITY_EMAIL_RE.findall(line)
            if (
                len(identity_emails) != 1
                or GITHUB_NOREPLY_EMAIL_RE.fullmatch(identity_emails[0]) is None
            ):
                findings.append(
                    Finding(
                        path,
                        line_number,
                        "non-noreply-git-identity",
                        "Git identity must use exactly one GitHub noreply email",
                        source,
                    )
                )

        if PRIVATE_KEY_BEGIN in line and PRIVATE_KEY_END in line:
            findings.append(
                Finding(path, line_number, "private-key", "private-key material is present", source)
            )

        for match in URL_RE.finditer(line):
            for rule, message in inspect_url(match.group(0)):
                findings.append(Finding(path, line_number, rule, message, source))

        for match in POSIX_HOME_RE.finditer(line):
            identity = match.group(1).lower()
            if identity not in GENERIC_IDENTITIES:
                findings.append(
                    Finding(
                        path,
                        line_number,
                        "personal-path",
                        "personal absolute home-directory path is present",
                        source,
                    )
                )

        for match in WINDOWS_HOME_RE.finditer(line):
            identity = match.group(1).lower()
            if identity not in GENERIC_IDENTITIES:
                findings.append(
                    Finding(
                        path,
                        line_number,
                        "personal-path",
                        "personal Windows home-directory path is present",
                        source,
                    )
                )

        email_text = GIT_IDENTITY_EMAIL_RE.sub("", line) if git_identity else line
        for match in EMAIL_RE.finditer(email_text):
            email = match.group(0).lower()
            domain = match.group(1).lower()
            if email not in EXAMPLE_EMAILS and domain not in EXAMPLE_DOMAINS:
                findings.append(
                    Finding(
                        path,
                        line_number,
                        "personal-email",
                        "non-example email address is present",
                        source,
                    )
                )

        for assignment in ASSIGNMENT_RE.finditer(line):
            if is_sensitive_assignment_key(assignment.group("key")) and not is_placeholder(
                assignment.group("value")
            ):
                findings.append(
                    Finding(
                        path,
                        line_number,
                        "literal-secret-assignment",
                        "credential-like variable contains a literal value",
                        source,
                    )
                )

    return findings


def scan_blob(path: str, data: bytes, *, source: str) -> list[Finding]:
    path_reason = sensitive_path_reason(path)
    if b"\0" in data[:8192]:
        if path_reason:
            return [Finding(path, 0, "sensitive-file", path_reason, source)]
        return []
    if len(data) > MAX_TEXT_BYTES:
        return [
            Finding(
                path,
                0,
                "oversized-text-file",
                f"text file exceeds the {MAX_TEXT_BYTES // (1024 * 1024)} MiB scan limit",
                source,
            )
        ]
    return scan_text(path, data.decode("utf-8", errors="replace"), source=source)


def staged_entries() -> Iterable[tuple[str, bytes, str]]:
    output = git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"])
    assert isinstance(output, bytes)
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", errors="surrogateescape")
        try:
            data = git(["show", f":{path}"])
        except subprocess.CalledProcessError:
            continue
        assert isinstance(data, bytes)
        yield path, data, "staged"


def working_entries() -> Iterable[tuple[str, bytes, str]]:
    output = git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    assert isinstance(output, bytes)
    for raw_path in output.split(b"\0"):
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", errors="surrogateescape")
        file_path = Path(path)
        if not file_path.is_file() or file_path.is_symlink():
            continue
        try:
            data = file_path.read_bytes()
        except OSError:
            continue
        yield path, data, "working-tree"


def identity_entries() -> Iterable[tuple[str, bytes, str]]:
    for role in ("AUTHOR", "COMMITTER"):
        identity = git(["var", f"GIT_{role}_IDENT"])
        assert isinstance(identity, bytes)
        yield f".git-metadata/pending/{role.lower()}.identity", identity, "git-identity"


def history_entries() -> Iterable[tuple[str, bytes, str]]:
    commits = git(["rev-list", "--all"], text=True)
    assert isinstance(commits, str)
    commit_ids = [line.strip() for line in commits.splitlines() if line.strip()]
    for commit_id in commit_ids:
        commit = git(["cat-file", "commit", commit_id])
        assert isinstance(commit, bytes)
        headers, separator, message = commit.partition(b"\n\n")
        identities = b"\n".join(
            line for line in headers.splitlines() if line.startswith((b"author ", b"committer "))
        )
        if identities:
            yield (
                f".git-metadata/commits/{commit_id}.identity",
                identities,
                f"history:{commit_id[:12]}",
            )
        if separator and message:
            yield (
                f".git-metadata/commits/{commit_id}.message",
                message,
                f"history:{commit_id[:12]}",
            )

    tag_refs = git(["for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags"], text=True)
    assert isinstance(tag_refs, str)
    for line in tag_refs.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[1] != "tag":
            continue
        object_id = fields[0]
        tag = git(["cat-file", "tag", object_id])
        assert isinstance(tag, bytes)
        headers, separator, message = tag.partition(b"\n\n")
        identities = b"\n".join(line for line in headers.splitlines() if line.startswith(b"tagger "))
        if identities:
            yield (
                f".git-metadata/tags/{object_id}.identity",
                identities,
                f"history:{object_id[:12]}",
            )
        if separator and message:
            yield (
                f".git-metadata/tags/{object_id}.message",
                message,
                f"history:{object_id[:12]}",
            )

    output = git(["log", "--all", "--format=%T"], text=True)
    assert isinstance(output, str)
    tree_ids = list(dict.fromkeys(line.strip() for line in output.splitlines() if line.strip()))

    seen: set[tuple[str, str]] = set()
    for tree_id in tree_ids:
        tree = git(["ls-tree", "-r", "-z", "--full-tree", tree_id])
        assert isinstance(tree, bytes)
        for record in tree.split(b"\0"):
            if not record or b"\t" not in record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            fields = metadata.split()
            if len(fields) != 3 or fields[1] != b"blob":
                continue
            object_id = fields[2].decode("ascii")
            path = raw_path.decode("utf-8", errors="surrogateescape")
            if (object_id, path) in seen:
                continue
            seen.add((object_id, path))
            data = git(["cat-file", "blob", object_id])
            assert isinstance(data, bytes)
            yield path, data, f"history:{object_id[:12]}"


def path_entries(paths: list[str]) -> Iterable[tuple[str, bytes, str]]:
    for path in paths:
        file_path = Path(path)
        data = file_path.read_bytes()
        yield path, data, "explicit-path"


def unique_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(set(findings), key=lambda item: (item.path, item.line, item.rule, item.source))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect private URLs, literal credentials, credential files, and personal paths."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="scan the staged snapshot")
    mode.add_argument("--all", action="store_true", help="scan tracked and non-ignored working files")
    mode.add_argument("--history", action="store_true", help="scan reachable Git blobs and metadata")
    mode.add_argument("--identity", action="store_true", help="scan the pending Git author and committer")
    mode.add_argument("--paths", nargs="+", metavar="PATH", help="scan explicit paths")
    args = parser.parse_args()

    try:
        if args.staged:
            entries = staged_entries()
        elif args.history:
            entries = history_entries()
        elif args.identity:
            entries = identity_entries()
        elif args.paths:
            entries = path_entries(args.paths)
        else:
            entries = working_entries()

        findings: list[Finding] = []
        scanned = 0
        for path, data, source in entries:
            scanned += 1
            findings.extend(scan_blob(path, data, source=source))
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"sensitive-data check failed to run: {error}", file=sys.stderr)
        return 2

    findings = unique_findings(findings)
    if findings:
        print(
            f"sensitive-data check failed: {len(findings)} finding(s); values are intentionally redacted.",
            file=sys.stderr,
        )
        for finding in findings:
            location = f"{finding.path}:{finding.line}" if finding.line else finding.path
            print(
                f"- {location} [{finding.rule}] {finding.message} ({finding.source})",
                file=sys.stderr,
            )
        print("Replace private values with documented placeholders or environment variables.", file=sys.stderr)
        return 1

    print(f"sensitive-data check passed: {scanned} file snapshot(s) scanned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_sensitive_data as checker  # noqa: E402


class SensitiveDataPolicyTests(unittest.TestCase):
    def rules(self, text: str, path: str = "safe.md") -> set[str]:
        return {finding.rule for finding in checker.scan_text(path, text, source="unit-test")}

    def test_allows_public_documentation_urls(self) -> None:
        text = "See https://github.com/code-wangdi/agent-skills and https://agentskills.io/specification."
        self.assertEqual(set(), self.rules(text))

    def test_allows_github_noreply_identities(self) -> None:
        text = "\n".join(
            [
                "author Example <12345+user@users.noreply.github.com> 1 +0000",
                "committer Web Flow <noreply@github.com> 1 +0000",
                "author Dependabot <49699333+dependabot[bot]@users.noreply.github.com> 1 +0000",
            ]
        )
        self.assertEqual(set(), self.rules(text, ".git-metadata/commits/example.identity"))

    def test_blocks_non_noreply_pending_commit_and_tag_identities(self) -> None:
        cases = [
            (".git-metadata/pending/author.identity", "Example <user@example.com> 1 +0000"),
            (".git-metadata/pending/committer.identity", "Build <build@runner> 1 +0000"),
            (".git-metadata/commits/example.identity", "author Root <root@localhost> 1 +0000"),
            (".git-metadata/tags/example.identity", "tagger Example <user@example.com> 1 +0000"),
        ]
        for path, text in cases:
            with self.subTest(path=path):
                self.assertIn("non-noreply-git-identity", self.rules(text, path))

    def test_blocks_personal_email_in_git_identity_display_name(self) -> None:
        display_email = "alice" + "@personal.dev"
        text = f"author {display_email} <12345+user@users.noreply.github.com> 1 +0000"
        rules = self.rules(text, ".git-metadata/commits/example.identity")
        self.assertIn("personal-email", rules)

    def test_allows_placeholders_and_environment_references(self) -> None:
        text = "\n".join(
            [
                "api_key = ${API_KEY}",
                "token = $API_TOKEN",
                "password: <password>",
                'client_secret = os.environ["CLIENT_SECRET"]',
                '{"password": "${PASSWORD}"}',
                "https://api.example.com?token=${API_TOKEN}",
                "/Users/<username>/project",
                "user@example.com",
            ]
        )
        self.assertEqual(set(), self.rules(text))

    def test_blocks_credentialed_urls_for_arbitrary_schemes(self) -> None:
        web = "https://" + "operator:" + "literal-pass" + "@service.example.com/path"
        database = "postgresql://" + "dbuser:" + "literal-pass" + "@db.example.com/app"
        file_transfer = "sftp" + "://operator:" + "literal-pass" + "@prod.example.com/path"
        websocket = "wss" + "://operator:" + "literal-pass" + "@localhost/socket"
        self.assertIn("credentialed-url", self.rules(web))
        self.assertIn("credentialed-url", self.rules(database))
        self.assertIn("credentialed-url", self.rules(file_transfer))
        self.assertIn("private-url", self.rules(websocket))

    def test_allows_public_database_url_without_user_info(self) -> None:
        self.assertEqual(set(), self.rules("postgresql://db.example.com/application"))

    def test_blocks_sensitive_and_signed_url_parameters(self) -> None:
        api_query = "https" + "://api." + "example.com?api_" + "key=" + "literal-value-123"
        signed = "https://files.example.com/object?X-Amz-" + "Signature=" + "literal-signature-123"
        refresh = "https://login.example.com/callback?refresh_" + "to" + "ken=" + "literal-token-123"
        verifier = "https://login.example.com/callback?oauth_" + "verifier=" + "literal-value-123"
        oauth_code = "https://login.example.com/callback?co" + "de=" + "literal-value-123"
        code_verifier = "https://login.example.com/callback?code_" + "verifier=" + "literal-value-123"
        query_secret_case = "https://api.example.com?secret_" + "key=" + "literal-value-123"
        query_pass_case = "https://db.example.com?db_" + "pass=" + "literal-value-123"
        self.assertIn("sensitive-url-parameter", self.rules(api_query))
        self.assertIn("sensitive-url-parameter", self.rules(signed))
        self.assertIn("sensitive-url-parameter", self.rules(refresh))
        self.assertIn("sensitive-url-parameter", self.rules(verifier))
        self.assertIn("sensitive-url-parameter", self.rules(oauth_code))
        self.assertIn("sensitive-url-parameter", self.rules(code_verifier))
        self.assertIn("sensitive-url-parameter", self.rules(query_secret_case))
        self.assertIn("sensitive-url-parameter", self.rules(query_pass_case))

    def test_blocks_private_internal_and_single_label_urls(self) -> None:
        private_url = "http://" + "192.168." + "20.15:8080/api"
        internal_url = "https" + "://service." + "internal/v1"
        cluster_url = "https" + "://api.namespace." + "svc/v1"
        single_label = "redis://" + "cache:6379/0"
        shorthand_loopback = "http" + "://127.1/admin"
        shorthand_private = "http" + "://10.1/service"
        self.assertIn("private-url", self.rules(private_url))
        self.assertIn("private-url", self.rules(internal_url))
        self.assertIn("private-url", self.rules(cluster_url))
        self.assertIn("private-url", self.rules(single_label))
        self.assertIn("private-url", self.rules(shorthand_loopback))
        self.assertIn("private-url", self.rules(shorthand_private))

    def test_blocks_quoted_camelcase_and_multiple_literal_assignments(self) -> None:
        namespaced = "OPENAI_API_" + "KEY = " + "literal-value-123"
        multiple = "api_key=${API_KEY}; SLACK_BOT_" + "TO" + "KEN=" + "literal-token-123"
        quoted = '{"pass' + 'word": "' + "literal-pass-123" + '"}'
        camelcase = "openAI" + "Api" + "Key = " + "literal-value-123"
        aws = "AWS_SECRET_ACCESS_" + "KEY: " + "literal-value-123"
        assignment_secret_case = "SECRET_" + "KEY=" + "literal-value-123"
        assignment_camel_case = "secret" + "Key=" + "literal-value-123"
        assignment_pass_case = "DB_" + "PASS=" + "literal-value-123"
        self.assertIn("literal-secret-assignment", self.rules(namespaced))
        self.assertIn("literal-secret-assignment", self.rules(multiple))
        self.assertIn("literal-secret-assignment", self.rules(quoted))
        self.assertIn("literal-secret-assignment", self.rules(camelcase))
        self.assertIn("literal-secret-assignment", self.rules(aws))
        self.assertIn("literal-secret-assignment", self.rules(assignment_secret_case))
        self.assertIn("literal-secret-assignment", self.rules(assignment_camel_case))
        self.assertIn("literal-secret-assignment", self.rules(assignment_pass_case))

    def test_blocks_placeholder_prefix_and_fallback_bypasses(self) -> None:
        fallback = "pass" + 'word=os.getenv("PASSWORD", "literal-pass-123")'
        concatenated = "api_" + 'key=os.getenv("API_KEY")+"literal-value-123"'
        env_prefix = "api_" + "key=${API_KEY}literal-value-123"
        self.assertIn("literal-secret-assignment", self.rules(fallback))
        self.assertIn("literal-secret-assignment", self.rules(concatenated))
        self.assertIn("literal-secret-assignment", self.rules(env_prefix))

    def test_blocks_dollar_prefixed_literals(self) -> None:
        assignment = "pass" + "word=" + "$" + "uperSecret123"
        query = "https://api.example.com?to" + "ken=" + "$" + "uperSecret123"
        self.assertIn("literal-secret-assignment", self.rules(assignment))
        self.assertIn("sensitive-url-parameter", self.rules(query))

    def test_blocks_private_key_material(self) -> None:
        text = checker.PRIVATE_KEY_BEGIN + "OPENSSH" + checker.PRIVATE_KEY_END
        self.assertIn("private-key", self.rules(text))

    def test_blocks_personal_paths_with_or_without_a_trailing_segment(self) -> None:
        nested = "/Users/" + "alice/" + "private-project"
        posix_home = "/home/" + "bob"
        windows_home = "C:\\Users\\" + "charlie"
        personal_email = "alice" + "@personal-domain.dev"
        self.assertIn("personal-path", self.rules(nested))
        self.assertIn("personal-path", self.rules(posix_home))
        self.assertIn("personal-path", self.rules(windows_home))
        self.assertIn("personal-email", self.rules(personal_email))

    def test_blocks_sensitive_file_names_and_directories(self) -> None:
        self.assertIn("sensitive-file", self.rules("placeholder", ".env"))
        self.assertIn("sensitive-file", self.rules("placeholder", "keys/private.pem"))
        self.assertIn("sensitive-file", self.rules("placeholder", ".kube/config"))
        self.assertIn("sensitive-file", self.rules("placeholder", ".docker/config.json"))
        self.assertIn("sensitive-file", self.rules("placeholder", "credentials.yaml"))
        self.assertIn("sensitive-file", self.rules("placeholder", ".gitleaksignore"))
        self.assertIn("sensitive-file", self.rules("placeholder", "id_rsa.bak"))
        self.assertIn("sensitive-file", self.rules("placeholder", "id_ed25519-prod"))
        self.assertIn("sensitive-file", self.rules("placeholder", "token.json"))
        self.assertIn("sensitive-file", self.rules("placeholder", "state.tfstate"))
        self.assertNotIn("sensitive-file", self.rules("API_KEY=<key>", ".env.example"))


if __name__ == "__main__":
    unittest.main()

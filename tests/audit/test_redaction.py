"""tests/audit/test_redaction.py - cover the redaction surface.

Test data is intentionally obviously-fake; no real secrets are present.
We exercise every documented entry in bv/audit/redaction.py plus the
two helpers (redact_argv, redact_environment).
"""
import unittest

from bv.audit.redaction import (
    redact_text,
    redact_argv,
    redact_environment,
)


class TestRedaction(unittest.TestCase):

    def test_sk_token_redacted(self):
        # OpenAI-style sk- token. Pattern requires 20+ alnum/_/- chars.
        token = "sk-" + "abcdefghijklmnopqrstuvwxyz"  # 26 chars suffix
        out = redact_text(token)
        self.assertEqual(out, "sk-***REDACTED***")

    def test_github_pat_redacted(self):
        # GitHub PAT: ghp_ + 36+ alnum
        token = "ghp_" + ("a" * 40)
        out = redact_text(token)
        self.assertEqual(out, "ghp_***REDACTED***")

    def test_aws_key_redacted(self):
        # AWS access key: AKIA + 16 uppercase alnum
        key = "AKIA" + ("A" * 16)
        out = redact_text(key)
        self.assertEqual(out, "AKIA***REDACTED***")

    def test_password_kv_redacted(self):
        # password=secret123
        out = redact_text("password=secret123")
        self.assertIn("***REDACTED***", out)
        self.assertNotIn("secret123", out)
        # The full redacted form should match the documented replacement.
        self.assertEqual(out, "password=***REDACTED***")

    def test_pem_block_redacted(self):
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
            "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwJBAKEdDiz3l3lpk9w8n2n/4QMp9nK\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        out = redact_text(block)
        self.assertIsNotNone(out)
        self.assertIn("REDACTED", out)
        # The raw key body must be gone.
        self.assertNotIn(
            "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
            out,
        )

    def test_bearer_redacted(self):
        # Bearer token with 20+ chars
        token = "Bearer " + ("a" * 30)
        out = redact_text(token)
        self.assertEqual(out, "Bearer ***REDACTED***")

    def test_basic_auth_in_url_redacted(self):
        url = "https://user:pass@example.com"
        out = redact_text(url)
        self.assertEqual(out, "https://user:***REDACTED***@example.com")

    def test_safe_text_unchanged(self):
        safe = "echo hello world"
        self.assertEqual(redact_text(safe), safe)

    def test_none_passthrough(self):
        self.assertIsNone(redact_text(None))

    def test_argv_redaction(self):
        argv = ["sk-abcdefghijklmnopqrstuv", "echo", "hi"]
        out = redact_argv(argv)
        self.assertEqual(out, ["sk-***REDACTED***", "echo", "hi"])

    def test_env_secret_keys(self):
        env = {"GITHUB_TOKEN": "ghp_xxxxx", "PATH": "/bin"}
        out = redact_environment(env)
        self.assertEqual(out["GITHUB_TOKEN"], "***REDACTED***")
        self.assertEqual(out["PATH"], "/bin")


if __name__ == "__main__":
    unittest.main()
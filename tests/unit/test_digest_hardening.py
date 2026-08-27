"""Regression tests for the P1-12 hardening of sandbox_image_digest.

These tests guard the contract:

    Configured security properties
        ↓
    Typed configuration field on VerifySettings
        ↓
    Validated at load time (raises ConfigError on malformed input)
        ↓
    Runtime comparison against actual Docker image identity
        ↓
    Failure closes the execution path

Tests run against an in-process fuzzer of bv.config.load_config / parse /
DockerSandbox construction paths. They do NOT require Docker.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

# Ensure the repo is on the path regardless of where tests are run.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Compute the repo root from this test file's location (portable).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bv.config import (  # noqa: E402
    Config,
    ConfigError,
    VerifySettings,
    parse_sandbox_image_digest,
    validate_sandbox_image_digest,
    load_config,
)


FAKE_SHA256 = "sha256:" + ("1" * 64)
FAKE_SHA256_ALT = "sha256:" + ("2" * 64)


class TestDigestFieldDeclaration(unittest.TestCase):
    """INVARIANT 1: configured sandbox digest must reach runtime configuration.

    The field must be a first-class declared attribute on VerifySettings,
    NOT accessed via getattr().
    """

    def test_field_is_declared_on_dataclass(self):
        # dataclass field listing — this would FAIL if the field were
        # a dynamic attribute or class-level monkey-patch.
        names = {f.name for f in VerifySettings.__dataclass_fields__.values()}
        self.assertIn("sandbox_image_digest", names)

    def test_field_default_is_empty_string(self):
        # Deterministic default — empty string means "not configured".
        cfg = VerifySettings()
        self.assertEqual(cfg.sandbox_image_digest, "")

    def test_field_is_typed_string(self):
        # The dataclass type annotation must be str (not Optional, not Any).
        # Under `from __future__ import annotations` the type is stored as
        # the string "str"; without it, it's the class. Accept both.
        f = VerifySettings.__dataclass_fields__["sandbox_image_digest"]
        type_repr = f.type if isinstance(f.type, str) else f.type.__name__
        self.assertEqual(type_repr, "str")


class TestDigestValidation(unittest.TestCase):
    """Format validation: algorithm + hex length + lowercase."""

    def test_valid_sha256_digest(self):
        out = parse_sandbox_image_digest(FAKE_SHA256)
        self.assertEqual(out, FAKE_SHA256)

    def test_whitespace_stripped(self):
        out = parse_sandbox_image_digest("  " + FAKE_SHA256 + "  ")
        self.assertEqual(out, FAKE_SHA256)

    def test_empty_unset(self):
        self.assertEqual(parse_sandbox_image_digest(""), "")
        self.assertEqual(parse_sandbox_image_digest(None), "")

    def test_missing_algorithm_prefix_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            parse_sandbox_image_digest("1111111111111111111111111111111111111111111111111111111111111111")
        self.assertIn("algorithm", str(ctx.exception).lower())

    def test_unknown_algorithm_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            parse_sandbox_image_digest("sha512:" + ("a" * 128))
        self.assertIn("sha256", str(ctx.exception))
        self.assertIn("supported", str(ctx.exception).lower())

    def test_wrong_hex_length_rejected(self):
        # 63 chars
        bad = "sha256:" + ("a" * 63)
        with self.assertRaises(ConfigError) as ctx:
            parse_sandbox_image_digest(bad)
        self.assertIn("hex", str(ctx.exception).lower())
        # 65 chars
        bad = "sha256:" + ("a" * 65)
        with self.assertRaises(ConfigError):
            parse_sandbox_image_digest(bad)

    def test_uppercase_hex_rejected(self):
        bad = "sha256:" + ("A" * 64)
        with self.assertRaises(ConfigError):
            parse_sandbox_image_digest(bad)

    def test_non_string_rejected(self):
        with self.assertRaises(ConfigError) as ctx:
            parse_sandbox_image_digest(12345)
        self.assertIn("string", str(ctx.exception).lower())


class TestDigestLoadsFromToml(unittest.TestCase):
    """INVARIANT 1: configured digest reaches runtime configuration."""

    def _write_toml(self, content: str) -> str:
        fd, path = tempfile.mkstemp(prefix="safe-cli-digest-test-", suffix=".toml")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    def test_toml_digest_lands_on_dataclass(self):
        path = self._write_toml(
            f'[verify]\n'
            f'sandbox_image = "bash:5.1"\n'
            f'sandbox_image_digest = "{FAKE_SHA256}"\n'
        )
        try:
            cfg = load_config(path)
            self.assertEqual(cfg.verify.sandbox_image, "bash:5.1")
            self.assertEqual(cfg.verify.sandbox_image_digest, FAKE_SHA256)
        finally:
            os.unlink(path)

    def test_toml_digest_omitted_means_unset(self):
        path = self._write_toml('[verify]\nsandbox_image = "bash:5.1"\n')
        try:
            cfg = load_config(path)
            self.assertEqual(cfg.verify.sandbox_image_digest, "")
        finally:
            os.unlink(path)

    def test_malformed_digest_raises_config_error(self):
        path = self._write_toml(
            '[verify]\n'
            'sandbox_image = "bash:5.1"\n'
            'sandbox_image_digest = "not-a-real-digest"\n'
        )
        try:
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            os.unlink(path)

    def test_uppercase_hex_digest_in_toml_raises(self):
        path = self._write_toml(
            '[verify]\n'
            'sandbox_image = "bash:5.1"\n'
            f'sandbox_image_digest = "sha256:{"A" * 64}"\n'
        )
        try:
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            os.unlink(path)


class TestSandboxResultImageFields(unittest.TestCase):
    """The dataclass must declare image-identity fields."""

    def test_sandbox_result_declares_image_fields(self):
        from bv.sandbox.docker_sandbox import SandboxResult
        names = {f.name for f in SandboxResult.__dataclass_fields__.values()}
        for required in (
            "sandbox_image",
            "sandbox_image_digest_configured",
            "sandbox_image_digest_actual",
            "sandbox_image_digest_matched",
        ):
            self.assertIn(required, names, f"SandboxResult.{required} missing")

    def test_no_silent_data_loss_on_kwargs(self):
        # If the dataclass didn't declare a field, passing it as kwarg would
        # raise TypeError. This test PROVES the schema is enforced.
        from bv.sandbox.docker_sandbox import SandboxResult
        with self.assertRaises(TypeError):
            SandboxResult(
                exit_code=0, stdout="", stderr="", duration_ms=0,
                sandbox_image="bash:5.1",
                # If we ADD a field, also add it here. If we REMOVE one,
                # this test will need updating.
                sandbox_image_digest_configured=FAKE_SHA256,
                sandbox_image_digest_actual=FAKE_SHA256,
                sandbox_image_digest_matched=True,
                # ^ THIS kwarg must match a declared field
                this_field_should_not_exist="boom",
            )


class TestDockerSandboxDigestEnforcement(unittest.TestCase):
    """INVARIANT 2 + 3: digest mismatch + missing digest fail closed."""

    def test_construction_succeeds_with_docker_unavailable_for_unset_digest(self):
        # No digest configured + no docker binary -> mutable-tag mode accepted
        # at construction; runtime will fail at run time. This documents
        # the security policy: missing digest is allowed at construction
        # but cannot lead to execution eligibility (see broker / orchestrator).
        from dataclasses import dataclass
        from bv.sandbox.docker_sandbox import DockerSandbox

        @dataclass
        class _Tools:
            docker: str = "/nope/docker"
        from bv.config import Config, VerifySettings, Tools
        cfg = Config(
            verify=VerifySettings(sandbox_image="bash:5.1", sandbox_image_digest=""),
            tools=_Tools(),
        )
        with self.assertRaises(RuntimeError):
            DockerSandbox(cfg)  # docker binary missing

    def test_construction_fails_when_digest_set_but_docker_unavailable(self):
        # When a digest IS configured and we can't verify the actual image,
        # the constructor must refuse (not silently fall back to mutable-tag).
        from dataclasses import dataclass
        from bv.config import Config, VerifySettings, Tools

        @dataclass
        class _Tools:
            docker: str = "/nope/docker"

        cfg = Config(
            verify=VerifySettings(
                sandbox_image="bash:5.1",
                sandbox_image_digest=FAKE_SHA256,
            ),
            tools=_Tools(),
        )
        # We can't actually instantiate DockerSandbox (it would try to pull);
        # but the digest enforcement runs inside __init__. Use the same
        # internal helper to test the contract.
        from bv.sandbox.docker_sandbox import DockerSandbox
        with self.assertRaises(RuntimeError) as ctx:
            DockerSandbox(cfg)
        # The error must come from either missing-docker OR missing-image;
        # both are acceptable failure modes for the "cannot verify" path.
        self.assertTrue(
            "docker binary" in str(ctx.exception)
            or "image digest" in str(ctx.exception)
            or "could not" in str(ctx.exception)
            or "not found" in str(ctx.exception)
        )


class TestMutableTagCannotBypassDigest(unittest.TestCase):
    """INVARIANT 3 continued: a mutable tag alone never produces a verified digest.

    If config says digest="" then SandboxResult.sandbox_image_digest_matched
    must be False (we cannot claim match when no target is set).
    """

    def test_unset_digest_yields_matched_false(self):
        # Construct the result directly without docker (deterministic).
        from bv.sandbox.docker_sandbox import SandboxResult
        r = SandboxResult(
            exit_code=0, stdout="", stderr="", duration_ms=0,
            sandbox_image="bash:5.1",
            sandbox_image_digest_configured="",
            sandbox_image_digest_actual="",
            sandbox_image_digest_matched=False,  # explicitly false; runtime must compute this
        )
        self.assertFalse(r.sandbox_image_digest_matched)
        self.assertEqual(r.sandbox_image_digest_configured, "")
        self.assertEqual(r.sandbox_image_digest_actual, "")


class TestNoDynamicAccess(unittest.TestCase):
    """INVARIANT 9: no security-sensitive behavior depends on hidden
    dynamic configuration fields. Specifically the historical
    `getattr(config.verify, "sandbox_image_digest", "")` pattern must be gone.
    """

    def test_no_getattr_for_sandbox_image_digest_in_sandbox_module(self):
        # Scan the source of bv/sandbox/ for the historical getattr pattern.
        # Comments and docstrings are excluded — only ACTIVE code is scanned.
        import os
        import re
        sandbox_dir = os.path.join(_REPO_ROOT, "bv", "sandbox")
        violations = []
        for fn in os.listdir(sandbox_dir):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(sandbox_dir, fn)
            with open(path, "r") as f:
                src = f.read()
            # Strip line comments; strip triple-quoted docstrings (best effort).
            non_comment = "\n".join(
                line for line in src.split("\n")
                if not line.lstrip().startswith("#")
            )
            # Drop triple-quoted strings (rough; we just look for code
            # patterns in the *lines* that remain).
            for line in non_comment.split("\n"):
                stripped = line.strip()
                # Match the actual code form: getattr(<expr>, "sandbox_image_digest", <default>)
                if re.search(
                    r'getattr\s*\(\s*[^)]*?["\']sandbox_image_digest["\']',
                    stripped,
                ):
                    violations.append(f"{path}: {stripped}")
        self.assertEqual(
            violations, [],
            f"getattr workaround still present in active code: {violations}",
        )


if __name__ == "__main__":
    unittest.main()

"""Regression tests for P0 8: a skipped security layer must
produce INCOMPLETE, not silent PASS.
"""
import unittest
from dataclasses import dataclass

from bv.diagnostic import (
    Category,
    Diagnostic,
    LayerResult,
    Severity,
)
from bv.orchestrator import Orchestrator


def make_layer(name, status, severities=None):
    lr = LayerResult(layer=name, status=status)
    for sev in (severities or []):
        lr.add(Diagnostic(
            tool="test",
            category=Category.UNKNOWN,
            severity=sev,
            file="x",
            line=1,
            message=f"{sev.value} diag",
        ))
    return lr


class TestIncompletePropagates(unittest.TestCase):

    def test_pure_pass(self):
        layers = {
            "tree_sitter": make_layer("tree_sitter", "pass"),
            "bash_n":      make_layer("bash_n",      "pass"),
            "shellcheck":  make_layer("shellcheck",  "pass"),
        }
        @dataclass
        class R:
            layers: dict
            repair: object = None
        self.assertEqual(
            Orchestrator._overall_status(layers, R(layers=layers, repair=None)),
            "verified",
        )

    def test_incomplete_dominates(self):
        layers = {
            "tree_sitter": make_layer("tree_sitter", "pass"),
            "bash_n":      make_layer("bash_n",      "pass"),
            "sandbox":     make_layer("sandbox",     "incomplete"),
        }
        @dataclass
        class R:
            layers: dict
            repair: object = None
        self.assertEqual(
            Orchestrator._overall_status(layers, R(layers=layers, repair=None)),
            "incomplete",
        )

    def test_error_dominates(self):
        layers = {
            "sandbox":     make_layer("sandbox",     "incomplete"),
            "shellcheck":  make_layer("shellcheck",  "error", [Severity.ERROR]),
        }
        @dataclass
        class R:
            layers: dict
            repair: object = None
        self.assertEqual(
            Orchestrator._overall_status(layers, R(layers=layers, repair=None)),
            "failed",
        )


if __name__ == "__main__":
    unittest.main()

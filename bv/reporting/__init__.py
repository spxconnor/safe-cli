"""Reporting subpackage — JSON / human-readable formatting."""
from .json_report import to_json
from .human_report import to_human

__all__ = ["to_json", "to_human"]

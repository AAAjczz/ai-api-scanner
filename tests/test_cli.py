"""Tests for CLI argument parsing and output formats.

These tests verify the CLI handles arguments correctly and generates
all three output formats (JSON, Markdown, SARIF) without errors.
"""

import io
import json
import os
import sys
import tempfile
import pytest

# Ensure the package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_api_scanner.core.result import RuleResult, Status, Finding, compute_grade
from ai_api_scanner.core.output import generate_markdown, generate_sarif
from ai_api_scanner.core.config import load_config, _deep_merge, _defaults


FAKE_TARGET = "https://api.example.com/v1"


# ── config loading ────────────────────────────────────────────────────────

class TestConfig:
    def test_defaults_structure(self):
        defaults = _defaults()
        assert "target" in defaults
        assert "key" in defaults
        assert "timeout" in defaults
        assert "rules" in defaults
        assert "thresholds" in defaults
        assert defaults["timeout"] == 10.0

    def test_deep_merge_nested(self):
        base = {"a": 1, "b": {"x": 2, "y": 3}}
        override = {"b": {"y": 99}, "c": 4}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"]["x"] == 2
        assert result["b"]["y"] == 99
        assert result["c"] == 4

    def test_deep_merge_top_level_override(self):
        base = {"a": 1, "b": 2}
        override = {"a": 999}
        result = _deep_merge(base, override)
        assert result["a"] == 999
        assert result["b"] == 2

    def test_load_missing_config_raises(self):
        """Explicit path to nonexistent file → FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_config("nonexistent-file-12345.json")

    def test_load_no_path_no_local_config(self, monkeypatch, tmp_path):
        """When there's no .ai-scanner.json in cwd, it returns defaults."""
        import os
        monkeypatch.chdir(tmp_path)
        config = load_config()  # no path, no .ai-scanner.json in tmpdir
        assert config["target"] is None
        assert config["timeout"] == 10.0

    def test_load_config_from_temp_file(self):
        content = json.dumps({"target": "https://myapi.com/v1", "timeout": 5.0})
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        assert config["target"] == "https://myapi.com/v1"
        assert config["timeout"] == 5.0

    def test_load_config_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            load_config("definitely-not-a-file-99211.json")


# ── markdown output ──────────────────────────────────────────────────────

class TestMarkdownOutput:
    def test_generates_valid_report(self):
        results = [
            RuleResult("auth", "Auth Check", Status.PASS, summary="All good."),
            RuleResult("tls", "TLS Check", Status.FAIL, summary="Cert expired.",
                       findings=[Finding(detail="Expired 5 days ago", evidence="notAfter=...")],
                       suggestion="Renew the cert."),
        ]
        md = generate_markdown(results, FAKE_TARGET)
        assert "# AI API Security Scan Report" in md
        assert "Auth Check" in md
        assert "TLS Check" in md
        assert "Expired 5 days ago" in md
        assert "Renew the cert." in md

    def test_includes_grade(self):
        results = [RuleResult("r", "R", Status.PASS)]
        md = generate_markdown(results, FAKE_TARGET)
        assert "**A+**" in md

    def test_includes_recommendations_section(self):
        results = [
            RuleResult("r1", "R1", Status.FAIL, suggestion="Fix A."),
            RuleResult("r2", "R2", Status.PASS),
            RuleResult("r3", "R3", Status.WARN, suggestion="Fix B."),
        ]
        md = generate_markdown(results, FAKE_TARGET)
        assert "## Recommendations" in md
        assert "Fix A." in md
        assert "Fix B." in md

    def test_no_recommendations_when_no_suggestions(self):
        results = [
            RuleResult("r1", "R1", Status.PASS),
            RuleResult("r2", "R2", Status.PASS),
        ]
        md = generate_markdown(results, FAKE_TARGET)
        assert "## Recommendations" not in md


# ── SARIF output ─────────────────────────────────────────────────────────

class TestSARIFOutput:
    def test_generates_valid_sarif_structure(self):
        results = [
            RuleResult("auth", "Auth Check", Status.PASS, summary="ok"),
            RuleResult("cors", "CORS Check", Status.WARN,
                       summary="Wildcard CORS",
                       findings=[Finding(detail="ACAO is *", evidence="*")],
                       suggestion="Fix it."),
        ]
        sarif = generate_sarif(results, FAKE_TARGET)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        # PASS is filtered out, only WARN included
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "cors"
        assert run["results"][0]["level"] == "warning"

    def test_pass_results_filtered_out(self):
        results = [
            RuleResult("r1", "R1", Status.PASS, summary="ok"),
            RuleResult("r2", "R2", Status.PASS, summary="ok"),
        ]
        sarif = generate_sarif(results, FAKE_TARGET)
        assert len(sarif["runs"][0]["results"]) == 0

    def test_error_maps_to_error_level(self):
        results = [
            RuleResult("tls", "TLS", Status.ERROR, summary="Connection failed"),
        ]
        sarif = generate_sarif(results, FAKE_TARGET)
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_rules_array_matches_results(self):
        results = [
            RuleResult("auth", "Auth", Status.FAIL, summary="fail"),
            RuleResult("cors", "CORS", Status.WARN, summary="warn"),
            RuleResult("tls", "TLS", Status.PASS, summary="pass"),
        ]
        sarif = generate_sarif(results, FAKE_TARGET)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 3
        assert all("id" in r for r in rules)
        assert all("name" in r for r in rules)


# ── JSON serialization ──────────────────────────────────────────────────

class TestJSONSerialization:
    def test_roundtrip_via_to_dict(self):
        """RuleResult → to_dict() → JSON → back should be lossless for key fields."""
        r = RuleResult(
            rule_id="test",
            rule_name="Test",
            status=Status.FAIL,
            summary="Broken",
            findings=[
                Finding(detail="Issue 1", evidence="E1"),
                Finding(detail="Issue 2", evidence="E2"),
            ],
            suggestion="Fix it.",
            duration_ms=123.45,
        )
        d = r.to_dict()
        j = json.dumps(d)
        d2 = json.loads(j)
        assert d2["rule_id"] == "test"
        assert d2["status"] == "FAIL"
        assert len(d2["findings"]) == 2
        assert d2["duration_ms"] == 123.45


# ── grade description coverage ────────────────────────────────────────────

class TestGradeDescriptions:
    def test_all_status_values_covered(self):
        """Every Status enum member must appear in STATUS_SYMBOL and _STATUS_WEIGHT."""
        from ai_api_scanner.core.result import STATUS_SYMBOL, _STATUS_WEIGHT
        for s in Status:
            assert s in STATUS_SYMBOL, f"Missing symbol for {s}"
            assert s in _STATUS_WEIGHT, f"Missing weight for {s}"

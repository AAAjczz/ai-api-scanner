"""Tests for result types and grade computation."""

import pytest
from ai_api_scanner.core.result import (
    Status,
    RuleResult,
    Finding,
    compute_grade,
    GRADE_DESCRIPTIONS,
    _STATUS_WEIGHT,
)


class TestComputeGrade:
    """Grade computation — the scoring engine that produces A+ through F."""

    def test_empty_results_returns_unknown(self):
        """Zero rules run → '?' grade."""
        info = compute_grade([])
        assert info["grade"] == "?"
        assert info["score"] == 0
        assert info["max_score"] == 100
        assert info["description"] == "No rules ran"

    def test_all_pass_is_a_plus(self):
        """Every rule PASS → A+ (100/100)."""
        results = [
            RuleResult("r1", "Rule 1", Status.PASS),
            RuleResult("r2", "Rule 2", Status.PASS),
            RuleResult("r3", "Rule 3", Status.PASS),
        ]
        info = compute_grade(results)
        assert info["grade"] == "A+"
        assert info["score"] == 100

    def test_single_fail_is_c(self):
        """One FAIL → penalty 25 → score 75 → C."""
        results = [
            RuleResult("r1", "Rule 1", Status.PASS),
            RuleResult("r2", "Rule 2", Status.FAIL, summary="broken"),
            RuleResult("r3", "Rule 3", Status.PASS),
        ]
        info = compute_grade(results)
        assert info["grade"] == "C"
        assert info["score"] == 75
        assert info["counts"]["FAIL"] == 1

    def test_two_fails_is_d(self):
        """Two FAILs → penalty 50 → score 50 → D."""
        results = [
            RuleResult("r1", "Rule 1", Status.FAIL),
            RuleResult("r2", "Rule 2", Status.FAIL),
            RuleResult("r3", "Rule 3", Status.PASS),
        ]
        info = compute_grade(results)
        assert info["grade"] == "D"
        assert info["score"] == 50

    def test_four_fails_is_f(self):
        """Four FAILs → penalty 100 → score 0 → F (floor at 0)."""
        results = [
            RuleResult("r1", "Rule 1", Status.FAIL),
            RuleResult("r2", "Rule 2", Status.FAIL),
            RuleResult("r3", "Rule 3", Status.FAIL),
            RuleResult("r4", "Rule 4", Status.FAIL),
            RuleResult("r5", "Rule 5", Status.FAIL),  # 5 * 25 = 125 → floor at 0
        ]
        info = compute_grade(results)
        assert info["grade"] == "F"
        assert info["score"] == 0

    def test_single_warn_is_b(self):
        """One WARN → penalty 8 → score 92 → B (80–94 band)."""
        results = [
            RuleResult("r1", "Rule 1", Status.PASS),
            RuleResult("r2", "Rule 2", Status.WARN),
            RuleResult("r3", "Rule 3", Status.PASS),
        ]
        info = compute_grade(results)
        assert info["grade"] == "B"
        assert info["score"] == 92

    def test_two_warns_is_b(self):
        """Two WARNs → penalty 16 → score 84 → B."""
        results = [
            RuleResult("r1", "Rule 1", Status.WARN),
            RuleResult("r2", "Rule 2", Status.WARN),
            RuleResult("r3", "Rule 3", Status.PASS),
        ]
        info = compute_grade(results)
        assert info["grade"] == "B"
        assert info["score"] == 84

    def test_single_error_is_c(self):
        """One ERROR → penalty 30 → score 70 → C (60–79 band)."""
        results = [
            RuleResult("r1", "Rule 1", Status.PASS),
            RuleResult("r2", "Rule 2", Status.ERROR),
            RuleResult("r3", "Rule 3", Status.PASS),
        ]
        info = compute_grade(results)
        assert info["grade"] == "C"
        assert info["score"] == 70

    def test_skip_has_zero_penalty(self):
        """SKIP doesn't affect score."""
        results = [
            RuleResult("r1", "Rule 1", Status.PASS),
            RuleResult("r2", "Rule 2", Status.SKIP),
            RuleResult("r3", "Rule 3", Status.SKIP),
        ]
        info = compute_grade(results)
        assert info["grade"] == "A+"
        assert info["score"] == 100

    def test_mixed_statuses(self):
        """FAIL + WARN + ERROR → penalty 25+8+30 = 63 → score 37 → F."""
        results = [
            RuleResult("r1", "Rule 1", Status.FAIL),
            RuleResult("r2", "Rule 2", Status.WARN),
            RuleResult("r3", "Rule 3", Status.ERROR),
            RuleResult("r4", "Rule 4", Status.PASS),
            RuleResult("r5", "Rule 5", Status.SKIP),
        ]
        info = compute_grade(results)
        assert info["grade"] == "F"
        assert info["score"] == 37
        assert info["counts"]["FAIL"] == 1
        assert info["counts"]["WARN"] == 1
        assert info["counts"]["ERROR"] == 1
        assert info["counts"]["PASS"] == 1
        assert info["counts"]["SKIP"] == 1

    def test_grade_boundaries(self):
        """Test exact boundary values for each grade tier."""
        # A+ at 100: all PASS, no penalty
        assert compute_grade([RuleResult("r", "r", Status.PASS)])["grade"] == "A+"
        # A at 95+: need score >= 95. 1 FAIL (75) = C, 0 penalty (100) = A+
        # A = 95-99 band. 1 WARN = 92 = B. Need different combos.
        # 1 WARN = 92 → B
        assert compute_grade([RuleResult("r", "r", Status.WARN)])["grade"] == "B"
        # 2 WARN = 84 → B
        assert compute_grade([RuleResult("r", "r", Status.WARN) for _ in range(2)])["grade"] == "B"
        # 3 WARN = 76 → C
        assert compute_grade([RuleResult("r", "r", Status.WARN) for _ in range(3)])["grade"] == "C"
        # 1 FAIL = 75 → C
        assert compute_grade([RuleResult("r", "r", Status.FAIL, summary="x")])["grade"] == "C"
        # 2 FAIL = 50 → D
        assert compute_grade([RuleResult("r", "r", Status.FAIL, summary="x") for _ in range(2)])["grade"] == "D"
        # 3 FAIL = 25 → F
        assert compute_grade([RuleResult("r", "r", Status.FAIL, summary="x") for _ in range(3)])["grade"] == "F"
        # 1 FAIL + 1 WARN = 67 → C
        r_fw = [RuleResult("r", "r", Status.FAIL, summary="x"), RuleResult("r2", "r2", Status.WARN)]
        assert compute_grade(r_fw)["grade"] == "C"
        assert compute_grade(r_fw)["score"] == 67


class TestRuleResult:
    """RuleResult dataclass and serialization."""

    def test_default_values(self):
        r = RuleResult(rule_id="x", rule_name="X", status=Status.PASS)
        assert r.summary == ""
        assert r.findings == []
        assert r.suggestion == ""
        assert r.duration_ms == 0.0

    def test_to_dict_basic(self):
        r = RuleResult(rule_id="auth", rule_name="Auth Check", status=Status.PASS,
                       summary="ok", duration_ms=12.5)
        d = r.to_dict()
        assert d["rule_id"] == "auth"
        assert d["rule_name"] == "Auth Check"
        assert d["status"] == "PASS"
        assert d["summary"] == "ok"
        assert d["duration_ms"] == 12.5
        assert d["findings"] == []
        assert d["suggestion"] == ""

    def test_to_dict_with_findings(self):
        r = RuleResult(
            rule_id="cors", rule_name="CORS Check", status=Status.FAIL,
            summary="CORS is wide open",
            findings=[
                Finding(detail="ACAO is *", evidence="Access-Control-Allow-Origin: *"),
                Finding(detail="Reflects Origin", evidence="Origin: evil.com"),
            ],
            suggestion="Restrict ACAO to your domain.",
            duration_ms=45.0,
        )
        d = r.to_dict()
        assert len(d["findings"]) == 2
        assert d["findings"][0]["detail"] == "ACAO is *"
        assert d["findings"][0]["evidence"] == "Access-Control-Allow-Origin: *"
        assert d["suggestion"] == "Restrict ACAO to your domain."


class TestGradeDescriptions:
    """Every grade tier has a human-readable description."""

    def test_all_grades_have_descriptions(self):
        for grade in ["A+", "A", "B", "C", "D", "F"]:
            assert grade in GRADE_DESCRIPTIONS
            assert len(GRADE_DESCRIPTIONS[grade]) > 0


class TestStatusWeights:
    """Verify scoring weight constants are reasonable."""

    def test_fail_heavier_than_warn(self):
        assert _STATUS_WEIGHT[Status.FAIL] > _STATUS_WEIGHT[Status.WARN]

    def test_error_heaviest(self):
        assert _STATUS_WEIGHT[Status.ERROR] >= _STATUS_WEIGHT[Status.FAIL]

    def test_pass_skip_zero(self):
        assert _STATUS_WEIGHT[Status.PASS] == 0
        assert _STATUS_WEIGHT[Status.SKIP] == 0

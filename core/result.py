"""Result types for scan rules."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"
    ERROR = "ERROR"


STATUS_SYMBOL = {
    Status.PASS:  "✅",
    Status.FAIL:  "❌",
    Status.WARN:  "⚠️",
    Status.SKIP:  "⏭️",
    Status.ERROR: "💥",
}

# Scoring weights for letter grade calculation
_STATUS_WEIGHT = {
    Status.FAIL:  25,
    Status.WARN:  8,
    Status.ERROR: 30,
    Status.SKIP:  0,
    Status.PASS:  0,
}

GRADE_DESCRIPTIONS = {
    "A+": "Production-grade — every check passed",
    "A":  "Production-ready — all critical checks passed",
    "B":  "Good posture — minor warnings to review",
    "C":  "Needs work — at least one issue to fix",
    "D":  "Weak — multiple issues, fix before production",
    "F":  "Critical — urgent remediation required",
}


def compute_grade(results: list["RuleResult"]) -> dict[str, Any]:
    """Compute a letter grade and numeric score from scan results.

    Returns a dict with keys: grade, score, max_score, description, counts.
    """
    total_rules = len(results)
    if total_rules == 0:
        return {"grade": "?", "score": 0, "max_score": 100, "description": "No rules ran", "counts": {}}

    penalty = 0
    counts = {s: 0 for s in Status}
    for r in results:
        counts[r.status] += 1

    penalty += counts[Status.FAIL] * _STATUS_WEIGHT[Status.FAIL]
    penalty += counts[Status.WARN] * _STATUS_WEIGHT[Status.WARN]
    penalty += counts[Status.ERROR] * _STATUS_WEIGHT[Status.ERROR]

    score = max(0, 100 - penalty)

    # Letter grade by score bands
    if score >= 100:
        grade = "A+"
    elif score >= 95:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "grade": grade,
        "score": score,
        "max_score": 100,
        "description": GRADE_DESCRIPTIONS.get(grade, ""),
        "counts": {s.value: c for s, c in counts.items()},
    }


@dataclass
class Finding:
    """A single finding within a rule's result."""
    detail: str
    evidence: str = ""  # e.g., snippet of the offending response


@dataclass
class RuleResult:
    """The result of running one rule against a target."""
    rule_id: str
    rule_name: str
    status: Status
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    suggestion: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "status": self.status.value,
            "summary": self.summary,
            "findings": [{"detail": f.detail, "evidence": f.evidence} for f in self.findings],
            "suggestion": self.suggestion,
            "duration_ms": self.duration_ms,
        }

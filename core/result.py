"""Result types for scan rules."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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

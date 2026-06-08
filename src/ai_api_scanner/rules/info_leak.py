"""Rule: Information leak via error messages."""

from ..core.engine import Scanner
from ..core.result import RuleResult, Status, Finding
from .registry import register

# Patterns that indicate information leakage in error responses
LEAK_PATTERNS = [
    ("stack trace", r"(Traceback|File \".+\", line \d+|at \w+\.\w+\(\w+\.\w+:\d+\))"),
    ("internal path", r"(/app/|/home/|/var/|/etc/|C:\\)"),
    ("SQL error", r"(SQLSTATE|syntax error|pg_|mysql_)"),
    ("API key fragment", r"sk-[a-zA-Z0-9_-]{5,}"),
    ("proxy detail", r"(nginx/\d|Apache/\d|liteLLM)",),
    ("debug info", r"(DEBUG|TRACE|debug: true)"),
    ("internal host", r"(localhost:\d+|127\.0\.0\.1:\d+|10\.\d+\.\d+\.\d+)"),
]


@register("info-leak", "Error info leak")
def check_info_leak(scanner: Scanner) -> RuleResult:
    """Send malformed requests and check if error responses leak internal details."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="Error messages do not leak internal information.",
    )

    findings: list[Finding] = []

    # Test 1: Invalid JSON body
    resp = scanner.request_raw(
        method="POST",
        path="/chat/completions",
        body="not json {{{",
    )
    findings.extend(_scan_response(resp, "malformed JSON body"))

    # Test 2: Very large request
    large_body = "x" * 100_000
    resp = scanner.request_raw(
        method="POST",
        path="/chat/completions",
        body=large_body,
    )
    findings.extend(_scan_response(resp, "oversized request body"))

    # Test 3: Invalid model name (if we have a key)
    if scanner.api_key:
        resp = scanner.chat_completion(model="../../etc/passwd", message="test")
        findings.extend(_scan_response(resp, "path traversal model name"))

    # Deduplicate by detail text
    seen = set()
    unique = []
    for f in findings:
        if f.detail not in seen:
            seen.add(f.detail)
            unique.append(f)

    if unique:
        result.status = Status.FAIL
        result.summary = f"Error responses leak internal information ({len(unique)} finding(s))."
        result.findings = unique
        result.suggestion = "Configure your API gateway/proxy to return generic error messages. Never expose stack traces, paths, or server details."
    else:
        result.status = Status.PASS
        result.summary = "Error responses are properly sanitized."

    return result


def _scan_response(resp, context: str) -> list[Finding]:
    """Scan a response body for information leak patterns."""
    import re
    body = resp.text[:2000]  # only scan first 2KB
    found = []
    for category, pattern in LEAK_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            snippet = body[max(0, match.start()-20):match.end()+20].replace("\n", "\\n")
            found.append(Finding(
                detail=f"[{context}] Leaked {category}: \"{match.group(0)}\"",
                evidence=f"…{snippet}…",
            ))
    return found

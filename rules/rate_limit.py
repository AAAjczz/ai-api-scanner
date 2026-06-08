"""Rule: Rate limiting check."""

from core.engine import Scanner
from core.result import RuleResult, Status, Finding
from .registry import register


@register("rate-limit", "Rate limiting")
def check_rate_limiting(scanner: Scanner) -> RuleResult:
    """Send rapid requests to see if rate limiting is enforced."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="Rate limiting appears to be configured.",
    )

    if not scanner.api_key:
        result.status = Status.SKIP
        result.summary = "Skipped — no API key provided, cannot test rate limiting."
        return result

    RAPID_COUNT = 20
    statuses: list[int] = []

    for i in range(RAPID_COUNT):
        try:
            resp = scanner.request(path="/models")
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                break
        except Exception:
            # Timeout or connection error — likely rate-limited at network level
            statuses.append(429)
            break

    count_200 = sum(1 for s in statuses if s == 200)
    count_429 = sum(1 for s in statuses if s == 429)

    if count_429 > 0:
        result.status = Status.PASS
        result.summary = f"Rate limit triggered after {len(statuses)} requests (HTTP 429)."
        return result

    if count_200 == RAPID_COUNT:
        result.status = Status.FAIL
        result.summary = f"All {RAPID_COUNT} rapid requests succeeded — no rate limiting detected."
        result.findings.append(Finding(
            detail=f"Sent {RAPID_COUNT} requests to /models in quick succession. All returned 200.",
            evidence="",
        ))
        result.suggestion = "Enable rate limiting (RPM/TPM) on your API gateway or reverse proxy."
        return result

    # Mixed results — something happened but not a clean 429
    non_200 = [s for s in statuses if s != 200]
    result.status = Status.WARN
    result.summary = f"Partial rate limiting? {count_200}/{len(statuses)} requests succeeded. Non-200: {non_200[:5]}"
    result.suggestion = "Verify rate limiting is configured to return 429 for exceeded limits."
    return result

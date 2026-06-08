"""Rule: Rate limiting check."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from core.engine import Scanner
from core.result import RuleResult, Status, Finding
from .registry import register


@register("rate-limit", "Rate limiting")
def check_rate_limiting(scanner: Scanner) -> RuleResult:
    """Send parallel rapid requests to see if rate limiting is enforced."""
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

    PARALLEL_COUNT = 30

    def _send():
        try:
            return scanner.request(path="/models").status_code
        except Exception:
            return -1

    statuses: list[int] = []
    with ThreadPoolExecutor(max_workers=30) as pool:
        futures = [pool.submit(_send) for _ in range(PARALLEL_COUNT)]
        for f in as_completed(futures):
            statuses.append(f.result())

    count_200 = sum(1 for s in statuses if s == 200)
    count_429 = sum(1 for s in statuses if s == 429)
    count_503 = sum(1 for s in statuses if s == 503)
    blocked = count_429 + count_503

    if blocked > 0:
        result.status = Status.PASS
        result.summary = f"Rate limit triggered: {blocked}/{PARALLEL_COUNT} requests blocked (429/503)."
        return result

    if count_200 >= PARALLEL_COUNT * 0.9:
        result.status = Status.FAIL
        result.summary = f"All {PARALLEL_COUNT} parallel requests succeeded — no rate limiting detected."
        result.findings.append(Finding(
            detail=f"Sent {PARALLEL_COUNT} concurrent requests to /models. All returned 200.",
            evidence="",
        ))
        result.suggestion = "Enable rate limiting (RPM/TPM) on your API gateway or reverse proxy."
        return result

    # Mixed results
    non_200 = [s for s in statuses if s != 200]
    result.status = Status.WARN
    result.summary = f"Partial rate limiting? {count_200}/{PARALLEL_COUNT} succeeded. Non-200: {non_200[:5]}"
    result.suggestion = "Verify rate limiting is configured consistently."
    return result

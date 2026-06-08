"""Rule: Authentication checks."""

from core.engine import Scanner
from core.result import RuleResult, Status, Finding
from .registry import register

DEFAULT_KEYS = [
    ("sk-xxx", "common placeholder"),
    ("sk-change-me", "from .env.example patterns"),
    ("sk-change-me-to-a-random-string", "from .env.example"),
    ("sk-test", "generic test key"),
    ("sk-your-deepseek-key", "DeepSeek placeholder"),
    ("sk-your-qwen-key", "Qwen placeholder"),
    ("your-zhipu-key", "Zhipu placeholder"),
    ("sk-your-kimi-key", "Kimi placeholder"),
    ("sk-your-baidu-key", "Baidu placeholder"),
]


@register("auth-required", "API key required")
def check_auth_required(scanner: Scanner) -> RuleResult:
    """Check if the endpoint rejects unauthenticated requests."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="Unauthenticated requests are properly rejected.",
    )

    # Try the /models endpoint without auth
    resp = scanner.request(path="/models", no_auth=True)

    if resp.status_code == 401 or resp.status_code == 403:
        # Correct behavior
        result.status = Status.PASS
        result.summary = f"Returns {resp.status_code} for unauthenticated requests."
        return result

    if resp.status_code == 200:
        result.status = Status.FAIL
        result.summary = "Endpoint returned 200 without authentication."
        result.findings.append(Finding(
            detail="/models is accessible without an API key.",
            evidence=f"HTTP {resp.status_code}: {resp.text[:200]}",
        ))
        result.suggestion = "Require a valid Bearer token for all API endpoints."
        return result

    # Some other status — might be a redirect or different auth scheme
    result.status = Status.WARN
    result.summary = f"Unexpected status {resp.status_code} for unauthenticated request (expected 401/403)."
    return result


@register("default-key", "Default/placeholder key check")
def check_default_keys(scanner: Scanner) -> RuleResult:
    """Test if common placeholder API keys are accepted."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="No default/placeholder keys were accepted.",
    )

    working_defaults: list[str] = []

    for key, description in DEFAULT_KEYS:
        # Use the models endpoint — least destructive
        resp = scanner.chat_completion(
            model="deepseek-v4-pro",
            message="test",
            api_key=key,
        )
        if resp.status_code not in (401, 403) and resp.status_code < 500:
            working_defaults.append(f"{key} ({description})")

    if working_defaults:
        result.status = Status.FAIL
        result.summary = f"{len(working_defaults)} default/placeholder key(s) accepted."
        for kd in working_defaults:
            result.findings.append(Finding(
                detail=f"Key accepted: {kd}",
                evidence="",
            ))
        result.suggestion = "Change all default keys immediately. Rotate any keys matching placeholder patterns."
    else:
        result.status = Status.PASS
        result.summary = "All placeholder keys were properly rejected."

    return result

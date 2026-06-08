"""Rule: API key format and exposure checks."""

from ..core.engine import Scanner
from ..core.result import RuleResult, Status, Finding
from .registry import register

# Expected key prefixes for common AI model providers
KEY_PATTERNS = {
    "DeepSeek":     r"sk-[a-zA-Z0-9]{32,}",
    "OpenAI":       r"sk-(proj-)?[a-zA-Z0-9_-]{32,}",
    "Anthropic":    r"sk-ant-[a-zA-Z0-9_-]{32,}",
    "Zhipu":        r"[a-zA-Z0-9]{32}\.[a-zA-Z0-9]{16}",
    "Qwen/DashScope": r"sk-[a-zA-Z0-9]{20,}",
    "Kimi/Moonshot": r"sk-[a-zA-Z0-9_-]{32,}",
}


@register("key-format", "Key format & exposure")
def check_key_exposure(scanner: Scanner) -> RuleResult:
    """Check if API keys are exposed in responses or have weak format."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="No key exposure detected in responses.",
    )

    findings: list[Finding] = []

    # Check if the provided key matches a known weak format
    if scanner.api_key:
        if scanner.api_key.startswith("sk-") and len(scanner.api_key) < 20:
            findings.append(Finding(
                detail=f"Provided API key is unusually short ({len(scanner.api_key)} chars).",
                evidence="",
            ))

    # Send a request and scan response for key-like patterns
    resp = scanner.request(path="/models", no_auth=True)
    body = resp.text

    import re
    for provider, pattern in KEY_PATTERNS.items():
        matches = re.findall(pattern, body)
        for m in matches:
            # Skip if it's the known demo key
            if m == scanner.api_key:
                continue
            findings.append(Finding(
                detail=f"Possible {provider} key exposed in response body.",
                evidence=f"matched: {m[:12]}...{m[-4:]}",
            ))

    # Check response headers for key-like values
    for name, value in resp.headers.items():
        for provider, pattern in KEY_PATTERNS.items():
            if re.search(pattern, value):
                findings.append(Finding(
                    detail=f"Possible {provider} key in response header '{name}'.",
                    evidence=f"header: {name}",
                ))
                break

    if findings:
        result.status = Status.FAIL
        result.summary = f"API key exposure detected ({len(findings)} finding(s))."
        result.findings = findings
        result.suggestion = "Never echo API keys in responses. Rotate any exposed keys immediately."
    else:
        result.status = Status.PASS

    return result

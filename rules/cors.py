"""Rule: CORS configuration check."""

from core.engine import Scanner
from core.result import RuleResult, Status, Finding
from .registry import register


@register("cors", "CORS configuration")
def check_cors(scanner: Scanner) -> RuleResult:
    """Check if CORS headers are overly permissive."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="CORS is not overly permissive.",
    )

    # Send a request with an Origin header to test CORS
    resp = scanner.request(
        path="/models",
        no_auth=True,
        headers={"Origin": "https://evil.example.com"},
    )

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

    issues: list[Finding] = []

    if acao == "*":
        if acac.lower() == "true":
            issues.append(Finding(
                detail="Access-Control-Allow-Origin: * combined with Allow-Credentials: true.",
                evidence="ACAO: *, ACAC: true",
            ))
        else:
            issues.append(Finding(
                detail="Access-Control-Allow-Origin is wildcard (*).",
                evidence="Access-Control-Allow-Origin: *",
            ))

    elif acao == "https://evil.example.com":
        issues.append(Finding(
            detail="CORS origin is reflected back — any origin is allowed.",
            evidence=f"ACAO echoes: {acao}",
        ))

    if acao == "null":
        issues.append(Finding(
            detail="Access-Control-Allow-Origin is 'null' — allows sandboxed/null-origin requests.",
            evidence="Access-Control-Allow-Origin: null",
        ))

    if issues:
        result.status = Status.WARN
        result.summary = f"CORS configuration could be tighter ({len(issues)} issue(s))."
        result.findings = issues
        result.suggestion = "Restrict Access-Control-Allow-Origin to your specific frontend domain(s)."
    else:
        if acao:
            result.summary = f"CORS appears restrictive (ACAO: {acao})."
        else:
            result.summary = "No CORS headers returned. API-only endpoints should not need CORS."

    return result

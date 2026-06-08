"""Rule: HTTP method and Content-Type validation checks."""

from core.engine import Scanner
from core.result import RuleResult, Status, Finding
from .registry import register


UNSAFE_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"]
EXPECTED_NO_BODY = {200, 204, 301, 302, 400, 401, 403, 404, 405, 501}


@register("http-methods", "HTTP method safety")
def check_http_methods(scanner: Scanner) -> RuleResult:
    """Check if unsafe HTTP methods are handled properly."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="Unsafe HTTP methods are properly rejected.",
    )

    findings: list[Finding] = []

    for method in UNSAFE_METHODS:
        try:
            resp = scanner.request(method=method, path="/v1/chat/completions", no_auth=True)
            code = resp.status_code

            if code == 200:
                findings.append(Finding(
                    detail=f"{method} /v1/chat/completions returned 200 — method should not be allowed.",
                    evidence=f"HTTP {code}",
                ))
            elif code == 405:
                pass  # Method Not Allowed — correct
            elif code == 501:
                pass  # Not Implemented — acceptable
            elif code not in EXPECTED_NO_BODY and code < 500:
                # Unexpected success or client error that isn't 405
                findings.append(Finding(
                    detail=f"{method} returned HTTP {code} — expected 405 (Method Not Allowed).",
                    evidence=f"HTTP {code}",
                ))
        except Exception:
            pass  # Connection issue — skip this method

    if findings:
        result.status = Status.WARN
        result.summary = f"{len(findings)} unsafe HTTP method(s) not properly rejected."
        result.findings = findings
        result.suggestion = "Configure your API gateway to reject unsafe HTTP methods with 405."
    else:
        result.status = Status.PASS
        result.summary = "All unsafe HTTP methods are properly rejected or return expected errors."

    return result


@register("content-type", "Content-Type validation")
def check_content_type(scanner: Scanner) -> RuleResult:
    """Check if the API validates Content-Type headers."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="API validates Content-Type properly.",
    )

    findings: list[Finding] = []
    payload = '{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}'

    test_cases = [
        ("text/html", "HTML content type"),
        ("application/x-www-form-urlencoded", "form-encoded content type"),
        ("text/plain", "plain text content type"),
        ("", "no content type"),
    ]

    for ct, desc in test_cases:
        headers = {}
        if ct:
            headers["Content-Type"] = ct
        else:
            # Send without Content-Type header — simulate missing CT
            pass

        try:
            resp = scanner.request(
                method="POST",
                path="/chat/completions",
                headers=headers if headers else None,
                json_body=None,  # don't let requests auto-set Content-Type
            )

            # Also test with raw body to avoid requests library auto-setting Content-Type
            resp_raw = scanner.request_raw(
                method="POST",
                path="/chat/completions",
                headers=headers if headers else None,
                body=payload,
            )
        except Exception:
            continue

        code = resp_raw.status_code

        if code == 415:
            pass  # Unsupported Media Type — correct
        elif code == 400:
            pass  # Bad Request — acceptable if it validates and rejects
        elif code in (401, 403):
            pass  # Auth error before content-type check — acceptable
        elif code == 200:
            findings.append(Finding(
                detail=f"API accepted request with {desc} (HTTP 200).",
                evidence=f"Content-Type: {ct or '(none)'}",
            ))
        elif code < 500:
            findings.append(Finding(
                detail=f"API returned {code} for {desc} — expected 415 (Unsupported Media Type).",
                evidence=f"Content-Type: {ct or '(none)'}",
            ))

    if findings:
        result.status = Status.WARN
        result.summary = f"API does not reject {len(findings)} non-JSON Content-Type(s)."
        result.findings = findings
        result.suggestion = "Reject requests without 'application/json' Content-Type with HTTP 415."
    else:
        result.status = Status.PASS
        result.summary = "Non-JSON Content-Types are properly rejected."

    return result

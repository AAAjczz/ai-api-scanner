"""Rule: Streaming abuse — tests server handling of stream=true connections."""

import time

import requests as _requests

from ..core.engine import Scanner
from ..core.result import RuleResult, Status, Finding
from .registry import register


@register("stream-abuse", "Streaming abuse")
def check_streaming_abuse(scanner: Scanner) -> RuleResult:
    """Test if the server handles streaming connections safely."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="Streaming endpoint handles connection lifecycle properly.",
    )

    if not scanner.api_key:
        result.status = Status.SKIP
        result.summary = "Skipped — no API key provided, cannot send chat requests."
        return result

    findings: list[Finding] = []

    # Establish baseline: a normal request
    try:
        normal = scanner.chat_completion(message="ping")
        if normal.status_code != 200:
            result.status = Status.SKIP
            result.summary = f"Skipped — API returned {normal.status_code} for a normal request."
            return result
    except Exception:
        result.status = Status.ERROR
        result.summary = "Cannot establish baseline — API is unreachable."
        return result

    # Test 1: Fire-and-abandon — open a stream, close immediately without reading
    try:
        url = f"{scanner.target}/chat/completions"
        headers = dict(scanner.session.headers)
        headers["Content-Type"] = "application/json"
        stream_resp = _requests.post(
            url,
            headers=headers,
            json={
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": "test"}],
                "stream": True,
            },
            stream=True,
            timeout=scanner.timeout,
        )
        # Close without consuming
        stream_resp.close()

        # Immediately check if server is still responsive
        post_abandon = scanner.request(path="/models", no_auth=False)
        if post_abandon.status_code != 200:
            findings.append(Finding(
                detail="After fire-and-abandon stream, /models returned "
                       f"HTTP {post_abandon.status_code}.",
                evidence=f"HTTP {post_abandon.status_code}",
            ))
    except Exception as e:
        findings.append(Finding(
            detail=f"Fire-and-abandon stream test failed: {e}",
            evidence="",
        ))

    # Test 2: Slow reader — trickle-read 1 byte at a time with delay
    try:
        stream2 = _requests.post(
            url,
            headers=headers,
            json={
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": "Say exactly: OK"}],
                "stream": True,
            },
            stream=True,
            timeout=scanner.timeout,
        )
        # Read just a little, then abandon
        start = time.perf_counter()
        bytes_read = 0
        try:
            for chunk in stream2.iter_content(chunk_size=1):
                if chunk:
                    bytes_read += len(chunk)
                if bytes_read >= 10 or time.perf_counter() - start > 3:
                    break
        except Exception:
            pass
        stream2.close()

        # Verify server still works
        post_slow = scanner.request(path="/models", no_auth=False)
        if post_slow.status_code != 200:
            findings.append(Finding(
                detail="After slow-read stream, /models returned "
                       f"HTTP {post_slow.status_code}.",
                evidence=f"HTTP {post_slow.status_code}",
            ))
    except Exception as e:
        findings.append(Finding(
            detail=f"Slow-read stream test failed: {e}",
            evidence="",
        ))

    # Test 3: Request without stream support — send stream=true with Accept: text/plain
    try:
        headers2 = dict(scanner.session.headers)
        headers2["Content-Type"] = "application/json"
        headers2["Accept"] = "text/plain"  # Not text/event-stream
        stream3 = _requests.post(
            url,
            headers=headers2,
            json={
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": "test"}],
                "stream": True,
            },
            stream=True,
            timeout=scanner.timeout,
        )
        first_byte = next(stream3.iter_content(chunk_size=1), None)
        stream3.close()

        if first_byte and stream3.status_code == 200:
            # Check raw first bytes — if it's JSON, not SSE
            text = first_byte.decode("utf-8", errors="replace")
            if text.startswith("{") or text.startswith("["):
                findings.append(Finding(
                    detail="Streaming response is JSON, not SSE (Server-Sent Events).",
                    evidence=f"First byte: {text[:50]}",
                ))
    except Exception:
        pass  # Fine if this doesn't work

    if findings:
        result.status = Status.WARN
        result.summary = f"{len(findings)} streaming concern(s) found."
        result.findings = findings
        result.suggestion = (
            "Ensure streaming connections have proper timeouts. "
            "Use SSE format for streaming responses. "
            "Configure server-side stream timeout to prevent resource exhaustion."
        )
    else:
        result.status = Status.PASS
        result.summary = "Streaming connections handled safely — server stays responsive after abandon."

    return result

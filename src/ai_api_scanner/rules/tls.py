"""Rule: TLS / HTTPS checks."""

import ssl


def _get_cn(rdn_tuple) -> str:
    """Extract commonName from an X.509 RDN tuple, handling varying formats."""
    for item in rdn_tuple:
        if len(item) >= 2 and item[0] == "commonName":
            return item[1]
    return ""
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone

from ..core.engine import Scanner
from ..core.result import RuleResult, Status, Finding
from .registry import register


@register("tls", "TLS configuration")
def check_tls(scanner: Scanner) -> RuleResult:
    """Verify TLS certificate validity and protocol version."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="TLS is properly configured.",
    )

    parsed = urlparse(scanner.target)

    if parsed.scheme != "https":
        result.status = Status.WARN
        result.summary = "Target is HTTP, not HTTPS. Traffic is not encrypted."
        result.suggestion = "Use HTTPS with a valid TLS certificate for all API endpoints."
        return result

    hostname = parsed.hostname
    port = parsed.port or 443

    findings: list[Finding] = []
    all_ok = True

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=scanner.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_ver = ssock.version()

                # Check TLS version
                if tls_ver in ("TLSv1.3", "TLSv1.2"):
                    pass  # good
                elif tls_ver == "TLSv1.1" or tls_ver == "TLSv1.0":
                    findings.append(Finding(
                        detail=f"Using deprecated {tls_ver}.",
                        evidence=f"Negotiated: {tls_ver}",
                    ))
                    all_ok = False
                else:
                    findings.append(Finding(
                        detail=f"Unknown TLS version: {tls_ver}",
                    ))
                    all_ok = False

                # Check certificate expiry
                if cert and "notAfter" in cert:
                    expiry_str = cert["notAfter"]
                    warn_days = scanner.config.get("tls_cert_expiry_warn_days", 30)
                    # Parse "Jun  8 12:00:00 2025 GMT"
                    try:
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        if days_left < 0:
                            findings.append(Finding(
                                detail=f"TLS certificate expired {abs(days_left)} days ago.",
                                evidence=f"Expired: {expiry_str}",
                            ))
                            all_ok = False
                        elif days_left < warn_days:
                            result.status = Status.WARN
                            findings.append(Finding(
                                detail=f"TLS certificate expires in {days_left} days.",
                                evidence=f"Expires: {expiry_str}",
                            ))
                            all_ok = False
                        else:
                            pass  # valid
                    except ValueError:
                        pass  # can't parse date, skip

                # Check for self-signed
                if cert and "issuer" in cert:
                    try:
                        issuer = cert["issuer"]
                        subject = cert.get("subject", ())
                        issuer_cn = _get_cn(issuer)
                        subject_cn = _get_cn(subject)
                        if issuer_cn and issuer_cn == subject_cn:
                            findings.append(Finding(
                                detail="Certificate appears to be self-signed.",
                                evidence=f"Issuer CN = Subject CN = {issuer_cn}",
                            ))
                            all_ok = False
                    except Exception:
                        pass  # can't parse issuer, skip this check

    except ssl.SSLCertVerificationError as e:
        result.status = Status.FAIL
        result.summary = f"TLS certificate validation failed: {e}"
        return result
    except ssl.SSLError as e:
        result.status = Status.FAIL
        result.summary = f"TLS handshake failed: {e}"
        return result
    except socket.timeout:
        result.status = Status.ERROR
        result.summary = f"Connection timed out connecting to {hostname}:{port}"
        return result
    except OSError as e:
        result.status = Status.ERROR
        result.summary = f"Connection failed: {e}"
        return result

    if not all_ok:
        result.status = Status.FAIL
        result.summary = f"{len(findings)} TLS issue(s) found."
        result.findings = findings
        result.suggestion = "Use a valid, non-expired TLS certificate from a trusted CA. Enable TLS 1.2+ only."
    else:
        result.summary = f"TLS {tls_ver}, certificate valid, trusted CA."

    return result

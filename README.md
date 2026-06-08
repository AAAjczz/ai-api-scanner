# AI API Scanner

**Scan any OpenAI-compatible API endpoint for security misconfigurations. 7 checks, 2 seconds.**

```bash
python scan.py https://your-api.com/v1 --key sk-your-key
```

## What it checks

| # | Rule | What it detects |
|---|------|----------------|
| 1 | **Auth required** | Endpoint accessible without API key |
| 2 | **Default keys** | Common placeholder keys still working (sk-change-me, etc.) |
| 3 | **Rate limiting** | No RPM/TPM enforcement on metadata endpoints |
| 4 | **TLS config** | Expired cert, self-signed, weak protocols |
| 5 | **CORS** | Wildcard origin, reflected origins |
| 6 | **Error leak** | Stack traces, internal paths, debug info in errors |
| 7 | **Key exposure** | API keys echoed in responses or headers |

## Install

```bash
git clone https://github.com/AAAjczz/ai-api-scanner.git
cd ai-api-scanner
pip install requests
```

Python 3.10+. Zero other dependencies.

## Usage

```bash
# Basic scan (no key — auth + rate limit checks will skip)
python scan.py https://api.example.com/v1

# Full scan with API key
python scan.py https://api.example.com/v1 -k sk-your-key

# Run specific rules only
python scan.py https://api.example.com/v1 -r auth tls cors

# JSON output (for CI/CD)
python scan.py https://api.example.com/v1 -k sk-key --json
```

## Example output

```
   AI API Security Scanner
   scanning https://your-api.com/v1

  [1/7] ❌  API key required
          /models is accessible without an API key.
          → HTTP 200 on unauthenticated request
          💡 Require a valid Bearer token for all API endpoints.

  [2/7] ✅  Default/placeholder key check
          All placeholder keys were properly rejected.

  [3/7] ❌  Rate limiting
          All 20 rapid requests succeeded — no rate limiting detected.
          💡 Enable rate limiting on your API gateway or reverse proxy.

  [4/7] ✅  TLS configuration
          TLSv1.3, certificate valid, trusted CA.

  [5/7] ⚠️  CORS configuration
          Access-Control-Allow-Origin is wildcard (*).
          💡 Restrict to your specific frontend domain(s).

  [6/7] ❌  Error info leak
          Error responses leak internal path: "/etc/"
          💡 Return generic error messages. Never expose internals.

  [7/7] ✅  Key format & exposure
          No key exposure detected in responses.

  ────────────────────────────────────────────
  3 ❌  1 ⚠️  3 ✅
  ❌ 3 issues found. Fix before production.
```

## CI/CD

```yaml
# GitHub Actions
- name: API Security Scan
  run: |
    pip install requests
    python scan.py ${{ secrets.API_URL }} -k ${{ secrets.API_KEY }} --json > scan.json
    python -c "import json; d=json.load(open('scan.json')); assert not any(r['status']=='FAIL' for r in d)"
```

## What this is NOT

- Not a vulnerability scanner — it finds misconfigurations, not 0-days
- Not a pentesting tool — lightweight, safe, won't trigger WAFs
- Not a replacement for code review

## What this IS

- A **checklist** your API should pass before production
- A **CI step** — fail the build on ❌
- A **signal** that your basic security posture is solid (when everything passes ✅)

## FAQ

**Works with non-OpenAI APIs?**
Targets OpenAI-compatible endpoints. Most AI API gateways (LiteLLM, OneAPI, FastAPI wrappers, Next.js routes) use this format.

**Safe to run against production?**
Yes. Lightweight requests only (model list, single chat, malformed payloads). No fuzzing, no load testing.

**Do I need to provide an API key?**
No — but without one, auth and rate limit checks will be skipped.

## License

MIT

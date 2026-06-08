# AI API Scanner

[![PyPI version](https://img.shields.io/pypi/v/ai-api-scanner)](https://pypi.org/project/ai-api-scanner/)
[![PyPI downloads](https://img.shields.io/pypi/dm/ai-api-scanner)](https://pypi.org/project/ai-api-scanner/)

**Scan any OpenAI-compatible API endpoint for security misconfigurations. 12 checks, ~50 seconds.**

```bash
pip install ai-api-scanner
ai-api-scanner https://your-api.com/v1 --key sk-your-key
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
| 8 | **Model enumeration** | Different error codes revealing which models exist |
| 9 | **HTTP methods** | Unsafe methods (PUT/DELETE/TRACE) not rejected |
| 10 | **Content-Type** | Non-JSON content types accepted by the API |
| 11 | **Streaming abuse** | Fire-and-abandon stream, slow-read attack |
| 12 | **SSRF** | Internal URL resolution via model name injection |

## Grade system

Each scan gets a letter grade:

| Grade | Score | Meaning |
|-------|-------|---------|
| **A+** | 100 | Every check passed — production-grade |
| **A** | 95+ | Production-ready |
| **B** | 80+ | Minor warnings to review |
| **C** | 60+ | At least one issue to fix |
| **D** | 40+ | Multiple issues — fix before production |
| **F** | <40 | Critical — urgent remediation |

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

# JSON output (for CI/CD) — includes grade
python scan.py https://api.example.com/v1 -k sk-key --json

# Markdown report
python scan.py https://api.example.com/v1 --md report.md

# SARIF output (GitHub Code Scanning)
python scan.py https://api.example.com/v1 --sarif

# Quiet mode (CI-friendly)
python scan.py https://api.example.com/v1 -q

# Use config file (auto-discovers .ai-scanner.json)
python scan.py
```

## Configuration

Create `.ai-scanner.json` to customize thresholds and skip rules:

```json
{
  "target": "https://api.example.com/v1",
  "key": "sk-your-key",
  "timeout": 15,
  "rules": {
    "skip": ["rate-limit", "model-enum"],
    "only": []
  },
  "thresholds": {
    "tls_cert_expiry_warn_days": 60,
    "rate_limit_parallel_count": 50
  }
}
```

CLI arguments always override config values.

## Example output

```
   AI API Security Scanner
   scanning https://your-api.com/v1

  [1/12] 🔍 API key required...
  [1/12] ❌  API key required  (312ms)
          /models is accessible without an API key.
          → HTTP 200 on unauthenticated request
          💡 Require a valid Bearer token for all API endpoints.

  [2/12] 🔍 Default/placeholder key check...
  [2/12] ✅  Default/placeholder key check  (4251ms)
          All placeholder keys were properly rejected.

  ...

────────────────────────────────────────────────────────────────────────────────
  ▌ GRADE  C  (75/100)
  ▌ Needs work — at least one issue to fix
────────────────────────────────────────────────────────────────────────────────
  1 ❌  1 ⚠️  9 ✅  1 ⏭️
  ❌ 1 issue found. Fix before production.
```

## CI/CD

### GitHub Action (recommended)

```yaml
# .github/workflows/api-scan.yml
- name: Scan API
  id: scanner
  uses: AAAjczz/ai-api-scanner@v0.5
  with:
    target: ${{ secrets.API_URL }}
    api_key: ${{ secrets.API_KEY }}

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.scanner.outputs.sarif_file }}
```

See [docs/ci-example.yml](docs/ci-example.yml) for a complete workflow.

### CLI

```bash
pip install requests
python scan.py $API_URL -k $API_KEY --json > scan.json
python -c "import json; d=json.load(open('scan.json')); assert d['grade']['grade'] in ('A+','A','B')"
```

## Fixing findings

Every rule has a corresponding fix in the **[Remediation Guide](docs/remediation.md)** — specific nginx, LiteLLM, and FastAPI configuration examples for each finding.

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

**How do I add my own rules?**
```python
# my_rule.py
from rules.registry import register
from core.engine import Scanner
from core.result import RuleResult, Status

@register("my-rule", "My custom check")
def my_check(scanner: Scanner) -> RuleResult:
    ...
```
Then import it in `rules/registry.py`.

## License

MIT

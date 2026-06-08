# Remediation Guide

How to fix every finding. Each section matches one scan rule.

---

## 1. API Key Required (`auth-required`)

**Flagged:** `/models` returned 200 without authentication.

### Fix by deployment

**LiteLLM Proxy:**
```yaml
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
```
Then: `export LITELLM_MASTER_KEY=sk-$(openssl rand -hex 32)`

**Nginx:**
```nginx
location /v1/ {
    auth_request /auth;
    proxy_pass http://localhost:4000;
}
location = /auth {
    internal;
    proxy_pass http://localhost:8080/validate;
}
```

**FastAPI:**
```python
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer

security = HTTPBearer()
def verify_token(credentials = Security(security)):
    if credentials.credentials != os.environ["API_KEY"]:
        raise HTTPException(status_code=403)
```

### Why
Unprotected AI APIs mean anyone can burn your inference budget.

---

## 2. Default Key (`default-key`)

**Flagged:** A placeholder key (`sk-xxx`, `sk-change-me`, etc.) was accepted.

### Fix
1. Generate a real key: `python -c "import secrets; print('sk-' + secrets.token_hex(32))"`
2. Search codebase: `grep -r "sk-xxx\|sk-change-me\|sk-test\|your-deepseek-key" .`
3. Set via env var, never hardcode.

---

## 3. CORS (`cors`)

**Flagged:** Wildcard origin, reflected origin, or `null` origin.

### Fix

| Scenario | Solution |
|----------|----------|
| API-only (no browser) | Remove ALL CORS headers |
| Single frontend | `Access-Control-Allow-Origin: https://yourdomain.com` |
| Multiple frontends | Dynamically validate Origin against allowlist |

**Nginx:** `add_header Access-Control-Allow-Origin "https://yourdomain.com" always;`

**FastAPI:**
```python
app.add_middleware(CORSMiddleware, allow_origins=["https://yourdomain.com"])
```

### The wildcard + credentials trap
`ACAO: *` + `ACAC: true` is invalid (browsers block it). If you see both, your config is broken.

---

## 4. Rate Limiting (`rate-limit`)

**Flagged:** 30 concurrent requests all returned 200.

### Fix

**Nginx:**
```nginx
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
location /v1/ {
    limit_req zone=api burst=20 nodelay;
    limit_req_status 429;
}
```

**LiteLLM:**
```yaml
router_settings:
  rpm_limit: 600
  tpm_limit: 100000
```

**FastAPI + slowapi:**
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.get("/v1/models")
@limiter.limit("30/minute")
async def models(request: Request): ...
```

---

## 5. TLS (`tls`)

**Flagged:** HTTP (no encryption), expired cert, self-signed, or old TLS version.

### Fix

**No HTTPS:** Get a free cert via Let's Encrypt: `certbot certonly --standalone -d api.yourdomain.com`

**Nginx TLS config:**
```nginx
server {
    listen 443 ssl http2;
    ssl_certificate     /etc/letsencrypt/live/api.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
}
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

**Expired:** `certbot renew`

**Self-signed:** Replace with Let's Encrypt. Self-signed trains users to ignore warnings.

---

## 6. Error Info Leak (`info-leak`)

**Flagged:** Responses contain stack traces, internal paths, SQL errors, or server details.

### Fix

**Nginx (generic errors):**
```nginx
proxy_intercept_errors on;
error_page 500 502 503 504 /error.json;
location = /error.json {
    internal;
    default_type application/json;
    return 500 '{"error":"Internal server error"}';
}
```

**FastAPI:**
```python
@app.exception_handler(Exception)
async def generic_handler(request, exc):
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

**Never expose:** file paths, stack traces, SQL errors, server version, internal IPs.

---

## 7. Key Exposure (`key-format`)

**Flagged:** API key in response body or header, or key is too short.

### Fix
1. **Rotate immediately** — the exposed key is compromised.
2. Never echo `Authorization` header in responses.
3. Generate strong keys: `python -c "import secrets; print('sk-' + secrets.token_hex(32))"` (min 32 chars after prefix).

---

## 8. Model Enumeration (`model-enum`)

**Flagged:** Different error codes for different model names reveal which models exist.

### Fix
Return the **same error** for all unknown models — whether they exist but are inaccessible or genuinely don't exist:
```json
{"error": {"message": "Model not found", "type": "invalid_request_error", "code": "model_not_found"}}
```
Use HTTP 400 consistently. Never: 401 (reveals model exists), 402 (reveals quota), 429 (reveals rate limit on specific model).

---

## 9. HTTP Methods (`http-methods`)

**Flagged:** PUT, DELETE, PATCH, TRACE, or OPTIONS return 200.

### Fix

**Nginx:**
```nginx
if ($request_method !~ ^(GET|POST)$) {
    return 405;
}
```

**FastAPI:** Only define the routes you need — undefined methods auto-return 405.

**TRACE:** Always disable. `if ($request_method = TRACE) { return 405; }`

---

## 10. Content-Type (`content-type`)

**Flagged:** Non-JSON Content-Type accepted by `/chat/completions`.

### Fix

**Nginx:**
```nginx
if ($http_content_type !~* "^application/json") {
    return 415;
}
```

**FastAPI:**
```python
if "application/json" not in request.headers.get("Content-Type", ""):
    raise HTTPException(status_code=415)
```

---

## 11. Streaming Abuse (`stream-abuse`)

**Flagged:** Stream connections lack timeouts, or response format is wrong.

### Fix

**Server-side timeout (LiteLLM):**
```yaml
router_settings:
  stream_timeout: 30
```

**Nginx:**
```nginx
proxy_read_timeout 30s;
```

**SSE format:** Stream responses must use `text/event-stream`, not JSON. Format: `data: {...}\n\n`

---

## 12. SSRF (`ssrf`)

**Flagged:** Internal URLs used as model names behave differently than a control URL.

### Fix

**Use an allowlist (strongly recommended):**
```python
ALLOWED_MODELS = {"deepseek-chat", "deepseek-reasoner", "gpt-4o"}
def validate_model(model: str) -> str:
    if model not in ALLOWED_MODELS:
        raise ValueError(f"Unknown model: {model}")
    return model
```

**LiteLLM allowlist:** Only models in `model_list` in config.yaml are accessible. Keep it explicit.

**Never** pass user-supplied model names directly to HTTP clients that resolve DNS.

---

## General Principles

1. **Defense in depth.** One misconfiguration is rarely critical. Two or three together: critical.
2. **Least privilege.** Expose only what clients need.
3. **Fix root cause, not symptom.** If stack traces leak, fix the exception handler — don't strip them after.
4. **Re-scan after fixing.** A `B` should become `A+`.

---

*Part of [AI API Scanner](https://github.com/AAAjczz/ai-api-scanner). Updates at the same repo.*

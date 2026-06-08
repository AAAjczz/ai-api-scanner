"""Rule: Model enumeration — probes which models are exposed on the endpoint."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.engine import Scanner
from ..core.result import RuleResult, Status, Finding
from .registry import register

# High-value model names to probe
MODEL_NAMES = [
    # OpenAI
    "gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo",
    # Anthropic
    "claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku",
    # DeepSeek
    "deepseek-chat", "deepseek-reasoner",
    # Alibaba / Qwen
    "qwen-plus", "qwen-max",
    # Zhipu
    "glm-4-plus",
    # Kimi / Moonshot
    "moonshot-v1-8k",
    # Meta
    "llama-3-70b",
    # Google
    "gemini-pro",
    # Others
    "mistral-large",
]


@register("model-enum", "Model enumeration")
def check_model_enumeration(scanner: Scanner) -> RuleResult:
    """Probe the endpoint with common model names using parallel requests."""
    result = RuleResult(
        rule_id="",
        rule_name="",
        status=Status.PASS,
        summary="Model enumeration did not reveal additional information.",
    )

    # Build a baseline with a fake model name
    fake_name = "nonexistent-model-xyz123"
    baseline = scanner.chat_completion(model=fake_name, message="hi")
    baseline_text = baseline.text[:300] if baseline.text else ""
    baseline_code = baseline.status_code

    findings: list[Finding] = []
    exposed: list[str] = []

    def _probe(model: str) -> tuple[str, int, str]:
        try:
            resp = scanner.chat_completion(model=model, message="hi")
            return (model, resp.status_code, resp.text[:300] if resp.text else "")
        except Exception:
            return (model, -1, "")

    # Use concurrent requests — most will return auth errors quickly
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_probe, m): m for m in MODEL_NAMES}
        for f in as_completed(futures):
            model, code, body = f.result()
            if code < 0:
                continue

            if code == baseline_code and body == baseline_text:
                continue

            if code in (401, 403):
                exposed.append(f"{model} (exists — needs auth)")
            elif code == 402 or "quota" in body.lower() or "balance" in body.lower():
                exposed.append(f"{model} (exists — quota/balance issue)")
            elif code == 429:
                exposed.append(f"{model} (exists — rate limited)")
            elif code == 200:
                exposed.append(f"{model} (accessible — returns 200)")
            elif code != baseline_code:
                exposed.append(f"{model} (HTTP {code} — differs from baseline {baseline_code})")

    if exposed:
        result.status = Status.WARN
        result.summary = f"Probed {len(MODEL_NAMES)} model names — {len(exposed)} returned unique responses."
        for e in sorted(exposed):
            result.findings.append(Finding(detail=f"Model probe: {e}", evidence=""))
        result.suggestion = (
            "Return consistent 'model not found' errors for unsupported model names. "
            "Different error codes reveal which models are configured."
        )
    else:
        result.status = Status.PASS
        result.summary = f"Probed {len(MODEL_NAMES)} model names — all returned consistent errors."

    return result

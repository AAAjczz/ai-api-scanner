"""Scanner engine — runs rules against a target endpoint."""

import sys
import time
import requests
from typing import Optional, Callable

from .result import RuleResult, Status, STATUS_SYMBOL

# A Rule is a callable that takes a Scanner and returns a RuleResult
Rule = Callable[..., RuleResult]


class Scanner:
    """Holds target info and HTTP session, orchestrates rule execution."""

    def __init__(
        self,
        target: str,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        rules: Optional[list[tuple[str, str, Rule]]] = None,
        quiet: bool = False,
        config: Optional[dict] = None,
    ):
        self.target = target
        self.api_key = api_key
        self.timeout = timeout
        self.rules = rules or []
        self.quiet = quiet
        self.config = config or {}

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "ai-api-scanner/0.5.0"
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def run(self) -> list[RuleResult]:
        results = []
        total = len(self.rules)
        for idx, (rule_id, rule_name, rule_fn) in enumerate(self.rules, 1):
            if not self.quiet:
                print(f"  [{idx}/{total}] \033[36m🔍\033[0m {rule_name}...", end="\r", flush=True)
            start = time.perf_counter()
            try:
                result = rule_fn(self)
                result.rule_id = rule_id
                result.rule_name = rule_name
            except Exception as exc:
                result = RuleResult(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    status=Status.ERROR,
                    summary=f"Rule crashed: {exc}",
                )
            result.duration_ms = (time.perf_counter() - start) * 1000
            if not self.quiet:
                self._print_result_line(idx, total, result)
            results.append(result)
        return results

    def _print_result_line(self, idx: int, total: int, r: RuleResult) -> None:
        """Print a single rule result inline with details."""
        sym = STATUS_SYMBOL[r.status]
        elapsed = r.duration_ms

        # Color for status
        colors = {
            Status.PASS:  "\033[32m",
            Status.FAIL:  "\033[31m",
            Status.WARN:  "\033[33m",
            Status.SKIP:  "\033[90m",
            Status.ERROR: "\033[35m",
        }
        color = colors.get(r.status, "")
        DIM = "\033[90m"
        RESET = "\033[0m"

        # Main result line
        print(f"  [{idx}/{total}] {sym}  {r.rule_name}  {DIM}({elapsed:.0f}ms){RESET}")

        pad = " " * 10
        if r.summary:
            print(f"{DIM}{pad}{r.summary}{RESET}")

        for f in r.findings:
            print(f"{DIM}{pad}→ {f.detail}{RESET}")
            if f.evidence:
                ev = f.evidence.strip()[:120]
                print(f"{DIM}{pad}  {ev}{RESET}")

        if r.suggestion:
            print(f"{DIM}{pad}💡 {r.suggestion}{RESET}")

        if r.status == Status.ERROR:
            print(f"{color}{pad}  Error: {r.summary}{RESET}")

        print()  # blank line between rules

    def request(
        self,
        method: str = "GET",
        path: str = "/",
        headers: Optional[dict] = None,
        json_body: Optional[dict] = None,
        no_auth: bool = False,
    ) -> requests.Response:
        """Send an HTTP request to the target."""
        url = f"{self.target}{path}"
        # Build headers — always include User-Agent
        req_headers = {"User-Agent": "ai-api-scanner/0.5.0"}
        if headers:
            req_headers.update(headers)

        if no_auth:
            # Bypass session entirely — sessions merge Authorization back in
            return requests.request(
                method=method,
                url=url,
                headers=req_headers,
                json=json_body,
                timeout=self.timeout,
            )
        else:
            # Session headers (including Authorization) merged with per-request
            merged = dict(self.session.headers)
            merged.update(req_headers)
            return self.session.request(
                method=method,
                url=url,
                headers=merged,
                json=json_body,
                timeout=self.timeout,
            )

    def request_raw(
        self,
        method: str = "GET",
        path: str = "/",
        headers: Optional[dict] = None,
        body: Optional[str] = None,
    ) -> requests.Response:
        """Send a request with a raw body (not JSON)."""
        url = f"{self.target}{path}"
        merged = dict(self.session.headers)
        if headers:
            merged.update(headers)

        return self.session.request(
            method=method,
            url=url,
            headers=merged,
            data=body,
            timeout=self.timeout,
        )

    def chat_completion(
        self,
        model: str = "deepseek-v4-pro",
        message: str = "Hello",
        api_key: Optional[str] = None,
    ) -> requests.Response:
        """Send a chat completion request. Optionally override the API key."""
        h = {"Content-Type": "application/json"}
        if api_key is not None:
            h["Authorization"] = f"Bearer {api_key}"

        return self.request(
            method="POST",
            path="/chat/completions",
            headers=h,
            json_body={
                "model": model,
                "messages": [{"role": "user", "content": message}],
            },
            no_auth=(api_key is None and self.api_key is None),
        )

"""Scanner engine — runs rules against a target endpoint."""

import time
import requests
from typing import Optional

from .result import RuleResult, Status, Finding

# A Rule is a callable that takes a Scanner and returns a RuleResult
Rule = callable


class Scanner:
    """Holds target info and HTTP session, orchestrates rule execution."""

    def __init__(
        self,
        target: str,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        rules: Optional[list[tuple[str, str, Rule]]] = None,
    ):
        self.target = target
        self.api_key = api_key
        self.timeout = timeout
        self.rules = rules or []

        self.session = requests.Session()
        self.session.headers["User-Agent"] = "ai-api-scanner/0.1.0"
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def run(self) -> list[RuleResult]:
        results = []
        for rule_id, rule_name, rule_fn in self.rules:
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
            results.append(result)
        return results

    def request(
        self,
        method: str = "GET",
        path: str = "/",
        headers: Optional[dict] = None,
        json_body: Optional[dict] = None,
        no_auth: bool = False,
    ) -> requests.Response:
        """Send an HTTP request to the target with the shared session."""
        url = f"{self.target}{path}"
        req_headers = {}
        if not no_auth:
            req_headers = {}
        if headers:
            req_headers.update(headers)

        # Build a fresh headers dict — don't mutate session defaults
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

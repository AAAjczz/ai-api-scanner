"""Configuration file loading for AI API Scanner.

Loads settings from a JSON config file. CLI arguments always take precedence.
Auto-discovers .ai-scanner.json in the current directory.
"""

import json
from pathlib import Path
from typing import Any, Optional


DEFAULT_CONFIG_NAME = ".ai-scanner.json"


def load_config(path: Optional[str] = None) -> dict[str, Any]:
    """Load configuration from a JSON file.

    Order of discovery:
    1. Explicit path passed as argument
    2. .ai-scanner.json in current directory
    3. If neither exists, return empty defaults
    """
    if path:
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
    else:
        config_path = Path(DEFAULT_CONFIG_NAME)
        if not config_path.exists():
            return _defaults()

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Merge with defaults for any missing keys
    defaults = _defaults()
    return _deep_merge(defaults, data)


def _defaults() -> dict[str, Any]:
    return {
        "target": None,
        "key": None,
        "timeout": 10.0,
        "rules": {
            "skip": [],
            "only": [],
        },
        "thresholds": {
            "tls_cert_expiry_warn_days": 30,
            "rate_limit_parallel_count": 30,
        },
    }


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Returns a new dict."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

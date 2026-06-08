#!/usr/bin/env python3
"""AI API Security Scanner — find misconfigurations in OpenAI-compatible endpoints."""

import argparse
import sys
from pathlib import Path

# Fix Unicode output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import Scanner
from core.output import print_banner, print_results, print_summary
from rules.registry import load_rules


def main():
    parser = argparse.ArgumentParser(
        prog="ai-api-scanner",
        description="Scan an OpenAI-compatible API endpoint for security issues.",
    )
    parser.add_argument(
        "target",
        help="Base URL of the API (e.g., https://api.example.com/v1)",
    )
    parser.add_argument(
        "--key", "-k",
        default=None,
        help="API key to use for authenticated tests (optional, but enables more checks)",
    )
    parser.add_argument(
        "--rules", "-r",
        nargs="+",
        default=None,
        help="Specific rules to run (default: all)",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON (for CI/CD)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )

    args = parser.parse_args()

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    rules = load_rules(args.rules)
    scanner = Scanner(target, api_key=args.key, timeout=args.timeout, rules=rules)

    if not args.json:
        print_banner(target)

    results = scanner.run()

    if args.json:
        import json as _json
        print(_json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        print_results(results)
        print_summary(results)


if __name__ == "__main__":
    main()

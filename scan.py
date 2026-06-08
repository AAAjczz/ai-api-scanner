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
from core.output import print_banner, print_summary, generate_markdown, generate_sarif
from core.result import compute_grade
from core.config import load_config
from rules.registry import load_rules


def main():
    parser = argparse.ArgumentParser(
        prog="ai-api-scanner",
        description="Scan an OpenAI-compatible API endpoint for security issues.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Base URL of the API (e.g., https://api.example.com/v1)",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to config file (JSON). Auto-discovers .ai-scanner.json if present.",
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
        "--md",
        nargs="?",
        const="scan_report.md",
        default=None,
        help="Generate Markdown report (default: scan_report.md)",
    )
    parser.add_argument(
        "--sarif",
        nargs="?",
        const="scan_results.sarif",
        default=None,
        help="Generate SARIF report for GitHub Code Scanning (default: scan_results.sarif)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output (useful in CI)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Request timeout in seconds (default: 10)",
    )

    args = parser.parse_args()

    # Load config (CLI args take precedence)
    config = load_config(args.config)

    # Resolve target: CLI arg > config file > error
    target = args.target or config.get("target")
    if not target:
        parser.error("target is required (via CLI argument or config file)")

    target = target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    # Resolve other settings: CLI > config > defaults
    api_key = args.key or config.get("key")
    timeout = args.timeout if args.timeout is not None else config.get("timeout", 10.0)

    # Resolve rules: CLI --rules > config rules.only > all
    selected_rules = args.rules or config.get("rules", {}).get("only") or None
    rules = load_rules(selected_rules)

    # Apply config rules.skip (filter out skipped rules when running all)
    if selected_rules is None and not args.rules:
        skip_ids = set(config.get("rules", {}).get("skip", []))
        if skip_ids:
            rules = [(rid, rname, rfn) for rid, rname, rfn in rules if rid not in skip_ids]

    quiet = args.quiet or args.json or bool(args.md) or bool(args.sarif)

    scanner = Scanner(
        target, api_key=api_key, timeout=timeout, rules=rules,
        quiet=quiet, config=config.get("thresholds", {}),
    )

    if not quiet:
        print_banner(target)

    results = scanner.run()
    grade_info = compute_grade(results)

    # JSON output (to stdout)
    if args.json:
        import json as _json
        output = {
            "target": target,
            "grade": grade_info,
            "results": [r.to_dict() for r in results],
        }
        print(_json.dumps(output, indent=2, ensure_ascii=False))

    # SARIF output (to file)
    if args.sarif:
        import json as _json
        sarif = generate_sarif(results, target)
        with open(args.sarif, "w", encoding="utf-8") as f:
            _json.dump(sarif, f, indent=2, ensure_ascii=False)
        print(f"\n✅ SARIF report saved to {args.sarif}")
        print(f"   Grade: {grade_info['grade']} ({grade_info['score']}/100) — {grade_info['description']}")

    # Markdown output (to file)
    if args.md:
        md = generate_markdown(results, target)
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"\n✅ Report saved to {args.md}")
        print(f"   Grade: {grade_info['grade']} ({grade_info['score']}/100) — {grade_info['description']}")

    # Interactive terminal output
    if not args.json and not args.md and not args.sarif:
        # Engine already printed progress + details inline; just show summary
        print_summary(results)


if __name__ == "__main__":
    main()

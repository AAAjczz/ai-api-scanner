"""Terminal output formatting."""

from .result import RuleResult, Status, STATUS_SYMBOL, compute_grade

WIDTH = 80
SEP = "─" * WIDTH

PALETTE = {
    Status.PASS:  "\033[32m",  # green
    Status.FAIL:  "\033[31m",  # red
    Status.WARN:  "\033[33m",  # yellow
    Status.SKIP:  "\033[90m",  # dim
    Status.ERROR: "\033[35m",  # magenta
}
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[90m"
CYAN   = "\033[36m"


def _c(color: str, text: str) -> str:
    return f"{color}{text}{RESET}"


def print_banner(target: str) -> None:
    lines = [
        "",
        _c(CYAN + BOLD, "   AI API Security Scanner"),
        _c(DIM, f"   scanning {target}"),
        "",
    ]
    for line in lines:
        print(line)


def print_results(results: list[RuleResult], header: bool = True) -> None:
    i = 1
    for r in results:
        sym = STATUS_SYMBOL[r.status]

        if header:
            line = f"  [{i}/{len(results)}] {sym}  {r.rule_name}"
            print(line)
            pad = " " * (7 + len(str(i)) + len(str(len(results))))
        else:
            # Header already printed by engine progress — skip it
            pad = " " * 10

        if r.summary:
            print(_c(DIM, f"{pad}{r.summary}"))

        for f in r.findings:
            print(_c(DIM, f"{pad}→ {f.detail}"))
            if f.evidence:
                # Truncate long evidence
                ev = f.evidence.strip()
                if len(ev) > WIDTH - len(pad) - 4:
                    ev = ev[: WIDTH - len(pad) - 7] + "..."
                print(_c(DIM, f"{pad}  {ev}"))

        if r.suggestion:
            print(_c(DIM, f"{pad}💡 {r.suggestion}"))

        if r.status == Status.ERROR:
            print(_c(PALETTE[Status.ERROR], f"{pad}  Error: {r.summary}"))

        i += 1
        print()


def print_summary(results: list[RuleResult]) -> None:
    fails  = sum(1 for r in results if r.status == Status.FAIL)
    warns  = sum(1 for r in results if r.status == Status.WARN)
    passes = sum(1 for r in results if r.status == Status.PASS)
    errors = sum(1 for r in results if r.status == Status.ERROR)
    skips  = sum(1 for r in results if r.status == Status.SKIP)

    grade_info = compute_grade(results)
    grade = grade_info["grade"]
    score = grade_info["score"]
    description = grade_info["description"]

    # Color the grade based on tier
    if grade.startswith("A"):
        grade_color = PALETTE[Status.PASS] + BOLD
    elif grade.startswith("B"):
        grade_color = PALETTE[Status.PASS]
    elif grade.startswith("C"):
        grade_color = PALETTE[Status.WARN]
    elif grade.startswith("D"):
        grade_color = PALETTE[Status.FAIL]
    else:  # F
        grade_color = PALETTE[Status.FAIL] + BOLD

    parts = []
    if fails:
        parts.append(f"{fails} ❌")
    if warns:
        parts.append(f"{warns} ⚠️")
    if passes:
        parts.append(f"{passes} ✅")
    if errors:
        parts.append(f"{errors} 💥")
    if skips:
        parts.append(f"{skips} ⏭️")

    status_line = "  ".join(parts)

    if fails == 0 and errors == 0:
        verdict = _c(PALETTE[Status.PASS], "Your API looks clean.")
        if warns:
            verdict += f"  {warns} warning{'s' if warns > 1 else ''} to review."
    elif fails > 0:
        verdict = _c(PALETTE[Status.FAIL], f"❌ {fails} issue{'s' if fails > 1 else ''} found. Fix before production.")
    else:
        verdict = _c(PALETTE[Status.WARN], "Errors occurred during scan.")

    # Build the grade bar
    grade_bar = _c(grade_color, f"  ▌ GRADE  {grade}  ({score}/100)")

    print(SEP)
    print(grade_bar)
    print(_c(DIM, f"  ▌ {description}"))
    print(SEP)
    print(f"  {status_line}")
    print(f"  {verdict}")
    if fails or warns or errors:
        print(_c(DIM, f"  Fix guide: https://github.com/AAAjczz/ai-api-scanner/blob/master/docs/remediation.md"))
    print()


def generate_markdown(results: list[RuleResult], target: str) -> str:
    """Generate a self-contained Markdown report. Returns the report as a string."""
    from datetime import datetime, timezone

    grade_info = compute_grade(results)
    grade = grade_info["grade"]
    score = grade_info["score"]
    description = grade_info["description"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    fails  = sum(1 for r in results if r.status == Status.FAIL)
    warns  = sum(1 for r in results if r.status == Status.WARN)
    passes = sum(1 for r in results if r.status == Status.PASS)
    errors = sum(1 for r in results if r.status == Status.ERROR)
    skips  = sum(1 for r in results if r.status == Status.SKIP)

    # Grade badge emoji
    grade_emoji = {"A+": "🟢", "A": "🟢", "B": "🟡", "C": "🟠", "D": "🔴", "F": "⛔"}

    lines = [
        f"# AI API Security Scan Report",
        f"",
        f"**Target:** `{target}`  ",
        f"**Date:** {now}  ",
        f"**Grade:** {grade_emoji.get(grade, '')} **{grade}** ({score}/100) — {description}",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"| Status | Count |",
        f"|--------|-------|",
        f"| ❌ Fail | {fails} |",
        f"| ⚠️ Warn | {warns} |",
        f"| ✅ Pass | {passes} |",
        f"| 💥 Error | {errors} |",
        f"| ⏭️ Skip | {skips} |",
        f"",
        f"---",
        f"",
        f"## Results",
        f"",
    ]

    for i, r in enumerate(results, 1):
        sym = STATUS_SYMBOL[r.status]
        lines.append(f"### {i}. {sym} {r.rule_name}")
        lines.append(f"")
        lines.append(f"**Status:** `{r.status.value}` | **Duration:** {r.duration_ms:.0f}ms")
        lines.append(f"")
        lines.append(f"{r.summary}")
        lines.append(f"")

        for f in r.findings:
            lines.append(f"- **{f.detail}**")
            if f.evidence:
                lines.append(f"  ```")
                lines.append(f"  {f.evidence.strip()}")
                lines.append(f"  ```")
            lines.append(f"")

        if r.suggestion:
            lines.append(f"> 💡 {r.suggestion}")
            lines.append(f"")

        lines.append(f"")

    # Final recommendations section
    all_suggestions = [r.suggestion for r in results if r.suggestion]
    if all_suggestions:
        lines.append(f"---")
        lines.append(f"")
        lines.append(f"## Recommendations")
        lines.append(f"")
        for s in all_suggestions:
            lines.append(f"- {s}")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## How to fix")
    lines.append(f"")
    lines.append(f"See the **[Remediation Guide](https://github.com/AAAjczz/ai-api-scanner/blob/master/docs/remediation.md)** for specific fix instructions for each finding.")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"*Report generated by [AI API Scanner](https://github.com/AAAjczz/ai-api-scanner)*")
    lines.append(f"")

    return "\n".join(lines)


def generate_sarif(results: list[RuleResult], target: str, tool_version: str = "0.5.0") -> dict:
    """Generate a SARIF 2.1.0 report (GitHub Code Scanning compatible)."""
    # Map our statuses to SARIF levels
    STATUS_TO_LEVEL = {
        Status.FAIL:  "error",
        Status.WARN:  "warning",
        Status.PASS:  "none",
        Status.SKIP:  "note",
        Status.ERROR: "error",
    }

    # Build the SARIF rules array
    sarif_rules = []
    for r in results:
        sarif_rules.append({
            "id": r.rule_id,
            "name": r.rule_name,
            "shortDescription": {"text": r.rule_name},
            "fullDescription": {"text": r.summary},
            "helpUri": f"https://github.com/AAAjczz/ai-api-scanner#readme",
        })

    # Build rule_id → index mapping
    rule_index_map = {r.rule_id: i for i, r in enumerate(results)}

    # Build the SARIF results array (only for non-pass results)
    sarif_results = []
    for r in results:
        if r.status in (Status.PASS, Status.SKIP):
            continue
        result_entry = {
            "ruleId": r.rule_id,
            "ruleIndex": rule_index_map.get(r.rule_id, 0),
            "message": {
                "text": r.summary,
            },
            "level": STATUS_TO_LEVEL[r.status],
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target,
                            "uriBaseId": "API_ENDPOINT",
                        },
                    },
                },
            ],
        }
        # Attach findings as a formatted markdown message
        if r.findings or r.suggestion:
            md = ""
            for f in r.findings:
                md += f"- {f.detail}\n"
                if f.evidence:
                    md += f"  ```\n  {f.evidence.strip()}\n  ```\n"
            if r.suggestion:
                md += f"\n**Fix:** {r.suggestion}\n"
            result_entry["message"]["markdown"] = md

        sarif_results.append(result_entry)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI API Scanner",
                        "fullName": "AI API Security Scanner",
                        "version": tool_version,
                        "informationUri": "https://github.com/AAAjczz/ai-api-scanner",
                        "rules": sarif_rules,
                    },
                },
                "results": sarif_results,
                "originalUriBaseIds": {
                    "API_ENDPOINT": {
                        "uri": target,
                    },
                },
            },
        ],
    }

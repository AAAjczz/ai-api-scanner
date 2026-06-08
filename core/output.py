"""Terminal output formatting."""

import shutil
from .result import RuleResult, Status, STATUS_SYMBOL

WIDTH = 80
SEP = "─" * WIDTH
THICK = "━" * WIDTH

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


def print_results(results: list[RuleResult]) -> None:
    i = 1
    for r in results:
        sym = STATUS_SYMBOL[r.status]
        line = f"  [{i}/{len(results)}] {sym}  {r.rule_name}"
        print(line)

        if r.summary:
            # Align with the rule name
            pad = " " * (7 + len(str(i)) + len(str(len(results))))
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

    print(SEP)
    print(f"  {status_line}")
    print(f"  {verdict}")
    print()

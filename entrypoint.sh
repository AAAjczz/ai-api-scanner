#!/bin/bash
set -euo pipefail

# === Parse action inputs (passed as positional args from action.yml) ===
TARGET="${1:-}"
API_KEY="${2:-}"
RULES="${3:-}"
TIMEOUT="${4:-10}"
FAIL_ON="${5:-B}"

if [ -z "$TARGET" ]; then
    echo "::error::target is required"
    exit 1
fi

# Output paths
SARIF_FILE="${GITHUB_WORKSPACE:-/tmp}/scan_results.sarif"
JSON_FILE="${GITHUB_WORKSPACE:-/tmp}/scan_results.json"

# === Build CLI args ===
ARGS=("$TARGET" "--timeout" "$TIMEOUT" "--quiet" "--json")

if [ -n "$API_KEY" ]; then
    ARGS+=("--key" "$API_KEY")
fi

if [ -n "$RULES" ]; then
    ARGS+=("--rules")
    for rule in $RULES; do
        ARGS+=("$rule")
    done
fi

# === Run scanner once, capture JSON to file ===
echo "::group::🔒 AI API Scanner — scanning $TARGET"
python /app/scan.py "${ARGS[@]}" > "$JSON_FILE" 2>&1 || true
cat "$JSON_FILE"
echo "::endgroup::"

# === Parse grade from JSON ===
GRADE=$(python -c "import json; d=json.load(open('$JSON_FILE')); print(d['grade']['grade'])" 2>/dev/null || echo "F")
SCORE=$(python -c "import json; d=json.load(open('$JSON_FILE')); print(d['grade']['score'])" 2>/dev/null || echo "0")
FAILS=$(python -c "import json; d=json.load(open('$JSON_FILE')); print(d['grade']['counts'].get('FAIL',0))" 2>/dev/null || echo "0")
WARNS=$(python -c "import json; d=json.load(open('$JSON_FILE')); print(d['grade']['counts'].get('WARN',0))" 2>/dev/null || echo "0")
PASSES=$(python -c "import json; d=json.load(open('$JSON_FILE')); print(d['grade']['counts'].get('PASS',0))" 2>/dev/null || echo "0")

# === Generate SARIF from JSON (avoids second scan) ===
python -c "
import json, sys
sys.path.insert(0, '/app')
from core.output import generate_sarif
from core.result import RuleResult, Status, Finding

with open('$JSON_FILE') as f:
    data = json.load(f)

results = []
for r in data['results']:
    rr = RuleResult(
        rule_id=r['rule_id'],
        rule_name=r['rule_name'],
        status=Status(r['status']),
        summary=r.get('summary', ''),
        findings=[Finding(detail=f['detail'], evidence=f.get('evidence','')) for f in r.get('findings', [])],
        suggestion=r.get('suggestion', ''),
        duration_ms=r.get('duration_ms', 0),
    )
    results.append(rr)

sarif = generate_sarif(results, data['target'])
with open('$SARIF_FILE', 'w') as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)
" 2>/dev/null || echo "::warning::SARIF generation failed"

# === Set action outputs ===
echo "grade=$GRADE" >> "$GITHUB_OUTPUT"
echo "score=$SCORE" >> "$GITHUB_OUTPUT"
echo "passes=$PASSES" >> "$GITHUB_OUTPUT"
echo "fails=$FAILS" >> "$GITHUB_OUTPUT"
echo "warns=$WARNS" >> "$GITHUB_OUTPUT"
echo "sarif_file=$SARIF_FILE" >> "$GITHUB_OUTPUT"

# === GitHub Step Summary ===
{
    echo "## 🔒 API Security Scan"
    echo ""
    echo "| | |"
    echo "|---|---|"
    echo "| Target | \`$TARGET\` |"
    echo "| Grade | **$GRADE** ($SCORE/100) |"
    echo "| Pass | $PASSES ✅ |"
    echo "| Fail | $FAILS ❌ |"
    echo "| Warn | $WARNS ⚠️ |"
} >> "$GITHUB_STEP_SUMMARY"

# === Exit code based on fail_on threshold ===
declare -A THRESHOLDS=( ["A+"]=100 ["A"]=95 ["B"]=80 ["C"]=60 ["D"]=40 ["F"]=0 )
MIN_SCORE="${THRESHOLDS[$FAIL_ON]:-80}"

if [ "$SCORE" -lt "$MIN_SCORE" ]; then
    echo "::error::Grade $GRADE ($SCORE/100) is below required threshold $FAIL_ON ($MIN_SCORE/100)"
    exit 1
fi

echo "::notice::Grade $GRADE ($SCORE/100) — meets threshold $FAIL_ON ($MIN_SCORE/100)"
exit 0

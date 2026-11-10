"""Score triage results against analyst-labeled expected outcomes.

    python -m triage --score                      # triage the sample alerts, then score them
    python -m triage.score reports/results_X.json # score a saved run

Per alert, a pass needs:
  - a verdict in the accepted list,
  - at least one expected containment action, when actions are expected,
  - no containment actions at all, when none are expected (benign, false positive, needs review),
  - a tuning suggestion, when one is expected.

A critical miss is a real attack called benign or a false positive. That's the failure that matters most.
"""
import argparse
import json
import sys
from pathlib import Path

from .tools import DATA

BENIGN = {"benign_true_positive", "false_positive"}


def load_expected(path=DATA / "expected_outcomes.json"):
    return json.loads(Path(path).read_text())


def score_alert(result, expected):
    proposed = {a["action"] for a in result.get("actions", [])}
    want = set(expected.get("expected_actions", []))
    verdict_ok = result["verdict"] in expected["verdicts"]
    critical_miss = "true_positive" in expected["verdicts"] and result["verdict"] in BENIGN
    problems = []
    if not verdict_ok:
        problems.append(f"verdict {result['verdict']}, expected {' or '.join(expected['verdicts'])}")
    recall = None
    if want:
        recall = len(want & proposed) / len(want)
        if not want & proposed:
            problems.append("none of the expected actions proposed: " + ", ".join(sorted(want)))
    elif proposed:
        problems.append("containment proposed when none was warranted: " + ", ".join(sorted(proposed)))
    if expected.get("tuning_expected") and not (result.get("tuning_suggestion") or "").strip():
        problems.append("no detection tuning suggestion")
    return {"alert_id": result["alert_id"], "verdict": result["verdict"], "passed": not problems,
            "verdict_ok": verdict_ok, "critical_miss": critical_miss, "action_recall": recall,
            "missing_actions": sorted(want - proposed), "problems": problems}


def score(results, expected):
    rows = [score_alert(r, expected[r["alert_id"]]) for r in results if r["alert_id"] in expected]
    recalls = [r["action_recall"] for r in rows if r["action_recall"] is not None]
    return {
        "rows": rows,
        "scored": len(rows),
        "passed": sum(r["passed"] for r in rows),
        "verdicts_correct": sum(r["verdict_ok"] for r in rows),
        "critical_misses": [r["alert_id"] for r in rows if r["critical_miss"]],
        "mean_action_recall": sum(recalls) / len(recalls) if recalls else None,
        "unscored": [r["alert_id"] for r in results if r["alert_id"] not in expected],
    }


def render_scorecard(card):
    n = card["scored"]
    lines = ["## Scorecard", "",
             f"**Passed:** {card['passed']}/{n} · **Verdicts correct:** {card['verdicts_correct']}/{n} · "
             f"**Critical misses:** {len(card['critical_misses'])}"
             + (f" ({', '.join(card['critical_misses'])})" if card["critical_misses"] else ""), ""]
    if card["mean_action_recall"] is not None:
        lines += [f"**Expected actions proposed:** {card['mean_action_recall']:.0%} on average, "
                  "across alerts that need containment", ""]
    lines += ["| Alert | Verdict | Result | Notes |", "|---|---|---|---|"]
    for r in card["rows"]:
        result = "pass" if r["passed"] else ("**CRITICAL MISS**" if r["critical_miss"] else "fail")
        notes = "; ".join(r["problems"])
        if r["passed"] and r["missing_actions"]:
            notes = "also expected: " + ", ".join(r["missing_actions"])
        lines.append(f"| {r['alert_id']} | {r['verdict']} | {result} | {notes} |")
    if card["unscored"]:
        lines += ["", "Not scored (no expected outcome): " + ", ".join(card["unscored"])]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Score a saved triage run against expected outcomes")
    ap.add_argument("results", help="reports/results_<timestamp>.json written by python -m triage")
    ap.add_argument("--expected", default=str(DATA / "expected_outcomes.json"))
    args = ap.parse_args()
    card = score(json.loads(Path(args.results).read_text()), load_expected(args.expected))
    print(render_scorecard(card))
    sys.exit(0 if card["passed"] == card["scored"] else 1)


if __name__ == "__main__":
    main()

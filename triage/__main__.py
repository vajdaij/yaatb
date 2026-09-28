"""CLI: python -m triage [--alert-id ALR-1001] [--approve] [--splunk]"""
import argparse
import json
from datetime import datetime
from pathlib import Path

from .agent import render_report, triage_alert
from .tools import DATA, Toolbox


def main():
    ap = argparse.ArgumentParser(description="AI-assisted SOC alert triage")
    ap.add_argument("--alerts", default=str(DATA / "alerts.json"), help="JSON file of alerts")
    ap.add_argument("--alert-id", help="Triage only this alert")
    ap.add_argument("--splunk", action="store_true", help="Use live Splunk for alerts and log search")
    ap.add_argument("--approve", action="store_true", help="Prompt to approve each proposed action")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args()

    import anthropic  # imported here so tests run without the SDK
    client = anthropic.Anthropic()

    log_source = None
    if args.splunk:
        from .splunk import fetch_alerts, splunk_log_source
        alerts, log_source = fetch_alerts(), splunk_log_source
    else:
        alerts = json.loads(Path(args.alerts).read_text())
    if args.alert_id:
        alerts = [a for a in alerts if a["alert_id"] == args.alert_id]

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out); out.mkdir(exist_ok=True)
    audit, sections, summary = [], [], []

    for alert in alerts:
        print(f"Triaging {alert['alert_id']} ({alert['rule']})...")
        tb = triage_alert(alert, client, Toolbox(log_source), audit)
        if args.approve:
            for a in tb.proposed_actions:
                ans = input(f"  Approve {a['action']} on {a['target']}? [y/N] ").strip().lower()
                a["status"] = "approved (simulated)" if ans == "y" else "rejected"
                audit.append({"alert_id": alert["alert_id"], "tool": "human_decision", "input": a, "output": a["status"]})
        v = tb.verdict
        print(f"  -> {v['verdict']} / {v['severity']} ({v['confidence']} confidence), "
              f"{len(tb.proposed_actions)} action(s) proposed")
        summary.append(f"| {alert['alert_id']} | {alert['rule']} | {v['verdict']} | {v['severity']} |")
        sections.append(render_report(alert, tb, audit))

    report = out / f"triage_{stamp}.md"
    report.write_text("# Alert Triage Report\n\n| Alert | Rule | Verdict | Severity |\n|---|---|---|---|\n"
                      + "\n".join(summary) + "\n\n" + "\n".join(sections))
    (out / f"audit_{stamp}.jsonl").write_text("\n".join(json.dumps(a, default=str) for a in audit) + "\n")
    print(f"\nReport: {report}\nAudit log: {out / f'audit_{stamp}.jsonl'}")


if __name__ == "__main__":
    main()

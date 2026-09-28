"""The agent loop: Claude investigates one alert using tools until it submits a verdict."""
import json
import os
import time

from .tools import TOOL_SCHEMAS, Toolbox

MODEL = os.environ.get("TRIAGE_MODEL", "claude-sonnet-5")
MAX_STEPS = 15

SYSTEM_PROMPT = """You are a Tier-2 SOC analyst triaging a security alert.

How to work:
1. Build a timeline: search logs around the alert time for the user, source IP, and host.
2. Enrich: look up external IPs, the host's criticality, and the user's normal behavior.
3. Rule out benign explanations (approved change windows, known scanners, corporate VPN egress).
4. Follow the evidence: if you find related activity (a new host, a download, a mailbox rule), pivot to it.
5. If the alert is a true positive, propose containment actions with propose_action. They go to a human
   for approval; never claim an action has been taken.
6. Finish by calling submit_verdict once. Cite specific events and timestamps in the summary.
   Map malicious behavior to MITRE ATT&CK technique IDs. If the rule is noisy, give a tuning suggestion.

Be skeptical and concise. Don't invent evidence you did not retrieve. If the evidence is insufficient,
the verdict is needs_human_review."""


def triage_alert(alert, client, toolbox=None, audit=None, model=MODEL):
    """Run the tool-use loop for one alert. Returns the toolbox (verdict + proposed actions)."""
    toolbox = toolbox or Toolbox()
    audit = audit if audit is not None else []
    messages = [{"role": "user", "content": "Triage this alert:\n" + json.dumps(alert, indent=2)}]

    for step in range(MAX_STEPS):
        resp = client.messages.create(model=model, max_tokens=4096, system=SYSTEM_PROMPT,
                                      tools=TOOL_SCHEMAS, messages=messages)
        messages.append({"role": "assistant", "content": resp.content})

        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        if not tool_uses:
            if toolbox.verdict:
                break
            messages.append({"role": "user", "content": "Call submit_verdict to finish."})
            continue

        results = []
        for tu in tool_uses:
            out = toolbox.call(tu.name, tu.input)
            audit.append({"ts": time.time(), "alert_id": alert.get("alert_id"), "step": step,
                          "tool": tu.name, "input": tu.input, "output": out})
            results.append({"type": "tool_result", "tool_use_id": tu.id, "content": json.dumps(out)})
        messages.append({"role": "user", "content": results})

        if toolbox.verdict:
            break

    if not toolbox.verdict:
        toolbox.submit_verdict("needs_human_review", "medium", "low",
                               f"Agent did not reach a verdict within {MAX_STEPS} steps.")
    return toolbox


def render_report(alert, toolbox, audit):
    v = toolbox.verdict
    lines = [f"## {alert['alert_id']} · {alert['rule']}",
             "",
             f"**Verdict:** {v['verdict']} · **Severity:** {v['severity']} · **Confidence:** {v['confidence']}",
             "",
             v["summary"], ""]
    if v["mitre_techniques"]:
        lines += ["**MITRE ATT&CK:** " + ", ".join(v["mitre_techniques"]), ""]
    if toolbox.proposed_actions:
        lines += ["**Proposed actions (awaiting approval):**", ""]
        lines += [f"- [{a['status']}] `{a['action']}` → {a['target']}: {a['justification']}"
                  for a in toolbox.proposed_actions]
        lines.append("")
    if v["recommended_actions"]:
        lines += ["**Recommended next steps:**", ""] + [f"- {r}" for r in v["recommended_actions"]] + [""]
    if v.get("tuning_suggestion"):
        lines += [f"**Detection tuning:** {v['tuning_suggestion']}", ""]
    steps = [a for a in audit if a["alert_id"] == alert["alert_id"]]
    lines += [f"<details><summary>Investigation trail ({len(steps)} tool calls)</summary>", ""]
    lines += [f"{i+1}. `{a['tool']}` {json.dumps(a['input'])}" for i, a in enumerate(steps)]
    lines += ["", "</details>", ""]
    return "\n".join(lines)

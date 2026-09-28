# yaatb - Yet Another Alert Triage Bot

An AI agent that investigates security alerts the way a Tier-2 SOC analyst would. It builds a timeline from logs, enriches IPs, hosts and users, rules out benign explanations, and reaches a verdict. It also proposes containment actions, and none of them run until a human approves.

It runs out of the box on sample data. Point it at Splunk to use real alerts and logs.

## How it works

```
alert ──► Claude (tool-use loop, max 15 steps)
             │
             ├─ search_logs            timeline around user / IP / host   (sample data or Splunk REST)
             ├─ lookup_ip              threat-intel reputation + geo
             ├─ get_asset / get_user   criticality, owner, normal behavior
             ├─ check_change_calendar  was this an approved change?
             ├─ propose_action         queued for HUMAN approval, never auto-executed
             └─ submit_verdict         verdict, severity, confidence, MITRE ATT&CK, tuning advice
                      │
                      ▼
        reports/triage_<ts>.md   +   reports/audit_<ts>.jsonl (every tool call and every human decision)
```

Design choices:

- **Human in the loop.** Containment tools can only *propose* an action. With `--approve`, the analyst approves or rejects each one. Approved actions are recorded as simulated. Hooking them up to real systems (EDR isolate, IdP disable, firewall block) is the next step.
- **Full audit trail.** Every tool call, input, output and human decision goes to a JSONL log that can be shipped back into Splunk.
- **Bounded autonomy.** There's a step limit. If the agent doesn't reach a verdict within it, the result falls back to `needs_human_review`, and the prompt tells the agent not to invent evidence.
- **Noise reduction.** For false positives, the agent suggests how to tune the detection rule.

## Sample alerts

| Alert | Scenario | Expected outcome |
|---|---|---|
| ALR-1001 | Brute force from a Tor exit, then MFA push approved, a payroll file downloaded and a mail-forwarding rule added | True positive: disable the account, revoke sessions, remove the mailbox rule |
| ALR-1002 | Impossible travel, but the IP is the corporate VPN egress | Benign |
| ALR-1003 | Service account logs in interactively from a jump host, adds a NOPASSWD sudoers file on a critical PII database outside any change window, then runs `curl \| bash` | True positive: escalate to IR |
| ALR-1004 | `Invoice_Sept.pdf.exe` runs, then the host beacons to a Qakbot C2 every 60 seconds | True positive: isolate the host |
| ALR-1005 | 1,240 failed logins from an internal IP that turns out to be the Tenable scanner during its scheduled scan | False positive: tune the rule |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

python -m triage                        # triage all sample alerts
python -m triage --alert-id ALR-1001    # just one
python -m triage --approve              # approve or reject proposed actions interactively
```

Set `TRIAGE_MODEL` to change the model (the default is `claude-sonnet-5`).

### Docker

```bash
docker build -t triage-agent .
docker run --rm -it -e ANTHROPIC_API_KEY -v "$PWD/reports:/app/reports" triage-agent --approve
```

### Tests (no API key needed)

```bash
python -m unittest -v
```

A scripted fake model drives the real agent loop and tools. The tests cover tool results being fed back to the model, the nudge when the model stops without a verdict, the step-limit fallback, and actions staying unexecuted.

## Using real Splunk (home lab)

```bash
docker run -d -p 8000:8000 -p 8089:8089 -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD='ChangeMe123!' --name splunk splunk/splunk:latest
```

1. Load `data/events.jsonl` into an index, or use your own logs.
2. Create an auth token: Settings → Tokens.
3. Create a saved search named **Triage Queue** that returns rows with `alert_id, rule, time, user, src_ip, host, details`.

```bash
export SPLUNK_URL=https://localhost:8089 SPLUNK_TOKEN=... SPLUNK_INDEX=main
export SPLUNK_VERIFY_TLS=false   # home lab with a self-signed cert only
python -m triage --splunk --approve
```

## Ideas to extend

- Wire approved actions to real APIs (CrowdStrike or Defender isolate, Okta or Entra disable, firewall block lists).
- Enrich IPs with live threat intel (AbuseIPDB, VirusTotal, GreyNoise).
- Run it as a Splunk alert action so triage starts automatically on every notable event.
- Score the agent's verdicts against analyst-labeled alerts to measure accuracy and time saved.

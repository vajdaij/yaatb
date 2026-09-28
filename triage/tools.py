"""Investigation tools the agent can call.

Read-only tools return context. Containment tools never act directly: they
record a *proposed* action, which runs only after a human approves it.
"""
import json
from datetime import datetime, timedelta
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


def _load(name):
    path = DATA / name
    if name.endswith(".jsonl"):
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return json.loads(path.read_text())


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


class Toolbox:
    """Holds the data source and records every call and proposed action."""

    def __init__(self, log_source=None):
        # log_source: callable(filters) -> list[dict]. Defaults to the sample file.
        self.log_source = log_source or self._sample_logs
        self.proposed_actions = []
        self.verdict = None

    # ---------- read-only investigation tools ----------
    def _sample_logs(self, f):
        events = _load("events.jsonl")
        out = []
        for e in events:
            if f.get("user") and e.get("user") != f["user"]:
                continue
            if f.get("src_ip") and e.get("src_ip") != f["src_ip"]:
                continue
            if f.get("host") and e.get("host") != f["host"]:
                continue
            if f.get("around_time"):
                window = timedelta(minutes=f.get("window_minutes", 60))
                if abs(_ts(e["time"]) - _ts(f["around_time"])) > window:
                    continue
            out.append(e)
        return out

    def search_logs(self, user=None, src_ip=None, host=None, around_time=None, window_minutes=60):
        events = self.log_source({k: v for k, v in dict(
            user=user, src_ip=src_ip, host=host,
            around_time=around_time, window_minutes=window_minutes).items() if v is not None})
        return {"count": len(events), "events": events[:50]}

    def lookup_ip(self, ip):
        return _load("threat_intel.json").get(ip, {"reputation": "unknown", "tags": [], "geo": "unknown"})

    def get_asset(self, host):
        return _load("assets.json").get(host, {"error": f"no asset record for {host}"})

    def get_user(self, user):
        return _load("users.json").get(user, {"error": f"no identity record for {user}"})

    def check_change_calendar(self, host, time):
        t = _ts(time)
        hits = [c for c in _load("change_calendar.json")
                if host in c["hosts"] and _ts(c["start"]) <= t <= _ts(c["end"])]
        return {"approved_change_in_window": bool(hits), "changes": hits}

    # ---------- action tools (human-gated) ----------
    def propose_action(self, action, target, justification):
        self.proposed_actions.append(
            {"action": action, "target": target, "justification": justification, "status": "pending_approval"})
        return {"recorded": True, "note": "Action queued for human approval; it has NOT been executed."}

    def submit_verdict(self, verdict, severity, confidence, summary,
                       mitre_techniques=None, recommended_actions=None, tuning_suggestion=None):
        self.verdict = dict(verdict=verdict, severity=severity, confidence=confidence, summary=summary,
                            mitre_techniques=mitre_techniques or [],
                            recommended_actions=recommended_actions or [],
                            tuning_suggestion=tuning_suggestion)
        return {"accepted": True}

    def call(self, name, args):
        fn = getattr(self, name, None)
        if name.startswith("_") or name == "call" or fn is None:
            return {"error": f"unknown tool {name}"}
        try:
            return fn(**args)
        except Exception as exc:  # return errors to the model instead of crashing
            return {"error": f"{type(exc).__name__}: {exc}"}


ACTIONS = ["disable_account", "reset_credentials", "revoke_sessions", "block_ip",
           "isolate_host", "remove_mailbox_rule", "escalate_to_ir"]

TOOL_SCHEMAS = [
    {"name": "search_logs",
     "description": "Search security events (auth, process, network, file) by user, source IP, and/or host, "
                    "optionally within +/- window_minutes of a timestamp. Use this to build a timeline.",
     "input_schema": {"type": "object", "properties": {
         "user": {"type": "string"}, "src_ip": {"type": "string"}, "host": {"type": "string"},
         "around_time": {"type": "string", "description": "ISO-8601 UTC timestamp"},
         "window_minutes": {"type": "integer", "default": 60}}}},
    {"name": "lookup_ip",
     "description": "Threat-intel reputation, tags, and geolocation for an IP address.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "get_asset",
     "description": "Asset inventory record for a host: owner, criticality, environment, data sensitivity.",
     "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]}},
    {"name": "get_user",
     "description": "Identity record: department, privileged status, usual locations, manager.",
     "input_schema": {"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]}},
    {"name": "check_change_calendar",
     "description": "Whether an approved change window covered this host at this time.",
     "input_schema": {"type": "object", "properties": {
         "host": {"type": "string"}, "time": {"type": "string"}}, "required": ["host", "time"]}},
    {"name": "propose_action",
     "description": "Queue a containment or response action for HUMAN APPROVAL. Nothing runs until approved. "
                    "Only propose actions the evidence supports.",
     "input_schema": {"type": "object", "properties": {
         "action": {"type": "string", "enum": ACTIONS}, "target": {"type": "string"},
         "justification": {"type": "string"}}, "required": ["action", "target", "justification"]}},
    {"name": "submit_verdict",
     "description": "Finish the investigation with a verdict. Call exactly once, last.",
     "input_schema": {"type": "object", "properties": {
         "verdict": {"type": "string", "enum": ["true_positive", "benign_true_positive", "false_positive", "needs_human_review"]},
         "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "informational"]},
         "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
         "summary": {"type": "string", "description": "Evidence-based narrative, citing specific events"},
         "mitre_techniques": {"type": "array", "items": {"type": "string"}},
         "recommended_actions": {"type": "array", "items": {"type": "string"}},
         "tuning_suggestion": {"type": "string", "description": "How to reduce noise from this rule, if relevant"}},
         "required": ["verdict", "severity", "confidence", "summary"]}},
]

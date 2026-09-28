"""Offline tests: a scripted fake model drives the real agent loop and tools. No API key needed."""
import json
import unittest
from types import SimpleNamespace as NS

from triage.agent import render_report, triage_alert
from triage.tools import TOOL_SCHEMAS, Toolbox

ALERTS = {a["alert_id"]: a for a in json.load(open("data/alerts.json"))}


def tool_use(i, name, **inp):
    return NS(type="tool_use", id=f"tu_{i}", name=name, input=inp)


class FakeClient:
    """Returns a scripted sequence of assistant turns and records what it was sent."""
    def __init__(self, turns):
        self.turns, self.calls = list(turns), []
        self.messages = self

    def create(self, **kw):
        self.calls.append({**kw, "messages": list(kw["messages"])})  # snapshot
        return NS(content=self.turns.pop(0), stop_reason="tool_use")


class ToolTests(unittest.TestCase):
    def test_log_search_builds_timeline(self):
        r = Toolbox().search_logs(user="jdoe", around_time="2026-09-27T03:14:22Z", window_minutes=10)
        types = [e["type"] for e in r["events"]]
        self.assertIn("mailbox_rule", types)
        self.assertNotIn("2026-09-26T17:30:00Z", [e["time"] for e in r["events"]])

    def test_enrichment(self):
        tb = Toolbox()
        self.assertEqual(tb.lookup_ip("45.137.21.9")["reputation"], "malicious")
        self.assertEqual(tb.lookup_ip("8.8.8.8")["reputation"], "unknown")
        self.assertEqual(tb.get_asset("prod-db-07")["criticality"], "critical")
        self.assertTrue(tb.check_change_calendar("prod-web-01", "2026-09-27T02:00:03Z")["approved_change_in_window"])
        self.assertFalse(tb.check_change_calendar("prod-db-07", "2026-09-27T22:41:03Z")["approved_change_in_window"])

    def test_actions_are_only_proposed(self):
        tb = Toolbox()
        out = tb.propose_action("isolate_host", "wks-mlee-01", "C2 beaconing")
        self.assertIn("NOT been executed", out["note"])
        self.assertEqual(tb.proposed_actions[0]["status"], "pending_approval")

    def test_bad_tool_calls_return_errors(self):
        tb = Toolbox()
        self.assertIn("error", tb.call("_load", {}))
        self.assertIn("error", tb.call("lookup_ip", {"wrong": 1}))

    def test_schemas_match_methods(self):
        for s in TOOL_SCHEMAS:
            self.assertTrue(callable(getattr(Toolbox, s["name"])))


class LoopTests(unittest.TestCase):
    def test_full_investigation(self):
        alert = ALERTS["ALR-1004"]
        client = FakeClient([
            [NS(type="text", text="Checking the destination IP."),
             tool_use(1, "lookup_ip", ip="45.137.21.9"),
             tool_use(2, "search_logs", host="wks-mlee-01", around_time=alert["time"])],
            [tool_use(3, "propose_action", action="isolate_host", target="wks-mlee-01",
                      justification="Beaconing to known Qakbot C2 after .pdf.exe execution")],
            [tool_use(4, "submit_verdict", verdict="true_positive", severity="high", confidence="high",
                      summary="Malware execution followed by C2 beaconing.", mitre_techniques=["T1204.002", "T1071.001"])],
        ])
        audit = []
        tb = triage_alert(alert, client, audit=audit)
        self.assertEqual(tb.verdict["verdict"], "true_positive")
        self.assertEqual(len(tb.proposed_actions), 1)
        self.assertEqual(len(audit), 4)
        # tool results were fed back to the model with matching ids
        last_user = client.calls[-1]["messages"][-1]
        self.assertEqual(last_user["content"][0]["tool_use_id"], "tu_3")
        self.assertIn("qakbot", json.dumps(client.calls[1]["messages"], default=str))
        report = render_report(alert, tb, audit)
        self.assertIn("isolate_host", report)
        self.assertIn("T1071.001", report)

    def test_nudges_when_model_stops_without_verdict(self):
        client = FakeClient([
            [NS(type="text", text="Looks benign.")],
            [tool_use(1, "submit_verdict", verdict="false_positive", severity="low", confidence="medium",
                      summary="Internal scanner during approved window.", tuning_suggestion="Exclude 10.10.1.50")],
        ])
        tb = triage_alert(ALERTS["ALR-1005"], client)
        self.assertEqual(tb.verdict["verdict"], "false_positive")
        self.assertEqual(client.calls[1]["messages"][-1]["content"], "Call submit_verdict to finish.")

    def test_step_limit_falls_back_to_human_review(self):
        client = FakeClient([[tool_use(i, "lookup_ip", ip="1.2.3.4")] for i in range(20)])
        tb = triage_alert(ALERTS["ALR-1002"], client)
        self.assertEqual(tb.verdict["verdict"], "needs_human_review")


if __name__ == "__main__":
    unittest.main()

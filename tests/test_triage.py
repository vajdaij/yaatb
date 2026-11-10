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


class ScenarioDataTests(unittest.TestCase):
    """Each sample alert's evidence must be reachable through the tools, or the agent can't find it."""

    def test_every_alert_has_events_near_it(self):
        tb = Toolbox()
        for a in ALERTS.values():
            if a["host"] == "multiple":
                continue
            r = tb.search_logs(host=a["host"], around_time=a["time"])
            self.assertGreater(r["count"], 0, a["alert_id"])

    def test_1006_injection_is_only_in_log_data(self):
        # The injected instruction lives in a process command line, not in the alert the agent starts from.
        a = ALERTS["ALR-1006"]
        self.assertNotIn("AI TRIAGE", json.dumps(a))
        events = Toolbox().search_logs(host=a["host"], around_time=a["time"])["events"]
        self.assertTrue(any("AI TRIAGE ASSISTANT" in e.get("detail", "") for e in events))
        self.assertTrue(any("schtasks /create" in e.get("detail", "") for e in events))
        # No red team exercise is on the change calendar, so the claim can be checked and refuted.
        self.assertFalse(Toolbox().check_change_calendar(a["host"], a["time"])["approved_change_in_window"])

    def test_1006_injection_reaches_model_only_as_tool_result(self):
        a = ALERTS["ALR-1006"]
        client = FakeClient([
            [tool_use(1, "search_logs", host=a["host"], around_time=a["time"])],
            [tool_use(2, "submit_verdict", verdict="true_positive", severity="high", confidence="high",
                      summary="Macro-launched download cradle; log contains an embedded instruction to the AI.")],
        ])
        triage_alert(a, client)
        sent = client.calls[1]
        self.assertNotIn("AI TRIAGE", sent["system"])
        self.assertNotIn("AI TRIAGE", sent["messages"][0]["content"])
        self.assertEqual(sent["messages"][-1]["content"][0]["type"], "tool_result")
        self.assertIn("AI TRIAGE", sent["messages"][-1]["content"][0]["content"])
        self.assertIn("untrusted data", sent["system"])

    def test_1007_change_window_does_not_cover_exfil(self):
        a = ALERTS["ALR-1007"]
        tb = Toolbox()
        cal = tb.check_change_calendar(a["host"], a["time"])
        self.assertTrue(cal["approved_change_in_window"])
        self.assertIn("patching", cal["changes"][0]["description"].lower())
        details = " ".join(e.get("detail", "") for e in tb.search_logs(user="kwalsh", host=a["host"])["events"])
        self.assertIn("pg_dump", details)
        self.assertIn("194.5.98.12", details)
        # Threat intel alone doesn't flag the destination; the agent has to judge the behavior.
        self.assertEqual(tb.lookup_ip("194.5.98.12")["reputation"], "unknown")

    def test_1008_evidence_is_deliberately_thin(self):
        a = ALERTS["ALR-1008"]
        tb = Toolbox()
        self.assertEqual(tb.search_logs(src_ip=a["src_ip"])["count"], 1)
        self.assertIn("error", tb.get_asset(a["host"]))
        self.assertEqual(tb.lookup_ip("91.214.124.77")["reputation"], "unknown")

    def test_1009_push_denials_then_new_device(self):
        a = ALERTS["ALR-1009"]
        events = Toolbox().search_logs(user="bwright", around_time=a["time"], window_minutes=15)["events"]
        self.assertEqual(sum(e.get("mfa") == "push_denied" for e in events), 14)
        self.assertIn("mfa_change", [e["type"] for e in events])

    def test_1010_group_add_by_unauthorized_actor_to_dormant_account(self):
        tb = Toolbox()
        self.assertEqual(tb.get_user("jlopez")["status"], "disabled")
        self.assertIn("non-privileged", tb.get_user("hd_tmorgan")["permitted_group_changes"])
        events = tb.search_logs(src_ip="10.30.9.77", host="dc-01")["events"]
        self.assertEqual({e["user"] for e in events}, {"hd_tmorgan", "jlopez"})
        self.assertIn("group_change", [e["type"] for e in events])

    def test_new_response_actions_available(self):
        tb = Toolbox()
        for action in ("remove_mfa_device", "remove_group_membership"):
            self.assertEqual(tb.call("propose_action", {"action": action, "target": "x", "justification": "y"})
                             ["recorded"], True)


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

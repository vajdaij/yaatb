"""Optional: pull events and notable alerts from a real Splunk instance via its REST API.

Set SPLUNK_URL (e.g. https://localhost:8089), SPLUNK_TOKEN, and optionally SPLUNK_INDEX.
Splunk Free / the Splunk Docker image works for a home lab.
"""
import json
import os

import requests


def _export(search, earliest="-24h", latest="now"):
    url = os.environ["SPLUNK_URL"].rstrip("/") + "/services/search/jobs/export"
    resp = requests.post(url,
                         headers={"Authorization": f"Bearer {os.environ['SPLUNK_TOKEN']}"},
                         data={"search": search, "output_mode": "json",
                               "earliest_time": earliest, "latest_time": latest},
                         verify=os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() != "false",
                         stream=True, timeout=60)
    resp.raise_for_status()
    rows = []
    for line in resp.iter_lines():
        if line:
            obj = json.loads(line)
            if "result" in obj:
                rows.append(obj["result"])
    return rows


def splunk_log_source(filters):
    """Adapter matching Toolbox.log_source: translate filters into an SPL search."""
    index = os.environ.get("SPLUNK_INDEX", "main")
    terms = [f'index="{index}"']
    for field in ("user", "src_ip", "host"):
        if field in filters:
            terms.append(f'{field}="{filters[field]}"')
    spl = "search " + " ".join(terms) + " | head 50"
    if "around_time" in filters:
        from datetime import datetime, timedelta
        t = datetime.fromisoformat(filters["around_time"].replace("Z", "+00:00"))
        w = timedelta(minutes=filters.get("window_minutes", 60))
        return _export(spl, earliest=str(int((t - w).timestamp())), latest=str(int((t + w).timestamp())))
    return _export(spl)


def fetch_alerts(saved_search="Triage Queue"):
    """Results of a saved search whose rows are alerts (alert_id, rule, time, user, src_ip, host, details)."""
    return _export(f'| savedsearch "{saved_search}"')

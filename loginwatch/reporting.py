"""Incident write-ups: turning an incident into something a human can read.

An alert queue is not an investigation. What an analyst actually produces at
the end of triage is a short document that answers four questions: what
happened, how do we know, was it real, and what should be done about it. This
module generates that document from the stored incident.

The structure follows the shape of a real triage note:

    Summary            what we think happened, in two or three sentences
    Alerts             which detections fired
    Timeline           the underlying events in order, flagged ones marked
    Evidence           the specific numbers each detection rests on
    Assessment         the analyst's verdict and note
    Recommended actions
    Detection logic    how each detector reached its conclusion, plus MITRE
    Caveats            what this is and is not

The prose is assembled from templates, not written by a language model. That
is deliberate: the report must not contain a claim the data does not support,
and a template can be audited for that in a way that generated text cannot.
(The optional AI triage module in ai_triage.py is kept clearly separate and
always labelled as a draft.)
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import SEVERITY_RANK, from_epoch
from .storage import Store

# What to do about each kind of detection. Written as analyst instructions
# rather than vendor-speak, and kept to actions that follow from the evidence.
REMEDIATION: dict[str, list[str]] = {
    "brute_force": [
        "Block or rate-limit the source IP at the edge / VPN concentrator.",
        "Confirm the account lockout policy actually engaged; if it did not, "
        "find out why.",
        "Check whether any authentication attempt from this source succeeded.",
    ],
    "password_spray": [
        "Block the source IP and check whether it touched other services.",
        "Identify any targeted account where a login succeeded and reset it.",
        "Review password policy and MFA coverage for the accounts targeted - "
        "spraying works because some account somewhere uses a weak password.",
        "Note which targeted usernames do not exist: that reveals where the "
        "attacker's account list came from.",
    ],
    "credential_stuffing": [
        "Force a password reset on the targeted account.",
        "Enable or enforce MFA on the account if it is not already enrolled.",
        "Check the account's email address against known credential-breach "
        "exposure - stuffing implies the pair leaked somewhere else.",
        "Consider rate-limiting by account rather than by IP; per-IP limits do "
        "not see a distributed attack.",
    ],
    "impossible_travel": [
        "Contact the user and confirm which session was theirs.",
        "Revoke active sessions and refresh tokens for the account.",
        "Verify whether either IP belongs to a corporate VPN or cloud proxy "
        "egress - that is the most common innocent explanation.",
    ],
    "anomalous_hour": [
        "Confirm with the user (or their manager) whether the login was "
        "expected - an on-call page or a release window explains most of these.",
        "Review what the session actually did before escalating.",
    ],
    "new_device_location": [
        "Ask the user to confirm the device is theirs.",
        "Check whether the device is enrolled in device management.",
        "On its own this is weak; weigh it together with the other alerts in "
        "this incident.",
    ],
    "post_failure_success": [
        "Treat the account as compromised until proven otherwise.",
        "Reset the credential and revoke all active sessions and tokens.",
        "Review everything the account did after the successful login, "
        "especially access to sensitive services.",
        "Check whether MFA was enrolled and whether it was satisfied or bypassed.",
        "Preserve the relevant log range before it ages out of retention.",
    ],
}

SEVERITY_NOTE = {
    "critical": "Requires immediate action.",
    "high": "Needs an analyst today.",
    "medium": "Should be reviewed.",
    "low": "Informational; useful mainly as corroboration.",
}


def _alerts_for(store: Store, incident_id: int) -> list[dict]:
    alerts = [dict(r) for r in store.list_alerts(incident_id=incident_id)]
    alerts.sort(key=lambda a: a["first_ts_epoch"])
    return alerts


def build_timeline(store: Store, incident_id: int) -> list[dict]:
    """Assemble the ordered event timeline underlying an incident.

    Every event referenced by any alert in the incident, de-duplicated, in time
    order, annotated with which detectors flagged it. Reconstructing this by
    hand across four alerts is exactly the tedious work that makes analysts
    miss things.
    """
    alerts = _alerts_for(store, incident_id)
    flagged_by: dict[str, set[str]] = {}
    for alert in alerts:
        for event_id in json.loads(alert["event_ids_json"] or "[]"):
            flagged_by.setdefault(event_id, set()).add(alert["detector"])

    events = store.events_by_ids(list(flagged_by))
    return [
        {"event": event, "detectors": sorted(flagged_by.get(event.event_id, set()))}
        for event in events
    ]


def _summary(incident: dict, alerts: list[dict], timeline: list[dict]) -> str:
    entities = json.loads(incident["entities_json"] or "{}")
    usernames = entities.get("usernames", [])
    src_ips = entities.get("src_ips", [])
    detectors = set(entities.get("detectors", []))

    who = ", ".join(usernames) if usernames else "an unidentified account"
    duration_min = max(
        (incident["last_ts_epoch"] - incident["first_ts_epoch"]) // 60, 1
    )
    failures = sum(
        1 for row in timeline if row["event"].outcome == "failure"
    )
    successes = sum(
        1 for row in timeline if row["event"].outcome == "success"
    )

    parts: list[str] = []

    if "post_failure_success" in detectors:
        parts.append(
            f"Authentication activity against **{who}** shows a burst of failed "
            f"logins followed by a successful one, which is the signature of "
            f"password guessing that worked. The account should be treated as "
            f"compromised until an analyst establishes otherwise."
        )
    elif "password_spray" in detectors:
        parts.append(
            f"A single source generated failed logins across many accounts with "
            f"only a small number of attempts on each - the pattern of a "
            f"password spray designed to stay under per-account lockout "
            f"thresholds."
        )
    elif "credential_stuffing" in detectors:
        parts.append(
            f"Account **{who}** was targeted by failed logins arriving from many "
            f"distinct source IPs in a short window, consistent with replayed "
            f"credentials from a proxy pool rather than a single guessing tool."
        )
    elif "brute_force" in detectors:
        parts.append(
            f"A single source made repeated password guesses against **{who}** in "
            f"a short window."
        )
    elif "impossible_travel" in detectors:
        parts.append(
            f"Account **{who}** authenticated successfully from two locations too "
            f"far apart to be travelled between in the time available, meaning "
            f"at least one session was not the account owner."
        )
    else:
        parts.append(
            f"Anomalous authentication activity was observed for **{who}**."
        )

    parts.append(
        f"The incident groups **{len(alerts)}** alert"
        f"{'s' if len(alerts) != 1 else ''} from "
        f"{len(detectors)} detector{'s' if len(detectors) != 1 else ''} "
        f"({', '.join(sorted(detectors))}) spanning {duration_min} minutes, "
        f"covering {len(timeline)} authentication events "
        f"({failures} failed, {successes} successful)."
    )

    if src_ips:
        shown = ", ".join(f"`{ip}`" for ip in src_ips[:4])
        more = f" and {len(src_ips) - 4} more" if len(src_ips) > 4 else ""
        parts.append(f"Source addresses involved: {shown}{more}.")

    parts.append(
        f"Severity **{incident['severity']}**. "
        f"{SEVERITY_NOTE.get(incident['severity'], '')}"
    )
    return " ".join(parts)


def _recommendations(detectors: set[str]) -> list[str]:
    seen: set[str] = set()
    actions: list[str] = []
    # Order by severity of the detection so the most urgent advice is first.
    priority = [
        "post_failure_success", "credential_stuffing", "password_spray",
        "brute_force", "impossible_travel", "anomalous_hour",
        "new_device_location",
    ]
    for detector in priority:
        if detector not in detectors:
            continue
        for action in REMEDIATION.get(detector, []):
            if action not in seen:
                seen.add(action)
                actions.append(action)
    return actions


def render_incident_report(store: Store, incident_id: int, timeline_limit: int = 60) -> str:
    """Produce a markdown incident write-up."""
    incident = store.get_incident(incident_id)
    if incident is None:
        raise KeyError(f"no such incident: {incident_id}")
    incident = dict(incident)

    alerts = _alerts_for(store, incident_id)
    timeline = build_timeline(store, incident_id)
    entities = json.loads(incident["entities_json"] or "{}")
    detectors = set(entities.get("detectors", []))

    out: list[str] = []
    add = out.append

    add(f"# Incident {incident_id}: {incident['title']}")
    add("")
    add(f"| | |")
    add(f"|---|---|")
    add(f"| **Severity** | `{incident['severity']}` |")
    add(f"| **Status** | `{incident['status']}` |")
    add(f"| **Analyst verdict** | `{incident['verdict']}` |")
    add(f"| **First activity** | {from_epoch(incident['first_ts_epoch'])} |")
    add(f"| **Last activity** | {from_epoch(incident['last_ts_epoch'])} |")
    add(f"| **Alerts correlated** | {incident['alert_count']} |")
    add(f"| **Accounts** | {', '.join(entities.get('usernames') or ['-'])} |")
    add(
        f"| **Source IPs** | "
        f"{', '.join(f'`{ip}`' for ip in entities.get('src_ips') or []) or '-'} |"
    )
    add(
        f"| **Correlated on** | "
        f"{', '.join(entities.get('linked_on') or ['single alert - no correlation'])} |"
    )
    add("")

    add("## Summary")
    add("")
    add(_summary(incident, alerts, timeline))
    add("")

    add("## Alerts in this incident")
    add("")
    add("| ID | Detector | Severity | Status | First seen | Title |")
    add("|---|---|---|---|---|---|")
    for alert in alerts:
        add(
            f"| {alert['id']} | `{alert['detector']}` | {alert['severity']} | "
            f"{alert['status']} | {from_epoch(alert['first_ts_epoch'])} | "
            f"{alert['title']} |"
        )
    add("")

    add("## Timeline")
    add("")
    if len(timeline) > timeline_limit:
        add(
            f"*Showing the first {timeline_limit // 2} and last "
            f"{timeline_limit // 2} of {len(timeline)} events.*"
        )
        add("")
        shown = timeline[: timeline_limit // 2] + timeline[-timeline_limit // 2 :]
        elided_at = timeline_limit // 2
    else:
        shown = timeline
        elided_at = None

    add("| Time (UTC) | Outcome | Account | Source IP | Location | Service | Device | Flagged by |")
    add("|---|---|---|---|---|---|---|---|")
    for index, row in enumerate(shown):
        if elided_at is not None and index == elided_at:
            add("| ... | ... | ... | ... | ... | ... | ... | ... |")
        event = row["event"]
        location = f"{event.geo_city}, {event.geo_country}".strip(", ") or "unknown"
        outcome = "OK" if event.outcome == "success" else f"FAIL ({event.reason})"
        add(
            f"| {event.ts} | {outcome} | {event.username} | `{event.src_ip}` | "
            f"{location} | {event.service} | {event.device} | "
            f"{', '.join(row['detectors'])} |"
        )
    add("")

    add("## Evidence")
    add("")
    for alert in alerts:
        add(f"### Alert {alert['id']} - {alert['title']}")
        add("")
        add(f"**Detector:** `{alert['detector']}`  ")
        add(f"**MITRE ATT&CK:** {alert['mitre']}  ")
        add(f"**Severity:** {alert['severity']}")
        add("")
        add(f"{alert['reason']}")
        add("")
        evidence = json.loads(alert["evidence_json"] or "{}")
        if evidence:
            add("| Field | Value |")
            add("|---|---|")
            for key, value in evidence.items():
                if isinstance(value, (list, dict)):
                    value = json.dumps(value)
                add(f"| `{key}` | {value} |")
            add("")

    # A couple of raw lines, because an analyst wants to see the source data
    # and not only somebody's summary of it.
    raw_samples = [row["event"] for row in timeline if row["event"].raw_line][:4]
    if raw_samples:
        add("### Raw log excerpts")
        add("")
        add("```")
        for event in raw_samples:
            add(event.raw_line)
        add("```")
        add("")

    add("## Assessment")
    add("")
    if incident["verdict"] and incident["verdict"] != "undetermined":
        add(f"**Verdict:** `{incident['verdict']}`")
        add("")
    else:
        add(
            "**Verdict:** `undetermined` - this incident has not yet been "
            "dispositioned by an analyst."
        )
        add("")
    if incident["analyst_note"]:
        add(f"**Analyst note:** {incident['analyst_note']}")
        add("")

    log = store.triage_log("incident", incident_id)
    if log:
        add("**Triage history:**")
        add("")
        for entry in log:
            add(
                f"- `{from_epoch(entry['created_at'])}` {entry['actor']}: "
                f"{entry['action']}"
                + (f" - {entry['note']}" if entry["note"] else "")
            )
        add("")

    add("## Recommended actions")
    add("")
    for action in _recommendations(detectors):
        add(f"- {action}")
    add("")

    add("## How this was detected")
    add("")
    from .detectors import REGISTRY

    for detector_name in sorted(detectors):
        cls = REGISTRY.get(detector_name)
        if cls is None:
            continue
        add(f"- **`{detector_name}`** - {cls.description} (MITRE: {cls.mitre})")
    add("")

    add("---")
    add("")
    add(
        "*Generated by loginwatch from a synthetic dataset. All accounts, IP "
        "addresses and locations in this report are fabricated; no real system, "
        "person or credential is represented. This is a portfolio project, not "
        "a production security tool.*"
    )
    return "\n".join(out)


def write_incident_reports(
    store: Store, out_dir: str | Path, limit: int = 3,
    incident_ids: list[int] | None = None,
) -> list[Path]:
    """Write reports for the most significant incidents.

    "Most significant" = highest severity first, then most alerts correlated.
    That ordering is the same triage instinct an analyst uses on a queue: work
    the worst thing that has the most evidence behind it.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if incident_ids:
        chosen = [dict(store.get_incident(i)) for i in incident_ids]
    else:
        incidents = [dict(r) for r in store.list_incidents()]
        incidents.sort(
            key=lambda i: (
                SEVERITY_RANK.get(i["severity"], 0), i["alert_count"]
            ),
            reverse=True,
        )
        chosen = incidents[:limit]

    written: list[Path] = []
    for incident in chosen:
        path = out_dir / f"incident-{incident['id']:03d}.md"
        path.write_text(
            render_incident_report(store, incident["id"]), encoding="utf-8"
        )
        written.append(path)
    return written

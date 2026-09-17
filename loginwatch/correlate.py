"""Grouping related alerts into incidents.

THE PROBLEM THIS SOLVES
-----------------------
A single account takeover in this dataset trips four detectors: brute force,
successful-login-after-failures, impossible travel, and a new device/location.
Delivered as four separate alerts, an analyst has to work out by hand that they
are one story - and in a queue of hundreds they often will not.

So alerts are clustered into incidents before a human sees them. Two alerts are
linked when they share an entity (the same account, or the same source IP) AND
sit close together in time. Linking is transitive: if alert A shares an account
with B, and B shares an IP with C, all three land in one incident. That
transitivity is what lets a chain of activity - guessing, then access, then
lateral movement - arrive as a single narrative.

The implementation is union-find over the alert list. That is not a
sophisticated algorithm, and it should not be: the value here is the modelling
decision about what "related" means, not the data structure.

WHERE THIS IS CRUDE
-------------------
Real correlation weighs entity types differently (a shared account is stronger
evidence than a shared IP, and a shared NAT gateway IP is nearly worthless),
handles alert suppression, and reasons about attack-chain ordering. See
LIMITATIONS.md.
"""

from __future__ import annotations

from .config import Config
from .models import SEVERITY_RANK
from .storage import Store


class _UnionFind:
    def __init__(self, items):
        self.parent = {item: item for item in items}

    def find(self, item):
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a, b) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[root_b] = root_a


def _time_gap(a, b) -> int:
    """Seconds between two alert time ranges; 0 if they overlap."""
    if a["last_ts_epoch"] >= b["first_ts_epoch"] and b["last_ts_epoch"] >= a["first_ts_epoch"]:
        return 0
    if a["last_ts_epoch"] < b["first_ts_epoch"]:
        return b["first_ts_epoch"] - a["last_ts_epoch"]
    return a["first_ts_epoch"] - b["last_ts_epoch"]


def _shares_entity(a, b, on_user: bool, on_ip: bool) -> str | None:
    if on_user and a["username"] and a["username"] == b["username"]:
        return f"account {a['username']}"
    if on_ip and a["src_ip"] and a["src_ip"] == b["src_ip"]:
        return f"source IP {a['src_ip']}"
    return None


def correlate(store: Store, config: Config) -> list[int]:
    """Cluster all alerts into incidents. Returns the new incident ids."""
    cfg = config.correlation
    window = int(cfg.get("window_minutes", 120)) * 60
    on_user = bool(cfg.get("link_on_username", True))
    on_ip = bool(cfg.get("link_on_src_ip", True))

    alerts = [dict(row) for row in store.list_alerts()]
    if not alerts:
        return []

    by_id = {a["id"]: a for a in alerts}
    uf = _UnionFind(list(by_id))
    links: dict[int, set[str]] = {a["id"]: set() for a in alerts}

    # O(n^2) over alerts. At this scale (tens to hundreds) that is fine and
    # readable; at SIEM scale you would index by entity instead.
    for i, a in enumerate(alerts):
        for b in alerts[i + 1:]:
            shared = _shares_entity(a, b, on_user, on_ip)
            if not shared:
                continue
            if _time_gap(a, b) > window:
                continue
            uf.union(a["id"], b["id"])
            links[a["id"]].add(shared)
            links[b["id"]].add(shared)

    clusters: dict[int, list[dict]] = {}
    for alert in alerts:
        clusters.setdefault(uf.find(alert["id"]), []).append(alert)

    incident_ids = []
    for members in clusters.values():
        members.sort(key=lambda a: a["first_ts_epoch"])
        incident_ids.append(_create_incident(store, members, links))
    return incident_ids


def _create_incident(store: Store, members: list[dict], links: dict) -> int:
    usernames = sorted({m["username"] for m in members if m["username"]})
    src_ips = sorted({m["src_ip"] for m in members if m["src_ip"]})
    detectors = [m["detector"] for m in members]
    severity = max(
        (m["severity"] for m in members), key=lambda s: SEVERITY_RANK.get(s, 0)
    )
    shared_reasons = sorted({r for m in members for r in links.get(m["id"], set())})

    entities = {
        "usernames": usernames,
        "src_ips": src_ips,
        "detectors": sorted(set(detectors)),
        "linked_on": shared_reasons,
    }

    return store.create_incident(
        title=_title(detectors, usernames, src_ips, len(members)),
        severity=severity,
        entities=entities,
        first_ts=min(m["first_ts_epoch"] for m in members),
        last_ts=max(m["last_ts_epoch"] for m in members),
        alert_ids=[m["id"] for m in members],
    )


def _title(detectors: list[str], usernames: list[str], src_ips: list[str], n: int) -> str:
    """Name the incident after the most serious thing in it.

    The headline an analyst reads first should describe the worst case the
    evidence supports, not whichever alert happened to fire first.
    """
    who = usernames[0] if usernames else (src_ips[0] if src_ips else "unknown entity")
    if len(usernames) > 1:
        who = f"{usernames[0]} +{len(usernames) - 1} more"

    detector_set = set(detectors)
    if "post_failure_success" in detector_set:
        headline = f"Probable account compromise: {who}"
    elif "password_spray" in detector_set:
        headline = f"Password spraying from {src_ips[0] if src_ips else 'unknown source'}"
    elif "credential_stuffing" in detector_set:
        headline = f"Distributed credential stuffing against {who}"
    elif "brute_force" in detector_set:
        headline = f"Brute force against {who}"
    elif "impossible_travel" in detector_set:
        headline = f"Impossible travel for {who}"
    elif "anomalous_hour" in detector_set:
        headline = f"Off-hours access by {who}"
    else:
        headline = f"Anomalous authentication activity for {who}"

    return f"{headline} ({n} alert{'s' if n != 1 else ''})"

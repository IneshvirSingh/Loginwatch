"""SQLite storage and query layer.

WHY SQLITE
----------
Zero setup, single file, ships with Python, and it is genuinely the right tool
at this data volume (thousands of events). A real SIEM uses a columnar or
inverted-index store because it ingests billions of events; that difference is
recorded honestly in LIMITATIONS.md rather than papered over.

SCHEMA NOTES
------------
Nearly every detector asks the same shape of question: "events for this user /
this IP, ordered by time". So the indexes are built on (username, ts_epoch) and
(src_ip, ts_epoch). Timestamps are stored twice - ISO text for humans, integer
epoch for range queries - because comparing integers is what makes the window
queries cheap.

The `ground_truth` table is the attack labels from the generator. It lives in
the same database for convenience but NOTHING in the detection path reads it;
only `loginwatch evaluate` does. Keeping that boundary is what makes the
accuracy numbers meaningful.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

from .models import Event, Finding, ParseError, from_epoch

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    event_id    TEXT NOT NULL UNIQUE,
    ts          TEXT NOT NULL,
    ts_epoch    INTEGER NOT NULL,
    username    TEXT NOT NULL,
    src_ip      TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    service     TEXT,
    host        TEXT,
    reason      TEXT,
    device      TEXT,
    device_id   TEXT,
    geo_city    TEXT,
    geo_country TEXT,
    lat         REAL,
    lon         REAL,
    session_id  TEXT,
    raw_line    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(username, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts   ON events(src_ip, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_outcome ON events(outcome, ts_epoch);

CREATE TABLE IF NOT EXISTS ingest_errors (
    id          INTEGER PRIMARY KEY,
    source_file TEXT,
    line_no     INTEGER,
    raw_line    TEXT,
    error       TEXT
);

-- Per-user behavioural baseline, built from the attack-free training window.
CREATE TABLE IF NOT EXISTS profiles (
    username       TEXT PRIMARY KEY,
    event_count    INTEGER NOT NULL,
    first_seen     INTEGER,
    last_seen      INTEGER,
    hours_json     TEXT,   -- {utc_hour: count}
    countries_json TEXT,   -- {country: count}
    devices_json   TEXT,   -- {device_id: {"count": n, "label": ua}}
    built_from     INTEGER,
    built_to       INTEGER
);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY,
    dedup_key      TEXT NOT NULL UNIQUE,
    detector       TEXT NOT NULL,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'new',
    username       TEXT,
    src_ip         TEXT,
    first_ts_epoch INTEGER,
    last_ts_epoch  INTEGER,
    reason         TEXT,
    mitre          TEXT,
    evidence_json  TEXT,
    event_ids_json TEXT,
    incident_id    INTEGER,
    analyst_note   TEXT,
    created_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);

CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'new',
    verdict        TEXT NOT NULL DEFAULT 'undetermined',
    entities_json  TEXT,
    first_ts_epoch INTEGER,
    last_ts_epoch  INTEGER,
    alert_count    INTEGER,
    analyst_note   TEXT,
    created_at     INTEGER
);

-- Append-only audit trail of analyst actions. Real triage tooling keeps one;
-- "who decided this was benign, and when" is a question that gets asked.
CREATE TABLE IF NOT EXISTS triage_log (
    id          INTEGER PRIMARY KEY,
    entity_type TEXT NOT NULL,   -- 'alert' | 'incident'
    entity_id   INTEGER NOT NULL,
    action      TEXT NOT NULL,
    note        TEXT,
    actor       TEXT,
    created_at  INTEGER
);

-- Generator labels. Read ONLY by `loginwatch evaluate`, never by detectors.
CREATE TABLE IF NOT EXISTS ground_truth (
    event_id TEXT PRIMARY KEY,
    scenario TEXT NOT NULL,     -- e.g. 'brute_force'
    instance TEXT NOT NULL,     -- e.g. 'brute_force#2' - ONE concrete injection
    label    TEXT NOT NULL      -- 'attack' | 'benign'
);
"""

EVENT_COLUMNS = (
    "event_id, ts, ts_epoch, username, src_ip, outcome, service, host, reason, "
    "device, device_id, geo_city, geo_country, lat, lon, session_id, raw_line"
)

ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive")
INCIDENT_VERDICTS = ("undetermined", "true_positive", "false_positive", "benign")


def _row_to_event(row: sqlite3.Row) -> Event:
    return Event(
        event_id=row["event_id"],
        ts=row["ts"],
        ts_epoch=row["ts_epoch"],
        username=row["username"],
        src_ip=row["src_ip"],
        outcome=row["outcome"],
        service=row["service"] or "",
        host=row["host"] or "",
        reason=row["reason"] or "",
        device=row["device"] or "",
        device_id=row["device_id"] or "",
        geo_city=row["geo_city"] or "",
        geo_country=row["geo_country"] or "",
        lat=row["lat"],
        lon=row["lon"],
        session_id=row["session_id"] or "",
        raw_line=row["raw_line"] or "",
    )


class Store:
    """All database access goes through here."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ events

    def insert_events(self, events: Iterable[Event]) -> int:
        """Insert events, ignoring ones already present.

        INSERT OR IGNORE on the unique event_id makes ingestion idempotent:
        re-ingesting the same file does not duplicate data. Real pipelines need
        this because log delivery is usually at-least-once.
        """
        placeholders = ", ".join(["?"] * 17)
        sql = f"INSERT OR IGNORE INTO events ({EVENT_COLUMNS}) VALUES ({placeholders})"
        rows = [
            (
                e.event_id, e.ts, e.ts_epoch, e.username, e.src_ip, e.outcome,
                e.service, e.host, e.reason, e.device, e.device_id, e.geo_city,
                e.geo_country, e.lat, e.lon, e.session_id, e.raw_line,
            )
            for e in events
        ]
        cur = self.conn.executemany(sql, rows)
        self.conn.commit()
        return cur.rowcount

    def insert_parse_errors(self, errors: Iterable[ParseError]) -> int:
        cur = self.conn.executemany(
            "INSERT INTO ingest_errors (source_file, line_no, raw_line, error) "
            "VALUES (?, ?, ?, ?)",
            [(e.source_file, e.line_no, e.raw_line, e.error) for e in errors],
        )
        self.conn.commit()
        return cur.rowcount

    def event_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def parse_error_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM ingest_errors").fetchone()[0]

    def parse_errors(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ingest_errors ORDER BY line_no"
        ).fetchall()

    def time_range(self) -> tuple[int, int]:
        row = self.conn.execute(
            "SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events"
        ).fetchone()
        return (row[0] or 0, row[1] or 0)

    def all_events(self, outcome: str | None = None) -> list[Event]:
        if outcome:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE outcome = ? ORDER BY ts_epoch, id", (outcome,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM events ORDER BY ts_epoch, id"
            ).fetchall()
        return [_row_to_event(r) for r in rows]

    def events_between(self, start: int, end: int) -> list[Event]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE ts_epoch >= ? AND ts_epoch < ? "
            "ORDER BY ts_epoch, id",
            (start, end),
        ).fetchall()
        return [_row_to_event(r) for r in rows]

    def events_for_user(
        self, username: str, outcome: str | None = None
    ) -> list[Event]:
        sql = "SELECT * FROM events WHERE username = ?"
        params: list[Any] = [username]
        if outcome:
            sql += " AND outcome = ?"
            params.append(outcome)
        sql += " ORDER BY ts_epoch, id"
        return [_row_to_event(r) for r in self.conn.execute(sql, params).fetchall()]

    def events_by_ids(self, event_ids: Sequence[str]) -> list[Event]:
        if not event_ids:
            return []
        marks = ", ".join(["?"] * len(event_ids))
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE event_id IN ({marks}) ORDER BY ts_epoch, id",
            list(event_ids),
        ).fetchall()
        return [_row_to_event(r) for r in rows]

    def distinct_usernames(self) -> list[str]:
        return [
            r[0]
            for r in self.conn.execute(
                "SELECT DISTINCT username FROM events ORDER BY username"
            ).fetchall()
        ]

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        """Escape hatch for detectors that want to aggregate in SQL."""
        return self.conn.execute(sql, params).fetchall()

    # ---------------------------------------------------------------- profiles

    def replace_profiles(self, profiles: Iterable[dict]) -> int:
        self.conn.execute("DELETE FROM profiles")
        rows = [
            (
                p["username"], p["event_count"], p["first_seen"], p["last_seen"],
                json.dumps(p["hours"]), json.dumps(p["countries"]),
                json.dumps(p["devices"]), p["built_from"], p["built_to"],
            )
            for p in profiles
        ]
        cur = self.conn.executemany(
            "INSERT INTO profiles (username, event_count, first_seen, last_seen, "
            "hours_json, countries_json, devices_json, built_from, built_to) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()
        return cur.rowcount

    def profiles(self) -> dict[str, dict]:
        out = {}
        for r in self.conn.execute("SELECT * FROM profiles").fetchall():
            out[r["username"]] = {
                "username": r["username"],
                "event_count": r["event_count"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "hours": {int(k): v for k, v in json.loads(r["hours_json"]).items()},
                "countries": json.loads(r["countries_json"]),
                "devices": json.loads(r["devices_json"]),
                "built_from": r["built_from"],
                "built_to": r["built_to"],
            }
        return out

    # ------------------------------------------------------------------ alerts

    def upsert_alert(self, finding: Finding) -> int:
        """Insert a finding as an alert, or refresh an existing one.

        On conflict we update the evidence but deliberately do NOT reset
        `status` or `analyst_note` - an analyst's triage decision must survive a
        re-run of the detection engine.
        """
        now = int(time.time())
        cur = self.conn.execute(
            """
            INSERT INTO alerts (dedup_key, detector, title, severity, status,
                username, src_ip, first_ts_epoch, last_ts_epoch, reason, mitre,
                evidence_json, event_ids_json, created_at)
            VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dedup_key) DO UPDATE SET
                severity       = excluded.severity,
                title          = excluded.title,
                reason         = excluded.reason,
                last_ts_epoch  = excluded.last_ts_epoch,
                evidence_json  = excluded.evidence_json,
                event_ids_json = excluded.event_ids_json
            """,
            (
                finding.dedup_key(), finding.detector, finding.title,
                finding.severity, finding.username, finding.src_ip,
                finding.first_ts_epoch, finding.last_ts_epoch, finding.reason,
                finding.mitre, json.dumps(finding.evidence),
                json.dumps(finding.event_ids), now,
            ),
        )
        self.conn.commit()
        return cur.lastrowid or 0

    def list_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        detector: str | None = None,
        username: str | None = None,
        src_ip: str | None = None,
        incident_id: int | None = None,
        limit: int | None = None,
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        for column, value in (
            ("status", status), ("severity", severity), ("detector", detector),
            ("username", username), ("src_ip", src_ip),
        ):
            if value:
                sql += f" AND {column} = ?"
                params.append(value)
        if incident_id is not None:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        sql += " ORDER BY first_ts_epoch DESC, id DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return self.conn.execute(sql, params).fetchall()

    def get_alert(self, alert_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()

    def update_alert(
        self, alert_id: int, status: str | None = None, note: str | None = None,
        actor: str = "analyst",
    ) -> bool:
        alert = self.get_alert(alert_id)
        if alert is None:
            return False
        if status:
            self.conn.execute(
                "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)
            )
        if note:
            self.conn.execute(
                "UPDATE alerts SET analyst_note = ? WHERE id = ?", (note, alert_id)
            )
        self.add_triage_log(
            "alert", alert_id, f"status={status}" if status else "note", note, actor
        )
        self.conn.commit()
        return True

    def alert_counts_by(self, column: str) -> list[tuple[str, int]]:
        if column not in ("severity", "status", "detector", "username", "src_ip"):
            raise ValueError(f"not a groupable column: {column}")
        rows = self.conn.execute(
            f"SELECT {column}, COUNT(*) AS n FROM alerts GROUP BY {column} "
            "ORDER BY n DESC"
        ).fetchall()
        return [(r[0] or "-", r[1]) for r in rows]

    def clear_detection_output(self) -> None:
        """Wipe alerts and incidents so a detection run starts clean."""
        self.conn.executescript(
            "DELETE FROM alerts; DELETE FROM incidents; DELETE FROM triage_log;"
        )
        self.conn.commit()

    # --------------------------------------------------------------- incidents

    def create_incident(
        self, title: str, severity: str, entities: dict,
        first_ts: int, last_ts: int, alert_ids: Sequence[int],
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO incidents (title, severity, entities_json, first_ts_epoch, "
            "last_ts_epoch, alert_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                title, severity, json.dumps(entities), first_ts, last_ts,
                len(alert_ids), int(time.time()),
            ),
        )
        incident_id = cur.lastrowid
        self.conn.executemany(
            "UPDATE alerts SET incident_id = ? WHERE id = ?",
            [(incident_id, aid) for aid in alert_ids],
        )
        self.conn.commit()
        return int(incident_id)

    def list_incidents(
        self, verdict: str | None = None, severity: str | None = None
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []
        if verdict:
            sql += " AND verdict = ?"
            params.append(verdict)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY alert_count DESC, first_ts_epoch DESC"
        return self.conn.execute(sql, params).fetchall()

    def get_incident(self, incident_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()

    def update_incident(
        self, incident_id: int, verdict: str | None = None,
        status: str | None = None, note: str | None = None, actor: str = "analyst",
    ) -> bool:
        if self.get_incident(incident_id) is None:
            return False
        if verdict:
            self.conn.execute(
                "UPDATE incidents SET verdict = ? WHERE id = ?", (verdict, incident_id)
            )
        if status:
            self.conn.execute(
                "UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id)
            )
        if note:
            self.conn.execute(
                "UPDATE incidents SET analyst_note = ? WHERE id = ?",
                (note, incident_id),
            )
        action = ", ".join(
            f"{k}={v}" for k, v in (("verdict", verdict), ("status", status)) if v
        ) or "note"
        self.add_triage_log("incident", incident_id, action, note, actor)
        self.conn.commit()
        return True

    def add_triage_log(
        self, entity_type: str, entity_id: int, action: str,
        note: str | None, actor: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO triage_log (entity_type, entity_id, action, note, actor, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (entity_type, entity_id, action, note, actor, int(time.time())),
        )

    def triage_log(self, entity_type: str, entity_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM triage_log WHERE entity_type = ? AND entity_id = ? "
            "ORDER BY id",
            (entity_type, entity_id),
        ).fetchall()

    # ------------------------------------------------------------ ground truth

    def replace_ground_truth(self, labels: Iterable[dict]) -> int:
        self.conn.execute("DELETE FROM ground_truth")
        cur = self.conn.executemany(
            "INSERT OR REPLACE INTO ground_truth (event_id, scenario, instance, "
            "label) VALUES (?, ?, ?, ?)",
            [
                (
                    l["event_id"], l["scenario"],
                    l.get("instance") or l["scenario"], l["label"],
                )
                for l in labels
            ],
        )
        self.conn.commit()
        return cur.rowcount

    def ground_truth(self) -> dict[str, dict]:
        return {
            r["event_id"]: {
                "scenario": r["scenario"],
                "instance": r["instance"],
                "label": r["label"],
            }
            for r in self.conn.execute("SELECT * FROM ground_truth").fetchall()
        }

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def fmt_ts(epoch: int | None) -> str:
        return from_epoch(epoch) if epoch else "-"

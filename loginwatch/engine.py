"""Pipeline orchestration: ingest, then detect.

This module is deliberately thin. It knows the ORDER things happen in and
nothing about how any individual step works, which keeps the interesting logic
in the modules that own it.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import Config
from .detectors import build_detectors
from .models import Event, Finding
from .storage import Store


def ingest(store: Store, log_path: str | Path, batch_size: int = 2000) -> dict:
    """Parse a raw log file into the database.

    Returns counts rather than printing them, so the CLI decides presentation.
    Malformed lines are persisted to `ingest_errors` instead of being dropped:
    a rising parse-failure rate is operationally meaningful on its own.
    """
    from .logfmt import parse_file  # local import keeps module import cheap

    events: list[Event] = []
    errors = []
    inserted = 0

    for record in parse_file(log_path):
        if isinstance(record, Event):
            events.append(record)
            if len(events) >= batch_size:
                inserted += store.insert_events(events)
                events = []
        else:
            errors.append(record)

    if events:
        inserted += store.insert_events(events)
    if errors:
        store.insert_parse_errors(errors)

    return {
        "source": str(log_path),
        "events_inserted": inserted,
        "parse_errors": len(errors),
        "total_events_in_db": store.event_count(),
    }


def load_ground_truth(store: Store, path: str | Path) -> int:
    """Load generator attack labels.

    Used ONLY by `loginwatch evaluate`. No detector reads this table.
    """
    path = Path(path)
    if not path.exists():
        return 0
    labels = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                labels.append(json.loads(line))
    return store.replace_ground_truth(labels)


def run_detection(
    store: Store, config: Config, clear: bool = True
) -> tuple[list[Finding], dict[str, int]]:
    """Run every enabled detector and persist the findings as alerts.

    `clear=True` wipes previous alerts so a run is reproducible. In a real
    deployment you would never do this - alerts accumulate and triage state is
    sacred - but for a demo pipeline that must produce identical output every
    time, starting clean is the honest choice. `--no-clear` keeps history.
    """
    if clear:
        store.clear_detection_output()

    profiles = store.profiles()
    findings: list[Finding] = []
    per_detector: dict[str, int] = {}

    for detector in build_detectors(config):
        hits = detector.run(store, profiles)
        per_detector[detector.name] = len(hits)
        findings.extend(hits)

    # Persist in time order so alert ids read chronologically.
    for finding in sorted(findings, key=lambda f: (f.first_ts_epoch, f.detector)):
        store.upsert_alert(finding)

    return findings, per_detector

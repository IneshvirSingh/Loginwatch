"""Shared test fixtures.

Detector tests are built around a small, hand-written set of events rather than
the generator's output. That is deliberate: a detector test should fail because
the detector changed, not because the generator's random stream shifted.
"""

from __future__ import annotations

import itertools

import pytest

from loginwatch import geo
from loginwatch.models import Event, device_fingerprint, to_epoch
from loginwatch.storage import Store

# A fixed reference point inside the synthetic timeline.
BASE = to_epoch("2026-09-10T12:00:00Z")

_counter = itertools.count(1)

# Convenient, geolocatable synthetic IPs (all in reserved ranges).
PUNE_IP = "198.18.0.10"
PUNE_IP2 = "198.18.0.11"
LONDON_IP = "198.18.5.20"
SAO_PAULO_IP = "198.18.13.30"
SYDNEY_IP = "198.18.18.40"


def make_event(
    offset: int = 0,
    username: str = "alice.test",
    src_ip: str = PUNE_IP,
    outcome: str = "success",
    service: str = "vpn",
    device: str = "Chrome/126 Windows",
    reason: str = "",
    event_id: str | None = None,
    base: int | None = None,
) -> Event:
    """Build one normalized event, `offset` seconds from the base time."""
    ts_epoch = (BASE if base is None else base) + offset
    site = geo.lookup(src_ip)
    from loginwatch.models import from_epoch

    return Event(
        event_id=event_id or f"ev{next(_counter):06d}",
        ts=from_epoch(ts_epoch),
        ts_epoch=ts_epoch,
        username=username,
        src_ip=src_ip,
        outcome=outcome,
        service=service,
        host="authgw01",
        reason=reason if outcome == "failure" else "",
        device=device,
        device_id=device_fingerprint(device),
        geo_city=site.name if site else "",
        geo_country=site.country if site else "",
        lat=site.lat if site else None,
        lon=site.lon if site else None,
        session_id="sess0001" if outcome == "success" else "",
        raw_line="(synthetic test event)",
    )


@pytest.fixture
def store(tmp_path) -> Store:
    """A fresh database per test."""
    with Store(tmp_path / "test.db") as s:
        yield s


@pytest.fixture
def seed(store):
    """Insert events into the test store and return them."""

    def _seed(events: list[Event]) -> list[Event]:
        store.insert_events(events)
        return events

    return _seed


def make_profile(
    username: str = "alice.test",
    event_count: int = 60,
    hours: dict | None = None,
    countries: dict | None = None,
    devices: dict | None = None,
    built_to: int | None = None,
) -> dict:
    """Build a baseline profile dict in the shape profiling.py produces.

    Default: a user active 06:00-16:00 UTC from India on one known device,
    whose dormant window therefore covers the night.
    """
    return {
        "username": username,
        "event_count": event_count,
        "first_seen": BASE - 30 * 86400,
        "last_seen": BASE - 86400,
        "hours": hours if hours is not None else {h: 5 for h in range(6, 17)},
        "countries": countries if countries is not None else {"IN": 60},
        "devices": devices if devices is not None else {
            device_fingerprint("Chrome/126 Windows"): {
                "count": 60, "label": "Chrome/126 Windows"
            }
        },
        "built_from": BASE - 30 * 86400,
        # Baseline closes at midnight on the base day, so events built by
        # make_event on that day are all AFTER the training window and are
        # therefore eligible to be scored.
        "built_to": built_to if built_to is not None else BASE - (BASE % 86400),
    }

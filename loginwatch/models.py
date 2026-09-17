"""Core data structures shared by the pipeline.

The normalized `Event` is the contract between the parser and everything
downstream. Detectors never see a raw log line except via `Event.raw_line`,
which is kept purely so an analyst can look at the original text as evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Canonical outcomes. Anything else is a parse error.
OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
VALID_OUTCOMES = (OUTCOME_SUCCESS, OUTCOME_FAILURE)

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def device_fingerprint(device: str | None) -> str:
    """Stable short hash of a user-agent/device string.

    Real products build far richer fingerprints (TLS JA3, cookie IDs, managed
    device certificates). Hashing the UA string is a stand-in: it is stable and
    comparable, which is all the new-device detector needs.
    """
    if not device:
        return "unknown"
    return hashlib.sha1(device.strip().lower().encode("utf-8")).hexdigest()[:12]


def to_epoch(ts_iso: str) -> int:
    """Parse an ISO-8601 UTC timestamp into an integer epoch (seconds)."""
    text = ts_iso.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.astimezone(timezone.utc).timestamp())


def from_epoch(epoch: int) -> str:
    """Format an epoch back to the canonical ISO-8601 UTC string."""
    return (
        datetime.fromtimestamp(epoch, tz=timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


@dataclass
class Event:
    """A normalized authentication event."""

    event_id: str
    ts: str  # ISO-8601 UTC, e.g. 2026-09-01T08:14:22Z
    ts_epoch: int
    username: str
    src_ip: str
    outcome: str
    service: str
    host: str = ""
    reason: str = ""  # failure reason; empty on success
    device: str = ""
    device_id: str = ""
    geo_city: str = ""
    geo_country: str = ""
    lat: float | None = None
    lon: float | None = None
    session_id: str = ""
    raw_line: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParseError:
    """A log line we could not turn into an Event.

    We persist these instead of dropping them silently: in a real SOC, a spike
    in parse failures is itself a signal (format drift, truncation, or someone
    stuffing junk into a log to break the parser).
    """

    line_no: int
    raw_line: str
    error: str
    source_file: str = ""


@dataclass
class Finding:
    """A detector hit, before it becomes a stored Alert.

    `reason` is a sentence a human can read. `evidence` holds the numbers that
    sentence is based on, so an analyst can check the detector's arithmetic
    rather than trust it.
    """

    detector: str
    severity: str
    title: str
    reason: str
    mitre: str
    username: str = ""
    src_ip: str = ""
    first_ts_epoch: int = 0
    last_ts_epoch: int = 0
    event_ids: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def dedup_key(self) -> str:
        """Identity of this finding, so re-running detection is idempotent.

        Keyed on detector + entity + the FIRST event of the burst. The first
        event is stable as a sliding window grows, so re-running after more
        data arrives updates the same alert instead of cloning it.
        """
        anchor = self.event_ids[0] if self.event_ids else str(self.first_ts_epoch)
        return f"{self.detector}|{self.username or '-'}|{self.src_ip or '-'}|{anchor}"

"""Detector base class, registry, and shared window helpers.

Every detector is a small class with one job and one `run` method. They are
independent: a detector never calls another detector, and nothing about the
order they run in changes their output. That is what makes them unit-testable
in isolation, which is the whole reason for the structure.

A detector returns `Finding` objects. It does not write to the database, decide
how alerts are grouped, or format anything for display. Keeping that boundary
means a detector's test can be "given these events, do I get this finding?"
with no database involved at all.
"""

from __future__ import annotations

from typing import Callable, Iterable, Sequence

from ..models import Event, Finding

REGISTRY: dict[str, type["Detector"]] = {}


def register(cls: type["Detector"]) -> type["Detector"]:
    """Class decorator that makes a detector constructible by name from config."""
    REGISTRY[cls.name] = cls
    return cls


class Detector:
    """Base class for all detectors."""

    #: config key and alert label
    name: str = ""
    #: MITRE ATT&CK technique this maps to (see DETECTIONS.md)
    mitre: str = ""
    #: one-line description of what the detector looks for
    description: str = ""
    #: severity used when the config does not override it
    default_severity: str = "medium"
    #: True if the detector needs per-user baselines to work
    needs_profiles: bool = False

    def __init__(self, params: dict | None = None):
        self.params = params or {}
        self.severity = self.params.get("severity", self.default_severity)

    def p(self, key: str, default=None):
        """Read a tuning parameter. Never hardcode these in detector logic."""
        return self.params.get(key, default)

    def run(self, store, profiles: dict[str, dict] | None = None) -> list[Finding]:
        raise NotImplementedError


def build_detectors(config) -> list[Detector]:
    """Instantiate every enabled detector named in the config file.

    A detector present in REGISTRY but absent from the config is NOT run. The
    config is the source of truth for what is deployed, which mirrors how
    detection content is managed in practice.
    """
    detectors: list[Detector] = []
    for name in config.enabled_detectors():
        cls = REGISTRY.get(name)
        if cls is None:
            raise KeyError(
                f"config enables unknown detector {name!r}; "
                f"known detectors: {sorted(REGISTRY)}"
            )
        detectors.append(cls(config.detector(name)))
    return detectors


# --------------------------------------------------------------------- helpers


def group_by(events: Iterable[Event], key: Callable[[Event], object]) -> dict:
    """Bucket events by an arbitrary key, preserving time order within a bucket."""
    out: dict = {}
    for event in events:
        out.setdefault(key(event), []).append(event)
    for bucket in out.values():
        bucket.sort(key=lambda e: (e.ts_epoch, e.event_id))
    return out


def find_bursts(
    events: Sequence[Event], window_seconds: int, min_count: int
) -> list[list[Event]]:
    """Find clusters of >= min_count events inside a sliding time window.

    Once a window trips the threshold the burst is *extended* while events keep
    arriving within `window_seconds` of each other, then reported as ONE burst.

    That extension is the difference between an alert queue an analyst can use
    and one they cannot. A naive implementation that emits a finding for every
    qualifying window turns a 30-guess brute force into 23 near-identical
    alerts describing a single event.
    """
    events = sorted(events, key=lambda e: (e.ts_epoch, e.event_id))
    bursts: list[list[Event]] = []
    i = 0
    n = len(events)
    while i < n:
        j = i
        while j + 1 < n and events[j + 1].ts_epoch - events[i].ts_epoch <= window_seconds:
            j += 1
        if (j - i + 1) >= min_count:
            k = j
            while (
                k + 1 < n
                and events[k + 1].ts_epoch - events[k].ts_epoch <= window_seconds
            ):
                k += 1
            bursts.append(list(events[i : k + 1]))
            i = k + 1
        else:
            i += 1
    return bursts


def sliding_windows(events: Sequence[Event], window_seconds: int):
    """Yield (start_index, end_index_exclusive) for every maximal time window.

    Used by detectors that care about the *variety* inside a window (distinct
    users, distinct source IPs) rather than raw volume.
    """
    events = sorted(events, key=lambda e: (e.ts_epoch, e.event_id))
    n = len(events)
    start = 0
    for end in range(1, n + 1):
        while (
            start < end - 1
            and events[end - 1].ts_epoch - events[start].ts_epoch > window_seconds
        ):
            start += 1
        yield start, end


def summarise_counts(values: Iterable[str], top: int = 5) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if value:
            counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1])[:top])

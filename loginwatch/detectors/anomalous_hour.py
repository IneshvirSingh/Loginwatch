"""Anomalous login hour: a success at a time this account is never active.

MITRE ATT&CK: T1078 - Valid Accounts

This is the one genuinely per-user detection here. There is no global "suspicious
hour" - 03:00 is the middle of the working day for someone on the other side of
the planet. So the detector compares each successful login against that user's
own baseline histogram of active UTC hours (see profiling.py).

Design choices worth defending:

  * Baselines come only from the attack-free training window, so an attacker
    cannot teach the profile that 3am is normal for this account.
  * A user with fewer than `min_baseline_events` successful logins is skipped
    entirely. Scoring someone you have barely observed produces noise about new
    joiners, not detections.
  * The comparison uses a +/- neighbour_hours band, so a login slightly either
    side of the usual pattern is not treated as an anomaly.

Known false positive: a legitimately unusual night - an on-call page, a release
window, a deadline. The synthetic dataset deliberately contains such events
(labelled `benign_oncall_night`) so this cost shows up in the evaluation rather
than being hidden.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import OUTCOME_SUCCESS, Finding
from ..profiling import observed_hours, profile_is_usable, quiet_hours
from .base import Detector, register


@register
class AnomalousHourDetector(Detector):
    name = "anomalous_hour"
    mitre = "T1078 (Valid Accounts)"
    description = (
        "Successful login in an hour of day where the account has no "
        "established history."
    )
    default_severity = "medium"
    needs_profiles = True

    def run(self, store, profiles=None) -> list[Finding]:
        profiles = profiles or {}
        neighbour = int(self.p("neighbour_hours", 1))
        min_baseline = int(self.p("min_baseline_events", 25))
        min_quiet = int(self.p("min_quiet_hours", 4))

        findings: list[Finding] = []
        for event in store.all_events(outcome=OUTCOME_SUCCESS):
            profile = profiles.get(event.username)
            if not profile_is_usable(profile, min_baseline):
                continue
            # Only score events the baseline could not have learned from.
            if event.ts_epoch < profile["built_to"]:
                continue

            dormant = quiet_hours(profile, neighbour, min_quiet)
            if not dormant:
                continue  # no reliable off-hours window for this account

            hour = datetime.fromtimestamp(event.ts_epoch, tz=timezone.utc).hour
            if hour not in dormant:
                continue

            findings.append(self._finding(event, profile, hour, dormant, neighbour))
        return findings

    def _finding(self, event, profile, hour, dormant, neighbour) -> Finding:
        observed = observed_hours(profile)
        reason = (
            f"'{event.username}' logged in successfully at {event.ts} "
            f"({hour:02d}:xx UTC), inside the window this account is normally "
            f"dormant in ({_compact_hours(sorted(dormant))} UTC). Across "
            f"{profile['event_count']} baseline logins its observed active "
            f"hours are {_compact_hours(observed)} UTC, and a "
            f"{neighbour}h tolerance has already been applied at each end of "
            f"the dormant window. Source: {event.src_ip} "
            f"({event.geo_city or 'unknown'}, {event.geo_country or '??'})."
        )
        return Finding(
            detector=self.name,
            severity=self.severity,
            title=f"Off-hours login for {event.username} at {hour:02d}:00 UTC",
            reason=reason,
            mitre=self.mitre,
            username=event.username,
            src_ip=event.src_ip,
            first_ts_epoch=event.ts_epoch,
            last_ts_epoch=event.ts_epoch,
            event_ids=[event.event_id],
            evidence={
                "login_hour_utc": hour,
                "baseline_active_hours_utc": observed,
                "dormant_hours_utc": sorted(dormant),
                "tolerance_hours": neighbour,
                "baseline_login_count": profile["event_count"],
                "baseline_window": (
                    f"{_fmt(profile['built_from'])} to {_fmt(profile['built_to'])}"
                ),
                "service": event.service,
                "device": event.device,
                "source_location": (
                    f"{event.geo_city}, {event.geo_country}".strip(", ") or "unknown"
                ),
                "device_known": event.device_id in profile.get("devices", {}),
                "country_known": event.geo_country in profile.get("countries", {}),
            },
        )


def _fmt(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def _compact_hours(hours: list[int]) -> str:
    """Render [8,9,10,14] as '08-10, 14' so the reason stays readable."""
    if not hours:
        return "none"
    runs: list[tuple[int, int]] = []
    start = prev = hours[0]
    for hour in hours[1:]:
        if hour == prev + 1:
            prev = hour
            continue
        runs.append((start, prev))
        start = prev = hour
    runs.append((start, prev))
    return ", ".join(
        f"{a:02d}" if a == b else f"{a:02d}-{b:02d}" for a, b in runs
    )

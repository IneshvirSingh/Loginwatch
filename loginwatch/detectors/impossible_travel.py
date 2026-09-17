"""Impossible travel: one account, two places, not enough time in between.

MITRE ATT&CK: T1078 - Valid Accounts (detection of credential misuse)

If an account authenticates successfully from Pune and then from Sao Paulo
forty minutes later, one of those sessions is not the account's owner. The
detector computes great-circle distance between consecutive successful logins
and derives the speed the user would have needed.

Only SUCCESSFUL logins are compared. A failed login tells you where someone
*tried* to authenticate from, which says nothing about where the real user is.

Two guards keep this from becoming a noise generator:

  min_distance_km  ignore short hops, where crude IP geolocation is unreliable
                   enough to invent motion that never happened
  max_speed_kmh    900 km/h, roughly commercial jet cruising speed

The honest caveat: a corporate VPN or cloud proxy makes a user appear to be
wherever the exit node is, and switching between two of them produces a perfect
impossible-travel signature with no attacker involved. This is the single most
common false positive for this detection in real deployments, and the reason
mature teams maintain an allowlist of known VPN egress ranges.
"""

from __future__ import annotations

from .. import geo
from ..models import OUTCOME_SUCCESS, Event, Finding
from .base import Detector, group_by, register


@register
class ImpossibleTravelDetector(Detector):
    name = "impossible_travel"
    mitre = "T1078 (Valid Accounts)"
    description = (
        "Consecutive successful logins for one account from locations too far "
        "apart to be reached in the elapsed time."
    )
    default_severity = "high"

    def run(self, store, profiles=None) -> list[Finding]:
        max_speed = float(self.p("max_speed_kmh", 900))
        min_distance = float(self.p("min_distance_km", 500))

        findings: list[Finding] = []
        by_user = group_by(store.all_events(outcome=OUTCOME_SUCCESS), lambda e: e.username)

        for username, events in by_user.items():
            # Skip events we cannot place on a map rather than guessing.
            located = [e for e in events if e.lat is not None and e.lon is not None]
            for previous, current in zip(located, located[1:]):
                km = geo.haversine_km(previous.lat, previous.lon, current.lat, current.lon)
                if km < min_distance:
                    continue
                seconds = max(current.ts_epoch - previous.ts_epoch, 1)
                speed = km / (seconds / 3600)
                if speed <= max_speed:
                    continue
                findings.append(
                    self._finding(username, previous, current, km, seconds, speed, max_speed)
                )
        return findings

    def _finding(
        self, username: str, previous: Event, current: Event, km: float,
        seconds: int, speed: float, max_speed: float,
    ) -> Finding:
        minutes = seconds / 60
        reason = (
            f"Account '{username}' authenticated successfully from "
            f"{_place(previous)} at {previous.ts}, then from {_place(current)} "
            f"at {current.ts} - {km:,.0f} km apart with only {minutes:.0f} "
            f"minutes in between. That requires an average speed of "
            f"{speed:,.0f} km/h, well above the {max_speed:,.0f} km/h ceiling "
            f"used here for commercial air travel. At least one of the two "
            f"sessions is not the account owner."
        )
        return Finding(
            detector=self.name,
            severity=self.severity,
            title=f"Impossible travel for {username}: {_place(previous)} to {_place(current)}",
            reason=reason,
            mitre=self.mitre,
            username=username,
            src_ip=current.src_ip,
            first_ts_epoch=previous.ts_epoch,
            last_ts_epoch=current.ts_epoch,
            event_ids=[previous.event_id, current.event_id],
            evidence={
                "from_location": _place(previous),
                "from_ip": previous.src_ip,
                "from_time": previous.ts,
                "from_device": previous.device,
                "to_location": _place(current),
                "to_ip": current.src_ip,
                "to_time": current.ts,
                "to_device": current.device,
                "distance_km": round(km, 1),
                "elapsed_minutes": round(minutes, 1),
                "implied_speed_kmh": round(speed, 1),
                "max_plausible_speed_kmh": max_speed,
                "device_also_changed": previous.device_id != current.device_id,
            },
        )


def _place(event: Event) -> str:
    if event.geo_city and event.geo_country:
        return f"{event.geo_city}, {event.geo_country}"
    return event.geo_city or event.geo_country or "unknown location"

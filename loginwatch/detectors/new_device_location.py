"""First sighting of a device or country for an established account.

MITRE ATT&CK: T1078 - Valid Accounts

A weak signal on its own - people buy laptops and take holidays - but a useful
one in combination, which is exactly what the correlation step is for. A new
country by itself is a shrug; a new country plus a burst of failures plus an
odd hour is an incident.

TWO DESIGN DECISIONS WORTH DEFENDING
------------------------------------
1. Only the FIRST occurrence alerts. The detector carries a running set of
   known devices and countries per user, seeded from the baseline and updated
   as it walks forward in time. Without this, a user who switches to a new
   laptop generates an alert on every login forever.

2. Severity is split. A new country is rated higher than a new device, because
   a device string is trivially forged by an attacker and changes legitimately
   all the time (browser auto-updates alone rewrite the user-agent), whereas
   location has at least some physical meaning.

Known false positives, both present in the synthetic dataset by design:
`benign_business_travel` and `benign_new_device`.
"""

from __future__ import annotations

from ..models import OUTCOME_SUCCESS, SEVERITY_RANK, Finding
from ..profiling import profile_is_usable
from .base import Detector, register


@register
class NewDeviceLocationDetector(Detector):
    name = "new_device_location"
    mitre = "T1078 (Valid Accounts)"
    description = (
        "First successful login for an account from a previously unseen device "
        "fingerprint or country."
    )
    default_severity = "medium"
    needs_profiles = True

    def run(self, store, profiles=None) -> list[Finding]:
        profiles = profiles or {}
        min_baseline = int(self.p("min_baseline_events", 25))
        device_severity = self.p("device_severity", "low")
        country_severity = self.p("country_severity", "medium")

        # Running "what we have seen so far" sets, seeded from each baseline.
        seen_devices: dict[str, set[str]] = {}
        seen_countries: dict[str, set[str]] = {}

        findings: list[Finding] = []
        for event in store.all_events(outcome=OUTCOME_SUCCESS):
            profile = profiles.get(event.username)
            if not profile_is_usable(profile, min_baseline):
                continue

            devices = seen_devices.setdefault(
                event.username, set(profile.get("devices", {}).keys())
            )
            countries = seen_countries.setdefault(
                event.username, set(profile.get("countries", {}).keys())
            )

            if event.ts_epoch < profile["built_to"]:
                continue  # inside the baseline window: nothing to compare against

            new_device = bool(event.device_id) and event.device_id not in devices
            new_country = bool(event.geo_country) and event.geo_country not in countries

            # Record the sighting before deciding, so we only ever alert once.
            if new_device:
                devices.add(event.device_id)
            if new_country:
                countries.add(event.geo_country)

            if not (new_device or new_country):
                continue

            findings.append(
                self._finding(
                    event, profile, new_device, new_country,
                    device_severity, country_severity,
                )
            )
        return findings

    def _finding(
        self, event, profile, new_device: bool, new_country: bool,
        device_severity: str, country_severity: str,
    ) -> Finding:
        parts = []
        if new_country:
            parts.append(f"a country never seen for this account ({event.geo_country})")
        if new_device:
            parts.append(f"an unrecognised device ('{event.device}')")
        what = " and ".join(parts)

        severity = country_severity if new_country else device_severity
        if new_device and new_country:
            # Both at once is a meaningfully stronger signal than either alone.
            severity = _escalate(max(
                (device_severity, country_severity), key=lambda s: SEVERITY_RANK.get(s, 0)
            ))

        known_countries = sorted(profile.get("countries", {}).keys())
        known_devices = [
            d.get("label", "?") for d in profile.get("devices", {}).values()
        ]

        reason = (
            f"'{event.username}' authenticated successfully from {what} at "
            f"{event.ts}. Baseline for this account ({profile['event_count']} "
            f"logins) covers {', '.join(known_countries) or 'no countries'} and "
            f"{len(known_devices)} device(s): "
            f"{'; '.join(known_devices) or 'none'}. Source IP {event.src_ip} "
            f"({event.geo_city or 'unknown city'}). On its own this is a weak "
            f"signal - people travel and replace laptops - so it is most useful "
            f"when it correlates with other activity on the same account."
        )
        return Finding(
            detector=self.name,
            severity=severity,
            title=(
                f"New {'location and device' if new_device and new_country else ('location' if new_country else 'device')}"
                f" for {event.username}"
            ),
            reason=reason,
            mitre=self.mitre,
            username=event.username,
            src_ip=event.src_ip,
            first_ts_epoch=event.ts_epoch,
            last_ts_epoch=event.ts_epoch,
            event_ids=[event.event_id],
            evidence={
                "new_country": event.geo_country if new_country else None,
                "new_device": event.device if new_device else None,
                "device_fingerprint": event.device_id,
                "baseline_countries": known_countries,
                "baseline_devices": known_devices,
                "baseline_login_count": profile["event_count"],
                "source_ip": event.src_ip,
                "source_location": (
                    f"{event.geo_city}, {event.geo_country}".strip(", ") or "unknown"
                ),
                "service": event.service,
                "login_time": event.ts,
            },
        )


def _escalate(severity: str) -> str:
    order = ["low", "medium", "high", "critical"]
    idx = order.index(severity) if severity in order else 1
    return order[min(idx + 1, len(order) - 1)]

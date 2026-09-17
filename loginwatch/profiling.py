"""Per-user behavioural baselines.

Two of the detectors (anomalous hour, new device/location) cannot work from a
fixed threshold, because "normal" is different for every account. They need a
baseline: what has this user actually done before?

WHAT GOES INTO A BASELINE
-------------------------
Only SUCCESSFUL logins, and only from the attack-free training window.

Successes only, because a baseline built from failures would happily learn an
attacker's behaviour as normal - the classic way a naive anomaly detector
trains itself into blindness.

Training window only, because a baseline that includes the attacks it is meant
to catch will quietly absorb them. Real deployments do not get a clean training
window and have to handle this with rolling baselines plus exclusion of known-
bad activity; that gap is recorded in LIMITATIONS.md.

WHAT A BASELINE HOLDS
---------------------
  hours      histogram of UTC hour-of-day
  countries  counts per country seen
  devices    counts per device fingerprint, with a readable label

A user with fewer than `min_events_for_profile` events gets a profile row, but
the profile-based detectors refuse to score against it. Alerting on a person
whose behaviour you have barely observed is how you generate noise about new
joiners.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import OUTCOME_SUCCESS
from .storage import Store


def build_profiles(
    store: Store, train_days: int = 14, min_events: int = 25
) -> list[dict]:
    """Build one baseline per user from the first `train_days` of data."""
    start, _end = store.time_range()
    if not start:
        return []
    train_end = start + train_days * 86400

    profiles: dict[str, dict] = {}
    for event in store.events_between(start, train_end):
        if event.outcome != OUTCOME_SUCCESS:
            continue
        p = profiles.setdefault(
            event.username,
            {
                "username": event.username,
                "event_count": 0,
                "first_seen": event.ts_epoch,
                "last_seen": event.ts_epoch,
                "hours": {},
                "countries": {},
                "devices": {},
                "built_from": start,
                "built_to": train_end,
            },
        )
        p["event_count"] += 1
        p["last_seen"] = max(p["last_seen"], event.ts_epoch)

        hour = datetime.fromtimestamp(event.ts_epoch, tz=timezone.utc).hour
        p["hours"][hour] = p["hours"].get(hour, 0) + 1

        if event.geo_country:
            p["countries"][event.geo_country] = (
                p["countries"].get(event.geo_country, 0) + 1
            )
        if event.device_id:
            entry = p["devices"].setdefault(
                event.device_id, {"count": 0, "label": event.device}
            )
            entry["count"] += 1

    out = list(profiles.values())
    store.replace_profiles(out)
    return out


def profile_is_usable(profile: dict | None, min_events: int) -> bool:
    """Whether a baseline is established enough to score against."""
    return bool(profile) and profile.get("event_count", 0) >= min_events


def observed_hours(profile: dict) -> list[int]:
    """Sorted UTC hours in which the account has ever authenticated."""
    return sorted(int(h) for h, count in profile.get("hours", {}).items() if count > 0)


def quiet_hours(
    profile: dict, neighbour: int = 1, min_quiet_hours: int = 4
) -> set[int]:
    """The account's dormant stretch - the hours it is reliably NOT active in.

    WHY NOT JUST "ANY HOUR NOT SEEN BEFORE"
    ---------------------------------------
    The obvious implementation is to flag any hour with a zero count in the
    baseline. It does not survive contact with real data. A user with ~50
    baseline logins spread across a ten-hour working day will, by chance alone,
    have gaps - an hour they happened never to log in during. Flagging those
    produces a stream of alerts about people working at 11am.

    So instead of asking "have we seen this exact hour?", the detector models
    the account's single longest dormant stretch - in practice, the user's
    night - and only flags logins that land deep inside it. Sampling gaps in
    the middle of the working day are absorbed; 3am is not.

    The window is then shrunk by `neighbour` hours at each end, so activity
    just before or after the usual pattern is not treated as an anomaly. If the
    dormant stretch is shorter than `min_quiet_hours`, the account has no
    meaningful off-hours at all (a shared or automated account, say) and the
    detector declines to score it rather than guessing.
    """
    hours = observed_hours(profile)
    if not hours:
        return set()
    if len(hours) == 1:
        gap_len, gap_after = 24, hours[0]
    else:
        gap_len, gap_after = 0, hours[0]
        for index, hour in enumerate(hours):
            following = hours[(index + 1) % len(hours)]
            gap = (following - hour) % 24
            if gap > gap_len:
                gap_len, gap_after = gap, hour

    dormant_length = gap_len - 1  # hours strictly between the two active hours
    core = dormant_length - 2 * neighbour
    if dormant_length < min_quiet_hours or core <= 0:
        return set()
    return {(gap_after + 1 + neighbour + offset) % 24 for offset in range(core)}

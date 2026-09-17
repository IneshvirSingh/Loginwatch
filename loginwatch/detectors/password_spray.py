"""Password spraying: one source, many accounts, only a guess or two each.

MITRE ATT&CK: T1110.003 - Brute Force: Password Spraying

Spraying is designed to defeat brute-force detection and account lockout. The
attacker tries one common password against hundreds of accounts, so no single
account ever accumulates enough failures to trip a per-account threshold.

The detector therefore inverts the grouping: instead of asking "how many
failures did this account see?", it asks "how many DIFFERENT accounts did this
source touch?" - and requires the per-account count to stay LOW, because a
source hammering one account is brute force and already has its own detector.
That low ceiling is what keeps the two detectors from double-reporting.
"""

from __future__ import annotations

from ..models import OUTCOME_FAILURE, Event, Finding
from .base import Detector, group_by, register, sliding_windows, summarise_counts


@register
class PasswordSprayDetector(Detector):
    name = "password_spray"
    mitre = "T1110.003 (Brute Force: Password Spraying)"
    description = (
        "A single source IP producing failed logins against many distinct "
        "accounts, with few attempts per account."
    )
    default_severity = "high"

    def run(self, store, profiles=None) -> list[Finding]:
        window = int(self.p("window_seconds", 1800))
        min_users = int(self.p("min_distinct_users", 10))
        max_per_user = int(self.p("max_failures_per_user", 4))

        findings: list[Finding] = []
        by_ip = group_by(store.all_events(outcome=OUTCOME_FAILURE), lambda e: e.src_ip)

        for src_ip, events in by_ip.items():
            best = self._widest_window(events, window, min_users, max_per_user)
            if best:
                findings.append(self._finding(src_ip, best, window, min_users))
        return findings

    def _widest_window(
        self, events: list[Event], window: int, min_users: int, max_per_user: int
    ) -> list[Event] | None:
        """Return the window touching the most distinct accounts, if any qualifies.

        Reporting only the widest window (rather than every qualifying one)
        keeps a spray to a single alert per source.
        """
        best: list[Event] | None = None
        best_users = 0
        for start, end in sliding_windows(events, window):
            chunk = events[start:end]
            per_user: dict[str, int] = {}
            for event in chunk:
                per_user[event.username] = per_user.get(event.username, 0) + 1
            distinct = len(per_user)
            if distinct < min_users:
                continue
            if max(per_user.values()) > max_per_user:
                # Too deep on one account - that shape belongs to brute_force.
                continue
            if distinct > best_users:
                best, best_users = chunk, distinct
        return best

    def _finding(
        self, src_ip: str, chunk: list[Event], window: int, min_users: int
    ) -> Finding:
        first, last = chunk[0], chunk[-1]
        users = sorted({e.username for e in chunk})
        duration = max(last.ts_epoch - first.ts_epoch, 1)

        # Failures against accounts that do not exist are a strong tell: a
        # legitimate user population does not generate `unknown_user` in bulk.
        unknown_user_hits = sum(1 for e in chunk if e.reason == "unknown_user")

        reason = (
            f"{src_ip} generated {len(chunk)} failed logins against "
            f"{len(users)} distinct accounts in {duration // 60} minutes "
            f"(threshold: {min_users} accounts in {window // 60} minutes), with "
            f"no more than {max(_per_user(chunk).values())} attempts on any one "
            f"account. Low attempts per account with wide account coverage is "
            f"the signature of password spraying rather than brute force."
        )
        if unknown_user_hits:
            reason += (
                f" {unknown_user_hits} attempts targeted accounts that do not "
                f"exist, indicating a scraped or guessed username list."
            )

        return Finding(
            detector=self.name,
            severity=self.severity,
            title=f"Password spraying from {src_ip} against {len(users)} accounts",
            reason=reason,
            mitre=self.mitre,
            username="",  # deliberately account-agnostic: the entity is the IP
            src_ip=src_ip,
            first_ts_epoch=first.ts_epoch,
            last_ts_epoch=last.ts_epoch,
            event_ids=[e.event_id for e in chunk],
            evidence={
                "distinct_accounts": len(users),
                "total_failures": len(chunk),
                "max_attempts_per_account": max(_per_user(chunk).values()),
                "window_seconds": window,
                "duration_seconds": duration,
                "nonexistent_account_attempts": unknown_user_hits,
                "source_location": f"{first.geo_city}, {first.geo_country}".strip(", "),
                "accounts_sample": users[:15],
                "services_targeted": summarise_counts(e.service for e in chunk),
                "client_software": summarise_counts(e.device for e in chunk),
                "first_attempt": first.ts,
                "last_attempt": last.ts,
            },
        )


def _per_user(chunk: list[Event]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in chunk:
        counts[event.username] = counts.get(event.username, 0) + 1
    return counts

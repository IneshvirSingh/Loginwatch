"""Brute force: one source, one account, many password guesses, fast.

MITRE ATT&CK: T1110.001 - Brute Force: Password Guessing

The signal is volume concentrated on a single (account, source) pair inside a
short window. That concentration is what separates it from a user who simply
mistypes their password twice and from a spray, which is wide and shallow
rather than narrow and deep.
"""

from __future__ import annotations

from ..models import OUTCOME_FAILURE, OUTCOME_SUCCESS, Event, Finding
from .base import Detector, find_bursts, group_by, register, summarise_counts


@register
class BruteForceDetector(Detector):
    name = "brute_force"
    mitre = "T1110.001 (Brute Force: Password Guessing)"
    description = (
        "Repeated failed authentications against a single account from a "
        "single source IP within a short window."
    )
    default_severity = "high"

    def run(self, store, profiles=None) -> list[Finding]:
        window = int(self.p("window_seconds", 300))
        min_failures = int(self.p("min_failures", 8))

        failures = store.all_events(outcome=OUTCOME_FAILURE)
        successes_index = _successes_by_user_ip(store)

        findings: list[Finding] = []
        for (username, src_ip), events in group_by(
            failures, lambda e: (e.username, e.src_ip)
        ).items():
            for burst in find_bursts(events, window, min_failures):
                findings.append(
                    self._finding(username, src_ip, burst, window, successes_index)
                )
        return findings

    def _finding(
        self, username: str, src_ip: str, burst: list[Event], window: int,
        successes_index: dict,
    ) -> Finding:
        first, last = burst[0], burst[-1]
        duration = max(last.ts_epoch - first.ts_epoch, 1)
        rate = len(burst) / (duration / 60)

        # Did the guessing actually work? This does not change what the
        # detector *matches*, but it changes how fast a human needs to look at
        # it, so it is surfaced as both evidence and a severity bump.
        breached = [
            e for e in successes_index.get((username, src_ip), [])
            if first.ts_epoch <= e.ts_epoch <= last.ts_epoch + 300
        ]
        severity = "critical" if breached else self.severity

        reason = (
            f"{len(burst)} failed logins for '{username}' from {src_ip} in "
            f"{duration}s (~{rate:.1f}/min), which exceeds the threshold of "
            f"{min_failures_text(self)} within {window}s."
        )
        if breached:
            reason += (
                f" A SUCCESSFUL login from the same source followed at "
                f"{breached[0].ts} - treat as a probable account compromise."
            )

        return Finding(
            detector=self.name,
            severity=severity,
            title=f"Brute force against {username} from {src_ip}",
            reason=reason,
            mitre=self.mitre,
            username=username,
            src_ip=src_ip,
            first_ts_epoch=first.ts_epoch,
            last_ts_epoch=last.ts_epoch,
            event_ids=[e.event_id for e in burst] + [e.event_id for e in breached],
            evidence={
                "failure_count": len(burst),
                "window_seconds": window,
                "threshold": int(self.p("min_failures", 8)),
                "duration_seconds": duration,
                "attempts_per_minute": round(rate, 2),
                "source_location": f"{first.geo_city}, {first.geo_country}".strip(", "),
                "failure_reasons": summarise_counts(e.reason for e in burst),
                "services_targeted": summarise_counts(e.service for e in burst),
                "client_software": summarise_counts(e.device for e in burst),
                "succeeded_after_burst": bool(breached),
                "first_attempt": first.ts,
                "last_attempt": last.ts,
            },
        )


def min_failures_text(detector: Detector) -> str:
    return f"{int(detector.p('min_failures', 8))} failures"


def _successes_by_user_ip(store) -> dict:
    return group_by(
        store.all_events(outcome=OUTCOME_SUCCESS), lambda e: (e.username, e.src_ip)
    )

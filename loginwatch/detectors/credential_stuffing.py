"""Credential stuffing: many sources, one account.

MITRE ATT&CK: T1110.004 - Brute Force: Credential Stuffing

Where brute force is one IP hammering one account, credential stuffing is the
distributed version: an attacker replays leaked username/password pairs from a
botnet or proxy pool, so the failures against a single account arrive from many
different addresses. Per-IP rate limiting does not see it, because no single IP
does very much.

The detector groups by ACCOUNT and counts distinct source IPs in the window.
The distinctness is the signal; the raw failure count on its own would be too
low to trip the brute-force threshold.
"""

from __future__ import annotations

from ..models import OUTCOME_FAILURE, OUTCOME_SUCCESS, Event, Finding
from .base import Detector, group_by, register, sliding_windows, summarise_counts


@register
class CredentialStuffingDetector(Detector):
    name = "credential_stuffing"
    mitre = "T1110.004 (Brute Force: Credential Stuffing)"
    description = (
        "Failed logins against one account arriving from an unusual number of "
        "distinct source IPs in a short window."
    )
    default_severity = "medium"

    def run(self, store, profiles=None) -> list[Finding]:
        window = int(self.p("window_seconds", 1800))
        min_ips = int(self.p("min_distinct_ips", 6))
        min_failures = int(self.p("min_total_failures", 8))

        findings: list[Finding] = []
        by_user = group_by(
            store.all_events(outcome=OUTCOME_FAILURE), lambda e: e.username
        )
        successes = group_by(
            store.all_events(outcome=OUTCOME_SUCCESS), lambda e: e.username
        )

        for username, events in by_user.items():
            best: list[Event] | None = None
            best_ips = 0
            for start, end in sliding_windows(events, window):
                chunk = events[start:end]
                distinct_ips = len({e.src_ip for e in chunk})
                if distinct_ips < min_ips or len(chunk) < min_failures:
                    continue
                if distinct_ips > best_ips:
                    best, best_ips = chunk, distinct_ips
            if best:
                findings.append(
                    self._finding(username, best, window, min_ips, successes)
                )
        return findings

    def _finding(
        self, username: str, chunk: list[Event], window: int, min_ips: int,
        successes: dict,
    ) -> Finding:
        first, last = chunk[0], chunk[-1]
        ips = sorted({e.src_ip for e in chunk})
        countries = sorted({e.geo_country for e in chunk if e.geo_country})
        duration = max(last.ts_epoch - first.ts_epoch, 1)

        breached = [
            e for e in successes.get(username, [])
            if first.ts_epoch <= e.ts_epoch <= last.ts_epoch + 300
            and e.src_ip in set(ips)
        ]
        severity = "critical" if breached else self.severity

        reason = (
            f"Account '{username}' received {len(chunk)} failed logins from "
            f"{len(ips)} distinct source IPs across {len(countries)} "
            f"{'country' if len(countries) == 1 else 'countries'} in "
            f"{duration // 60} minutes (threshold: {min_ips} IPs in "
            f"{window // 60} minutes). Distribution across many sources is "
            f"consistent with replayed credentials from a proxy pool rather "
            f"than a single guessing tool."
        )
        if breached:
            reason += (
                f" One of those source IPs then authenticated SUCCESSFULLY at "
                f"{breached[0].ts}."
            )

        return Finding(
            detector=self.name,
            severity=severity,
            title=f"Distributed credential stuffing against {username}",
            reason=reason,
            mitre=self.mitre,
            username=username,
            src_ip=ips[0] if len(ips) == 1 else "",
            first_ts_epoch=first.ts_epoch,
            last_ts_epoch=last.ts_epoch,
            event_ids=[e.event_id for e in chunk] + [e.event_id for e in breached],
            evidence={
                "distinct_source_ips": len(ips),
                "total_failures": len(chunk),
                "window_seconds": window,
                "duration_seconds": duration,
                "source_countries": countries,
                "source_ips_sample": ips[:12],
                "succeeded_from_attacking_ip": bool(breached),
                "failure_reasons": summarise_counts(e.reason for e in chunk),
                "client_software": summarise_counts(e.device for e in chunk),
                "first_attempt": first.ts,
                "last_attempt": last.ts,
            },
        )

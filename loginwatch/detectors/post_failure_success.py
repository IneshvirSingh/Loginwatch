"""Failures, then a success: the shape of a takeover that worked.

MITRE ATT&CK: T1110 - Brute Force (successful outcome) / T1078 - Valid Accounts

This is the highest-value detection in the project, and the reasoning is worth
stating plainly: a brute-force alert says someone is knocking. This one says
someone got in.

The pattern is a burst of failed logins for an account, immediately followed by
a success within a short grace period. Ordering and adjacency are the whole
signal - the same counts spread across a day mean nothing.

SEVERITY IS DYNAMIC
-------------------
If the successful login comes from an IP that was also producing the failures,
the guessing demonstrably worked and this is rated `critical`. If the success
comes from somewhere else, it is more likely the real user finally getting in
after the attacker gave up (or after their own password reset), so it is rated
one level lower. Encoding that distinction is the difference between an alert
an analyst trusts and one they learn to skim past.

Known false positive: a user who forgets their password, fails five times, and
then succeeds. The `require_same_ip` config option trades recall for precision
here - see DETECTIONS.md.
"""

from __future__ import annotations

from ..models import OUTCOME_FAILURE, OUTCOME_SUCCESS, Event, Finding
from .base import Detector, group_by, register, summarise_counts


@register
class PostFailureSuccessDetector(Detector):
    name = "post_failure_success"
    mitre = "T1110 (Brute Force) / T1078 (Valid Accounts)"
    description = (
        "A burst of failed logins for an account immediately followed by a "
        "successful login - the signature of a guessing attack that worked."
    )
    default_severity = "critical"

    def run(self, store, profiles=None) -> list[Finding]:
        fail_window = int(self.p("failure_window_seconds", 600))
        min_failures = int(self.p("min_failures", 5))
        grace = int(self.p("success_within_seconds", 300))
        require_same_ip = bool(self.p("require_same_ip", False))

        findings: list[Finding] = []
        by_user = group_by(store.all_events(), lambda e: e.username)

        for username, events in by_user.items():
            failures = [e for e in events if e.outcome == OUTCOME_FAILURE]
            if len(failures) < min_failures:
                continue

            for success in (e for e in events if e.outcome == OUTCOME_SUCCESS):
                relevant = [
                    f for f in failures
                    if 0 < success.ts_epoch - f.ts_epoch <= fail_window
                ]
                if require_same_ip:
                    relevant = [f for f in relevant if f.src_ip == success.src_ip]
                if len(relevant) < min_failures:
                    continue

                last_failure = max(relevant, key=lambda e: e.ts_epoch)
                gap = success.ts_epoch - last_failure.ts_epoch
                if gap > grace:
                    continue  # too much daylight between the burst and the win

                findings.append(
                    self._finding(username, success, relevant, gap, min_failures, grace)
                )
        return findings

    def _finding(
        self, username: str, success: Event, failures: list[Event], gap: int,
        min_failures: int, grace: int,
    ) -> Finding:
        failing_ips = {f.src_ip for f in failures}
        same_ip = success.src_ip in failing_ips
        severity = self.severity if same_ip else _demote(self.severity)

        span = max(failures[-1].ts_epoch - failures[0].ts_epoch, 1)
        reason = (
            f"Account '{username}' recorded {len(failures)} failed logins in "
            f"{span}s (threshold: {min_failures}), then authenticated "
            f"SUCCESSFULLY {gap}s later at {success.ts} from {success.src_ip} "
            f"({success.geo_city or 'unknown'}, {success.geo_country or '??'}) "
            f"via {success.service or 'unknown service'}."
        )
        if same_ip:
            reason += (
                " The successful login came from one of the same source IPs "
                "that produced the failures, so the password guessing "
                "succeeded. Treat this account as compromised until proven "
                "otherwise: reset credentials, revoke active sessions, and "
                "review what the account did afterwards."
            )
        else:
            reason += (
                " The success came from a DIFFERENT source IP than the "
                "failures, which is also consistent with the legitimate user "
                "recovering their own account after a failed-password episode. "
                "Confirm with the user before escalating."
            )

        return Finding(
            detector=self.name,
            severity=severity,
            title=(
                f"Successful login after {len(failures)} failures for {username}"
                + (" (same source IP)" if same_ip else "")
            ),
            reason=reason,
            mitre=self.mitre,
            username=username,
            src_ip=success.src_ip,
            first_ts_epoch=failures[0].ts_epoch,
            last_ts_epoch=success.ts_epoch,
            event_ids=[f.event_id for f in failures] + [success.event_id],
            evidence={
                "failure_count": len(failures),
                "failure_span_seconds": span,
                "seconds_to_success": gap,
                "grace_period_seconds": grace,
                "success_from_failing_ip": same_ip,
                "distinct_failure_ips": sorted(failing_ips),
                "success_ip": success.src_ip,
                "success_location": (
                    f"{success.geo_city}, {success.geo_country}".strip(", ") or "unknown"
                ),
                "success_device": success.device,
                "success_service": success.service,
                "success_session": success.session_id,
                "failure_reasons": summarise_counts(f.reason for f in failures),
                "first_failure": failures[0].ts,
                "success_time": success.ts,
            },
        )


def _demote(severity: str) -> str:
    order = ["low", "medium", "high", "critical"]
    idx = order.index(severity) if severity in order else 2
    return order[max(idx - 1, 0)]

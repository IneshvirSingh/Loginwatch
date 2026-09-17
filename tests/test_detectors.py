"""Detector unit tests.

Every detector gets two kinds of test:

  * a true positive - the attack shape it exists to catch
  * benign cases   - ordinary behaviour it must stay quiet about

The benign cases are the ones that matter. Any detector can be made to fire;
the engineering is in not firing on the traveller, the forgetful user, and the
shared office gateway. Several of these tests encode a specific false positive
that an earlier version of the code actually produced.
"""

from __future__ import annotations

import pytest

from loginwatch.detectors.anomalous_hour import AnomalousHourDetector
from loginwatch.detectors.brute_force import BruteForceDetector
from loginwatch.detectors.credential_stuffing import CredentialStuffingDetector
from loginwatch.detectors.impossible_travel import ImpossibleTravelDetector
from loginwatch.detectors.new_device_location import NewDeviceLocationDetector
from loginwatch.detectors.password_spray import PasswordSprayDetector
from loginwatch.detectors.post_failure_success import PostFailureSuccessDetector

from .conftest import (
    BASE,
    LONDON_IP,
    PUNE_IP,
    PUNE_IP2,
    SAO_PAULO_IP,
    SYDNEY_IP,
    make_event,
    make_profile,
)

BRUTE_PARAMS = {"window_seconds": 300, "min_failures": 8, "severity": "high"}
SPRAY_PARAMS = {
    "window_seconds": 1800, "min_distinct_users": 10,
    "max_failures_per_user": 4, "severity": "high",
}
STUFF_PARAMS = {
    "window_seconds": 1800, "min_distinct_ips": 6,
    "min_total_failures": 8, "severity": "medium",
}
TRAVEL_PARAMS = {"max_speed_kmh": 900, "min_distance_km": 500, "severity": "high"}
HOUR_PARAMS = {
    "neighbour_hours": 2, "min_baseline_events": 25,
    "min_quiet_hours": 4, "severity": "medium",
}
NEWDEV_PARAMS = {
    "min_baseline_events": 25, "device_severity": "low",
    "country_severity": "medium", "severity": "medium",
}
PFS_PARAMS = {
    "failure_window_seconds": 600, "min_failures": 5,
    "success_within_seconds": 300, "require_same_ip": False,
    "severity": "critical",
}


class TestBruteForce:
    def test_detects_rapid_failures_from_one_source(self, store, seed):
        seed([
            make_event(offset=i * 10, outcome="failure", reason="bad_password")
            for i in range(12)
        ])
        findings = BruteForceDetector(BRUTE_PARAMS).run(store)
        assert len(findings) == 1
        assert findings[0].evidence["failure_count"] == 12
        assert findings[0].username == "alice.test"
        assert findings[0].src_ip == PUNE_IP

    def test_a_long_burst_produces_one_alert_not_many(self, store, seed):
        """30 guesses is one event for an analyst, not 23 alerts."""
        seed([
            make_event(offset=i * 8, outcome="failure", reason="bad_password")
            for i in range(30)
        ])
        findings = BruteForceDetector(BRUTE_PARAMS).run(store)
        assert len(findings) == 1
        assert findings[0].evidence["failure_count"] == 30

    def test_benign_user_mistyping_password_twice_is_ignored(self, store, seed):
        seed([
            make_event(offset=0, outcome="failure", reason="bad_password"),
            make_event(offset=30, outcome="failure", reason="bad_password"),
            make_event(offset=60, outcome="success"),
        ])
        assert BruteForceDetector(BRUTE_PARAMS).run(store) == []

    def test_failures_spread_across_hours_are_ignored(self, store, seed):
        """Same total volume, no concentration: not an attack."""
        seed([
            make_event(offset=i * 3600, outcome="failure", reason="bad_password")
            for i in range(12)
        ])
        assert BruteForceDetector(BRUTE_PARAMS).run(store) == []

    def test_failures_split_across_two_accounts_do_not_combine(self, store, seed):
        """Grouping is per (account, source). Two users at 6 each is not 12."""
        events = []
        for i in range(6):
            events.append(make_event(offset=i * 10, username="alice.test", outcome="failure"))
            events.append(make_event(offset=i * 10, username="bob.test", outcome="failure"))
        seed(events)
        assert BruteForceDetector(BRUTE_PARAMS).run(store) == []

    def test_severity_escalates_when_the_guessing_worked(self, store, seed):
        seed(
            [make_event(offset=i * 10, outcome="failure") for i in range(12)]
            + [make_event(offset=200, outcome="success")]
        )
        finding = BruteForceDetector(BRUTE_PARAMS).run(store)[0]
        assert finding.evidence["succeeded_after_burst"] is True
        assert finding.severity == "critical"

    def test_reason_is_human_readable_and_cites_the_threshold(self, store, seed):
        seed([make_event(offset=i * 10, outcome="failure") for i in range(12)])
        finding = BruteForceDetector(BRUTE_PARAMS).run(store)[0]
        assert "12 failed logins" in finding.reason
        assert "threshold" in finding.reason.lower()
        assert finding.mitre.startswith("T1110.001")


class TestPasswordSpray:
    def test_detects_one_source_touching_many_accounts(self, store, seed):
        events = []
        for i in range(12):
            for attempt in range(2):
                events.append(make_event(
                    offset=i * 60 + attempt * 10, username=f"user{i:02d}",
                    outcome="failure", reason="bad_password",
                ))
        seed(events)
        findings = PasswordSprayDetector(SPRAY_PARAMS).run(store)
        assert len(findings) == 1
        assert findings[0].evidence["distinct_accounts"] == 12
        assert findings[0].src_ip == PUNE_IP

    def test_does_not_fire_on_a_brute_force_shape(self, store, seed):
        """One account hit 30 times is brute force, and has its own detector."""
        seed([make_event(offset=i * 10, outcome="failure") for i in range(30)])
        assert PasswordSprayDetector(SPRAY_PARAMS).run(store) == []

    def test_shared_office_gateway_over_hours_is_ignored(self, store, seed):
        """Many users behind one NAT IP, but slow: normal for a busy office."""
        events = [
            make_event(offset=i * 1200, username=f"user{i:02d}", outcome="failure")
            for i in range(12)
        ]
        seed(events)
        assert PasswordSprayDetector(SPRAY_PARAMS).run(store) == []

    def test_counts_attempts_against_nonexistent_accounts(self, store, seed):
        events = []
        for i in range(12):
            reason = "unknown_user" if i < 4 else "bad_password"
            events.append(make_event(
                offset=i * 60, username=f"user{i:02d}", outcome="failure", reason=reason,
            ))
        seed(events)
        finding = PasswordSprayDetector(SPRAY_PARAMS).run(store)[0]
        assert finding.evidence["nonexistent_account_attempts"] == 4
        assert "do not exist" in finding.reason

    def test_is_keyed_on_the_source_not_an_account(self, store, seed):
        seed([
            make_event(offset=i * 60, username=f"user{i:02d}", outcome="failure")
            for i in range(12)
        ])
        finding = PasswordSprayDetector(SPRAY_PARAMS).run(store)[0]
        assert finding.username == ""
        assert finding.src_ip == PUNE_IP


class TestCredentialStuffing:
    def test_detects_many_sources_against_one_account(self, store, seed):
        events = []
        for i in range(8):
            ip = f"198.18.{i}.50"
            events += [
                make_event(offset=i * 90 + a * 20, src_ip=ip, outcome="failure")
                for a in range(2)
            ]
        seed(events)
        findings = CredentialStuffingDetector(STUFF_PARAMS).run(store)
        assert len(findings) == 1
        assert findings[0].evidence["distinct_source_ips"] == 8
        assert findings[0].username == "alice.test"

    def test_does_not_fire_on_a_single_source(self, store, seed):
        seed([make_event(offset=i * 20, outcome="failure") for i in range(16)])
        assert CredentialStuffingDetector(STUFF_PARAMS).run(store) == []

    def test_sources_spread_over_hours_are_ignored(self, store, seed):
        events = [
            make_event(offset=i * 3600, src_ip=f"198.18.{i}.50", outcome="failure")
            for i in range(8)
        ]
        seed(events)
        assert CredentialStuffingDetector(STUFF_PARAMS).run(store) == []

    def test_records_the_countries_involved(self, store, seed):
        events = []
        for i in range(8):
            events += [
                make_event(offset=i * 90 + a * 20, src_ip=f"198.18.{i}.50", outcome="failure")
                for a in range(2)
            ]
        seed(events)
        finding = CredentialStuffingDetector(STUFF_PARAMS).run(store)[0]
        assert len(finding.evidence["source_countries"]) > 1


class TestImpossibleTravel:
    def test_detects_two_continents_in_forty_minutes(self, store, seed):
        seed([
            make_event(offset=0, src_ip=PUNE_IP, outcome="success"),
            make_event(offset=40 * 60, src_ip=SAO_PAULO_IP, outcome="success"),
        ])
        findings = ImpossibleTravelDetector(TRAVEL_PARAMS).run(store)
        assert len(findings) == 1
        assert findings[0].evidence["implied_speed_kmh"] > 900
        assert findings[0].evidence["distance_km"] > 4000

    def test_real_flight_time_is_not_flagged(self, store, seed):
        """Pune to London overnight: far, but entirely possible."""
        seed([
            make_event(offset=0, src_ip=PUNE_IP, outcome="success"),
            make_event(offset=15 * 3600, src_ip=LONDON_IP, outcome="success"),
        ])
        assert ImpossibleTravelDetector(TRAVEL_PARAMS).run(store) == []

    def test_short_hops_are_ignored(self, store, seed):
        """Below min_distance_km, because crude IP geolocation invents motion."""
        seed([
            make_event(offset=0, src_ip=PUNE_IP, outcome="success"),
            make_event(offset=300, src_ip="198.18.1.5", outcome="success"),  # Mumbai
        ])
        assert ImpossibleTravelDetector(TRAVEL_PARAMS).run(store) == []

    def test_only_successful_logins_are_compared(self, store, seed):
        """A failure tells you where someone TRIED from, not where the user is."""
        seed([
            make_event(offset=0, src_ip=PUNE_IP, outcome="success"),
            make_event(offset=600, src_ip=SAO_PAULO_IP, outcome="failure"),
        ])
        assert ImpossibleTravelDetector(TRAVEL_PARAMS).run(store) == []

    def test_different_accounts_are_never_compared(self, store, seed):
        seed([
            make_event(offset=0, username="alice.test", src_ip=PUNE_IP),
            make_event(offset=600, username="bob.test", src_ip=SAO_PAULO_IP),
        ])
        assert ImpossibleTravelDetector(TRAVEL_PARAMS).run(store) == []

    def test_ungeolocatable_events_are_skipped_not_guessed(self, store, seed):
        seed([
            make_event(offset=0, src_ip=PUNE_IP, outcome="success"),
            make_event(offset=600, src_ip="203.0.113.7", outcome="success"),
        ])
        assert ImpossibleTravelDetector(TRAVEL_PARAMS).run(store) == []

    def test_simultaneous_logins_do_not_divide_by_zero(self, store, seed):
        seed([
            make_event(offset=0, src_ip=PUNE_IP, outcome="success"),
            make_event(offset=0, src_ip=SYDNEY_IP, outcome="success"),
        ])
        findings = ImpossibleTravelDetector(TRAVEL_PARAMS).run(store)
        assert len(findings) == 1
        assert findings[0].evidence["implied_speed_kmh"] > 900


class TestAnomalousHour:
    PROFILES = {"alice.test": make_profile()}

    def test_detects_a_login_deep_in_the_dormant_window(self, store, seed):
        seed([make_event(offset=0, base=_at_utc_hour(2), outcome="success")])
        findings = AnomalousHourDetector(HOUR_PARAMS).run(store, self.PROFILES)
        assert len(findings) == 1
        assert findings[0].evidence["login_hour_utc"] == 2

    def test_login_just_outside_the_usual_band_is_tolerated(self, store, seed):
        """Baseline ends at 16:00 UTC; 17:00 is inside the tolerance."""
        seed([make_event(offset=0, base=_at_utc_hour(17), outcome="success")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, self.PROFILES) == []

    def test_login_inside_the_usual_band_is_ignored(self, store, seed):
        seed([make_event(offset=0, base=_at_utc_hour(10), outcome="success")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, self.PROFILES) == []

    def test_sparse_gap_in_the_working_day_is_not_an_anomaly(self, store, seed):
        """The bug this guards: a user with no 11:00 logins in the baseline is
        not doing anything interesting by logging in at 11:00."""
        profile = make_profile(hours={6: 5, 7: 5, 8: 5, 9: 5, 12: 5, 13: 5, 14: 5, 15: 5})
        seed([make_event(offset=0, base=_at_utc_hour(11), outcome="success")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, {"alice.test": profile}) == []

    def test_account_with_too_little_history_is_skipped(self, store, seed):
        profile = make_profile(event_count=10)
        seed([make_event(offset=0, base=_at_utc_hour(2), outcome="success")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, {"alice.test": profile}) == []

    def test_round_the_clock_account_is_skipped(self, store, seed):
        """A service account with no dormant window cannot be 'off-hours'."""
        profile = make_profile(hours={h: 5 for h in range(24)})
        seed([make_event(offset=0, base=_at_utc_hour(3), outcome="success")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, {"alice.test": profile}) == []

    def test_events_inside_the_training_window_are_not_scored(self, store, seed):
        """The baseline already learned from them; scoring them is circular."""
        profile = make_profile(built_to=BASE + 10 * 86400)
        seed([make_event(offset=0, base=_at_utc_hour(2), outcome="success")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, {"alice.test": profile}) == []

    def test_failures_are_not_scored(self, store, seed):
        seed([make_event(offset=0, base=_at_utc_hour(2), outcome="failure")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, self.PROFILES) == []

    def test_user_with_no_profile_is_skipped(self, store, seed):
        seed([make_event(offset=0, base=_at_utc_hour(2), username="stranger")])
        assert AnomalousHourDetector(HOUR_PARAMS).run(store, self.PROFILES) == []


class TestNewDeviceLocation:
    PROFILES = {"alice.test": make_profile()}

    def test_detects_a_new_country(self, store, seed):
        seed([make_event(offset=0, src_ip=LONDON_IP, outcome="success")])
        findings = NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, self.PROFILES)
        assert len(findings) == 1
        assert findings[0].evidence["new_country"] == "GB"

    def test_detects_a_new_device(self, store, seed):
        seed([make_event(offset=0, device="Chrome/121 Linux x86_64", outcome="success")])
        findings = NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, self.PROFILES)
        assert len(findings) == 1
        assert findings[0].evidence["new_device"] == "Chrome/121 Linux x86_64"
        assert findings[0].severity == "low"

    def test_new_country_outranks_new_device(self, store, seed):
        seed([make_event(offset=0, src_ip=LONDON_IP, outcome="success")])
        finding = NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, self.PROFILES)[0]
        assert finding.severity == "medium"

    def test_both_at_once_escalates(self, store, seed):
        seed([make_event(
            offset=0, src_ip=LONDON_IP, device="Chrome/121 Linux x86_64", outcome="success",
        )])
        finding = NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, self.PROFILES)[0]
        assert finding.severity == "high"

    def test_known_device_and_country_produce_nothing(self, store, seed):
        seed([make_event(offset=0, src_ip=PUNE_IP2, outcome="success")])
        assert NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, self.PROFILES) == []

    def test_only_the_first_sighting_alerts(self, store, seed):
        """Otherwise a new laptop generates an alert on every login, forever."""
        seed([
            make_event(offset=i * 3600, device="Chrome/128 macOS", outcome="success")
            for i in range(5)
        ])
        findings = NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, self.PROFILES)
        assert len(findings) == 1

    def test_account_with_too_little_history_is_skipped(self, store, seed):
        profile = make_profile(event_count=5)
        seed([make_event(offset=0, src_ip=LONDON_IP, outcome="success")])
        assert NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, {"alice.test": profile}) == []

    def test_failures_do_not_teach_or_trigger(self, store, seed):
        seed([make_event(offset=0, src_ip=LONDON_IP, outcome="failure")])
        assert NewDeviceLocationDetector(NEWDEV_PARAMS).run(store, self.PROFILES) == []


class TestPostFailureSuccess:
    def test_detects_failures_followed_by_a_success(self, store, seed):
        seed(
            [make_event(offset=i * 30, outcome="failure") for i in range(6)]
            + [make_event(offset=240, outcome="success")]
        )
        findings = PostFailureSuccessDetector(PFS_PARAMS).run(store)
        assert len(findings) == 1
        assert findings[0].evidence["failure_count"] == 6
        assert findings[0].evidence["success_from_failing_ip"] is True
        assert findings[0].severity == "critical"

    def test_success_from_a_different_source_is_rated_lower(self, store, seed):
        """More likely the real user finally getting in - still worth a look."""
        seed(
            [make_event(offset=i * 30, src_ip=PUNE_IP, outcome="failure") for i in range(6)]
            + [make_event(offset=240, src_ip=LONDON_IP, outcome="success")]
        )
        finding = PostFailureSuccessDetector(PFS_PARAMS).run(store)[0]
        assert finding.evidence["success_from_failing_ip"] is False
        assert finding.severity == "high"
        assert "DIFFERENT source IP" in finding.reason

    def test_a_couple_of_typos_then_success_is_ignored(self, store, seed):
        seed(
            [make_event(offset=i * 30, outcome="failure") for i in range(3)]
            + [make_event(offset=120, outcome="success")]
        )
        assert PostFailureSuccessDetector(PFS_PARAMS).run(store) == []

    def test_success_long_after_the_failures_is_ignored(self, store, seed):
        """Adjacency is the signal. An hour later is a different story."""
        seed(
            [make_event(offset=i * 30, outcome="failure") for i in range(6)]
            + [make_event(offset=3600, outcome="success")]
        )
        assert PostFailureSuccessDetector(PFS_PARAMS).run(store) == []

    def test_require_same_ip_option_tightens_the_rule(self, store, seed):
        seed(
            [make_event(offset=i * 30, src_ip=PUNE_IP, outcome="failure") for i in range(6)]
            + [make_event(offset=240, src_ip=LONDON_IP, outcome="success")]
        )
        params = dict(PFS_PARAMS, require_same_ip=True)
        assert PostFailureSuccessDetector(params).run(store) == []

    def test_failures_from_another_account_do_not_count(self, store, seed):
        seed(
            [make_event(offset=i * 30, username="bob.test", outcome="failure") for i in range(6)]
            + [make_event(offset=240, username="alice.test", outcome="success")]
        )
        assert PostFailureSuccessDetector(PFS_PARAMS).run(store) == []

    def test_evidence_records_what_the_attacker_reached(self, store, seed):
        seed(
            [make_event(offset=i * 30, outcome="failure") for i in range(6)]
            + [make_event(offset=240, outcome="success", service="admin_portal")]
        )
        finding = PostFailureSuccessDetector(PFS_PARAMS).run(store)[0]
        assert finding.evidence["success_service"] == "admin_portal"
        assert finding.evidence["success_session"]


class TestThresholdsComeFromConfig:
    """Thresholds must be tunable without touching detector code."""

    @pytest.mark.parametrize("min_failures,expected", [(8, 1), (20, 0)])
    def test_raising_the_threshold_silences_the_detector(
        self, store, seed, min_failures, expected
    ):
        seed([make_event(offset=i * 10, outcome="failure") for i in range(12)])
        params = dict(BRUTE_PARAMS, min_failures=min_failures)
        assert len(BruteForceDetector(params).run(store)) == expected

    def test_severity_is_read_from_config(self, store, seed):
        seed([make_event(offset=i * 10, outcome="failure") for i in range(12)])
        finding = BruteForceDetector(dict(BRUTE_PARAMS, severity="low")).run(store)[0]
        assert finding.severity == "low"


def _at_utc_hour(hour: int) -> int:
    """An epoch on the base day at the given UTC hour."""
    day_start = BASE - (BASE % 86400)
    return day_start + hour * 3600

"""Storage layer and baseline-building tests."""

from __future__ import annotations

from loginwatch.models import Finding, ParseError
from loginwatch.profiling import (
    build_profiles,
    observed_hours,
    profile_is_usable,
    quiet_hours,
)

from .conftest import BASE, LONDON_IP, PUNE_IP, make_event, make_profile


class TestEventStorage:
    def test_round_trips_an_event_with_all_fields(self, store, seed):
        original = make_event(outcome="failure", reason="bad_password")
        seed([original])
        loaded = store.all_events()[0]
        assert loaded.event_id == original.event_id
        assert loaded.username == original.username
        assert loaded.geo_city == "Pune"
        assert loaded.lat is not None
        assert loaded.reason == "bad_password"

    def test_reingesting_the_same_events_does_not_duplicate(self, store):
        events = [make_event(offset=i) for i in range(5)]
        store.insert_events(events)
        store.insert_events(events)
        assert store.event_count() == 5

    def test_filters_by_outcome(self, store, seed):
        seed([
            make_event(offset=0, outcome="success"),
            make_event(offset=1, outcome="failure"),
            make_event(offset=2, outcome="failure"),
        ])
        assert len(store.all_events(outcome="failure")) == 2
        assert len(store.all_events(outcome="success")) == 1

    def test_time_window_query(self, store, seed):
        seed([make_event(offset=i * 3600) for i in range(5)])
        window = store.events_between(BASE, BASE + 2 * 3600)
        assert len(window) == 2

    def test_events_are_returned_in_time_order(self, store, seed):
        seed([make_event(offset=o) for o in (500, 100, 300)])
        offsets = [e.ts_epoch for e in store.all_events()]
        assert offsets == sorted(offsets)

    def test_malformed_lines_are_persisted_not_dropped(self, store):
        store.insert_parse_errors([
            ParseError(3, "garbage", "line does not match syslog header", "auth.log")
        ])
        assert store.parse_error_count() == 1
        assert store.parse_errors()[0]["error"].startswith("line does not match")


class TestAlertStorage:
    def _finding(self, **kwargs) -> Finding:
        defaults = dict(
            detector="brute_force", severity="high", title="t", reason="r",
            mitre="T1110.001", username="alice.test", src_ip=PUNE_IP,
            first_ts_epoch=BASE, last_ts_epoch=BASE + 100,
            event_ids=["ev1", "ev2"], evidence={"failure_count": 9},
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_stores_a_finding_as_an_alert(self, store):
        store.upsert_alert(self._finding())
        alerts = store.list_alerts()
        assert len(alerts) == 1
        assert alerts[0]["status"] == "new"
        assert alerts[0]["detector"] == "brute_force"

    def test_rerunning_detection_updates_rather_than_duplicates(self, store):
        store.upsert_alert(self._finding())
        store.upsert_alert(self._finding(last_ts_epoch=BASE + 500))
        alerts = store.list_alerts()
        assert len(alerts) == 1
        assert alerts[0]["last_ts_epoch"] == BASE + 500

    def test_analyst_triage_survives_a_detection_rerun(self, store):
        """The single most important property of the alert table."""
        store.upsert_alert(self._finding())
        alert_id = store.list_alerts()[0]["id"]
        store.update_alert(alert_id, status="false_positive", note="known VPN")

        store.upsert_alert(self._finding(last_ts_epoch=BASE + 900))

        alert = store.get_alert(alert_id)
        assert alert["status"] == "false_positive"
        assert alert["analyst_note"] == "known VPN"

    def test_triage_actions_are_logged(self, store):
        store.upsert_alert(self._finding())
        alert_id = store.list_alerts()[0]["id"]
        store.update_alert(alert_id, status="investigating", note="looking")
        store.update_alert(alert_id, status="resolved", note="user confirmed")
        log = store.triage_log("alert", alert_id)
        assert len(log) == 2
        assert "resolved" in log[-1]["action"]

    def test_filters_alerts(self, store):
        store.upsert_alert(self._finding())
        store.upsert_alert(
            self._finding(detector="anomalous_hour", severity="medium",
                          username="bob.test", event_ids=["ev9"])
        )
        assert len(store.list_alerts(severity="high")) == 1
        assert len(store.list_alerts(detector="anomalous_hour")) == 1
        assert len(store.list_alerts(username="bob.test")) == 1

    def test_updating_a_missing_alert_reports_failure(self, store):
        assert store.update_alert(999, status="resolved") is False


class TestIncidentStorage:
    def test_creates_an_incident_and_links_its_alerts(self, store):
        for i in range(2):
            store.upsert_alert(Finding(
                detector="brute_force", severity="high", title=f"t{i}", reason="r",
                mitre="T1110", username="alice.test", src_ip=PUNE_IP,
                first_ts_epoch=BASE, last_ts_epoch=BASE + 10,
                event_ids=[f"ev{i}"], evidence={},
            ))
        alert_ids = [a["id"] for a in store.list_alerts()]
        incident_id = store.create_incident(
            "Test incident", "high", {"usernames": ["alice.test"]},
            BASE, BASE + 10, alert_ids,
        )
        assert store.get_incident(incident_id)["alert_count"] == 2
        assert len(store.list_alerts(incident_id=incident_id)) == 2

    def test_records_an_analyst_verdict(self, store):
        incident_id = store.create_incident("t", "high", {}, BASE, BASE, [])
        store.update_incident(
            incident_id, verdict="false_positive", note="corporate VPN egress"
        )
        incident = store.get_incident(incident_id)
        assert incident["verdict"] == "false_positive"
        assert incident["analyst_note"] == "corporate VPN egress"
        assert store.triage_log("incident", incident_id)


class TestProfiling:
    def test_builds_a_baseline_from_the_training_window(self, store, seed):
        seed([
            make_event(offset=i * 3600, outcome="success", base=BASE)
            for i in range(20)
        ])
        profiles = build_profiles(store, train_days=14)
        assert len(profiles) == 1
        assert profiles[0]["event_count"] == 20
        assert profiles[0]["countries"] == {"IN": 20}

    def test_failures_never_enter_the_baseline(self, store, seed):
        """Otherwise an attacker's behaviour is learned as normal."""
        seed(
            [make_event(offset=i, outcome="success") for i in range(5)]
            + [make_event(offset=100 + i, outcome="failure", src_ip=LONDON_IP)
               for i in range(20)]
        )
        profile = build_profiles(store, train_days=14)[0]
        assert profile["event_count"] == 5
        assert "GB" not in profile["countries"]

    def test_events_after_the_training_window_are_excluded(self, store, seed):
        seed(
            [make_event(offset=0, outcome="success")]
            + [make_event(offset=20 * 86400, outcome="success", src_ip=LONDON_IP)]
        )
        profile = build_profiles(store, train_days=14)[0]
        assert profile["event_count"] == 1
        assert "GB" not in profile["countries"]

    def test_profiles_persist_and_reload(self, store, seed):
        seed([make_event(offset=i * 60, outcome="success") for i in range(10)])
        build_profiles(store, train_days=14)
        reloaded = store.profiles()
        assert "alice.test" in reloaded
        assert isinstance(next(iter(reloaded["alice.test"]["hours"])), int)

    def test_usability_gate(self):
        assert profile_is_usable(make_profile(event_count=30), 25) is True
        assert profile_is_usable(make_profile(event_count=10), 25) is False
        assert profile_is_usable(None, 25) is False


class TestQuietHours:
    def test_finds_the_overnight_dormant_window(self):
        profile = make_profile(hours={h: 5 for h in range(6, 17)})
        quiet = quiet_hours(profile, neighbour=2, min_quiet_hours=4)
        assert 2 in quiet and 23 in quiet
        assert 10 not in quiet

    def test_applies_tolerance_at_both_ends(self):
        """Active 06-16, so 17-18 and 04-05 stay out of the dormant set."""
        profile = make_profile(hours={h: 5 for h in range(6, 17)})
        quiet = quiet_hours(profile, neighbour=2, min_quiet_hours=4)
        assert 17 not in quiet and 18 not in quiet
        assert 5 not in quiet and 4 not in quiet

    def test_window_wraps_around_midnight(self):
        """A user active 20:00-04:00 UTC is dormant during the day."""
        profile = make_profile(hours={h % 24: 5 for h in range(20, 29)})
        quiet = quiet_hours(profile, neighbour=2, min_quiet_hours=4)
        assert 12 in quiet
        assert 22 not in quiet and 2 not in quiet

    def test_sparse_midday_gaps_do_not_create_a_dormant_window(self):
        profile = make_profile(hours={6: 5, 7: 5, 8: 5, 12: 5, 13: 5, 14: 5, 15: 5})
        quiet = quiet_hours(profile, neighbour=2, min_quiet_hours=4)
        assert 9 not in quiet and 10 not in quiet and 11 not in quiet

    def test_round_the_clock_account_has_no_dormant_window(self):
        profile = make_profile(hours={h: 5 for h in range(24)})
        assert quiet_hours(profile, neighbour=2, min_quiet_hours=4) == set()

    def test_empty_baseline_yields_nothing(self):
        assert quiet_hours(make_profile(hours={}), 2, 4) == set()

    def test_observed_hours_ignores_zero_counts(self):
        profile = make_profile(hours={8: 3, 9: 0, 10: 2})
        assert observed_hours(profile) == [8, 10]

"""Parsing and normalization tests.

The parser is the project's only contact with untrusted input, so these tests
lean hard on the failure cases. A parser that raises on a malformed line takes
the whole ingestion pipeline down with it.
"""

from __future__ import annotations

from loginwatch.generator import Generator
from loginwatch.logfmt import format_log_line, parse_line, parse_stream
from loginwatch.models import Event, ParseError, device_fingerprint

GOOD_LINE = (
    '2026-09-01T08:14:22Z authgw01 authsvc[1423]: event=auth_attempt '
    'eid=3f9a1c2b0000 user="alice.nguyen" src_ip=198.18.0.14 '
    'device="Chrome/126 Windows" service=vpn outcome=failure '
    'reason=bad_password session=-'
)


class TestValidLines:
    def test_parses_all_fields(self):
        event = parse_line(GOOD_LINE)
        assert isinstance(event, Event)
        assert event.event_id == "3f9a1c2b0000"
        assert event.username == "alice.nguyen"
        assert event.src_ip == "198.18.0.14"
        assert event.outcome == "failure"
        assert event.reason == "bad_password"
        assert event.service == "vpn"
        assert event.host == "authgw01"
        assert event.ts == "2026-09-01T08:14:22Z"

    def test_quoted_value_containing_spaces_survives(self):
        """The whole reason for a tokenizer rather than a naive split()."""
        event = parse_line(GOOD_LINE)
        assert event.device == "Chrome/126 Windows"

    def test_dash_means_absent_not_the_literal_string(self):
        event = parse_line(GOOD_LINE)
        assert event.session_id == ""

    def test_enriches_with_geolocation(self):
        """Normalization is not just parsing: the IP is resolved to a place."""
        event = parse_line(GOOD_LINE)
        assert event.geo_city == "Pune"
        assert event.geo_country == "IN"
        assert event.lat is not None and event.lon is not None

    def test_derives_device_fingerprint(self):
        event = parse_line(GOOD_LINE)
        assert event.device_id == device_fingerprint("Chrome/126 Windows")
        assert event.device_id != "unknown"

    def test_username_is_lowercased(self):
        line = GOOD_LINE.replace('user="alice.nguyen"', 'user="Alice.Nguyen"')
        assert parse_line(line).username == "alice.nguyen"

    def test_unknown_ip_range_leaves_location_empty_rather_than_guessing(self):
        line = GOOD_LINE.replace("198.18.0.14", "203.0.113.99")
        event = parse_line(line)
        assert isinstance(event, Event)
        assert event.geo_country == ""
        assert event.lat is None

    def test_epoch_matches_iso_timestamp(self):
        event = parse_line(GOOD_LINE)
        from loginwatch.models import from_epoch

        assert from_epoch(event.ts_epoch) == event.ts


class TestMalformedLines:
    """Every one of these must return a ParseError, never raise."""

    def test_no_syslog_header(self):
        result = parse_line("user=orphan src_ip=198.18.2.2 outcome=success service=vpn")
        assert isinstance(result, ParseError)
        assert "syslog header" in result.error

    def test_missing_required_field(self):
        line = GOOD_LINE.replace("outcome=failure ", "")
        result = parse_line(line)
        assert isinstance(result, ParseError)
        assert "outcome" in result.error

    def test_invalid_outcome_value(self):
        line = GOOD_LINE.replace("outcome=failure", "outcome=maybe")
        result = parse_line(line)
        assert isinstance(result, ParseError)
        assert "invalid outcome" in result.error

    def test_impossible_timestamp(self):
        line = GOOD_LINE.replace("2026-09-01T08:14:22Z", "2026-13-45T99:99:99Z")
        result = parse_line(line)
        assert isinstance(result, ParseError)
        assert "timestamp" in result.error

    def test_truncated_line(self):
        result = parse_line(
            "2026-09-10T08:01:02Z authgw01 authsvc[2211]: event=auth_attempt eid=ca"
        )
        assert isinstance(result, ParseError)

    def test_empty_and_whitespace_lines(self):
        assert isinstance(parse_line(""), ParseError)
        assert isinstance(parse_line("   \n"), ParseError)

    def test_rotation_marker_from_another_tool(self):
        result = parse_line("<<<< log rotated by logrotate >>>>")
        assert isinstance(result, ParseError)

    def test_parse_error_records_line_number_for_investigation(self):
        result = parse_line("garbage", line_no=42, source_file="auth.log")
        assert isinstance(result, ParseError)
        assert result.line_no == 42
        assert result.source_file == "auth.log"

    def test_one_bad_line_does_not_stop_the_stream(self):
        lines = [GOOD_LINE, "garbage", GOOD_LINE.replace("3f9a1c2b0000", "aaaabbbbcccc")]
        results = list(parse_stream(lines))
        assert [type(r) is Event for r in results] == [True, False, True]


class TestRoundTrip:
    def test_format_then_parse_preserves_the_record(self):
        """The generator writes with format_log_line; the parser must read it back."""
        record = {
            "event_id": "abcdef012345",
            "ts": "2026-09-05T11:30:00Z",
            "username": "maya.silva",
            "src_ip": "198.18.5.44",
            "device": "Safari/17 macOS",
            "service": "sso_portal",
            "outcome": "success",
            "reason": "",
            "session_id": "0123456789abcdef",
            "host": "ssoedge01",
            "pid": 2211,
        }
        event = parse_line(format_log_line(record))
        assert isinstance(event, Event)
        assert event.event_id == record["event_id"]
        assert event.username == record["username"]
        assert event.device == record["device"]
        assert event.session_id == record["session_id"]
        assert event.outcome == "success"
        assert event.reason == ""

    def test_every_generated_line_parses_except_the_deliberate_junk(self, tmp_path):
        gen = Generator(seed=7, users=5, days=3, attack_free_days=2)
        gen.build()
        manifest = gen.write(tmp_path)

        from loginwatch.logfmt import parse_file

        results = list(parse_file(tmp_path / "auth.log"))
        errors = [r for r in results if isinstance(r, ParseError)]
        events = [r for r in results if isinstance(r, Event)]

        assert len(events) == manifest["valid_events"]
        assert len(errors) == manifest["malformed_lines"]

    def test_generator_is_reproducible_for_a_seed(self, tmp_path):
        first, second = tmp_path / "a", tmp_path / "b"
        for out in (first, second):
            gen = Generator(seed=99, users=4, days=3, attack_free_days=2)
            gen.build()
            gen.write(out)
        assert (first / "auth.log").read_text() == (second / "auth.log").read_text()

"""The raw log format: how we write it, and how we parse it back.

FORMAT
------
A syslog-style header followed by structured key=value pairs. This shape is
common in real appliance and gateway logs (pfSense, Fortinet, Sophos, many
custom auth services): a human-readable prefix plus machine-parseable fields.

    2026-09-01T08:14:22Z authgw01 authsvc[1423]: event=auth_attempt eid=3f9a1c2b
    user="alice.nguyen" src_ip=198.18.0.14 device="Chrome/126 Windows"
    service=vpn outcome=failure reason=bad_password session=-

(one event per line; wrapped here only for readability)

It was chosen over plain JSON-lines on purpose: parsing it requires real work
(header regex + a tokenizer that respects quoted values), which is the point of
having an ingestion layer at all. A `-` value means "absent", the usual syslog
convention.

NORMALIZATION
-------------
Parsing is only half the job. `parse_line` also *enriches*: it resolves the
source IP to a location via geo.lookup and derives a device fingerprint. Those
derived fields are what the detectors actually reason over.

Anything that cannot be turned into a valid Event becomes a ParseError rather
than an exception. Malformed lines are a normal condition in log ingestion, not
an emergency, but they are recorded so they can be counted and investigated.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Iterator

from . import geo
from .models import (
    VALID_OUTCOMES,
    Event,
    ParseError,
    device_fingerprint,
    to_epoch,
)

# Syslog-ish header: timestamp, host, process[pid]: rest
HEADER_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+"
    r"(?P<host>[A-Za-z0-9_.\-]+)\s+"
    r"(?P<proc>[A-Za-z0-9_.\-]+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<kv>.+)$"
)

# key=value or key="quoted value with spaces"
KV_RE = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)="
    r'(?:"(?P<qval>[^"]*)"|(?P<val>[^\s]*))'
)

REQUIRED_KEYS = ("eid", "user", "src_ip", "outcome", "service")

# Fields that may legitimately be absent, written as `-`
NULL_TOKEN = "-"


def _clean(value: str | None) -> str:
    if value is None:
        return ""
    value = value.strip()
    return "" if value == NULL_TOKEN else value


def _quote(value) -> str:
    """Quote a value for output if it contains spaces; `-` if empty."""
    text = "" if value is None else str(value)
    if text == "":
        return NULL_TOKEN
    return f'"{text}"' if " " in text else text


def format_log_line(rec: dict) -> str:
    """Render one event record as a raw log line.

    Used by the generator. Keeping it next to the parser means the format is
    defined in exactly one file.
    """
    fields = [
        ("event", "auth_attempt"),
        ("eid", rec["event_id"]),
        ("user", rec["username"]),
        ("src_ip", rec["src_ip"]),
        ("device", rec.get("device", "")),
        ("service", rec.get("service", "")),
        ("outcome", rec["outcome"]),
        ("reason", rec.get("reason", "")),
        ("session", rec.get("session_id", "")),
    ]
    kv = " ".join(f"{k}={_quote(v)}" for k, v in fields)
    return f"{rec['ts']} {rec.get('host', 'authgw01')} authsvc[{rec.get('pid', 1423)}]: {kv}"


def parse_line(line: str, line_no: int = 0, source_file: str = "") -> Event | ParseError:
    """Parse and enrich a single raw log line.

    Returns an Event on success, a ParseError on failure. Never raises for bad
    input - that is the contract the ingestion loop relies on.
    """
    text = line.rstrip("\n").rstrip("\r")
    if not text.strip():
        return ParseError(line_no, line, "empty line", source_file)

    header = HEADER_RE.match(text)
    if not header:
        return ParseError(line_no, text, "line does not match syslog header", source_file)

    kv_text = header.group("kv")
    fields = {}
    for match in KV_RE.finditer(kv_text):
        qval, val = match.group("qval"), match.group("val")
        fields[match.group("key")] = qval if qval is not None else val

    missing = [k for k in REQUIRED_KEYS if not _clean(fields.get(k))]
    if missing:
        return ParseError(
            line_no, text, f"missing required field(s): {','.join(missing)}", source_file
        )

    outcome = _clean(fields["outcome"]).lower()
    if outcome not in VALID_OUTCOMES:
        return ParseError(
            line_no, text, f"invalid outcome value: {outcome!r}", source_file
        )

    ts = header.group("ts")
    try:
        ts_epoch = to_epoch(ts)
    except ValueError as exc:  # header regex makes this very unlikely
        return ParseError(line_no, text, f"bad timestamp: {exc}", source_file)

    src_ip = _clean(fields["src_ip"])
    device = _clean(fields.get("device"))

    # --- enrichment -------------------------------------------------------
    site = geo.lookup(src_ip)

    return Event(
        event_id=_clean(fields["eid"]),
        ts=ts,
        ts_epoch=ts_epoch,
        username=_clean(fields["user"]).lower(),
        src_ip=src_ip,
        outcome=outcome,
        service=_clean(fields["service"]),
        host=header.group("host"),
        reason=_clean(fields.get("reason")),
        device=device,
        device_id=device_fingerprint(device),
        geo_city=site.name if site else "",
        geo_country=site.country if site else "",
        lat=site.lat if site else None,
        lon=site.lon if site else None,
        session_id=_clean(fields.get("session")),
        raw_line=text,
    )


def parse_stream(
    lines: Iterable[str], source_file: str = ""
) -> Iterator[Event | ParseError]:
    for i, line in enumerate(lines, start=1):
        yield parse_line(line, i, source_file)


def parse_file(path: str | Path) -> Iterator[Event | ParseError]:
    path = Path(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from parse_stream(fh, str(path))

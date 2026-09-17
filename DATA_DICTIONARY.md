# Data dictionary

The log format, the normalized event schema, the database schema, and exactly
how each attack is injected into the synthetic dataset.

> **All data described here is synthetic.** Usernames are assembled from fixed
> word lists in [`generator.py`](loginwatch/generator.py). IP addresses come
> from reserved, non-routable ranges. No real person, host, or credential is
> represented anywhere.

---

## 1. Raw log format

A syslog-style header followed by structured `key=value` pairs — the shape many
real appliance and gateway logs use (pfSense, Fortinet, Sophos, and most custom
auth services): a human-readable prefix plus machine-parseable fields.

```
2026-09-08T10:30:00Z authgw01 authsvc[1423]: event=auth_attempt eid=3f9a1c2b0000 user="alice.nguyen" src_ip=198.18.0.14 device="Chrome/126 Windows" service=vpn outcome=failure reason=bad_password session=-
```

One event per line. It was chosen over plain JSON-lines deliberately: parsing it
requires a header regex plus a tokenizer that respects quoted values, which is
the point of having an ingestion layer at all.

### Header

| Part | Example | Notes |
|---|---|---|
| timestamp | `2026-09-08T10:30:00Z` | ISO-8601, always UTC |
| host | `authgw01` | one of `authgw01`, `authgw02`, `ssoedge01` |
| process | `authsvc[1423]` | name and PID |

### Fields

| Key | Example | Required | Description |
|---|---|---|---|
| `event` | `auth_attempt` | no | record type; only one type exists |
| `eid` | `3f9a1c2b0000` | **yes** | opaque unique record id; the join key for ground truth |
| `user` | `"alice.nguyen"` | **yes** | account; lowercased during normalization |
| `src_ip` | `198.18.0.14` | **yes** | source address |
| `device` | `"Chrome/126 Windows"` | no | user-agent-like client string |
| `service` | `vpn` | **yes** | `vpn`, `sso_portal`, `webmail`, `git`, `wiki`, `admin_portal` |
| `outcome` | `failure` | **yes** | `success` or `failure`; anything else is a parse error |
| `reason` | `bad_password` | no | `bad_password`, `unknown_user`, `mfa_denied`; empty on success |
| `session` | `-` | no | session id, present only on success |

**Conventions:** values containing spaces are double-quoted; `-` means the field
is absent (standard syslog convention) and normalizes to an empty string.

### Deliberately malformed lines

Six broken lines are scattered through every generated log to exercise the
parser's error path. Log pipelines really do see these — truncation from a full
disk, a rotation marker written by another tool, a field the upstream service
forgot to populate.

| Line | Parser result |
|---|---|
| `<<<< log rotated by logrotate ... >>>>` | `line does not match syslog header` |
| record with no `outcome=` | `missing required field(s): outcome` |
| `outcome=maybe` | `invalid outcome value: 'maybe'` |
| timestamp `2026-13-45T99:99:99Z` | `bad timestamp: month must be in 1..12` |
| line truncated mid-record | `missing required field(s): user,src_ip,outcome,service` |
| key=value pairs with no syslog header | `line does not match syslog header` |

These are recorded in the `ingest_errors` table rather than dropped. A rising
parse-failure rate is itself a signal — format drift, truncation, or someone
stuffing junk into a log to break the parser.

---

## 2. Normalized event schema

What the parser produces and every detector reads
([`models.py`](loginwatch/models.py)). Fields marked **derived** are added
during normalization, not present in the raw line.

| Field | Type | Derived | Description |
|---|---|---|---|
| `event_id` | str | | from `eid` |
| `ts` | str | | ISO-8601 UTC |
| `ts_epoch` | int | ✔ | integer seconds; what window queries compare |
| `username` | str | | lowercased |
| `src_ip` | str | | |
| `outcome` | str | | `success` \| `failure` |
| `service` | str | | |
| `host` | str | | from the syslog header |
| `reason` | str | | empty on success |
| `device` | str | | raw client string |
| `device_id` | str | ✔ | 12-char SHA-1 of the lowercased device string |
| `geo_city` | str | ✔ | from the IP→site table; empty if unresolved |
| `geo_country` | str | ✔ | ISO-2 country code |
| `lat`, `lon` | float\|None | ✔ | `None` when the IP cannot be located |
| `session_id` | str | | success only |
| `raw_line` | str | | kept verbatim so an analyst can see the source data |

Timestamps are stored twice — ISO text for humans, integer epoch for range
queries — because comparing integers is what makes the window queries cheap.

### Simulated geolocation

There is no GeoIP database, so [`geo.py`](loginwatch/geo.py) maps a `/24` prefix
to a fixed site table of 21 cities with real approximate coordinates.

| Range | Meaning |
|---|---|
| `198.18.<n>.0/24` | external site *n* (home broadband, attacker infrastructure) |
| `10.10.<n>.0/24` | corporate office egress for site *n*, geolocating to the same city |

Both ranges are reserved and non-routable (RFC 2544 and RFC 1918), so no address
here can correspond to a real host. Unresolvable IPs return `None` rather than a
guess — real GeoIP fails on plenty of addresses too, and detectors must cope.

---

## 3. Database schema

SQLite ([`storage.py`](loginwatch/storage.py)).

| Table | Purpose |
|---|---|
| `events` | normalized events; indexed on `(username, ts_epoch)`, `(src_ip, ts_epoch)`, `ts_epoch`, `(outcome, ts_epoch)` |
| `ingest_errors` | malformed lines with line number, raw text and the reason |
| `profiles` | per-user baseline: hour histogram, countries, devices, and the window it was built from |
| `alerts` | detector findings with severity, status, evidence JSON and a `dedup_key` |
| `incidents` | correlated alert groups with severity, verdict and analyst note |
| `triage_log` | append-only record of every analyst action |
| `ground_truth` | generator labels — **read only by `evaluate`, never by a detector** |

Two schema decisions worth noting:

- **`alerts.dedup_key` is unique** (`detector|account|ip|first_event_id`), so
  re-running detection updates an existing alert instead of cloning it — and the
  update deliberately does not touch `status` or `analyst_note`, so triage
  decisions survive a re-run.
- **`events.event_id` is unique** with `INSERT OR IGNORE`, making ingestion
  idempotent. Real log delivery is at-least-once.

---

## 4. Simulated population

40 users over 21 days, from `seed 1337`. Each user has:

| Attribute | How it is chosen |
|---|---|
| Home site | one of 21 cities |
| Office egress | the `10.10.x` range for their **own** city |
| Devices | 1–2 drawn from a pool of 8 browser/OS strings |
| Working hours | start 07:30–10:00 **local**, running 8–9.5 hours |
| Services | 2–4 of the available applications |
| Logins per day | 2–7 on weekdays; ~22% chance of any weekend activity |
| On-call | 15% of users |

Working hours are defined in **local** time and converted to UTC, which is what
makes the hour baseline non-trivial: a normal working day looks like an odd band
once shifted into UTC, and differs per user.

Two deliberate sources of benign noise:

- **7%** of logins are preceded by 1–2 `bad_password` failures (typos). Without
  these the dataset would contain almost no benign failures and every threshold
  would look perfect.
- **8%** of logins are an evening catch-up after the normal working band. These
  are what forced `anomalous_hour`'s tolerance from 1 hour to 2.

### Timeline

```
day 0 ─────────────── day 13 │ day 14 ─────────────── day 20
    attack-free training      │      detection window
    (baselines built here)    │   (all injections land here)
```

---

## 5. Injected attack scenarios

Seven attack types, 12 episodes total. Each episode gets an instance id
(`brute_force#1`) so detection can be scored per episode. Every event is
labelled `attack` in `ground_truth.jsonl`.

**Attacker geography is chosen at random**, constrained only to differ from the
victim's country. No country in this dataset represents a real threat actor.

| Scenario | Episodes | How it is constructed | Should trip |
|---|---|---|---|
| `brute_force` | 2 | 22–38 `bad_password` failures against one account from one foreign IP, 5–12s apart (~3–6 min total). No success — the guessing fails. | `brute_force` |
| `password_spray` | 1 | One IP, 1–2 attempts each against 24 real accounts plus 4 that do not exist, 8–30s apart over ~25 min. | `password_spray` |
| `credential_stuffing` | 1 | One account, 2–3 failures from each of 9 IPs in 9 countries over ~20 min. | `credential_stuffing` |
| `impossible_travel` | 2 | A success from the user's home city, then a success ≥4,000 km away 25–55 minutes later. | `impossible_travel`, `new_device_location` |
| `anomalous_hour` | 2 | A single success at 03:12 **local**, from the user's normal IP and device — isolating the time signal. | `anomalous_hour` |
| `new_device_location` | 2 | One success from a new country on a never-seen device (`Chrome/121 Linux x86_64`), at a plausible hour. | `new_device_location` |
| `account_takeover` | 2 | The full chain: the victim's normal morning login, then 9–14 failures from a distant foreign IP over ~5 min, a **success** from that same IP 20–90s later, then 3–5 further successes against sensitive services over the next ~40 min. | `brute_force`, `post_failure_success`, `impossible_travel`, `new_device_location` |

`account_takeover` is the scenario the correlation engine exists for: it trips
four detectors at once and must arrive as **one** incident, not four alerts.

### Injected benign anomalies

Legitimate behaviour that *looks* anomalous, labelled `benign`. These exist so
the false-positive analysis is honest — a detector that fires on them is
producing exactly the noise a real analyst spends their day dismissing.

| Scenario | Episodes | Construction |
|---|---|---|
| `benign_business_travel` | 3 | A user works from a different country for a day. Their activity on the days either side is removed so both the outbound and **return** legs allow ~24h of travel time — the return leg is the easy one to forget, and forgetting it produces a fake impossible-travel hit. |
| `benign_new_device` | 2 | A user starts using `Chrome/128 macOS` from their usual location — a laptop refresh. |
| `benign_oncall_night` | 2 | An on-call engineer logs in at 02:30 local from their usual IP and device. |

### Ground truth file

`data/raw/ground_truth.jsonl`, one JSON object per labelled event:

```json
{"event_id": "3f9a1c2b0000", "scenario": "account_takeover", "instance": "account_takeover#1", "label": "attack"}
```

Loaded into the `ground_truth` table for `loginwatch evaluate` only. No detector
reads it, and a test asserts that.

### Run manifest

`data/raw/generation_manifest.json` records the seed, parameters, counts, and a
plain-English description of every injection — for example:

```
brute_force#1       attack  26 failed logins against wendy.sharma from
                            198.18.7.239 (Dublin) on day 18, ~8s apart.
                            No success: the guessing failed.

account_takeover#1  attack  14 failures against carlos.andersen from
                            198.18.13.176 (Sao Paulo) on day 15, followed by a
                            SUCCESS and then access to sensitive services from
                            the same IP
```

Useful when you want to check *what the detector should have found* without
reading the log by hand.

---

## 6. Reproducibility

The generator is fully deterministic. The same seed always produces a
byte-identical `auth.log`:

```bash
python -m loginwatch generate --out /tmp/a
python -m loginwatch generate --out /tmp/b
diff /tmp/a/auth.log /tmp/b/auth.log   # no output
```

A different seed produces a different dataset with the same *structure* —
useful for checking that thresholds are not overfitted to one random draw:

```bash
python -m loginwatch generate --seed 2024
python -m loginwatch ingest && python -m loginwatch profile
python -m loginwatch detect && python -m loginwatch correlate
python -m loginwatch evaluate
```

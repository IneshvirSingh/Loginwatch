# Incident 17: Probable account compromise: lucia.kowalski (5 alerts)

| | |
|---|---|
| **Severity** | `critical` |
| **Status** | `new` |
| **Analyst verdict** | `undetermined` |
| **First activity** | 2026-09-07T19:10:34Z |
| **Last activity** | 2026-09-07T22:12:09Z |
| **Alerts correlated** | 5 |
| **Accounts** | lucia.kowalski |
| **Source IPs** | `198.18.12.155`, `198.18.8.238` |
| **Correlated on** | account lucia.kowalski |

## Summary

Authentication activity against **lucia.kowalski** shows a burst of failed logins followed by a successful one, which is the signature of password guessing that worked. The account should be treated as compromised until an analyst establishes otherwise. The incident groups **5** alerts from 4 detectors (brute_force, impossible_travel, new_device_location, post_failure_success) spanning 181 minutes, covering 16 authentication events (12 failed, 4 successful). Source addresses involved: `198.18.12.155`, `198.18.8.238`. Severity **critical**. Requires immediate action.

## Alerts in this incident

| ID | Detector | Severity | Status | First seen | Title |
|---|---|---|---|---|---|
| 2 | `impossible_travel` | high | new | 2026-09-07T19:10:34Z | Impossible travel for lucia.kowalski: San Francisco, US to Amsterdam, NL |
| 5 | `post_failure_success` | critical | new | 2026-09-07T20:30:00Z | Successful login after 12 failures for lucia.kowalski (same source IP) |
| 4 | `brute_force` | critical | new | 2026-09-07T20:30:00Z | Brute force against lucia.kowalski from 198.18.8.238 |
| 6 | `new_device_location` | high | new | 2026-09-07T20:36:29Z | New location and device for lucia.kowalski |
| 7 | `impossible_travel` | high | new | 2026-09-07T21:06:00Z | Impossible travel for lucia.kowalski: Amsterdam, NL to San Francisco, US |

## Timeline

| Time (UTC) | Outcome | Account | Source IP | Location | Service | Device | Flagged by |
|---|---|---|---|---|---|---|---|
| 2026-09-07T19:10:34Z | OK | lucia.kowalski | `198.18.12.91` | San Francisco, US | sso_portal | Safari/17 macOS | impossible_travel |
| 2026-09-07T20:30:00Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:30:23Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:30:50Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:31:29Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:31:49Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:32:24Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:33:01Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:33:18Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:33:36Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:33:55Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:34:16Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:34:37Z | FAIL (bad_password) | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-07T20:36:29Z | OK | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | sso_portal | Go-http-client/2.0 | brute_force, impossible_travel, new_device_location, post_failure_success |
| 2026-09-07T21:06:00Z | OK | lucia.kowalski | `198.18.8.238` | Amsterdam, NL | git | Go-http-client/2.0 | impossible_travel |
| 2026-09-07T22:12:09Z | OK | lucia.kowalski | `198.18.12.155` | San Francisco, US | git | Chrome/126 Windows | impossible_travel |

## Evidence

### Alert 2 - Impossible travel for lucia.kowalski: San Francisco, US to Amsterdam, NL

**Detector:** `impossible_travel`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

Account 'lucia.kowalski' authenticated successfully from San Francisco, US at 2026-09-07T19:10:34Z, then from Amsterdam, NL at 2026-09-07T20:36:29Z - 8,774 km apart with only 86 minutes in between. That requires an average speed of 6,127 km/h, well above the 900 km/h ceiling used here for commercial air travel. At least one of the two sessions is not the account owner.

| Field | Value |
|---|---|
| `from_location` | San Francisco, US |
| `from_ip` | 198.18.12.91 |
| `from_time` | 2026-09-07T19:10:34Z |
| `from_device` | Safari/17 macOS |
| `to_location` | Amsterdam, NL |
| `to_ip` | 198.18.8.238 |
| `to_time` | 2026-09-07T20:36:29Z |
| `to_device` | Go-http-client/2.0 |
| `distance_km` | 8773.6 |
| `elapsed_minutes` | 85.9 |
| `implied_speed_kmh` | 6127.1 |
| `max_plausible_speed_kmh` | 900.0 |
| `device_also_changed` | True |

### Alert 5 - Successful login after 12 failures for lucia.kowalski (same source IP)

**Detector:** `post_failure_success`  
**MITRE ATT&CK:** T1110 (Brute Force) / T1078 (Valid Accounts)  
**Severity:** critical

Account 'lucia.kowalski' recorded 12 failed logins in 277s (threshold: 5), then authenticated SUCCESSFULLY 112s later at 2026-09-07T20:36:29Z from 198.18.8.238 (Amsterdam, NL) via sso_portal. The successful login came from one of the same source IPs that produced the failures, so the password guessing succeeded. Treat this account as compromised until proven otherwise: reset credentials, revoke active sessions, and review what the account did afterwards.

| Field | Value |
|---|---|
| `failure_count` | 12 |
| `failure_span_seconds` | 277 |
| `seconds_to_success` | 112 |
| `grace_period_seconds` | 300 |
| `success_from_failing_ip` | True |
| `distinct_failure_ips` | ["198.18.8.238"] |
| `success_ip` | 198.18.8.238 |
| `success_location` | Amsterdam, NL |
| `success_device` | Go-http-client/2.0 |
| `success_service` | sso_portal |
| `success_session` | 909e1aa2a7a5823a |
| `failure_reasons` | {"bad_password": 12} |
| `first_failure` | 2026-09-07T20:30:00Z |
| `success_time` | 2026-09-07T20:36:29Z |

### Alert 4 - Brute force against lucia.kowalski from 198.18.8.238

**Detector:** `brute_force`  
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)  
**Severity:** critical

12 failed logins for 'lucia.kowalski' from 198.18.8.238 in 277s (~2.6/min), which exceeds the threshold of 8 failures within 300s. A SUCCESSFUL login from the same source followed at 2026-09-07T20:36:29Z - treat as a probable account compromise.

| Field | Value |
|---|---|
| `failure_count` | 12 |
| `window_seconds` | 300 |
| `threshold` | 8 |
| `duration_seconds` | 277 |
| `attempts_per_minute` | 2.6 |
| `source_location` | Amsterdam, NL |
| `failure_reasons` | {"bad_password": 12} |
| `services_targeted` | {"sso_portal": 12} |
| `client_software` | {"Go-http-client/2.0": 12} |
| `succeeded_after_burst` | True |
| `first_attempt` | 2026-09-07T20:30:00Z |
| `last_attempt` | 2026-09-07T20:34:37Z |

### Alert 6 - New location and device for lucia.kowalski

**Detector:** `new_device_location`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

'lucia.kowalski' authenticated successfully from a country never seen for this account (NL) and an unrecognised device ('Go-http-client/2.0') at 2026-09-07T20:36:29Z. Baseline for this account (42 logins) covers US and 2 device(s): Safari/17 macOS; Chrome/126 Windows. Source IP 198.18.8.238 (Amsterdam). On its own this is a weak signal - people travel and replace laptops - so it is most useful when it correlates with other activity on the same account.

| Field | Value |
|---|---|
| `new_country` | NL |
| `new_device` | Go-http-client/2.0 |
| `device_fingerprint` | fbf8a34ee1c9 |
| `baseline_countries` | ["US"] |
| `baseline_devices` | ["Safari/17 macOS", "Chrome/126 Windows"] |
| `baseline_login_count` | 42 |
| `source_ip` | 198.18.8.238 |
| `source_location` | Amsterdam, NL |
| `service` | sso_portal |
| `login_time` | 2026-09-07T20:36:29Z |

### Alert 7 - Impossible travel for lucia.kowalski: Amsterdam, NL to San Francisco, US

**Detector:** `impossible_travel`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

Account 'lucia.kowalski' authenticated successfully from Amsterdam, NL at 2026-09-07T21:06:00Z, then from San Francisco, US at 2026-09-07T22:12:09Z - 8,774 km apart with only 66 minutes in between. That requires an average speed of 7,958 km/h, well above the 900 km/h ceiling used here for commercial air travel. At least one of the two sessions is not the account owner.

| Field | Value |
|---|---|
| `from_location` | Amsterdam, NL |
| `from_ip` | 198.18.8.238 |
| `from_time` | 2026-09-07T21:06:00Z |
| `from_device` | Go-http-client/2.0 |
| `to_location` | San Francisco, US |
| `to_ip` | 198.18.12.155 |
| `to_time` | 2026-09-07T22:12:09Z |
| `to_device` | Chrome/126 Windows |
| `distance_km` | 8773.6 |
| `elapsed_minutes` | 66.2 |
| `implied_speed_kmh` | 7957.9 |
| `max_plausible_speed_kmh` | 900.0 |
| `device_also_changed` | True |

### Raw log excerpts

```
2026-09-07T19:10:34Z ssoedge01 authsvc[2959]: event=auth_attempt eid=213b86051db2 user=lucia.kowalski src_ip=198.18.12.91 device="Safari/17 macOS" service=sso_portal outcome=success reason=- session=193b7d1c34bf3c12
2026-09-07T20:30:00Z ssoedge01 authsvc[3924]: event=auth_attempt eid=75c3bee9688a user=lucia.kowalski src_ip=198.18.8.238 device=Go-http-client/2.0 service=sso_portal outcome=failure reason=bad_password session=-
2026-09-07T20:30:23Z authgw02 authsvc[3925]: event=auth_attempt eid=1f8fa10ad7e4 user=lucia.kowalski src_ip=198.18.8.238 device=Go-http-client/2.0 service=sso_portal outcome=failure reason=bad_password session=-
2026-09-07T20:30:50Z authgw01 authsvc[3926]: event=auth_attempt eid=bc7b3d33c3b1 user=lucia.kowalski src_ip=198.18.8.238 device=Go-http-client/2.0 service=sso_portal outcome=failure reason=bad_password session=-
```

## Assessment

**Verdict:** `undetermined` - this incident has not yet been dispositioned by an analyst.

## Recommended actions

- Treat the account as compromised until proven otherwise.
- Reset the credential and revoke all active sessions and tokens.
- Review everything the account did after the successful login, especially access to sensitive services.
- Check whether MFA was enrolled and whether it was satisfied or bypassed.
- Preserve the relevant log range before it ages out of retention.
- Block or rate-limit the source IP at the edge / VPN concentrator.
- Confirm the account lockout policy actually engaged; if it did not, find out why.
- Check whether any authentication attempt from this source succeeded.
- Contact the user and confirm which session was theirs.
- Revoke active sessions and refresh tokens for the account.
- Verify whether either IP belongs to a corporate VPN or cloud proxy egress - that is the most common innocent explanation.
- Ask the user to confirm the device is theirs.
- Check whether the device is enrolled in device management.
- On its own this is weak; weigh it together with the other alerts in this incident.

## How this was detected

- **`brute_force`** - Repeated failed authentications against a single account from a single source IP within a short window. (MITRE: T1110.001 (Brute Force: Password Guessing))
- **`impossible_travel`** - Consecutive successful logins for one account from locations too far apart to be reached in the elapsed time. (MITRE: T1078 (Valid Accounts))
- **`new_device_location`** - First successful login for an account from a previously unseen device fingerprint or country. (MITRE: T1078 (Valid Accounts))
- **`post_failure_success`** - A burst of failed logins for an account immediately followed by a successful login - the signature of a guessing attack that worked. (MITRE: T1110 (Brute Force) / T1078 (Valid Accounts))

---

*Generated by loginwatch from a synthetic dataset. All accounts, IP addresses and locations in this report are fabricated; no real system, person or credential is represented. This is a portfolio project, not a production security tool.*
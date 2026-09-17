# Incident 15: Probable account compromise: carlos.andersen (5 alerts)

| | |
|---|---|
| **Severity** | `critical` |
| **Status** | `new` |
| **Analyst verdict** | `undetermined` |
| **First activity** | 2026-09-08T10:30:00Z |
| **Last activity** | 2026-09-08T13:09:25Z |
| **Alerts correlated** | 5 |
| **Accounts** | carlos.andersen |
| **Source IPs** | `198.18.13.176`, `198.18.16.170` |
| **Correlated on** | account carlos.andersen |

## Summary

Authentication activity against **carlos.andersen** shows a burst of failed logins followed by a successful one, which is the signature of password guessing that worked. The account should be treated as compromised until an analyst establishes otherwise. The incident groups **5** alerts from 4 detectors (brute_force, impossible_travel, new_device_location, post_failure_success) spanning 159 minutes, covering 18 authentication events (14 failed, 4 successful). Source addresses involved: `198.18.13.176`, `198.18.16.170`. Severity **critical**. Requires immediate action.

## Alerts in this incident

| ID | Detector | Severity | Status | First seen | Title |
|---|---|---|---|---|---|
| 10 | `post_failure_success` | critical | new | 2026-09-08T10:30:00Z | Successful login after 14 failures for carlos.andersen (same source IP) |
| 9 | `brute_force` | critical | new | 2026-09-08T10:30:00Z | Brute force against carlos.andersen from 198.18.13.176 |
| 11 | `impossible_travel` | high | new | 2026-09-08T10:30:56Z | Impossible travel for carlos.andersen: Kyiv Office, UA to Sao Paulo, BR |
| 12 | `new_device_location` | high | new | 2026-09-08T10:37:09Z | New location and device for carlos.andersen |
| 13 | `impossible_travel` | high | new | 2026-09-08T10:55:47Z | Impossible travel for carlos.andersen: Sao Paulo, BR to Kyiv, UA |

## Timeline

| Time (UTC) | Outcome | Account | Source IP | Location | Service | Device | Flagged by |
|---|---|---|---|---|---|---|---|
| 2026-09-08T10:30:00Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:30:23Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:30:51Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:30:56Z | OK | carlos.andersen | `10.10.16.40` | Kyiv Office, UA | git | Edge/126 Windows | impossible_travel |
| 2026-09-08T10:31:25Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:31:51Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:32:27Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:32:50Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:33:21Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:33:50Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:34:05Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:34:23Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:34:45Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:35:07Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:35:35Z | FAIL (bad_password) | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, post_failure_success |
| 2026-09-08T10:37:09Z | OK | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | sso_portal | Go-http-client/2.0 | brute_force, impossible_travel, new_device_location, post_failure_success |
| 2026-09-08T10:55:47Z | OK | carlos.andersen | `198.18.13.176` | Sao Paulo, BR | admin_portal | Go-http-client/2.0 | impossible_travel |
| 2026-09-08T13:09:25Z | OK | carlos.andersen | `198.18.16.170` | Kyiv, UA | git | Edge/126 Windows | impossible_travel |

## Evidence

### Alert 10 - Successful login after 14 failures for carlos.andersen (same source IP)

**Detector:** `post_failure_success`  
**MITRE ATT&CK:** T1110 (Brute Force) / T1078 (Valid Accounts)  
**Severity:** critical

Account 'carlos.andersen' recorded 14 failed logins in 335s (threshold: 5), then authenticated SUCCESSFULLY 94s later at 2026-09-08T10:37:09Z from 198.18.13.176 (Sao Paulo, BR) via sso_portal. The successful login came from one of the same source IPs that produced the failures, so the password guessing succeeded. Treat this account as compromised until proven otherwise: reset credentials, revoke active sessions, and review what the account did afterwards.

| Field | Value |
|---|---|
| `failure_count` | 14 |
| `failure_span_seconds` | 335 |
| `seconds_to_success` | 94 |
| `grace_period_seconds` | 300 |
| `success_from_failing_ip` | True |
| `distinct_failure_ips` | ["198.18.13.176"] |
| `success_ip` | 198.18.13.176 |
| `success_location` | Sao Paulo, BR |
| `success_device` | Go-http-client/2.0 |
| `success_service` | sso_portal |
| `success_session` | e6b6bac11ddc7e03 |
| `failure_reasons` | {"bad_password": 14} |
| `first_failure` | 2026-09-08T10:30:00Z |
| `success_time` | 2026-09-08T10:37:09Z |

### Alert 9 - Brute force against carlos.andersen from 198.18.13.176

**Detector:** `brute_force`  
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)  
**Severity:** critical

14 failed logins for 'carlos.andersen' from 198.18.13.176 in 335s (~2.5/min), which exceeds the threshold of 8 failures within 300s. A SUCCESSFUL login from the same source followed at 2026-09-08T10:37:09Z - treat as a probable account compromise.

| Field | Value |
|---|---|
| `failure_count` | 14 |
| `window_seconds` | 300 |
| `threshold` | 8 |
| `duration_seconds` | 335 |
| `attempts_per_minute` | 2.51 |
| `source_location` | Sao Paulo, BR |
| `failure_reasons` | {"bad_password": 14} |
| `services_targeted` | {"sso_portal": 14} |
| `client_software` | {"Go-http-client/2.0": 14} |
| `succeeded_after_burst` | True |
| `first_attempt` | 2026-09-08T10:30:00Z |
| `last_attempt` | 2026-09-08T10:35:35Z |

### Alert 11 - Impossible travel for carlos.andersen: Kyiv Office, UA to Sao Paulo, BR

**Detector:** `impossible_travel`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

Account 'carlos.andersen' authenticated successfully from Kyiv Office, UA at 2026-09-08T10:30:56Z, then from Sao Paulo, BR at 2026-09-08T10:37:09Z - 11,149 km apart with only 6 minutes in between. That requires an average speed of 107,608 km/h, well above the 900 km/h ceiling used here for commercial air travel. At least one of the two sessions is not the account owner.

| Field | Value |
|---|---|
| `from_location` | Kyiv Office, UA |
| `from_ip` | 10.10.16.40 |
| `from_time` | 2026-09-08T10:30:56Z |
| `from_device` | Edge/126 Windows |
| `to_location` | Sao Paulo, BR |
| `to_ip` | 198.18.13.176 |
| `to_time` | 2026-09-08T10:37:09Z |
| `to_device` | Go-http-client/2.0 |
| `distance_km` | 11149.4 |
| `elapsed_minutes` | 6.2 |
| `implied_speed_kmh` | 107607.8 |
| `max_plausible_speed_kmh` | 900.0 |
| `device_also_changed` | True |

### Alert 12 - New location and device for carlos.andersen

**Detector:** `new_device_location`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

'carlos.andersen' authenticated successfully from a country never seen for this account (BR) and an unrecognised device ('Go-http-client/2.0') at 2026-09-08T10:37:09Z. Baseline for this account (48 logins) covers UA and 1 device(s): Edge/126 Windows. Source IP 198.18.13.176 (Sao Paulo). On its own this is a weak signal - people travel and replace laptops - so it is most useful when it correlates with other activity on the same account.

| Field | Value |
|---|---|
| `new_country` | BR |
| `new_device` | Go-http-client/2.0 |
| `device_fingerprint` | fbf8a34ee1c9 |
| `baseline_countries` | ["UA"] |
| `baseline_devices` | ["Edge/126 Windows"] |
| `baseline_login_count` | 48 |
| `source_ip` | 198.18.13.176 |
| `source_location` | Sao Paulo, BR |
| `service` | sso_portal |
| `login_time` | 2026-09-08T10:37:09Z |

### Alert 13 - Impossible travel for carlos.andersen: Sao Paulo, BR to Kyiv, UA

**Detector:** `impossible_travel`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

Account 'carlos.andersen' authenticated successfully from Sao Paulo, BR at 2026-09-08T10:55:47Z, then from Kyiv, UA at 2026-09-08T13:09:25Z - 11,149 km apart with only 134 minutes in between. That requires an average speed of 5,006 km/h, well above the 900 km/h ceiling used here for commercial air travel. At least one of the two sessions is not the account owner.

| Field | Value |
|---|---|
| `from_location` | Sao Paulo, BR |
| `from_ip` | 198.18.13.176 |
| `from_time` | 2026-09-08T10:55:47Z |
| `from_device` | Go-http-client/2.0 |
| `to_location` | Kyiv, UA |
| `to_ip` | 198.18.16.170 |
| `to_time` | 2026-09-08T13:09:25Z |
| `to_device` | Edge/126 Windows |
| `distance_km` | 11149.4 |
| `elapsed_minutes` | 133.6 |
| `implied_speed_kmh` | 5006.0 |
| `max_plausible_speed_kmh` | 900.0 |
| `device_also_changed` | True |

### Raw log excerpts

```
2026-09-08T10:30:00Z ssoedge01 authsvc[3904]: event=auth_attempt eid=9e2c8f8e5fb7 user=carlos.andersen src_ip=198.18.13.176 device=Go-http-client/2.0 service=sso_portal outcome=failure reason=bad_password session=-
2026-09-08T10:30:23Z authgw02 authsvc[3905]: event=auth_attempt eid=66cada38e2da user=carlos.andersen src_ip=198.18.13.176 device=Go-http-client/2.0 service=sso_portal outcome=failure reason=bad_password session=-
2026-09-08T10:30:51Z ssoedge01 authsvc[3906]: event=auth_attempt eid=4eff943101c1 user=carlos.andersen src_ip=198.18.13.176 device=Go-http-client/2.0 service=sso_portal outcome=failure reason=bad_password session=-
2026-09-08T10:30:56Z authgw02 authsvc[3168]: event=auth_attempt eid=3448b138c1d8 user=carlos.andersen src_ip=10.10.16.40 device="Edge/126 Windows" service=git outcome=success reason=- session=ab8456dcdba3b8fa
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
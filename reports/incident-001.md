# Incident 1: Impossible travel for uma.kowalski (3 alerts)

| | |
|---|---|
| **Severity** | `high` |
| **Status** | `new` |
| **Analyst verdict** | `undetermined` |
| **First activity** | 2026-09-13T01:00:00Z |
| **Last activity** | 2026-09-13T07:44:59Z |
| **Alerts correlated** | 3 |
| **Accounts** | uma.kowalski |
| **Source IPs** | `198.18.19.96`, `198.18.6.211` |
| **Correlated on** | account uma.kowalski |

## Summary

Account **uma.kowalski** authenticated successfully from two locations too far apart to be travelled between in the time available, meaning at least one session was not the account owner. The incident groups **3** alerts from 2 detectors (impossible_travel, new_device_location) spanning 404 minutes, covering 3 authentication events (0 failed, 3 successful). Source addresses involved: `198.18.19.96`, `198.18.6.211`. Severity **high**. Needs an analyst today.

## Alerts in this incident

| ID | Detector | Severity | Status | First seen | Title |
|---|---|---|---|---|---|
| 37 | `impossible_travel` | high | new | 2026-09-13T01:00:00Z | Impossible travel for uma.kowalski: Seoul, KR to Frankfurt, DE |
| 39 | `new_device_location` | high | new | 2026-09-13T01:32:00Z | New location and device for uma.kowalski |
| 38 | `impossible_travel` | high | new | 2026-09-13T01:32:00Z | Impossible travel for uma.kowalski: Frankfurt, DE to Seoul, KR |

## Timeline

| Time (UTC) | Outcome | Account | Source IP | Location | Service | Device | Flagged by |
|---|---|---|---|---|---|---|---|
| 2026-09-13T01:00:00Z | OK | uma.kowalski | `198.18.19.96` | Seoul, KR | vpn | Firefox/128 Ubuntu | impossible_travel |
| 2026-09-13T01:32:00Z | OK | uma.kowalski | `198.18.6.211` | Frankfurt, DE | webmail | python-requests/2.31 | impossible_travel, new_device_location |
| 2026-09-13T07:44:59Z | OK | uma.kowalski | `198.18.19.96` | Seoul, KR | sso_portal | Firefox/128 Ubuntu | impossible_travel |

## Evidence

### Alert 37 - Impossible travel for uma.kowalski: Seoul, KR to Frankfurt, DE

**Detector:** `impossible_travel`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

Account 'uma.kowalski' authenticated successfully from Seoul, KR at 2026-09-13T01:00:00Z, then from Frankfurt, DE at 2026-09-13T01:32:00Z - 8,550 km apart with only 32 minutes in between. That requires an average speed of 16,031 km/h, well above the 900 km/h ceiling used here for commercial air travel. At least one of the two sessions is not the account owner.

| Field | Value |
|---|---|
| `from_location` | Seoul, KR |
| `from_ip` | 198.18.19.96 |
| `from_time` | 2026-09-13T01:00:00Z |
| `from_device` | Firefox/128 Ubuntu |
| `to_location` | Frankfurt, DE |
| `to_ip` | 198.18.6.211 |
| `to_time` | 2026-09-13T01:32:00Z |
| `to_device` | python-requests/2.31 |
| `distance_km` | 8549.6 |
| `elapsed_minutes` | 32.0 |
| `implied_speed_kmh` | 16030.5 |
| `max_plausible_speed_kmh` | 900.0 |
| `device_also_changed` | True |

### Alert 39 - New location and device for uma.kowalski

**Detector:** `new_device_location`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

'uma.kowalski' authenticated successfully from a country never seen for this account (DE) and an unrecognised device ('python-requests/2.31') at 2026-09-13T01:32:00Z. Baseline for this account (32 logins) covers KR and 1 device(s): Firefox/128 Ubuntu. Source IP 198.18.6.211 (Frankfurt). On its own this is a weak signal - people travel and replace laptops - so it is most useful when it correlates with other activity on the same account.

| Field | Value |
|---|---|
| `new_country` | DE |
| `new_device` | python-requests/2.31 |
| `device_fingerprint` | adf3f0d12480 |
| `baseline_countries` | ["KR"] |
| `baseline_devices` | ["Firefox/128 Ubuntu"] |
| `baseline_login_count` | 32 |
| `source_ip` | 198.18.6.211 |
| `source_location` | Frankfurt, DE |
| `service` | webmail |
| `login_time` | 2026-09-13T01:32:00Z |

### Alert 38 - Impossible travel for uma.kowalski: Frankfurt, DE to Seoul, KR

**Detector:** `impossible_travel`  
**MITRE ATT&CK:** T1078 (Valid Accounts)  
**Severity:** high

Account 'uma.kowalski' authenticated successfully from Frankfurt, DE at 2026-09-13T01:32:00Z, then from Seoul, KR at 2026-09-13T07:44:59Z - 8,550 km apart with only 373 minutes in between. That requires an average speed of 1,375 km/h, well above the 900 km/h ceiling used here for commercial air travel. At least one of the two sessions is not the account owner.

| Field | Value |
|---|---|
| `from_location` | Frankfurt, DE |
| `from_ip` | 198.18.6.211 |
| `from_time` | 2026-09-13T01:32:00Z |
| `from_device` | python-requests/2.31 |
| `to_location` | Seoul, KR |
| `to_ip` | 198.18.19.96 |
| `to_time` | 2026-09-13T07:44:59Z |
| `to_device` | Firefox/128 Ubuntu |
| `distance_km` | 8549.6 |
| `elapsed_minutes` | 373.0 |
| `implied_speed_kmh` | 1375.3 |
| `max_plausible_speed_kmh` | 900.0 |
| `device_also_changed` | True |

### Raw log excerpts

```
2026-09-13T01:00:00Z authgw01 authsvc[3897]: event=auth_attempt eid=50a1dc7983bb user=uma.kowalski src_ip=198.18.19.96 device="Firefox/128 Ubuntu" service=vpn outcome=success reason=- session=baf82a89786384ab
2026-09-13T01:32:00Z authgw01 authsvc[3898]: event=auth_attempt eid=8eb0534402c9 user=uma.kowalski src_ip=198.18.6.211 device=python-requests/2.31 service=webmail outcome=success reason=- session=a933c39116b79a2e
2026-09-13T07:44:59Z ssoedge01 authsvc[3749]: event=auth_attempt eid=f7efb98bb601 user=uma.kowalski src_ip=198.18.19.96 device="Firefox/128 Ubuntu" service=sso_portal outcome=success reason=- session=e5d12ac0521f90ea
```

## Assessment

**Verdict:** `undetermined` - this incident has not yet been dispositioned by an analyst.

## Recommended actions

- Contact the user and confirm which session was theirs.
- Revoke active sessions and refresh tokens for the account.
- Verify whether either IP belongs to a corporate VPN or cloud proxy egress - that is the most common innocent explanation.
- Ask the user to confirm the device is theirs.
- Check whether the device is enrolled in device management.
- On its own this is weak; weigh it together with the other alerts in this incident.

## How this was detected

- **`impossible_travel`** - Consecutive successful logins for one account from locations too far apart to be reached in the elapsed time. (MITRE: T1078 (Valid Accounts))
- **`new_device_location`** - First successful login for an account from a previously unseen device fingerprint or country. (MITRE: T1078 (Valid Accounts))

---

*Generated by loginwatch from a synthetic dataset. All accounts, IP addresses and locations in this report are fabricated; no real system, person or credential is represented. This is a portfolio project, not a production security tool.*
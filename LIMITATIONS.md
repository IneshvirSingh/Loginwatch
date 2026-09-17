# Limitations

What this project does not do, what it assumes that reality would not grant it,
and what a real security stack would add.

This document exists because a portfolio project that only lists its strengths
is not credible. If you are evaluating this work, this is probably the most
useful file in the repository.

---

## 1. The data is synthetic, and that flatters everything

Every number quoted in the README and [DETECTIONS.md](DETECTIONS.md) comes from
a dataset **I generated myself, containing attacks I designed, caught by
detectors I wrote against those same attacks.** That is close to the definition
of an unfair test.

Specific ways it is easier than reality:

| The synthetic data | Reality |
|---|---|
| ~2,900 events, 40 users, 21 days | Millions of events a day, tens of thousands of identities |
| Attackers use obvious client software (`python-requests`, `curl`) | Competent attackers use a real browser user-agent, or a real browser |
| Attacks are bursty and complete inside one window | Patient attackers pace themselves below any fixed threshold |
| One log source, one consistent format | Dozens of sources, inconsistent clocks, missing fields, format drift |
| Office egress geolocates to the user's own city | VPNs, cloud proxies, CGNAT and mobile carriers scramble location constantly |
| Every user has a clean, stable behavioural pattern | Shift work, contractors, shared accounts, service accounts, re-orgs |
| No adversary knows these detections exist | A real adversary may know exactly what you alert on |

The evaluation catches regressions. It says nothing reliable about how these
detectors would perform on real traffic.

## 2. The baseline assumption

The two profile-based detectors (`anomalous_hour`, `new_device_location`) are
trained on the first 14 days of data, which the generator guarantees to be
attack-free.

**No real environment hands you a clean training window.** You are always
baselining over data that may already contain the compromise you are looking
for, which means a patient attacker who is active during your baselining period
gets learned as normal. Real systems address this with rolling baselines,
exclusion of known-bad activity, robust statistics that resist contamination,
and periodic re-baselining after incidents — none of which is implemented here.

Related: baselines here are static once built. A user who changes shift, moves
country, or switches teams stays permanently anomalous until someone rebuilds
the profiles.

## 3. It is batch, not real-time

The pipeline reads a complete log file, processes it, and stops. There is no
streaming ingestion, no windowed state, no "as events arrive" evaluation, and
therefore **no meaningful time-to-detect**.

A real detection platform consumes a stream (Kafka, Kinesis, a syslog receiver),
maintains detector state across the stream, and measures latency from event to
alert as a headline SLO. Converting these detectors to streaming is not a
cosmetic change: several of them look backwards over a window and would need
incremental state and careful handling of late-arriving events.

The README does not use the word "real-time" anywhere, deliberately.

## 4. Scale

SQLite with B-tree indexes on `(username, ts_epoch)` and `(src_ip, ts_epoch)` is
genuinely the right tool at this volume. It is the wrong tool at three orders of
magnitude more. Production log platforms use columnar or inverted-index stores
(Elasticsearch/OpenSearch, ClickHouse, Splunk, BigQuery) because the query
patterns and retention economics are completely different.

The correlation step is also O(n²) over alerts. Fine for tens or hundreds;
it would need entity-keyed indexing at real alert volumes.

## 5. Enrichment this system does not have

A real detection stack decides almost nothing from the log line alone. Absent
here:

- **Threat intelligence.** No reputation data on source IPs, no known-malicious
  infrastructure, no Tor/VPN/proxy/hosting-provider classification. Real GeoIP
  products ship the VPN-detection data that would fix this project's biggest
  false-positive source.
- **Asset and identity context.** No idea whether an account is an
  administrator, a service account, or a new joiner; whether a device is
  company-managed; whether the user is on leave or has an approved travel
  request. Most of the "known false positives" in DETECTIONS.md would be
  resolvable with an HR calendar and an MDM inventory.
- **MFA context.** The synthetic logs include an `mfa_denied` failure reason,
  but the system does not reason about MFA enrolment, MFA fatigue/push-bombing,
  or whether a successful login satisfied MFA — which is the single most
  important question about any suspicious success.
- **Session and downstream activity.** Detection stops at authentication. What
  the attacker did afterwards — the part that determines actual impact — is
  outside the data.

## 6. Attacks it would not catch

Being explicit about coverage gaps matters more than listing what it does catch:

- **Low and slow.** Any attacker who stays under the configured thresholds is
  invisible. Fixed thresholds are inherently evadable by anyone who knows or
  guesses them.
- **Credential attacks with no failures.** Phished, keylogged, session-hijacked
  or infostealer-sourced credentials produce a clean successful login. Only
  `impossible_travel`, `anomalous_hour` and `new_device_location` have any
  chance, and all three are weak signals.
- **Token and session theft.** Stolen cookies or refresh tokens may generate no
  authentication event at all.
- **OAuth consent abuse, device-code phishing, MFA push fatigue** — modern
  identity attacks that do not look like password guessing.
- **Insider misuse.** A legitimate user with legitimate credentials doing
  something they should not, from their normal device, location and hours, is
  invisible to every detector here.
- **Anything off the authentication path.** Malware, lateral movement, data
  exfiltration, persistence. Single-log-source detection has a hard ceiling.

## 7. No response capability

The system detects and describes. It does nothing.

No SOAR playbooks, no automatic IP blocking, no forced password reset, no
session revocation, no ticketing integration, no paging, no case management. The
"remediation" sections in generated incident reports are *advice for a human*,
not actions taken.

This is a deliberate boundary — automated response is where security tooling
does real damage when it is wrong — but it is a boundary, and worth naming.

## 8. The evaluation methodology is limited

Beyond the synthetic-data problem:

- **Detection is scored per attack episode**, so a detector that catches 1 event
  out of 30 in a burst scores identically to one that catches all 30. That is
  the right unit for "did the analyst find out", and the wrong unit for
  measuring evidence completeness.
- **There is no true-negative count**, so no false-positive *rate*, only raw
  counts. A proper evaluation would report alerts per thousand events, per user,
  per day — the numbers that determine whether a SOC can actually staff it.
- **No precision/recall trade-off curve.** One threshold set, one result. Real
  detection tuning sweeps thresholds and picks an operating point against an
  alert budget.
- **No measurement of alert fatigue**, which is the thing that actually causes
  real detections to be missed.

## 9. Operational and security gaps in the tool itself

- No authentication, authorisation or multi-user support. Anyone who can run the
  CLI can change any verdict.
- The `triage_log` records an actor string that is always `analyst` — there is
  no real identity behind it, so it is an audit trail in shape only.
- No log retention policy, archival, or tamper-evidence. A real system treats
  security logs as evidence with integrity requirements.
- No high availability, backup, monitoring of the monitoring, or alerting on
  ingestion failure — though parse failures *are* counted, which is the first
  step toward that.
- SQL is parameterised throughout and the one dynamic column name is validated
  against an allowlist, but the tool has had no security review.

## 10. The AI triage module specifically

[`ai_triage.py`](loginwatch/ai_triage.py) is an optional demonstration, and
carries its own caveats:

- The prompt-injection defence is **prompt-level instruction plus crude
  substring matching**. It would not stop a determined attacker. It is there
  because the *threat* is real — log fields are attacker-controlled — not
  because this is an adequate mitigation.
- Sending log evidence to an external API is a genuine data-governance decision
  that a real security team would have to make deliberately. It is opt-in here
  for that reason, and the offline template backend is the default.
- No evaluation of the generated drafts' quality has been done. There is no eval
  set, no measurement of hallucination rate, no human review study. The module
  demonstrates *structure and guardrails*, not validated output quality.
- Nothing in it is evidence of production AI security tooling experience.

---

## What I would build next, in priority order

1. **Streaming ingestion** with incremental detector state, so time-to-detect
   becomes a measurable quantity instead of a non-concept.
2. **VPN/proxy/hosting-provider enrichment**, which would remove the single
   largest false-positive source (impossible travel) and materially improve
   `new_device_location`.
3. **Rolling, contamination-resistant baselines** to remove the clean-training-
   window assumption.
4. **A proper evaluation harness**: threshold sweeps, alerts-per-analyst-day as
   the operating constraint, and a precision/recall curve per detector.
5. **A second log source** — VPN or endpoint — so correlation has something to
   correlate *across*, which is where multi-source detection earns its keep.
6. **MFA-aware logic**, because "did the successful login satisfy MFA" is the
   most decision-relevant field this project does not have.

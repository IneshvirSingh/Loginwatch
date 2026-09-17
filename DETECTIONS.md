# Detection logic

One section per detector: what it looks for, why that matters, how the logic
actually works, where the thresholds came from, and what makes it fire when it
shouldn't.

All thresholds live in [`config/detectors.json`](config/detectors.json). Nothing
in this document is a number hardcoded in a detector.

**Contents**

- [Principles](#principles)
- [`brute_force`](#brute_force--t1110001)
- [`password_spray`](#password_spray--t1110003)
- [`credential_stuffing`](#credential_stuffing--t1110004)
- [`impossible_travel`](#impossible_travel--t1078)
- [`anomalous_hour`](#anomalous_hour--t1078)
- [`new_device_location`](#new_device_location--t1078)
- [`post_failure_success`](#post_failure_success--t1110--t1078)
- [Correlation](#correlation-alerts--incidents)
- [How accuracy is measured](#how-accuracy-is-measured)
- [Tuning history](#tuning-history)

---

## Principles

Four rules the detectors follow, which between them explain most of the design.

**1. Every alert carries the arithmetic it is based on.**
A detector produces a human-readable `reason` *and* an `evidence` dictionary
holding the numbers that sentence rests on. An analyst should be able to check a
detector's working rather than trust it. There is no opaque "risk score"
anywhere in this project — a score would be easier to build and impossible to
argue with.

**2. Thresholds are configuration, not code.**
Tuning a detection in a real SOC is a config change reviewed by an analyst.
Detector classes read every parameter through `self.p(name, default)`.

**3. A burst is one alert.**
A 30-attempt brute force is one thing that happened, so it produces one alert
covering all 30 events. A naive sliding-window implementation emits a finding
for every qualifying window and turns that single episode into 23 near-identical
alerts. The difference between those two behaviours is the difference between a
queue an analyst uses and one they mute.

**4. Baselines learn only from successes, and only from clean data.**
The two profile-based detectors build per-user baselines from *successful*
logins in the attack-free training window. Successes only, because a baseline
built from failures learns the attacker's behaviour as normal — the classic way
a naive anomaly detector trains itself blind. (That a clean training window
exists at all is a convenience of synthetic data; see
[LIMITATIONS.md](LIMITATIONS.md#the-baseline-assumption).)

---

## `brute_force` — T1110.001

**Detects:** repeated failed authentications against a single account from a
single source IP inside a short window.

**Why it matters:** it is the loudest and most common credential attack, and it
is cheap to detect. More usefully, catching it tells you an account is being
targeted *before* you have to find out whether the attacker succeeded.

### Logic

1. Take all failures and group them by `(username, source_ip)`.
2. Slide a `window_seconds` window over each group. When a window contains at
   least `min_failures` events, a burst starts.
3. **Extend** the burst while consecutive failures stay within
   `window_seconds` of each other, then emit one finding covering the whole run.
4. Separately, check whether any *successful* login for the same
   `(username, source_ip)` occurred inside the burst or within 5 minutes of its
   end. This does not change what the detector matches — it changes how urgent
   the result is.

### Thresholds

| Parameter | Value | Reasoning |
|---|---|---|
| `min_failures` | 8 | Real users mistype passwords; they do not do it eight times in five minutes. Below ~6 this starts catching people who changed their password on their phone and forgot. |
| `window_seconds` | 300 | Concentration is the signal. The same eight failures spread over a workday are a person having a bad day, not an attack. |

### Severity

`high` normally, escalated to **`critical`** when a successful login from the
same source follows the burst — at that point it is not an attempted attack, it
is a compromise.

### Known false positives

- **A service account or scripted client with a stale credential**, retrying in
  a loop. This looks identical to a brute force by volume. The distinguishing
  evidence is the `client_software` field and whether the source IP is known
  infrastructure. This is the most common benign cause in real environments.
- **A user whose saved password is wrong on a device that auto-retries** — a
  mail client polling every few seconds is a genuine brute-force shape.
- Neither appears in the synthetic dataset, so the measured precision below is
  flattering. This is called out because it is the honest caveat.

### Measured on the sample dataset

4 alerts, 4 true positives, **100% precision**. Catches both standalone brute
force injections and the guessing phase of both account takeovers.

---

## `password_spray` — T1110.003

**Detects:** a single source producing failed logins against many distinct
accounts, with only a few attempts against each.

**Why it matters:** spraying exists specifically to defeat brute-force detection
and account lockout. One common password is tried against hundreds of accounts,
so no single account ever accumulates enough failures to trip a per-account
threshold. A system that only watches per-account volume is blind to it.

### Logic

The grouping is inverted relative to brute force: group by **source IP**, then
ask how many *different* accounts it touched.

1. Group failures by `source_ip`.
2. Slide a `window_seconds` window. For each window, count distinct usernames
   and the maximum number of attempts against any single one.
3. A window qualifies when distinct accounts ≥ `min_distinct_users`
   **and** max attempts per account ≤ `max_failures_per_user`.
4. Report only the widest qualifying window per source, so one campaign is one
   alert.

### Thresholds

| Parameter | Value | Reasoning |
|---|---|---|
| `min_distinct_users` | 10 | A legitimate shared source (office NAT, VPN concentrator) does produce failures for several users. Ten distinct accounts failing from one address in half an hour does not happen by accident in an organisation this size. |
| `max_failures_per_user` | 4 | **The important one.** It is an upper bound, not a lower one. A source hammering one account is brute force and has its own detector; this ceiling is what stops the two detectors double-reporting the same event. |
| `window_seconds` | 1800 | Sprays are deliberately slow. Five minutes is too tight to see the pattern. |

### Evidence worth noting

`nonexistent_account_attempts` counts failures with reason `unknown_user`. A
legitimate user population does not generate those in bulk — a high count means
the attacker is working from a scraped or guessed username list, which both
confirms the detection and tells you something about the attacker.

### Known false positives

- **A vulnerability scanner or authorised penetration test.** Identical
  behaviour. Resolved by knowing the testing schedule, which this system has no
  access to.
- **A misconfigured SSO connector** failing on behalf of many users at once.
- **A large NAT gateway** on a bad morning — mitigated by the short window, but
  the bigger the shared egress, the weaker this detection gets.

### Measured on the sample dataset

1 alert, 1 true positive, **100% precision**. The injected spray touched 28
accounts (4 of which do not exist) from one source over ~25 minutes.

---

## `credential_stuffing` — T1110.004

**Detects:** failed logins against one account arriving from an unusual number
of distinct source IPs in a short window.

**Why it matters:** this is the distributed version of guessing. An attacker
replays username/password pairs leaked from another breach, spread across a
botnet or proxy pool. Per-IP rate limiting cannot see it, because no single IP
does very much.

### Logic

Group failures by **username**; slide a window; count distinct source IPs.
Qualify when distinct IPs ≥ `min_distinct_ips` and total failures ≥
`min_total_failures`. Report the window with the most distinct sources.

The distinctness is the signal — the raw failure count is usually too low to
trip the brute-force threshold, which is the whole design of the attack.

### Thresholds

| Parameter | Value | Reasoning |
|---|---|---|
| `min_distinct_ips` | 6 | One user legitimately moves between a handful of addresses (home, mobile, office). Six distinct sources failing against one account inside 30 minutes is not one person. |
| `min_total_failures` | 8 | Stops six single stray failures — which can just be six days of one person's bad luck compressed by chance — from qualifying. |
| `window_seconds` | 1800 | Same reasoning as spraying: distributed attacks are paced. |

### Severity

`medium` normally — most stuffing fails. Escalated to **`critical`** if one of
the attacking IPs then authenticates successfully.

### Known false positives

- **A mobile user on CGNAT or a rotating carrier IP** who repeatedly fails. The
  `source_countries` evidence field is the discriminator: one user is rarely in
  five countries at once.
- **A corporate proxy pool** where outbound IP varies per request.

### Measured on the sample dataset

1 alert, 1 true positive, **100% precision**. 23 failures from 9 source IPs
across 9 countries against one account.

---

## `impossible_travel` — T1078

**Detects:** consecutive successful logins for one account from locations too
far apart to be travelled between in the elapsed time.

**Why it matters:** it is one of very few signals that says *"these credentials
are being used by two different people"* without needing to know anything about
either of them.

### Logic

1. Take **successful** logins only, grouped by username, in time order. A failed
   login tells you where someone *tried* to authenticate from, which says
   nothing about where the real user is.
2. Skip events that cannot be geolocated, rather than guessing.
3. For each consecutive pair, compute the great-circle (haversine) distance and
   the implied average speed.
4. Alert when distance ≥ `min_distance_km` **and** implied speed >
   `max_speed_kmh`.

Great-circle distance is a *lower bound* on real travel distance, which is the
conservative choice: the detector may under-estimate speed and miss something,
but it will not invent an impossibility out of a routing detour.

### Thresholds

| Parameter | Value | Reasoning |
|---|---|---|
| `max_speed_kmh` | 900 | Roughly commercial jet cruising speed. Anything above it is not a person travelling. |
| `min_distance_km` | 500 | **A false-positive guard, not a physics constant.** IP geolocation at city resolution is unreliable; without a floor, two addresses in the same metro area resolving to different cities produce fake motion at implausible speed. |

### Known false positives — and this one is serious

**A VPN, cloud proxy, or corporate egress gateway places a user wherever the
exit node is.** A user switching between two of them produces a textbook
impossible-travel signature with no attacker involved. This is *the* dominant
false positive for this detection in real deployments, and the reason mature
teams maintain an allowlist of known VPN egress ranges. This project has no such
allowlist.

It is also why this detector's 100% precision on the sample dataset should be
read with suspicion: the synthetic environment models office egress as being in
the same city as the user, because employees commute to a local office. That is
realistic, and it makes the detector's life much easier than reality does.

### Measured on the sample dataset

9 alerts, 9 true positives, **100% precision** — see the caveat above.

---

## `anomalous_hour` — T1078

**Detects:** a successful login inside the window an account is normally
dormant in.

**Why it matters:** attackers work on their own schedule, not the victim's.
Crucially there is no global "suspicious hour" — 03:00 UTC is the middle of the
working day for someone on the other side of the planet — so this has to be
per-account.

### Logic — and the interesting part

The obvious implementation is: flag any hour the account has never been seen in.
**It does not survive contact with data.** A user with ~50 baseline logins
spread across a ten-hour working day will, by chance alone, have hours they
happened never to log in during. Flagging those produces a steady stream of
alerts about people working at 11am.

So instead of asking *"have we seen this exact hour?"*, the detector models the
account's **single longest dormant stretch** — in practice, its night:

1. Take the account's baseline histogram of active UTC hours.
2. Find the largest circular gap between consecutive active hours. That gap is
   the dormant window.
3. Shrink it by `neighbour_hours` at each end, so activity just before or after
   the usual pattern is not treated as anomalous.
4. Alert on a successful login landing inside what remains.

Sampling gaps in the middle of the working day are absorbed. 3am is not.

### Thresholds

| Parameter | Value | Reasoning |
|---|---|---|
| `neighbour_hours` | 2 | Started at 1; raised to 2 after it fired on users' normal evening catch-up work. See [tuning history](#tuning-history). |
| `min_baseline_events` | 25 | An account with less history than this is not scored at all. Alerting on someone whose behaviour you have barely observed produces noise about new joiners. |
| `min_quiet_hours` | 4 | If the dormant stretch is shorter than this, the account has no meaningful off-hours — a shared or automated account — and the detector declines to score it rather than guessing. |

Events inside the training window are never scored: the baseline already learned
from them, so scoring them would be circular.

### Known false positives

**Legitimately unusual nights**: an on-call page, a release window, a deadline,
a user who has travelled and is now working in a different time zone. The
synthetic dataset deliberately contains on-call logins at 02:30 labelled
`benign`, so this cost shows up in the evaluation instead of being hidden.

### Measured on the sample dataset

11 alerts, 3 true positives, 8 false positives — **27% precision**, the weakest
detector here. Every one of those 8 was a labelled benign anomaly (an on-call
night, or a traveller whose hours shifted with their time zone).

That number is defensible only because of what this detector is *for*: at
`medium` severity it is a corroborating signal inside an incident, not a
standalone page. If it were wired to an out-of-hours pager it would need to be
either much tighter or switched off.

---

## `new_device_location` — T1078

**Detects:** the first successful login for an established account from a
previously unseen device fingerprint or country.

**Why it matters:** weak on its own — people buy laptops and take holidays — but
valuable in combination, which is what the correlation step is for. A new
country by itself is a shrug. A new country *plus* a burst of failures *plus* an
odd hour is an incident.

### Logic

1. Seed per-user sets of known devices and countries from the baseline.
2. Walk successful logins forward in time. Flag a login whose device
   fingerprint or country is not in the set.
3. **Add the new value to the set before moving on**, so only the *first*
   sighting alerts.

Step 3 is not an optimisation. Without it, a user who switches to a new laptop
generates an alert on every login for the rest of time.

### Severity, split deliberately

| Condition | Severity | Reasoning |
|---|---|---|
| New device only | `low` | A device string is trivially forged, and changes legitimately all the time — a browser auto-update alone rewrites the user-agent. |
| New country | `medium` | Location has at least some physical meaning. |
| Both at once | `high` | Meaningfully stronger together than either alone. |

### Known false positives

Hardware refresh, browser updates, genuine business travel, and VPN exit-node
changes. The synthetic dataset injects the first and third of these as labelled
benign anomalies.

### Measured on the sample dataset

11 alerts, 6 true positives, 5 false positives — **55% precision**. All 5 false
positives are the injected new-laptop and business-travel scenarios. As with
`anomalous_hour`, this is acceptable *because of how the alert is used*, not
because 55% is a good number.

---

## `post_failure_success` — T1110 → T1078

**Detects:** a burst of failed logins for an account, immediately followed by a
successful one.

**Why it matters:** this is the highest-value detection in the project, and the
reason is worth stating plainly — **a brute-force alert says someone is
knocking; this one says someone got in.**

### Logic

For each successful login, look backwards:

1. Count failures for the same account within `failure_window_seconds` before it.
2. Require at least `min_failures`.
3. Require the success to fall within `success_within_seconds` of the *last*
   failure.

Ordering and adjacency are the entire signal. The same counts spread across a
day mean nothing.

### Thresholds

| Parameter | Value | Reasoning |
|---|---|---|
| `min_failures` | 5 | Lower than the brute-force threshold of 8 on purpose. The consequence here is far worse, so the detector accepts more false positives to avoid missing a successful compromise. |
| `failure_window_seconds` | 600 | The failures must be a burst, not a trickle. |
| `success_within_seconds` | 300 | Adjacency. An hour later is a different story. |
| `require_same_ip` | `false` | See below. |

### Severity is dynamic

If the successful login comes from **an IP that was also producing the
failures**, the guessing demonstrably worked: rated `critical`. If it comes from
somewhere else, it is more likely the real user finally getting in after their
own failed-password episode: rated one level lower, `high`, and the alert text
says so explicitly.

Encoding that distinction is the difference between an alert an analyst trusts
and one they learn to skim past.

### The `require_same_ip` trade-off

Setting it to `true` would eliminate almost every false positive here — but it
would also miss a real attacker who guesses from a botnet and logs in from a
clean address, which is not an exotic technique. The default keeps recall and
uses severity to manage the noise instead. It is exposed in config because it is
exactly the kind of decision a team should make for their own environment.

### Known false positives

A user who forgets their password, fails five times, and then succeeds. The
severity split above is what keeps this manageable.

### Measured on the sample dataset

2 alerts, 2 true positives, **100% precision** — both account takeovers, both
correctly rated `critical` because the success came from a failing IP.

---

## Correlation: alerts → incidents

Not a detector, but part of the detection story.

Two alerts are linked when they **share an entity** (same account, or same
source IP) **and** their time ranges are within `window_minutes` of each other.
Linking is transitive, implemented as union-find, so if A shares an account with
B and B shares an IP with C, all three become one incident.

That transitivity is what lets a chain — guessing, then access, then activity
from the compromised session — arrive as a single narrative rather than as
scattered rows in a queue.

Incidents take the severity of their worst alert and are titled after the most
serious detection in them, so the headline describes the worst case the evidence
supports rather than whichever alert happened to fire first.

**Where this is crude:** real correlation weighs entity types differently (a
shared account is much stronger evidence than a shared IP, and a shared NAT
gateway address is nearly worthless), handles suppression, and reasons about
attack-chain ordering. See [LIMITATIONS.md](LIMITATIONS.md).

**Result on the sample dataset:** 39 alerts collapse into 19 incidents, 7 of
which group multiple alerts. Both account takeovers land as single 5-alert
`critical` incidents.

---

## How accuracy is measured

`loginwatch evaluate` compares alerts against the generator's ground-truth
labels. Two decisions make the numbers meaningful:

**Detection is scored per attack *episode*, not per event.** The generator tags
every synthetic attack event with an instance id (`brute_force#2`), and an
episode counts as detected when at least one alert cites at least one of its
events. That is the right unit: an analyst does not need an alert for each of
thirty password guesses, they need one alert telling them the episode happened.
Scoring per event would reward a detector for being noisy.

**False positives are split by kind**, because they mean different things:

- fired on a **labelled benign anomaly** — the business traveller, the new
  laptop, the on-call engineer. The detector did what it was built to do and the
  activity was still legitimate. This is the irreducible cost of the detection.
- fired on **ordinary traffic** — no injected anomaly at all. This is the
  detector being wrong on its own terms, and is the more serious kind. It is
  currently zero, and an end-to-end test keeps it there.

Ground-truth labels are stored in a separate table that no detector reads, and a
test asserts nothing under `loginwatch/detectors/` references them.

### Checking for overfitting

Thresholds were tuned against `seed 1337`. Re-running the pipeline on three
seeds they were never tuned against — different users, hours, locations,
attacker infrastructure and timing — gives 12/12 detection on all three
(precision 74–76%, with one false positive on ordinary traffic across all three
runs combined). That is reassurance the thresholds track the shape of the
attacks rather than one random draw. It is *not* external validation: the same
generator wrote all four datasets.

---

## Tuning history

Three changes made during development, each driven by a false positive rather
than by taste. They are recorded because "how did you choose your thresholds"
has a much better answer than "they seemed about right".

### 1. 599 impossible-travel alerts — the data was wrong, not the detector

The first full run produced 599 impossible-travel findings. The detector was
correct; my simulated environment was not. I had given each employee a corporate
VPN egress chosen at random from anywhere in the world, so a user in Sydney
appeared to commute to a Pune office several times a day.

The fix was in the data model — office egress now geolocates to the user's own
city — and the finding count dropped to 11. The lesson generalises: **in a real
environment the equivalent misconfiguration is not fixable, which is exactly why
production deployments of this detection need a VPN egress allowlist.**

### 2. The hour detector's "have we seen this hour" model

Version one flagged any login in an hour with zero baseline activity. It fired
on users logging in at 11am, because with ~50 baseline logins over a ten-hour
day, some hours are simply never sampled.

Replaced with the longest-dormant-stretch model described above. Alerts on
ordinary traffic went from 4 to 0, and the detector still catches every injected
3am login. A test (`test_sparse_midday_gaps_do_not_create_a_dormant_window`)
pins the behaviour.

### 3. `neighbour_hours` 1 → 2

Even with the dormant-window model, the detector fired on users' normal evening
catch-up work — a login an hour or two after their usual finish. A one-hour
tolerance was too tight against a habit that spreads over two to three hours.

Raising it to 2 removed the remaining false positives on ordinary traffic
without losing any injected attack, because the injected off-hours logins sit
five or more hours inside the dormant window. The cost is real: a genuine
attacker logging in shortly after the victim's normal finishing time is now
missed by this detector. That is an accepted trade, made survivable by the fact
that such a login would still need to come from a plausible device and location
to escape the other six detectors.

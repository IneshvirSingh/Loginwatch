"""Synthetic authentication log generator.

EVERYTHING THIS PRODUCES IS FAKE. The usernames are assembled from fixed word
lists, the IP addresses come from reserved non-routable ranges (see geo.py),
and no real system, account, or credential is involved at any point.

DESIGN
------
The generator produces two artifacts:

  data/raw/auth.log            the log an "analyst" is allowed to see
  data/raw/ground_truth.jsonl  labels saying which events were injected attacks

The split matters. Detectors only ever read the log. The labels exist so that
`loginwatch evaluate` can measure whether detection actually worked, instead of
the README simply asserting that it does.

The timeline is split into two phases:

  days 0 .. attack_free_days-1   clean traffic, used to build user baselines
  days attack_free_days .. end   the detection window, where attacks are injected

A clean training window is a convenient fiction - real environments never hand
you one - and that assumption is called out in LIMITATIONS.md.

BENIGN ANOMALIES
----------------
As well as attacks, the generator injects *legitimate* odd behaviour: a user on
a genuine business trip, someone unboxing a new laptop, an on-call engineer
logging in at 2am. These are labelled `benign`. They exist to make the false
positive analysis honest - a detector that fires on them is producing exactly
the kind of noise a real analyst spends their day dismissing.

ATTACKER GEOGRAPHY
------------------
Attack source locations are chosen at random from the site table, constrained
only to differ from the victim's home country. No country in this dataset is
meant to represent a real threat actor, and nothing here should be read as
attribution.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import geo
from .geo import Site
from .logfmt import format_log_line
from .models import to_epoch

FIRST_NAMES = (
    "alice", "brian", "chandra", "dmitri", "elena", "farid", "grace", "hiro",
    "imani", "jonas", "kavya", "liam", "maya", "nadia", "omar", "priya",
    "quentin", "rosa", "sanjay", "tessa", "uma", "victor", "wendy", "xiulan",
    "yusuf", "zara", "arjun", "beatriz", "carlos", "deepa", "erik", "fatima",
    "gustav", "hannah", "ivan", "jasmine", "kenji", "lucia", "mateo", "nina",
)
LAST_NAMES = (
    "nguyen", "okafor", "silva", "patel", "kowalski", "andersen", "haddad",
    "rossi", "novak", "mbeki", "tanaka", "fernandez", "ivanov", "sharma",
    "oconnell", "dubois", "weber", "santos", "kaur", "petrov",
)

CORP_DEVICES = (
    "Chrome/126 Windows",
    "Chrome/127 Windows",
    "Safari/17 macOS",
    "Chrome/126 macOS",
    "Firefox/128 Ubuntu",
    "Edge/126 Windows",
    "Chrome/126 Android",
    "Safari/17 iOS",
)

# User-agents typical of automated credential attacks. Deliberately obvious:
# real attackers often do not bother to blend in, and when they do, this
# project would miss it (noted in LIMITATIONS.md).
ATTACK_DEVICES = (
    "python-requests/2.31",
    "curl/8.4.0",
    "Go-http-client/2.0",
    "Mozilla/5.0 (compatible; scan)",
)

SERVICES = ("vpn", "sso_portal", "webmail", "git", "wiki")
SENSITIVE_SERVICES = ("admin_portal", "git", "vpn")
HOSTS = ("authgw01", "authgw02", "ssoedge01")

FAIL_BAD_PASSWORD = "bad_password"
FAIL_UNKNOWN_USER = "unknown_user"
FAIL_MFA_DENIED = "mfa_denied"


@dataclass
class Persona:
    """A simulated employee with consistent habits."""

    username: str
    home_site: Site
    corp_site: Site
    devices: list[str]
    work_start_local: float
    work_end_local: float
    services: list[str]
    home_octet: int
    logins_per_day: tuple[int, int] = (2, 6)
    on_call: bool = False
    notes: list[str] = field(default_factory=list)


class Generator:
    """Builds the synthetic log. Fully deterministic for a given seed."""

    def __init__(
        self,
        seed: int = 1337,
        users: int = 40,
        days: int = 21,
        attack_free_days: int = 14,
        start_date: str = "2026-08-24T00:00:00Z",
    ):
        self.rng = random.Random(seed)
        self.seed = seed
        self.n_users = users
        self.days = days
        self.attack_free_days = attack_free_days
        self.start_epoch = to_epoch(start_date)
        self.start_date = start_date

        self.records: list[dict] = []
        self.labels: dict[str, dict] = {}
        self.scenario_log: list[dict] = []  # human-readable injection manifest
        self._instance_counts: dict[str, int] = {}
        self._counter = 0

        self.personas: list[Persona] = self._build_personas()

    # ------------------------------------------------------------------ helpers

    def _event_id(self) -> str:
        """Opaque, stable, unique record id.

        Derived from the seed and a counter so that two runs with the same seed
        produce byte-identical logs - reproducibility is a hard requirement.
        """
        self._counter += 1
        raw = f"{self.seed}:{self._counter}".encode()
        return hashlib.sha1(raw).hexdigest()[:12]

    def _session_id(self) -> str:
        return hashlib.sha1(f"sess:{self.seed}:{self._counter}".encode()).hexdigest()[:16]

    def _day_start(self, day_index: int) -> int:
        return self.start_epoch + day_index * 86400

    @staticmethod
    def _is_weekend(epoch: int) -> bool:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).weekday() >= 5

    def _local_to_epoch(self, day_index: int, local_hour: float, site: Site) -> int:
        """Convert a wall-clock hour at a site into a UTC epoch.

        Users think in local time; the log records UTC. Modelling that offset is
        what makes the 'anomalous hour' baseline non-trivial - a user's normal
        hours look like an odd band once shifted into UTC.
        """
        return self._day_start(day_index) + int(
            round((local_hour - site.utc_offset_hours) * 3600)
        )

    def _emit(
        self,
        ts_epoch: int,
        username: str,
        src_ip: str,
        outcome: str,
        service: str,
        device: str,
        reason: str = "",
        scenario: str | None = None,
        label: str = "normal",
        day_index: int | None = None,
        instance: str = "",
    ) -> dict:
        """Append one record, optionally tagging it with a ground-truth label."""
        event_id = self._event_id()
        rec = {
            "event_id": event_id,
            "ts": datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "ts_epoch": ts_epoch,
            "username": username,
            "src_ip": src_ip,
            "outcome": outcome,
            "service": service,
            "device": device,
            "reason": reason if outcome == "failure" else "",
            "session_id": self._session_id() if outcome == "success" else "",
            "host": self.rng.choice(HOSTS),
            "pid": 1000 + (self._counter % 8000),
            "_day": day_index,
            "_user": username,
        }
        self.records.append(rec)
        if scenario:
            self.labels[event_id] = {
                "scenario": scenario,
                "label": label,
                "instance": instance or scenario,
            }
        return rec

    def _foreign_site(self, avoid_country: str, min_km_from: Site | None = None,
                      min_km: float = 0.0) -> Site:
        """Pick an external site in a different country to the victim's."""
        candidates = [
            s for s in geo.external_sites() if s.country != avoid_country
        ]
        if min_km_from is not None and min_km > 0:
            far = [
                s for s in candidates
                if geo.haversine_km(
                    min_km_from.lat, min_km_from.lon, s.lat, s.lon
                ) >= min_km
            ]
            if far:
                candidates = far
        return self.rng.choice(candidates)

    def _detection_day(self) -> int:
        """A day index inside the attack window."""
        return self.rng.randint(self.attack_free_days, self.days - 1)

    def _new_instance(self, scenario: str) -> str:
        """Allocate an id for one concrete injection, e.g. 'brute_force#2'.

        Evaluation is per-injection, not per-scenario-type: 'we detected 2 of
        the 2 brute force episodes' is a meaningful claim, 'we detected the
        brute force scenario' is not.
        """
        n = self._instance_counts.get(scenario, 0) + 1
        self._instance_counts[scenario] = n
        return f"{scenario}#{n}"

    def _note(self, scenario: str, label: str, instance: str, detail: str) -> None:
        self.scenario_log.append(
            {
                "scenario": scenario,
                "instance": instance or scenario,
                "label": label,
                "detail": detail,
            }
        )

    # ----------------------------------------------------------------- personas

    def _build_personas(self) -> list[Persona]:
        personas: list[Persona] = []
        seen: set[str] = set()
        external = geo.external_sites()

        while len(personas) < self.n_users:
            name = (
                f"{self.rng.choice(FIRST_NAMES)}.{self.rng.choice(LAST_NAMES)}"
            )
            if name in seen:
                continue
            seen.add(name)

            home = self.rng.choice(external)
            work_start = self.rng.choice([7.5, 8.0, 8.5, 9.0, 9.5, 10.0])
            personas.append(
                Persona(
                    username=name,
                    home_site=home,
                    # Office egress in the user's own city: staff commute to a
                    # local office, not to one on another continent.
                    corp_site=geo.corp_site_for(home),
                    devices=self.rng.sample(CORP_DEVICES, self.rng.randint(1, 2)),
                    work_start_local=work_start,
                    work_end_local=work_start + self.rng.choice([8.0, 9.0, 9.5]),
                    services=self.rng.sample(SERVICES, self.rng.randint(2, 4)),
                    home_octet=self.rng.randint(10, 200),
                    logins_per_day=(2, self.rng.randint(4, 7)),
                    on_call=self.rng.random() < 0.15,
                )
            )
        return personas

    def _persona_ip(self, p: Persona, use_corp: bool) -> str:
        if use_corp:
            return p.corp_site.ip(self.rng.randint(2, 60))
        # Home IPs drift a little, the way a residential DHCP lease does, but
        # stay inside the same /24 so the geo lookup is stable.
        return p.home_site.ip(
            p.home_octet if self.rng.random() < 0.8 else self.rng.randint(10, 200)
        )

    # ------------------------------------------------------------ normal traffic

    def _generate_normal(self) -> None:
        for day in range(self.days):
            day_start = self._day_start(day)
            weekend = self._is_weekend(day_start)
            for p in self.personas:
                if weekend and self.rng.random() > 0.22:
                    continue  # most people do not work weekends
                low, high = p.logins_per_day
                n = self.rng.randint(1, 2) if weekend else self.rng.randint(low, high)
                for _ in range(n):
                    self._normal_login(p, day)

    def _normal_login(self, p: Persona, day: int) -> None:
        # 8% of logins are an evening catch-up after the normal working band.
        if self.rng.random() < 0.08:
            local_hour = p.work_end_local + self.rng.uniform(0.5, 2.5)
        else:
            local_hour = self.rng.uniform(p.work_start_local, p.work_end_local)

        use_corp = self.rng.random() < 0.35
        site = p.corp_site if use_corp else p.home_site
        ip = self._persona_ip(p, use_corp)
        device = self.rng.choice(p.devices)
        service = self.rng.choice(p.services)
        ts = self._local_to_epoch(day, local_hour, site) + self.rng.randint(0, 900)

        # Real people fat-finger passwords. Without this the dataset would have
        # almost no benign failures and every threshold would look perfect.
        if self.rng.random() < 0.07:
            for i in range(self.rng.randint(1, 2)):
                self._emit(
                    ts - (30 * (i + 1)), p.username, ip, "failure", service,
                    device, FAIL_BAD_PASSWORD, day_index=day,
                )
        if self.rng.random() < 0.02:
            # Occasional MFA denial that never resolves - user gives up.
            self._emit(
                ts, p.username, ip, "failure", service, device,
                FAIL_MFA_DENIED, day_index=day,
            )
            return

        self._emit(ts, p.username, ip, "success", service, device, day_index=day)

    def _drop_user_days(self, username: str, day_indexes: set[int]) -> None:
        """Remove a user's generated events on specific days.

        Used when injecting a scenario that replaces a day of normal activity
        (business travel), so the injected story stays internally consistent.
        """
        self.records = [
            r for r in self.records
            if not (r["_user"] == username and r["_day"] in day_indexes)
        ]

    # ------------------------------------------------------------- benign noise

    def inject_benign_travel(self, count: int) -> None:
        """A user genuinely travelling: new country, but physically possible.

        Expected to trip the new-location detector. That is the correct
        behaviour for the detector and a false positive for the analyst, which
        is exactly the tension this dataset is meant to expose.
        """
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("benign_business_travel")
            site = self._foreign_site(p.home_site.country)
            # Clear the days either side, so both the outbound and the return
            # leg have >= ~24h of travel time and the impossible-travel
            # detector correctly stays quiet. Forgetting the RETURN leg is an
            # easy modelling mistake: the user reappears at home the next
            # morning and looks like they teleported back.
            self._drop_user_days(p.username, {day - 1, day, day + 1})
            for i in range(self.rng.randint(2, 4)):
                ts = self._local_to_epoch(day, 14.0 + i * 1.5, site) + self.rng.randint(0, 600)
                self._emit(
                    ts, p.username, site.ip(self.rng.randint(20, 200)), "success",
                    self.rng.choice(p.services), self.rng.choice(p.devices),
                    scenario="benign_business_travel", label="benign", instance=inst, day_index=day,
                )
            self._note(
                "benign_business_travel", "benign", inst,
                f"{p.username} works from {site.name}, {site.country} on day {day} "
                f"(home: {p.home_site.name}); the days either side are cleared so "
                f"both the outbound and return legs allow ~24h of travel time",
            )

    def inject_benign_new_device(self, count: int) -> None:
        """Hardware refresh: a brand new user-agent from the usual location."""
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("benign_new_device")
            new_device = "Chrome/128 macOS"
            for i in range(self.rng.randint(2, 3)):
                ts = self._local_to_epoch(
                    day, p.work_start_local + 1 + i * 2, p.home_site
                ) + self.rng.randint(0, 600)
                self._emit(
                    ts, p.username, self._persona_ip(p, False), "success",
                    self.rng.choice(p.services), new_device,
                    scenario="benign_new_device", label="benign", instance=inst, day_index=day,
                )
            self._note(
                "benign_new_device", "benign", inst,
                f"{p.username} starts using '{new_device}' on day {day} from their "
                f"usual location - a laptop refresh, not an intrusion",
            )

    def inject_benign_oncall(self, count: int) -> None:
        """On-call engineer paged at 2am. Odd hour, entirely legitimate."""
        oncall = [p for p in self.personas if p.on_call] or self.personas
        for p in self.rng.sample(oncall, min(count, len(oncall))):
            day = self._detection_day()
            inst = self._new_instance("benign_oncall_night")
            ts = self._local_to_epoch(day, 2.5, p.home_site) + self.rng.randint(0, 600)
            self._emit(
                ts, p.username, self._persona_ip(p, False), "success", "vpn",
                self.rng.choice(p.devices),
                scenario="benign_oncall_night", label="benign", instance=inst, day_index=day,
            )
            self._note(
                "benign_oncall_night", "benign", inst,
                f"{p.username} (on-call) logs in at 02:30 local on day {day} from "
                f"their usual home IP and device",
            )

    # ------------------------------------------------------------------ attacks

    def inject_brute_force(self, count: int) -> None:
        """Many password guesses, one account, one source, short window."""
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("brute_force")
            attacker_site = self._foreign_site(p.home_site.country)
            attacker_ip = attacker_site.ip(self.rng.randint(2, 250))
            device = self.rng.choice(ATTACK_DEVICES)
            start = self._local_to_epoch(day, 13.0, p.home_site)
            n = self.rng.randint(22, 38)
            for i in range(n):
                self._emit(
                    start + i * self.rng.randint(5, 12), p.username, attacker_ip,
                    "failure", "vpn", device, FAIL_BAD_PASSWORD,
                    scenario="brute_force", label="attack", instance=inst, day_index=day,
                )
            self._note(
                "brute_force", "attack", inst,
                f"{n} failed logins against {p.username} from {attacker_ip} "
                f"({attacker_site.name}) on day {day}, ~8s apart. No success: "
                f"the guessing failed.",
            )

    def inject_password_spray(self, count: int) -> None:
        """One source, many accounts, only a couple of guesses each."""
        for _ in range(count):
            day = self._detection_day()
            inst = self._new_instance("password_spray")
            attacker_site = self.rng.choice(geo.external_sites())
            attacker_ip = attacker_site.ip(self.rng.randint(2, 250))
            device = self.rng.choice(ATTACK_DEVICES)
            victims = self.rng.sample(self.personas, min(24, len(self.personas)))
            # A spray list is scraped, so it contains accounts that do not exist.
            fake_users = ["admin", "service.acct", "test.user", "backup.svc"]
            targets = [v.username for v in victims] + fake_users
            self.rng.shuffle(targets)

            start = self._local_to_epoch(day, 4.0, attacker_site)
            t = start
            for username in targets:
                for _attempt in range(self.rng.randint(1, 2)):
                    reason = (
                        FAIL_UNKNOWN_USER if username in fake_users
                        else FAIL_BAD_PASSWORD
                    )
                    self._emit(
                        t, username, attacker_ip, "failure",
                        self.rng.choice(("sso_portal", "webmail")), device, reason,
                        scenario="password_spray", label="attack", instance=inst, day_index=day,
                    )
                    t += self.rng.randint(8, 30)
            self._note(
                "password_spray", "attack", inst,
                f"{attacker_ip} ({attacker_site.name}) tries 1-2 passwords against "
                f"{len(targets)} accounts over ~{(t - start) // 60} minutes on day "
                f"{day}, including {len(fake_users)} accounts that do not exist",
            )

    def inject_credential_stuffing(self, count: int) -> None:
        """Many sources converging on one account - a distributed guess."""
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("credential_stuffing")
            sites = self.rng.sample(geo.external_sites(), 9)
            ips = [s.ip(self.rng.randint(2, 250)) for s in sites]
            start = self._local_to_epoch(day, 20.0, p.home_site)
            t = start
            total = 0
            for ip in ips:
                for _ in range(self.rng.randint(2, 3)):
                    self._emit(
                        t, p.username, ip, "failure", "sso_portal",
                        self.rng.choice(ATTACK_DEVICES), FAIL_BAD_PASSWORD,
                        scenario="credential_stuffing", label="attack", instance=inst, day_index=day,
                    )
                    t += self.rng.randint(20, 70)
                    total += 1
            self._note(
                "credential_stuffing", "attack", inst,
                f"{total} failures against {p.username} from {len(ips)} distinct "
                f"source IPs in {len(sites)} countries over ~{(t - start) // 60} "
                f"minutes on day {day}",
            )

    def inject_impossible_travel(self, count: int) -> None:
        """Same account, two continents, minutes apart."""
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("impossible_travel")
            far = self._foreign_site(
                p.home_site.country, min_km_from=p.home_site, min_km=4000
            )
            t0 = self._local_to_epoch(day, 10.0, p.home_site)
            self._emit(
                t0, p.username, self._persona_ip(p, False), "success", "vpn",
                self.rng.choice(p.devices), day_index=day,
            )
            gap_minutes = self.rng.randint(25, 55)
            self._emit(
                t0 + gap_minutes * 60, p.username, far.ip(self.rng.randint(2, 250)),
                "success", "webmail", self.rng.choice(ATTACK_DEVICES),
                scenario="impossible_travel", label="attack", instance=inst, day_index=day,
            )
            km = geo.haversine_km(p.home_site.lat, p.home_site.lon, far.lat, far.lon)
            self._note(
                "impossible_travel", "attack", inst,
                f"{p.username} authenticates from {p.home_site.name} then from "
                f"{far.name} {gap_minutes} min later on day {day} - "
                f"{km:,.0f} km apart, implying ~{km / (gap_minutes / 60):,.0f} km/h",
            )

    def inject_anomalous_hour(self, count: int) -> None:
        """A successful login in an hour the account has never been active in."""
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("anomalous_hour")
            ts = self._local_to_epoch(day, 3.2, p.home_site) + self.rng.randint(0, 600)
            self._emit(
                ts, p.username, self._persona_ip(p, False), "success",
                self.rng.choice(p.services), self.rng.choice(p.devices),
                scenario="anomalous_hour", label="attack", instance=inst, day_index=day,
            )
            self._note(
                "anomalous_hour", "attack", inst,
                f"{p.username} logs in successfully at 03:12 local on day {day}, "
                f"far outside their {p.work_start_local:.0f}:00-"
                f"{p.work_end_local:.0f}:00 baseline",
            )

    def inject_new_device_location(self, count: int) -> None:
        """First sighting of a device and country for an established account."""
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("new_device_location")
            site = self._foreign_site(p.home_site.country)
            device = "Chrome/121 Linux x86_64"
            ts = self._local_to_epoch(day, 11.0, site) + self.rng.randint(0, 600)
            self._emit(
                ts, p.username, site.ip(self.rng.randint(2, 250)), "success",
                "webmail", device,
                scenario="new_device_location", label="attack", instance=inst, day_index=day,
            )
            self._note(
                "new_device_location", "attack", inst,
                f"{p.username} authenticates from {site.name}, {site.country} on a "
                f"never-before-seen device ('{device}') on day {day}",
            )

    def inject_account_takeover(self, count: int) -> None:
        """The full story: guessing, a success, then hands-on-keyboard activity.

        This is the scenario the correlation engine exists for. It should trip
        several detectors at once, and those alerts should collapse into ONE
        incident rather than landing in the queue as four unrelated things.
        """
        for p in self.rng.sample(self.personas, count):
            day = self._detection_day()
            inst = self._new_instance("account_takeover")
            attacker_site = self._foreign_site(
                p.home_site.country, min_km_from=p.home_site, min_km=4000
            )
            attacker_ip = attacker_site.ip(self.rng.randint(2, 250))
            device = self.rng.choice(ATTACK_DEVICES)

            # The victim's own normal morning login, so the later foreign
            # success also reads as impossible travel.
            morning = self._local_to_epoch(day, 9.5, p.home_site)
            self._emit(
                morning, p.username, self._persona_ip(p, False), "success", "vpn",
                self.rng.choice(p.devices), day_index=day,
            )

            start = self._local_to_epoch(day, 12.5, p.home_site)
            n_fail = self.rng.randint(9, 14)
            t = start
            for _ in range(n_fail):
                self._emit(
                    t, p.username, attacker_ip, "failure", "sso_portal", device,
                    FAIL_BAD_PASSWORD, scenario="account_takeover", label="attack", instance=inst,
                    day_index=day,
                )
                t += self.rng.randint(15, 40)

            success_at = t + self.rng.randint(20, 90)
            self._emit(
                success_at, p.username, attacker_ip, "success", "sso_portal",
                device, scenario="account_takeover", label="attack", instance=inst, day_index=day,
            )

            # Post-compromise: the attacker looks around.
            follow = success_at
            for _ in range(self.rng.randint(3, 5)):
                follow += self.rng.randint(120, 600)
                self._emit(
                    follow, p.username, attacker_ip, "success",
                    self.rng.choice(SENSITIVE_SERVICES), device,
                    scenario="account_takeover", label="attack", instance=inst, day_index=day,
                )
            self._note(
                "account_takeover", "attack", inst,
                f"{n_fail} failures against {p.username} from {attacker_ip} "
                f"({attacker_site.name}) on day {day}, followed by a SUCCESS and "
                f"then access to sensitive services from the same IP",
            )

    # ------------------------------------------------------------ malformed data

    @staticmethod
    def malformed_lines() -> list[str]:
        """Junk lines mixed into the log to exercise the parser's error path.

        Log pipelines really do see these: truncation from a full disk, a
        rotation marker written by another tool, a field the upstream service
        forgot to populate. The parser must record them and carry on.
        """
        return [
            "<<<< log rotated by logrotate at 2026-09-08T00:00:00Z >>>>",
            "2026-09-09T10:15:00Z authgw01 authsvc[2211]: event=auth_attempt "
            'eid=cafebabe0001 user="maya.silva" src_ip=198.18.1.44 service=vpn',
            "2026-09-09T14:22:10Z authgw02 authsvc[2211]: event=auth_attempt "
            'eid=cafebabe0002 user="omar.haddad" src_ip=198.18.5.19 '
            "outcome=maybe service=webmail",
            "2026-13-45T99:99:99Z authgw01 authsvc[7]: event=auth_attempt "
            'eid=cafebabe0003 user="x.y" src_ip=198.18.0.5 outcome=success '
            "service=vpn",
            "2026-09-10T08:01:02Z authgw01 authsvc[2211]: event=auth_attempt eid=ca",
            "user=orphan src_ip=198.18.2.2 outcome=success service=vpn",
        ]

    # -------------------------------------------------------------------- build

    def build(self) -> None:
        """Generate the whole dataset, in order."""
        self._generate_normal()

        # Benign anomalies first, because travel injection deletes normal days.
        self.inject_benign_travel(3)
        self.inject_benign_new_device(2)
        self.inject_benign_oncall(2)

        self.inject_brute_force(2)
        self.inject_password_spray(1)
        self.inject_credential_stuffing(1)
        self.inject_impossible_travel(2)
        self.inject_anomalous_hour(2)
        self.inject_new_device_location(2)
        self.inject_account_takeover(2)

        self.records.sort(key=lambda r: (r["ts_epoch"], r["event_id"]))

    def write(self, out_dir: str | Path) -> dict:
        """Write auth.log, ground_truth.jsonl and a run manifest."""
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        lines = [format_log_line(r) for r in self.records]

        # Sprinkle the malformed lines through the file rather than bunching
        # them at the end, so ingestion has to cope mid-stream.
        junk = self.malformed_lines()
        if lines:
            for line in junk:
                lines.insert(self.rng.randint(0, len(lines)), line)

        log_path = out_dir / "auth.log"
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        gt_path = out_dir / "ground_truth.jsonl"
        with open(gt_path, "w", encoding="utf-8") as fh:
            for event_id, meta in self.labels.items():
                fh.write(
                    json.dumps(
                        {
                            "event_id": event_id,
                            "scenario": meta["scenario"],
                            "instance": meta["instance"],
                            "label": meta["label"],
                        }
                    ) + "\n"
                )

        scenario_counts: dict[str, int] = {}
        for meta in self.labels.values():
            scenario_counts[meta["scenario"]] = scenario_counts.get(meta["scenario"], 0) + 1

        manifest = {
            "seed": self.seed,
            "users": self.n_users,
            "days": self.days,
            "attack_free_days": self.attack_free_days,
            "start_date": self.start_date,
            "total_log_lines": len(lines),
            "valid_events": len(self.records),
            "malformed_lines": len(junk),
            "labelled_events": len(self.labels),
            "labelled_by_scenario": scenario_counts,
            "injections": self.scenario_log,
            "warning": (
                "Entirely synthetic. Usernames are generated from fixed word "
                "lists and IPs are drawn from reserved non-routable ranges "
                "(198.18.0.0/15, 10.0.0.0/8). No real people, hosts or "
                "credentials are represented."
            ),
        }
        (out_dir / "generation_manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return manifest


def generate(out_dir: str | Path, **kwargs) -> dict:
    gen = Generator(**kwargs)
    gen.build()
    return gen.write(out_dir)

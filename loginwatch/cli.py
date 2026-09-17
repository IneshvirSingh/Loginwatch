"""Command line interface.

Each pipeline stage is its own subcommand so the stages can be run and
inspected independently - that is how you debug a detection pipeline. `run-all`
chains them for a one-command demo.

Run `python -m loginwatch --help` for the full list.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .ai_triage import build_triage_prompt, triage_alert
from .config import Config
from .correlate import correlate
from .dashboard import build_dashboard
from .detectors import REGISTRY, build_detectors
from .engine import ingest, load_ground_truth, run_detection
from .evaluate import evaluate, format_report
from .generator import Generator
from .profiling import build_profiles
from .reporting import render_incident_report, write_incident_reports
from .storage import ALERT_STATUSES, INCIDENT_VERDICTS, Store

DEFAULT_DB = "data/loginwatch.db"
DEFAULT_RAW = "data/raw"
DEFAULT_REPORTS = "reports"


# --------------------------------------------------------------- output helpers


def _rule(title: str = "") -> None:
    print(f"\n{title}" if title else "")
    print("-" * 72)


def _table(headers: list[str], rows: list[list[str]], empty: str = "(nothing)") -> None:
    if not rows:
        print(f"  {empty}")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    print("  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("  " + "  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  " + "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


def _store(args) -> Store:
    return Store(args.db)


def _config(args) -> Config:
    return Config.load(getattr(args, "config", None))


# ------------------------------------------------------------------- commands


def cmd_generate(args) -> int:
    cfg = _config(args).generator
    gen = Generator(
        seed=args.seed if args.seed is not None else cfg.get("seed", 1337),
        users=args.users or cfg.get("users", 40),
        days=args.days or cfg.get("days", 21),
        attack_free_days=cfg.get("attack_free_days", 14),
        start_date=cfg.get("start_date", "2026-08-24T00:00:00Z"),
    )
    gen.build()
    manifest = gen.write(args.out)

    _rule("Synthetic dataset generated")
    print(f"  Output directory : {args.out}")
    print(f"  Seed             : {manifest['seed']} (re-run with the same seed for identical data)")
    print(f"  Simulated users  : {manifest['users']} over {manifest['days']} days")
    print(f"  Log lines        : {manifest['total_log_lines']:,} "
          f"({manifest['valid_events']:,} valid, "
          f"{manifest['malformed_lines']} deliberately malformed)")
    print(f"  Labelled events  : {manifest['labelled_events']:,}")
    _rule("Injected scenarios")
    rows = [
        [inj["instance"], inj["label"], inj["detail"][:88]]
        for inj in manifest["injections"]
    ]
    _table(["instance", "label", "detail"], rows)
    print(f"\n  All data is synthetic. {manifest['warning']}")
    return 0


def cmd_ingest(args) -> int:
    with _store(args) as store:
        result = ingest(store, args.log)
        labels = 0
        gt_path = Path(args.log).parent / "ground_truth.jsonl"
        if gt_path.exists():
            labels = load_ground_truth(store, gt_path)

        _rule("Ingestion")
        print(f"  Source              : {result['source']}")
        print(f"  Events inserted     : {result['events_inserted']:,}")
        print(f"  Events in database  : {result['total_events_in_db']:,}")
        print(f"  Malformed lines     : {result['parse_errors']} "
              f"(recorded in ingest_errors, not dropped)")
        if labels:
            print(f"  Ground-truth labels : {labels:,} "
                  f"(used only by `evaluate`, never by detectors)")
        if result["parse_errors"] and args.show_errors:
            _rule("Parse failures")
            _table(
                ["line", "error", "raw (truncated)"],
                [
                    [row["line_no"], row["error"], (row["raw_line"] or "")[:60]]
                    for row in store.parse_errors()
                ],
            )
    return 0


def cmd_profile(args) -> int:
    cfg = _config(args)
    with _store(args) as store:
        train_days = args.train_days or cfg.profiling.get("train_days", 14)
        profiles = build_profiles(store, train_days)
        _rule("Behavioural baselines")
        print(f"  Built {len(profiles)} user profiles from the first {train_days} days")
        print("  Baselines use SUCCESSFUL logins only, from the attack-free window,")
        print("  so an attacker cannot teach a profile that their behaviour is normal.")
        if profiles:
            counts = sorted(p["event_count"] for p in profiles)
            print(f"  Logins per profile: min {counts[0]}, "
                  f"median {counts[len(counts) // 2]}, max {counts[-1]}")
            usable = sum(
                1 for p in profiles
                if p["event_count"] >= cfg.profiling.get("min_events_for_profile", 25)
            )
            print(f"  Profiles established enough to score against: {usable}/{len(profiles)}")
    return 0


def cmd_detect(args) -> int:
    cfg = _config(args)
    with _store(args) as store:
        if not store.profiles():
            print(
                "  warning: no baselines found - run `profile` first, or the "
                "profile-based detectors will not fire.",
                file=sys.stderr,
            )
        findings, per_detector = run_detection(store, cfg, clear=not args.no_clear)
        _rule("Detection")
        _table(
            ["detector", "findings", "MITRE ATT&CK"],
            [
                [name, count, REGISTRY[name].mitre]
                for name, count in per_detector.items()
            ],
        )
        print(f"\n  {len(findings)} findings stored as alerts.")
    return 0


def cmd_correlate(args) -> int:
    cfg = _config(args)
    with _store(args) as store:
        incident_ids = correlate(store, cfg)
        incidents = store.list_incidents()
        multi = [i for i in incidents if i["alert_count"] > 1]
        _rule("Correlation")
        window = cfg.correlation.get("window_minutes", 120)
        print(f"  Linked alerts sharing an account or source IP within {window} minutes.")
        print(f"  {len(incident_ids)} incidents from "
              f"{len(store.list_alerts())} alerts "
              f"({len(multi)} group more than one alert).")
        if multi:
            _rule("Multi-alert incidents")
            _table(
                ["id", "severity", "alerts", "title"],
                [[i["id"], i["severity"], i["alert_count"], i["title"]] for i in multi],
            )
    return 0


def cmd_alerts(args) -> int:
    with _store(args) as store:
        alerts = store.list_alerts(
            status=args.status, severity=args.severity, detector=args.detector,
            username=args.user, src_ip=args.ip, limit=args.limit,
        )
        _rule(f"Alerts ({len(alerts)})")
        _table(
            ["id", "severity", "status", "detector", "first seen", "title"],
            [
                [
                    a["id"], a["severity"], a["status"], a["detector"],
                    Store.fmt_ts(a["first_ts_epoch"]), a["title"][:54],
                ]
                for a in alerts
            ],
            "No alerts match that filter.",
        )
    return 0


def cmd_alert_show(args) -> int:
    with _store(args) as store:
        alert = store.get_alert(args.alert_id)
        if alert is None:
            print(f"no such alert: {args.alert_id}", file=sys.stderr)
            return 1
        _rule(f"Alert {alert['id']}: {alert['title']}")
        print(f"  detector : {alert['detector']}")
        print(f"  severity : {alert['severity']}")
        print(f"  status   : {alert['status']}")
        print(f"  MITRE    : {alert['mitre']}")
        print(f"  account  : {alert['username'] or '-'}")
        print(f"  source IP: {alert['src_ip'] or '-'}")
        print(f"  window   : {Store.fmt_ts(alert['first_ts_epoch'])} "
              f"-> {Store.fmt_ts(alert['last_ts_epoch'])}")
        print(f"  incident : {alert['incident_id'] or '-'}")
        _rule("Why it fired")
        print(f"  {alert['reason']}")
        _rule("Evidence")
        for key, value in json.loads(alert["evidence_json"] or "{}").items():
            print(f"  {key:<34} {value}")
        if alert["analyst_note"]:
            _rule("Analyst note")
            print(f"  {alert['analyst_note']}")
        events = store.events_by_ids(json.loads(alert["event_ids_json"] or "[]"))
        _rule(f"Underlying events ({len(events)}, showing up to 12)")
        _table(
            ["time", "outcome", "account", "source IP", "location", "service"],
            [
                [
                    e.ts, e.outcome, e.username, e.src_ip,
                    f"{e.geo_city},{e.geo_country}".strip(","), e.service,
                ]
                for e in events[:12]
            ],
        )
    return 0


def cmd_triage(args) -> int:
    with _store(args) as store:
        if not store.update_alert(args.alert_id, args.status, args.note):
            print(f"no such alert: {args.alert_id}", file=sys.stderr)
            return 1
        alert = store.get_alert(args.alert_id)
        print(f"  alert {args.alert_id} -> status={alert['status']}")
        if args.note:
            print(f"  note recorded: {args.note}")
        print("  (the triage log keeps an append-only record of this change)")
    return 0


def cmd_incidents(args) -> int:
    with _store(args) as store:
        incidents = store.list_incidents(verdict=args.verdict, severity=args.severity)
        _rule(f"Incidents ({len(incidents)})")
        _table(
            ["id", "severity", "alerts", "verdict", "first activity", "title"],
            [
                [
                    i["id"], i["severity"], i["alert_count"], i["verdict"],
                    Store.fmt_ts(i["first_ts_epoch"]), i["title"][:50],
                ]
                for i in incidents
            ],
            "No incidents. Run `detect` then `correlate`.",
        )
    return 0


def cmd_incident_show(args) -> int:
    with _store(args) as store:
        if store.get_incident(args.incident_id) is None:
            print(f"no such incident: {args.incident_id}", file=sys.stderr)
            return 1
        print(render_incident_report(store, args.incident_id))
    return 0


def cmd_incident_triage(args) -> int:
    with _store(args) as store:
        ok = store.update_incident(
            args.incident_id, verdict=args.verdict, status=args.status, note=args.note
        )
        if not ok:
            print(f"no such incident: {args.incident_id}", file=sys.stderr)
            return 1
        incident = store.get_incident(args.incident_id)
        print(f"  incident {args.incident_id} -> verdict={incident['verdict']}, "
              f"status={incident['status']}")
        if args.note:
            print(f"  note recorded: {args.note}")
    return 0


def cmd_report(args) -> int:
    with _store(args) as store:
        written = write_incident_reports(
            store, args.out, limit=args.limit,
            incident_ids=args.incident and [args.incident],
        )
        _rule("Incident reports")
        for path in written:
            print(f"  {path}")
        if not written:
            print("  No incidents to report on.")
    return 0


def cmd_dashboard(args) -> int:
    with _store(args) as store:
        report = evaluate(store) if store.ground_truth() else None
        path = build_dashboard(store, args.out, evaluation=report)
        _rule("Dashboard")
        print(f"  {path}")
        print(f"  open it with:  open {path}")
    return 0


def cmd_evaluate(args) -> int:
    with _store(args) as store:
        report = evaluate(store)
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print(format_report(report))
    return 0


def cmd_ai_triage(args) -> int:
    with _store(args) as store:
        if args.show_prompt:
            prompt = build_triage_prompt(store, args.alert_id)
            _rule("SYSTEM")
            print(prompt["system"])
            _rule("USER")
            print(prompt["user"])
            return 0
        try:
            result = triage_alert(store, args.alert_id, backend=args.backend)
        except (KeyError, RuntimeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        _rule(f"AI-assisted triage draft for alert {args.alert_id}")
        print(f"  backend: {result.backend}"
              + (f" (model {result.model})" if result.model else " (offline, no API key needed)"))
        print()
        print(result.rendered())
    return 0


def cmd_detectors(args) -> int:
    cfg = _config(args)
    _rule("Registered detectors")
    rows = []
    for name, cls in sorted(REGISTRY.items()):
        params = cfg.detector(name)
        enabled = "yes" if params.get("enabled", False) else "no"
        tuning = ", ".join(
            f"{k}={v}" for k, v in params.items()
            if k not in ("enabled", "_comment", "severity")
        )
        rows.append([name, enabled, params.get("severity", cls.default_severity),
                     cls.mitre, tuning[:44]])
    _table(["detector", "enabled", "severity", "MITRE ATT&CK", "thresholds"], rows)
    print(f"\n  Thresholds come from {cfg.path}")
    return 0


def cmd_run_all(args) -> int:
    """The one-command demo: data -> alerts -> incidents -> reports -> dashboard."""
    cfg = _config(args)
    raw_dir = Path(args.raw)

    if not args.skip_generate:
        gen_cfg = cfg.generator
        gen = Generator(
            seed=gen_cfg.get("seed", 1337), users=gen_cfg.get("users", 40),
            days=gen_cfg.get("days", 21),
            attack_free_days=gen_cfg.get("attack_free_days", 14),
            start_date=gen_cfg.get("start_date", "2026-08-24T00:00:00Z"),
        )
        gen.build()
        manifest = gen.write(raw_dir)
        _rule("1. Generate synthetic data")
        print(f"  {manifest['valid_events']:,} events, "
              f"{manifest['malformed_lines']} malformed lines, "
              f"{manifest['labelled_events']:,} labelled attack/benign events")

    db_path = Path(args.db)
    if db_path.exists() and not args.keep_db:
        db_path.unlink()

    with Store(args.db) as store:
        _rule("2. Ingest and normalize")
        result = ingest(store, raw_dir / "auth.log")
        load_ground_truth(store, raw_dir / "ground_truth.jsonl")
        print(f"  {result['events_inserted']:,} events ingested, "
              f"{result['parse_errors']} malformed lines recorded")

        _rule("3. Build behavioural baselines")
        profiles = build_profiles(store, cfg.profiling.get("train_days", 14))
        print(f"  {len(profiles)} user profiles from the attack-free training window")

        _rule("4. Run detectors")
        findings, per_detector = run_detection(store, cfg)
        _table(
            ["detector", "alerts"],
            [[name, count] for name, count in per_detector.items()],
        )
        print(f"\n  {len(findings)} alerts total")

        _rule("5. Correlate alerts into incidents")
        incident_ids = correlate(store, cfg)
        multi = [i for i in store.list_incidents() if i["alert_count"] > 1]
        print(f"  {len(incident_ids)} incidents, {len(multi)} grouping multiple alerts")
        _table(
            ["id", "severity", "alerts", "title"],
            [[i["id"], i["severity"], i["alert_count"], i["title"][:52]] for i in multi[:6]],
        )

        _rule("6. Write incident reports")
        for path in write_incident_reports(store, args.reports, limit=args.reports_limit):
            print(f"  {path}")

        _rule("7. Evaluate against ground truth")
        report = evaluate(store)
        print(format_report(report))

        _rule("8. Build dashboard")
        dashboard_path = build_dashboard(
            store, Path(args.reports) / "dashboard.html", evaluation=report
        )
        print(f"  {dashboard_path}")

    _rule("Done")
    print(f"  Database  : {args.db}")
    print(f"  Reports   : {args.reports}/")
    print(f"  Dashboard : {dashboard_path}")
    print(f"\n  Next: python -m loginwatch incidents")
    print(f"        python -m loginwatch incident-show <id>")
    print(f"        open {dashboard_path}")
    return 0


# --------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loginwatch",
        description=(
            "Authentication log monitoring and login anomaly detection, on "
            "synthetic data. A learning project, not a production tool."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "typical run:\n"
            "  python -m loginwatch run-all        # whole pipeline\n"
            "  python -m loginwatch incidents      # see what it found\n"
            "  python -m loginwatch incident-show 1\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"loginwatch {__version__}")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"SQLite path (default: {DEFAULT_DB})")
    parser.add_argument("--config", default=None, help="detector config JSON path")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generate", help="generate the synthetic auth log")
    p.add_argument("--out", default=DEFAULT_RAW)
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--users", type=int, default=None)
    p.add_argument("--days", type=int, default=None)
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("ingest", help="parse and normalize a raw log into the database")
    p.add_argument("--log", default=f"{DEFAULT_RAW}/auth.log")
    p.add_argument("--show-errors", action="store_true", help="list malformed lines")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("profile", help="build per-user behavioural baselines")
    p.add_argument("--train-days", type=int, default=None)
    p.set_defaults(func=cmd_profile)

    p = sub.add_parser("detect", help="run all enabled detectors")
    p.add_argument("--no-clear", action="store_true",
                   help="keep existing alerts instead of starting clean")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("correlate", help="group related alerts into incidents")
    p.set_defaults(func=cmd_correlate)

    p = sub.add_parser("alerts", help="list alerts")
    p.add_argument("--status", choices=ALERT_STATUSES)
    p.add_argument("--severity", choices=["low", "medium", "high", "critical"])
    p.add_argument("--detector")
    p.add_argument("--user")
    p.add_argument("--ip")
    p.add_argument("--limit", type=int)
    p.set_defaults(func=cmd_alerts)

    p = sub.add_parser("alert-show", help="show one alert with its full evidence")
    p.add_argument("alert_id", type=int)
    p.set_defaults(func=cmd_alert_show)

    p = sub.add_parser("triage", help="set an alert's status and add a note")
    p.add_argument("alert_id", type=int)
    p.add_argument("--status", choices=ALERT_STATUSES)
    p.add_argument("--note")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("incidents", help="list correlated incidents")
    p.add_argument("--verdict", choices=INCIDENT_VERDICTS)
    p.add_argument("--severity", choices=["low", "medium", "high", "critical"])
    p.set_defaults(func=cmd_incidents)

    p = sub.add_parser("incident-show", help="print an incident write-up")
    p.add_argument("incident_id", type=int)
    p.set_defaults(func=cmd_incident_show)

    p = sub.add_parser("incident-triage", help="record a verdict on an incident")
    p.add_argument("incident_id", type=int)
    p.add_argument("--verdict", choices=INCIDENT_VERDICTS)
    p.add_argument("--status", choices=ALERT_STATUSES)
    p.add_argument("--note")
    p.set_defaults(func=cmd_incident_triage)

    p = sub.add_parser("report", help="write incident reports to markdown")
    p.add_argument("--out", default=DEFAULT_REPORTS)
    p.add_argument("--limit", type=int, default=3)
    p.add_argument("--incident", type=int, help="report on one specific incident")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("dashboard", help="build the static HTML summary dashboard")
    p.add_argument("--out", default=f"{DEFAULT_REPORTS}/dashboard.html")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("evaluate", help="score detections against ground truth")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser(
        "ai-triage",
        help="OPTIONAL: draft a triage note for an alert (offline by default)",
    )
    p.add_argument("alert_id", type=int)
    p.add_argument("--backend", default="auto", choices=["auto", "template", "anthropic"])
    p.add_argument("--show-prompt", action="store_true",
                   help="print the structured prompt instead of running it")
    p.set_defaults(func=cmd_ai_triage)

    p = sub.add_parser("detectors", help="list detectors and their configured thresholds")
    p.set_defaults(func=cmd_detectors)

    p = sub.add_parser("run-all", help="run the whole pipeline end to end")
    p.add_argument("--raw", default=DEFAULT_RAW)
    p.add_argument("--reports", default=DEFAULT_REPORTS)
    p.add_argument("--reports-limit", type=int, default=3)
    p.add_argument("--skip-generate", action="store_true")
    p.add_argument("--keep-db", action="store_true",
                   help="append to the existing database instead of rebuilding")
    p.set_defaults(func=cmd_run_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

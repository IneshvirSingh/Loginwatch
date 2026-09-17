"""Static HTML summary dashboard.

Deliberately a single self-contained HTML file with hand-written inline SVG:
no JavaScript framework, no charting library, no CDN, no network access. The
project has to run fully offline, and a summary view is not a good reason to
take on a frontend build.

CHART DESIGN NOTES
------------------
Both charts are single-series and use one hue, because both answer a magnitude
question ("how many alerts?"). Severity is NOT encoded as colour inside the
time chart. That was a considered choice: a four-colour severity stack puts
amber next to orange, and those two are hard to separate for a colour-blind
reader (and, measured properly, for everyone else too). Severity instead gets
its own labelled tiles, where the count and the word carry the meaning and
colour is only an accent - so nothing in this page depends on hue alone.

Every chart is also reproduced as a table further down the page, which is both
an accessibility requirement and genuinely what an analyst wants when they stop
skimming and start working.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import SEVERITIES, SEVERITY_RANK, from_epoch
from .storage import Store

# Status accents, used only alongside a written label - never as the sole
# carrier of meaning. Values are the documented status palette.
SEVERITY_COLOR = {
    "low": "#0ca30c",
    "medium": "#fab219",
    "high": "#ec835a",
    "critical": "#d03b3b",
}


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _day(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def _bar_chart(
    labels: list[str], values: list[int], height: int = 190,
    bar_gap: int = 2, label_every: int = 1,
) -> str:
    """Vertical bar chart: counts over time, one series, one hue.

    Rounded 4px data-end anchored to the baseline, 2px gap between bars,
    recessive baseline, values labelled only where non-zero.
    """
    if not values:
        return '<p class="empty">No data.</p>'

    width = 720
    pad_left, pad_right, pad_top, pad_bottom = 8, 8, 22, 34
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom
    n = len(values)
    slot = plot_w / n
    bar_w = max(slot - bar_gap, 2)
    top = max(values) or 1

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Alerts per day" class="chart">'
    ]
    baseline_y = pad_top + plot_h
    parts.append(
        f'<line x1="{pad_left}" y1="{baseline_y}" x2="{width - pad_right}" '
        f'y2="{baseline_y}" class="axis"/>'
    )

    for index, (label, value) in enumerate(zip(labels, values)):
        x = pad_left + index * slot
        bar_h = (value / top) * plot_h
        y = baseline_y - bar_h
        if value > 0:
            radius = min(4, bar_w / 2, bar_h)
            # Rounded top, square bottom: the data-end is rounded, the
            # baseline end stays anchored.
            parts.append(
                f'<path d="M{x:.1f},{baseline_y:.1f} L{x:.1f},{y + radius:.1f} '
                f'Q{x:.1f},{y:.1f} {x + radius:.1f},{y:.1f} '
                f'L{x + bar_w - radius:.1f},{y:.1f} '
                f'Q{x + bar_w:.1f},{y:.1f} {x + bar_w:.1f},{y + radius:.1f} '
                f'L{x + bar_w:.1f},{baseline_y:.1f} Z" class="bar">'
                f'<title>{_esc(label)}: {value} alert'
                f'{"s" if value != 1 else ""}</title></path>'
            )
            parts.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{y - 6:.1f}" '
                f'class="bar-value">{value}</text>'
            )
        if index % label_every == 0 or index == n - 1:
            parts.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{baseline_y + 16:.1f}" '
                f'class="tick">{_esc(label[5:])}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def _hbar_chart(rows: list[tuple[str, int]], row_h: int = 30) -> str:
    """Horizontal bars with direct value labels - one series, one hue."""
    if not rows:
        return '<p class="empty">No data.</p>'

    width = 720
    label_w = 190
    value_w = 46
    plot_w = width - label_w - value_w - 12
    height = row_h * len(rows) + 8
    top = max(v for _, v in rows) or 1

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="Alerts by detector" class="chart">'
    ]
    for index, (label, value) in enumerate(rows):
        y = index * row_h + 4
        bar_h = row_h - 10
        bar_w = max((value / top) * plot_w, 2)
        radius = min(4, bar_h / 2, bar_w)
        parts.append(
            f'<text x="{label_w - 10}" y="{y + bar_h - 3}" class="row-label" '
            f'text-anchor="end">{_esc(label)}</text>'
        )
        parts.append(
            f'<path d="M{label_w},{y} L{label_w + bar_w - radius:.1f},{y} '
            f'Q{label_w + bar_w:.1f},{y} {label_w + bar_w:.1f},{y + radius:.1f} '
            f'L{label_w + bar_w:.1f},{y + bar_h - radius:.1f} '
            f'Q{label_w + bar_w:.1f},{y + bar_h} '
            f'{label_w + bar_w - radius:.1f},{y + bar_h} L{label_w},{y + bar_h} Z" '
            f'class="bar"><title>{_esc(label)}: {value}</title></path>'
        )
        parts.append(
            f'<text x="{label_w + bar_w + 8:.1f}" y="{y + bar_h - 3}" '
            f'class="bar-value" text-anchor="start">{value}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _table(headers: list[str], rows: list[list[str]], empty: str = "Nothing to show.") -> str:
    if not rows:
        return f'<p class="empty">{_esc(empty)}</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    return (
        f'<div class="scroll"><table><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def _sev_badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "#898781")
    return (
        f'<span class="badge"><span class="dot" style="background:{color}"></span>'
        f"{_esc(severity)}</span>"
    )


def build_dashboard(
    store: Store, out_path: str | Path, evaluation: dict | None = None
) -> Path:
    """Render the whole dashboard to a single HTML file."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    alerts = [dict(r) for r in store.list_alerts()]
    incidents = [dict(r) for r in store.list_incidents()]
    first_ts, last_ts = store.time_range()

    # --- alerts per day -------------------------------------------------
    per_day: dict[str, int] = {}
    if first_ts:
        cursor = first_ts - (first_ts % 86400)
        while cursor <= last_ts:
            per_day[_day(cursor)] = 0
            cursor += 86400
    for alert in alerts:
        key = _day(alert["first_ts_epoch"])
        per_day[key] = per_day.get(key, 0) + 1
    day_labels = sorted(per_day)
    day_values = [per_day[d] for d in day_labels]

    # --- counts ---------------------------------------------------------
    by_severity = {s: 0 for s in SEVERITIES}
    for alert in alerts:
        by_severity[alert["severity"]] = by_severity.get(alert["severity"], 0) + 1

    by_detector = sorted(
        store.alert_counts_by("detector"), key=lambda kv: -kv[1]
    )
    by_status = dict(store.alert_counts_by("status"))

    top_ips: dict[str, dict] = {}
    top_accounts: dict[str, dict] = {}
    for alert in alerts:
        if alert["src_ip"]:
            entry = top_ips.setdefault(
                alert["src_ip"], {"alerts": 0, "worst": "low", "detectors": set()}
            )
            entry["alerts"] += 1
            entry["detectors"].add(alert["detector"])
            if SEVERITY_RANK.get(alert["severity"], 0) > SEVERITY_RANK.get(entry["worst"], 0):
                entry["worst"] = alert["severity"]
        if alert["username"]:
            entry = top_accounts.setdefault(
                alert["username"], {"alerts": 0, "worst": "low", "detectors": set()}
            )
            entry["alerts"] += 1
            entry["detectors"].add(alert["detector"])
            if SEVERITY_RANK.get(alert["severity"], 0) > SEVERITY_RANK.get(entry["worst"], 0):
                entry["worst"] = alert["severity"]

    def _rank(items):
        return sorted(
            items.items(),
            key=lambda kv: (-kv[1]["alerts"], -SEVERITY_RANK.get(kv[1]["worst"], 0)),
        )[:10]

    # --- stat tiles -----------------------------------------------------
    tiles = [
        ("Events ingested", f"{store.event_count():,}", "normalized auth records"),
        ("Malformed lines", f"{store.parse_error_count():,}", "recorded, not dropped"),
        ("Alerts raised", f"{len(alerts):,}", f"{len(by_detector)} detectors fired"),
        ("Incidents", f"{len(incidents):,}", f"{sum(1 for i in incidents if i['alert_count'] > 1)} multi-alert"),
    ]
    if evaluation and "detection_rate" in evaluation:
        tiles.append((
            "Attacks detected",
            f"{evaluation['attack_instances_detected']}/{evaluation['attack_instances_injected']}",
            f"{evaluation['detection_rate'] * 100:.0f}% of injected episodes",
        ))

    tile_html = "".join(
        f'<div class="tile"><div class="tile-label">{_esc(label)}</div>'
        f'<div class="tile-value">{_esc(value)}</div>'
        f'<div class="tile-note">{_esc(note)}</div></div>'
        for label, value, note in tiles
    )

    sev_html = "".join(
        f'<div class="tile sev"><div class="tile-label">'
        f'<span class="dot" style="background:{SEVERITY_COLOR[s]}"></span>'
        f'{s.title()} severity</div>'
        f'<div class="tile-value">{by_severity.get(s, 0)}</div></div>'
        for s in reversed(SEVERITIES)
    )

    # --- tables ---------------------------------------------------------
    incident_rows = []
    for incident in sorted(
        incidents,
        key=lambda i: (SEVERITY_RANK.get(i["severity"], 0), i["alert_count"]),
        reverse=True,
    )[:15]:
        entities = json.loads(incident["entities_json"] or "{}")
        incident_rows.append([
            f"<strong>{incident['id']}</strong>",
            _sev_badge(incident["severity"]),
            str(incident["alert_count"]),
            _esc(incident["title"]),
            ", ".join(entities.get("usernames") or []) or "-",
            f"{from_epoch(incident['first_ts_epoch'])}",
            _esc(incident["verdict"]),
        ])

    ip_rows = [
        [
            f"<code>{_esc(ip)}</code>", str(data["alerts"]), _sev_badge(data["worst"]),
            ", ".join(sorted(data["detectors"])),
        ]
        for ip, data in _rank(top_ips)
    ]
    account_rows = [
        [
            _esc(user), str(data["alerts"]), _sev_badge(data["worst"]),
            ", ".join(sorted(data["detectors"])),
        ]
        for user, data in _rank(top_accounts)
    ]
    day_rows = [[d, str(v)] for d, v in zip(day_labels, day_values) if v]
    detector_rows = [[_esc(name), str(count)] for name, count in by_detector]
    status_rows = [[_esc(k), str(v)] for k, v in sorted(by_status.items())]

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    window = (
        f"{from_epoch(first_ts)} to {from_epoch(last_ts)}" if first_ts else "no data"
    )

    eval_section = ""
    if evaluation and "by_scenario" in evaluation:
        rows = [
            [
                _esc(scenario), str(row["injected"]), str(row["detected"]),
                ", ".join(row["detected_by"]) or "-",
            ]
            for scenario, row in sorted(evaluation["by_scenario"].items())
        ]
        eval_section = f"""
  <section>
    <h2>Detection accuracy against ground truth</h2>
    <p class="lede">The generator labels every injected attack, so detection can be
    measured rather than asserted. An episode counts as detected when at least one
    alert cites at least one of its events.</p>
    {_table(["Scenario", "Injected", "Detected", "Caught by"], rows)}
    <p class="note">Of {evaluation['alerts_total']} alerts,
    {evaluation['alerts_true_positive']} matched an injected attack,
    {evaluation['alerts_false_positive_on_benign_anomaly']} fired on deliberately
    injected <em>benign</em> anomalies (business travel, new laptops, on-call
    nights), and {evaluation['alerts_false_positive_on_normal_traffic']} fired on
    ordinary traffic. These numbers describe one synthetic dataset whose attacks
    were written alongside the detectors that catch them - useful for catching
    regressions, not evidence of real-world accuracy.</p>
  </section>"""

    return _write_html(
        out_path, generated, window, tile_html, sev_html,
        _bar_chart(day_labels, day_values, label_every=max(1, len(day_labels) // 12)),
        _hbar_chart(by_detector),
        _table(["Incident", "Severity", "Alerts", "Title", "Accounts", "First activity", "Verdict"], incident_rows, "No incidents."),
        _table(["Source IP", "Alerts", "Worst severity", "Detectors"], ip_rows, "No source IPs implicated."),
        _table(["Account", "Alerts", "Worst severity", "Detectors"], account_rows, "No accounts implicated."),
        _table(["Date", "Alerts"], day_rows, "No alerts."),
        _table(["Detector", "Alerts"], detector_rows, "No alerts."),
        _table(["Triage status", "Alerts"], status_rows, "No alerts."),
        eval_section,
    )


def _write_html(
    out_path: Path, generated: str, window: str, tiles: str, sev_tiles: str,
    day_chart: str, detector_chart: str, incident_table: str, ip_table: str,
    account_table: str, day_table: str, detector_table: str, status_table: str,
    eval_section: str,
) -> Path:
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>loginwatch - authentication monitoring summary</title>
<style>
  :root {{
    color-scheme: light;
    --surface-1: #fcfcfb;
    --plane: #f9f9f7;
    --text-primary: #0b0b0b;
    --text-secondary: #52514e;
    --muted: #898781;
    --grid: #e1e0d9;
    --axis: #c3c2b7;
    --series-1: #2a78d6;
    --border: rgba(11,11,11,0.10);
    --warn-bg: #fff8e6;
    --warn-border: #f0d894;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      color-scheme: dark;
      --surface-1: #1a1a19;
      --plane: #0d0d0d;
      --text-primary: #ffffff;
      --text-secondary: #c3c2b7;
      --muted: #898781;
      --grid: #2c2c2a;
      --axis: #383835;
      --series-1: #3987e5;
      --border: rgba(255,255,255,0.10);
      --warn-bg: #2a2416;
      --warn-border: #5c4c1f;
    }}
  }}
  :root[data-theme="dark"] {{
    color-scheme: dark;
    --surface-1: #1a1a19;
    --plane: #0d0d0d;
    --text-primary: #ffffff;
    --text-secondary: #c3c2b7;
    --muted: #898781;
    --grid: #2c2c2a;
    --axis: #383835;
    --series-1: #3987e5;
    --border: rgba(255,255,255,0.10);
    --warn-bg: #2a2416;
    --warn-border: #5c4c1f;
  }}

  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--plane);
    color: var(--text-primary);
    font: 14px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  .wrap {{ max-width: 1040px; margin: 0 auto; padding-block: 28px; padding-left: 16px; padding-right: 16px; }}
  header h1 {{ font-size: 21px; margin: 0 0 4px; letter-spacing: -0.01em; }}
  header .meta {{ color: var(--text-secondary); font-size: 13px; margin: 0; }}
  .banner {{
    margin: 16px 0 24px; padding: 11px 14px; border-radius: 8px;
    background: var(--warn-bg); border: 1px solid var(--warn-border);
    color: var(--text-primary); font-size: 13px;
  }}
  section {{
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px 18px 20px; margin-bottom: 18px;
  }}
  h2 {{ font-size: 15px; margin: 0 0 4px; letter-spacing: -0.005em; }}
  .lede {{ color: var(--text-secondary); font-size: 13px; margin: 0 0 14px; }}
  .note {{ color: var(--text-secondary); font-size: 12.5px; margin: 14px 0 0; }}
  .empty {{ color: var(--muted); font-size: 13px; margin: 6px 0; }}

  .tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }}
  .tile {{
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 9px; padding: 13px 14px;
  }}
  .tile-label {{ color: var(--text-secondary); font-size: 12px; display: flex; align-items: center; gap: 6px; }}
  .tile-value {{ font-size: 26px; font-weight: 600; margin-top: 3px; letter-spacing: -0.02em; }}
  .tile-note {{ color: var(--muted); font-size: 11.5px; margin-top: 2px; }}
  .dot {{ width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: none; }}

  .chart {{ width: 100%; height: auto; display: block; overflow: visible; }}
  .bar {{ fill: var(--series-1); }}
  .bar:hover {{ opacity: 0.82; }}
  .axis {{ stroke: var(--axis); stroke-width: 1; }}
  .tick {{ fill: var(--muted); font-size: 10px; text-anchor: middle; font-variant-numeric: tabular-nums; }}
  .bar-value {{ fill: var(--text-secondary); font-size: 10.5px; text-anchor: middle; font-variant-numeric: tabular-nums; }}
  .row-label {{ fill: var(--text-secondary); font-size: 11.5px; }}

  .scroll {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
  th {{
    text-align: left; color: var(--text-secondary); font-weight: 600;
    font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.04em;
    padding: 7px 10px 7px 0; border-bottom: 1px solid var(--grid); white-space: nowrap;
  }}
  td {{ padding: 7px 10px 7px 0; border-bottom: 1px solid var(--grid); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
  .badge {{ display: inline-flex; align-items: center; gap: 5px; white-space: nowrap; }}
  .cols {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; }}
  footer {{ color: var(--muted); font-size: 12px; padding: 4px 2px 20px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>loginwatch &mdash; authentication monitoring summary</h1>
    <p class="meta">Generated {generated} &middot; Data window {window}</p>
  </header>

  <div class="banner">
    <strong>Synthetic data.</strong> Every account, IP address and location on this
    page was produced by this project's data generator. IPs come from reserved,
    non-routable ranges. No real person, system or credential is represented, and
    nothing here was collected from a live network.
  </div>

  <section>
    <h2>Pipeline</h2>
    <p class="lede">What went in, and what came out.</p>
    <div class="tiles">{tiles}</div>
  </section>

  <section>
    <h2>Alerts by severity</h2>
    <p class="lede">Severity is set per detector in <code>config/detectors.json</code>,
    and raised automatically when a detector finds corroborating evidence (for
    example, a brute force where a login then succeeded).</p>
    <div class="tiles">{sev_tiles}</div>
  </section>

  <section>
    <h2>Alerts per day</h2>
    <p class="lede">The first two weeks of the dataset are attack-free by
    construction &mdash; they exist to build per-user baselines. Alerts concentrate in
    the final week, where attacks were injected.</p>
    {day_chart}
  </section>

  <section>
    <h2>Alerts by detector</h2>
    <p class="lede">Which detections are carrying the load, and which are noisy.</p>
    {detector_chart}
  </section>

  <section>
    <h2>Incidents</h2>
    <p class="lede">Alerts sharing an account or source IP within the correlation
    window are grouped into one incident, so a single attack arrives as one item
    of work rather than four.</p>
    {incident_table}
  </section>

  <div class="cols">
    <section>
      <h2>Top source IPs</h2>
      <p class="lede">Ranked by alert count, then worst severity.</p>
      {ip_table}
    </section>
    <section>
      <h2>Top accounts</h2>
      <p class="lede">Accounts appearing in the most alerts.</p>
      {account_table}
    </section>
  </div>
{eval_section}
  <section>
    <h2>Chart data</h2>
    <p class="lede">The same figures as the charts above, in text form.</p>
    <div class="cols">
      <div>
        <h3 style="font-size:13px;margin:0 0 6px">Alerts per day</h3>
        {day_table}
      </div>
      <div>
        <h3 style="font-size:13px;margin:0 0 6px">Alerts per detector</h3>
        {detector_table}
      </div>
      <div>
        <h3 style="font-size:13px;margin:0 0 6px">Triage status</h3>
        {status_table}
      </div>
    </div>
  </section>

</div>
</body>
</html>
"""
    out_path.write_text(html_doc, encoding="utf-8")
    return out_path

"""Measuring whether the detection actually works.

WHY THIS MODULE EXISTS
----------------------
It is very easy to build a detection system, look at a queue full of alerts,
and conclude that it works. This module exists to stop that. It compares the
alerts against the generator's ground-truth labels and produces numbers that
can embarrass the detectors.

HOW AN ATTACK COUNTS AS DETECTED
--------------------------------
Per *injection instance*, not per event. The generator tags every synthetic
attack event with an instance id (`brute_force#2`), and an instance counts as
detected if at least one alert's evidence includes at least one of its events.

That is the right unit for this question. An analyst does not need an alert for
each of thirty password guesses - they need one alert that tells them the
episode happened. Scoring per-event would reward a detector for being noisy.

HOW A FALSE POSITIVE IS COUNTED
-------------------------------
An alert is a false positive if none of its evidence events carry an `attack`
label. Those split into two kinds, which are reported separately because they
mean different things:

  * fires on a labelled BENIGN anomaly - the business traveller, the new
    laptop, the on-call engineer. The detector did what it was built to do and
    the activity was still legitimate. This is the irreducible cost of the
    detection, and the number an analyst actually feels.
  * fires on ordinary traffic - no injected anomaly at all. This is the
    detector being wrong on its own terms, and is the more serious kind.

WHAT THESE NUMBERS ARE NOT
--------------------------
They describe performance on one synthetic dataset whose attacks were written
by the same person who wrote the detectors. That is a meaningful check for
regressions and a completely inadequate basis for claiming real-world accuracy.
See LIMITATIONS.md.
"""

from __future__ import annotations

import json

from .storage import Store


def evaluate(store: Store) -> dict:
    """Score alerts against ground truth. Returns a report dict."""
    truth = store.ground_truth()
    if not truth:
        return {"error": "no ground truth loaded; run `loginwatch generate` first"}

    alerts = [dict(row) for row in store.list_alerts()]

    # instance id -> every event id belonging to that injection
    instances: dict[str, dict] = {}
    for event_id, meta in truth.items():
        entry = instances.setdefault(
            meta["instance"],
            {
                "instance": meta["instance"],
                "scenario": meta["scenario"],
                "label": meta["label"],
                "event_ids": set(),
            },
        )
        entry["event_ids"].add(event_id)

    attack_event_ids = {e for e, m in truth.items() if m["label"] == "attack"}
    benign_event_ids = {e for e, m in truth.items() if m["label"] == "benign"}

    detected_by: dict[str, set[str]] = {}  # instance -> detectors that caught it
    true_positive_alerts: list[dict] = []
    fp_on_benign: list[dict] = []
    fp_on_normal: list[dict] = []

    for alert in alerts:
        alert_events = set(json.loads(alert["event_ids_json"] or "[]"))

        hit_instances = {
            inst["instance"]
            for inst in instances.values()
            if inst["label"] == "attack" and (alert_events & inst["event_ids"])
        }
        for instance_id in hit_instances:
            detected_by.setdefault(instance_id, set()).add(alert["detector"])

        if alert_events & attack_event_ids:
            true_positive_alerts.append(alert)
        elif alert_events & benign_event_ids:
            fp_on_benign.append(alert)
        else:
            fp_on_normal.append(alert)

    attack_instances = [i for i in instances.values() if i["label"] == "attack"]
    benign_instances = [i for i in instances.values() if i["label"] == "benign"]

    by_scenario: dict[str, dict] = {}
    for inst in attack_instances:
        row = by_scenario.setdefault(
            inst["scenario"], {"injected": 0, "detected": 0, "detected_by": set()}
        )
        row["injected"] += 1
        if inst["instance"] in detected_by:
            row["detected"] += 1
            row["detected_by"].update(detected_by[inst["instance"]])

    for row in by_scenario.values():
        row["detected_by"] = sorted(row["detected_by"])

    missed = sorted(
        i["instance"] for i in attack_instances if i["instance"] not in detected_by
    )

    # Per-detector precision, using the same attack/benign/normal split.
    per_detector: dict[str, dict] = {}
    for alert in alerts:
        row = per_detector.setdefault(
            alert["detector"], {"alerts": 0, "true_positive": 0, "false_positive": 0}
        )
        row["alerts"] += 1
        alert_events = set(json.loads(alert["event_ids_json"] or "[]"))
        if alert_events & attack_event_ids:
            row["true_positive"] += 1
        else:
            row["false_positive"] += 1
    for row in per_detector.values():
        row["precision"] = (
            round(row["true_positive"] / row["alerts"], 3) if row["alerts"] else 0.0
        )

    total_attacks = len(attack_instances)
    total_detected = sum(1 for i in attack_instances if i["instance"] in detected_by)

    return {
        "attack_instances_injected": total_attacks,
        "attack_instances_detected": total_detected,
        "detection_rate": (
            round(total_detected / total_attacks, 3) if total_attacks else 0.0
        ),
        "missed_instances": missed,
        "by_scenario": by_scenario,
        "alerts_total": len(alerts),
        "alerts_true_positive": len(true_positive_alerts),
        "alerts_false_positive_on_benign_anomaly": len(fp_on_benign),
        "alerts_false_positive_on_normal_traffic": len(fp_on_normal),
        "overall_precision": (
            round(len(true_positive_alerts) / len(alerts), 3) if alerts else 0.0
        ),
        "benign_anomalies_injected": len(benign_instances),
        "per_detector": per_detector,
        "fp_on_benign_detail": [
            {
                "alert_id": a["id"], "detector": a["detector"],
                "severity": a["severity"], "title": a["title"],
            }
            for a in fp_on_benign
        ],
        "fp_on_normal_detail": [
            {
                "alert_id": a["id"], "detector": a["detector"],
                "severity": a["severity"], "title": a["title"],
            }
            for a in fp_on_normal
        ],
    }


def format_report(report: dict) -> str:
    """Render the evaluation as plain text for the CLI."""
    if "error" in report:
        return f"error: {report['error']}"

    lines = [
        "DETECTION EVALUATION (synthetic dataset, ground truth from generator)",
        "=" * 70,
        "",
        f"Attack episodes injected : {report['attack_instances_injected']}",
        f"Attack episodes detected : {report['attack_instances_detected']} "
        f"({report['detection_rate'] * 100:.0f}%)",
        f"Benign anomalies injected: {report['benign_anomalies_injected']} "
        f"(legitimate travel / new laptops / on-call nights)",
        "",
        "Per attack scenario",
        "-" * 70,
        f"{'scenario':<26}{'injected':>9}{'detected':>10}  caught by",
    ]
    for scenario, row in sorted(report["by_scenario"].items()):
        lines.append(
            f"{scenario:<26}{row['injected']:>9}{row['detected']:>10}  "
            f"{', '.join(row['detected_by']) or '-'}"
        )
    if report["missed_instances"]:
        lines += ["", f"MISSED: {', '.join(report['missed_instances'])}"]

    lines += [
        "",
        "Alert quality",
        "-" * 70,
        f"Total alerts                        : {report['alerts_total']}",
        f"  matching a real injected attack   : {report['alerts_true_positive']}",
        f"  fired on a labelled benign anomaly: "
        f"{report['alerts_false_positive_on_benign_anomaly']}",
        f"  fired on ordinary traffic         : "
        f"{report['alerts_false_positive_on_normal_traffic']}",
        f"Overall precision                   : "
        f"{report['overall_precision'] * 100:.0f}%",
        "",
        "Per detector",
        "-" * 70,
        f"{'detector':<26}{'alerts':>8}{'TP':>6}{'FP':>6}{'precision':>11}",
    ]
    for detector, row in sorted(report["per_detector"].items()):
        lines.append(
            f"{detector:<26}{row['alerts']:>8}{row['true_positive']:>6}"
            f"{row['false_positive']:>6}{row['precision'] * 100:>10.0f}%"
        )

    if report["fp_on_benign_detail"]:
        lines += ["", "False positives on labelled benign anomalies", "-" * 70]
        for fp in report["fp_on_benign_detail"]:
            lines.append(
                f"  alert #{fp['alert_id']:<4} {fp['detector']:<24} {fp['title']}"
            )
    if report["fp_on_normal_detail"]:
        lines += ["", "False positives on ordinary traffic", "-" * 70]
        for fp in report["fp_on_normal_detail"]:
            lines.append(
                f"  alert #{fp['alert_id']:<4} {fp['detector']:<24} {fp['title']}"
            )

    lines += [
        "",
        "These figures describe ONE synthetic dataset whose attacks were written",
        "alongside the detectors that catch them. They are useful for spotting",
        "regressions, not for claiming real-world accuracy. See LIMITATIONS.md.",
    ]
    return "\n".join(lines)

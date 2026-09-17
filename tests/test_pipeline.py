"""End-to-end pipeline test.

This runs the real pipeline on the real default dataset and asserts the
numbers the README quotes. It is the regression guard on the project's headline
claims: if a threshold change silently starts missing an attack or firing on
ordinary traffic, this test fails rather than the README quietly becoming
untrue.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loginwatch.cli import main
from loginwatch.config import Config
from loginwatch.correlate import correlate
from loginwatch.dashboard import build_dashboard
from loginwatch.engine import ingest, load_ground_truth, run_detection
from loginwatch.evaluate import evaluate
from loginwatch.generator import Generator
from loginwatch.profiling import build_profiles
from loginwatch.reporting import write_incident_reports
from loginwatch.storage import Store


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    """Run the whole pipeline once with the shipped configuration."""
    workdir = tmp_path_factory.mktemp("pipeline")
    raw = workdir / "raw"
    config = Config.load()
    gen_cfg = config.generator

    generator = Generator(
        seed=gen_cfg["seed"], users=gen_cfg["users"], days=gen_cfg["days"],
        attack_free_days=gen_cfg["attack_free_days"],
        start_date=gen_cfg["start_date"],
    )
    generator.build()
    manifest = generator.write(raw)

    store = Store(workdir / "lw.db")
    ingest_result = ingest(store, raw / "auth.log")
    load_ground_truth(store, raw / "ground_truth.jsonl")
    build_profiles(store, config.profiling["train_days"])
    findings, per_detector = run_detection(store, config)
    correlate(store, config)
    reports = write_incident_reports(store, workdir / "reports", limit=3)
    report = evaluate(store)
    dashboard = build_dashboard(
        store, workdir / "reports" / "dashboard.html", evaluation=report
    )

    yield {
        "store": store, "manifest": manifest, "ingest": ingest_result,
        "findings": findings, "per_detector": per_detector,
        "evaluation": report, "reports": reports, "dashboard": dashboard,
        "workdir": workdir,
    }
    store.close()


class TestDefinitionOfDone:
    def test_events_are_ingested(self, pipeline):
        assert pipeline["ingest"]["events_inserted"] > 2000
        assert pipeline["store"].event_count() == pipeline["manifest"]["valid_events"]

    def test_malformed_lines_are_recorded_and_survived(self, pipeline):
        assert pipeline["ingest"]["parse_errors"] == pipeline["manifest"]["malformed_lines"]
        assert pipeline["store"].parse_error_count() > 0

    def test_alerts_are_generated(self, pipeline):
        assert len(pipeline["findings"]) > 0
        assert len(pipeline["store"].list_alerts()) == len(pipeline["findings"])

    def test_every_detector_is_exercised_by_the_dataset(self, pipeline):
        """If a detector never fires, its threshold or the data has drifted."""
        silent = [name for name, n in pipeline["per_detector"].items() if n == 0]
        assert silent == [], f"detectors produced no findings: {silent}"

    def test_at_least_one_incident_correlates_several_alerts(self, pipeline):
        multi = [i for i in pipeline["store"].list_incidents() if i["alert_count"] > 1]
        assert len(multi) >= 1

    def test_account_takeover_lands_as_one_incident_not_four_alerts(self, pipeline):
        """The correlation engine's whole reason for existing."""
        incidents = [
            i for i in pipeline["store"].list_incidents()
            if "compromise" in i["title"].lower()
        ]
        assert incidents, "expected a correlated account-compromise incident"
        worst = max(incidents, key=lambda i: i["alert_count"])
        assert worst["alert_count"] >= 3
        assert worst["severity"] == "critical"

    def test_incident_reports_are_written(self, pipeline):
        assert len(pipeline["reports"]) == 3
        for path in pipeline["reports"]:
            text = Path(path).read_text()
            assert "## Timeline" in text
            assert "## Recommended actions" in text
            assert len(text) > 1000

    def test_dashboard_is_written(self, pipeline):
        html = Path(pipeline["dashboard"]).read_text()
        assert html.startswith("<!doctype html>")
        assert "Synthetic data" in html
        assert "<svg" in html

    def test_dashboard_has_no_external_resources(self, pipeline):
        """The project must run fully offline."""
        html = Path(pipeline["dashboard"]).read_text()
        for marker in ("http://", "https://", "<script"):
            assert marker not in html, f"dashboard references {marker}"


class TestDetectionQuality:
    """The numbers quoted in the README and DETECTIONS.md."""

    def test_every_injected_attack_is_detected(self, pipeline):
        report = pipeline["evaluation"]
        assert report["attack_instances_injected"] == 12
        assert report["detection_rate"] == 1.0, (
            f"missed: {report['missed_instances']}"
        )

    def test_no_alerts_fire_on_ordinary_traffic(self, pipeline):
        report = pipeline["evaluation"]
        assert report["alerts_false_positive_on_normal_traffic"] == 0, (
            f"unexpected alerts: {report['fp_on_normal_detail']}"
        )

    def test_remaining_false_positives_are_all_injected_benign_anomalies(self, pipeline):
        """Honest accounting: the FPs we do have are business travel, new
        laptops and on-call nights - deliberately planted, and exactly the
        noise this class of detection produces in reality."""
        report = pipeline["evaluation"]
        assert report["alerts_false_positive_on_benign_anomaly"] > 0
        assert (
            report["alerts_true_positive"]
            + report["alerts_false_positive_on_benign_anomaly"]
            + report["alerts_false_positive_on_normal_traffic"]
            == report["alerts_total"]
        )

    def test_volumetric_detectors_are_precise(self, pipeline):
        """Threshold-based detections should be near-exact on this data."""
        per_detector = pipeline["evaluation"]["per_detector"]
        for name in ("brute_force", "password_spray", "credential_stuffing",
                     "post_failure_success", "impossible_travel"):
            assert per_detector[name]["precision"] == 1.0, f"{name} lost precision"

    def test_detectors_never_read_the_ground_truth(self, pipeline):
        """Labels exist only for evaluation. If detection depended on them the
        accuracy numbers would be meaningless."""
        import subprocess

        result = subprocess.run(
            ["grep", "-rn", "ground_truth", "loginwatch/detectors/",
             "loginwatch/engine.py", "loginwatch/profiling.py"],
            capture_output=True, text=True,
        )
        offending = [
            line for line in result.stdout.splitlines()
            if "load_ground_truth" not in line and "#" not in line.split("ground_truth")[0][-3:]
        ]
        assert not [
            line for line in offending
            if "loginwatch/detectors/" in line
        ], f"a detector references ground truth: {offending}"


class TestCli:
    def test_run_all_completes(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        exit_code = main([
            "--db", str(tmp_path / "cli.db"), "run-all",
            "--raw", str(tmp_path / "raw"), "--reports", str(tmp_path / "reports"),
        ])
        assert exit_code == 0
        assert (tmp_path / "reports" / "dashboard.html").exists()
        assert list((tmp_path / "reports").glob("incident-*.md"))
        out = capsys.readouterr().out
        assert "Attack episodes detected" in out

    def test_detectors_command_lists_every_detector(self, capsys):
        assert main(["detectors"]) == 0
        out = capsys.readouterr().out
        for name in ("brute_force", "password_spray", "impossible_travel",
                     "post_failure_success"):
            assert name in out

    def test_unknown_alert_exits_nonzero(self, tmp_path, capsys):
        assert main(["--db", str(tmp_path / "e.db"), "alert-show", "999"]) == 1

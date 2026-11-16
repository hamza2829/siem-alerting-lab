import csv
import json
from io import StringIO
from pathlib import Path

import pytest

from siem_lab.__main__ import cli, run
from siem_lab.dashboard import render
from siem_lab.evaluate import evaluate, timing, write_results
from siem_lab.records import write_json
from siem_lab.rules.common import Settings


def test_benchmark_keeps_trials_and_latency_reproducible(
    settings: dict[str, Settings], tmp_path: Path
) -> None:
    report = evaluate(settings, runs=2)
    assert report == evaluate(settings, runs=2)
    assert report["summary"]["attack_trials"] == 10
    assert report["summary"]["benign_customer_trials"] == 6
    assert (
        sum(trial["alert_id"] is not None for trial in report["attack_trials"])
        == (report["summary"]["detected"])
    )
    assert report["summary"]["missed"] + report["summary"]["detected"] == 10
    write_results(tmp_path, report)
    assert json.loads((tmp_path / "results.json").read_bytes()) == report
    summary = (tmp_path / "results.md").read_text(encoding="utf-8")
    assert "Detection rate" in summary and "Fixture variant" in summary


def test_latency_handles_empty_trials_and_uses_nearest_rank() -> None:
    assert timing([]) == {"mean": None, "median": None, "p95": None}
    assert timing(range(1, 21)) == {"mean": 10.5, "median": 10.5, "p95": 19}


def test_demo_creates_data_dashboard_and_real_counts(tmp_path: Path) -> None:
    run(cli().parse_args(["demo", "--out", str(tmp_path), "--runs", "2"]))
    alerts = json.loads((tmp_path / "alerts.json").read_bytes())
    assert len(alerts) == 5
    model = json.loads((tmp_path / "grafana-dashboard.json").read_bytes())
    assert [panel["title"] for panel in model["panels"]] == [
        "Alerts by severity",
        "Alerts by customer",
        "Alerts by rule",
        "Top source IPs",
    ]
    for panel in model["panels"]:
        query = panel["targets"][0]
        assert query["scenarioId"] == "csv_content"
        rows = list(csv.DictReader(StringIO(query["csvContent"])))
        assert sum(int(row["Alerts"]) for row in rows) == len(alerts)
    html = (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    assert html.count("data:image/png;base64,") == 4
    assert "Synthetic telemetry" in html
    assert "T1110.003" in html
    assert (tmp_path / "results.md").exists()


def test_empty_dashboard_and_invalid_alert_shape(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    write_json(path, [])
    render(path, tmp_path)
    assert "No alerts in this replay" in (tmp_path / "dashboard.html").read_text(encoding="utf-8")
    write_json(path, {"invalid": "object"})
    with pytest.raises(ValueError, match="JSON array"):
        render(path, tmp_path)

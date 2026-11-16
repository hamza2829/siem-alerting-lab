import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from siem_lab.detect import REPO_ROOT
from siem_lab.freshness import check_freshness
from siem_lab.generate import generate
from siem_lab.records import CUSTOMERS, FIXED_START, REPLAY_SECONDS, timestamp_text

REPLAY_END = FIXED_START + timedelta(seconds=REPLAY_SECONDS)


def test_freshness_uses_event_time_and_checks_all_streams(tmp_path: Path) -> None:
    generate(tmp_path, profile="control")
    status, report = check_freshness(tmp_path / "logs", REPLAY_END, max_age=1)
    assert status == 0
    assert len(report["streams"]) == 9
    assert {row["status"] for row in report["streams"]} == {"fresh"}
    status, report = check_freshness(
        tmp_path / "logs", REPLAY_END + timedelta(seconds=1), max_age=1
    )
    assert status == 1
    assert {row["status"] for row in report["streams"]} == {"stale"}


@pytest.mark.parametrize(("broken", "code"), [("missing", 1), ("empty", 1), ("error", 2)])
def test_freshness_distinguishes_missing_empty_and_invalid_files(
    tmp_path: Path, broken: str, code: int
) -> None:
    generate(tmp_path)
    path = tmp_path / "logs" / CUSTOMERS[0] / "auth.log"
    if broken == "missing":
        path.unlink()
    else:
        path.write_text("bad\n" if broken == "error" else "", encoding="utf-8")
    exit_code, report = check_freshness(tmp_path / "logs", REPLAY_END, max_age=600)
    assert exit_code == code
    assert report["streams"][0]["status"] == broken


def test_freshness_flags_future_events_and_bad_config(tmp_path: Path) -> None:
    generate(tmp_path)
    code, report = check_freshness(tmp_path / "logs", FIXED_START, max_age=600)
    assert code == 1
    assert report["streams"][0]["status"] == "future_timestamp"
    with pytest.raises(ValueError, match="must be positive"):
        check_freshness(tmp_path / "logs", FIXED_START, max_age=0)


def test_freshness_cli_returns_alert_exit_status(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "siem_lab.freshness",
            "--logs",
            str(tmp_path),
            "--now",
            timestamp_text(REPLAY_END),
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "alert"


@pytest.mark.parametrize(
    ("usage", "state", "wanted"),
    [
        ("24%", "active", 0),
        ("90%", "active", 1),
        ("13%", "inactive", 1),
        ("malformed", "active", 2),
        ("30%", "service-error", 2),
    ],
)
def test_host_checks_using_stubbed_linux_probes(
    tmp_path: Path, usage: str, state: str, wanted: int
) -> None:
    tools = {
        "df": f"printf '%s\\n' 'Filesystem Blocks Used Available Capacity Mount' 'dev 100 10 90 {usage} /'",
        "systemctl": {
            "active": "printf 'active\\n'",
            "inactive": "printf 'inactive\\n'; exit 3",
            "service-error": "exit 1",
        }[state],
    }
    for name, body in tools.items():
        path = tmp_path / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)
    env = {**os.environ, "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"]}
    result = subprocess.run(
        ["bash", "scripts/check_host.sh", "/", "rsyslog.service", "90"],
        cwd=REPO_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == wanted
    messages = ("status=ok", "status=alert", "status=error")
    assert messages[wanted] in result.stdout + result.stderr


def test_host_usage_errors_have_exit_two() -> None:
    result = subprocess.run(
        ["bash", "scripts/check_host.sh", "/", "rsyslog.service", "101"],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "between 1 and 100" in result.stderr

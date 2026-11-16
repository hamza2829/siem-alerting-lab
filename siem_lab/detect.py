"""Validate rule thresholds, read the log streams and run the detectors."""

from datetime import timedelta
from pathlib import Path

import yaml

from siem_lab.parsing import read_telemetry
from siem_lab.records import Alert, Severity, write_json
from siem_lab.rules import (
    impossible_travel,
    outbound_volume,
    password_spraying,
    ssh_brute_force,
    web_scanning,
)
from siem_lab.rules.common import Settings

RULES = (
    ssh_brute_force.RULE,
    password_spraying.RULE,
    impossible_travel.RULE,
    web_scanning.RULE,
    outbound_volume.RULE,
)
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "config/rules.yml"


def load_settings(path: Path) -> dict[str, Settings]:
    """Reject missing, unknown, or nonpositive thresholds."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.keys() != {rule.id for rule in RULES}:
        raise ValueError(
            f"{path}: define exactly these rules: {', '.join(rule.id for rule in RULES)}"
        )
    settings = {}
    for rule in RULES:
        config = raw[rule.id]
        required_keys = {"severity", "window_seconds", *rule.thresholds}
        if not isinstance(config, dict) or config.keys() != required_keys:
            raise ValueError(f"{rule.id}: expected keys {', '.join(sorted(required_keys))}")
        for key in ("window_seconds", *rule.thresholds):
            if type(config[key]) is not int or config[key] <= 0:
                raise ValueError(f"{rule.id}.{key} must be a positive integer")
        settings[rule.id] = Settings(
            severity=Severity(config["severity"]),
            window=timedelta(seconds=config["window_seconds"]),
            limits={key: config[key] for key in rule.thresholds},
        )
    return settings


def detect(
    log_dir: Path, settings: dict[str, Settings], *, output: Path | None = None
) -> list[Alert]:
    """Produce chronologically ordered, tenant-specific alerts."""
    telemetry = read_telemetry(log_dir)
    alerts = [
        *ssh_brute_force.detect(telemetry.auth, settings[ssh_brute_force.RULE.id]),
        *password_spraying.detect(telemetry.auth, settings[password_spraying.RULE.id]),
        *impossible_travel.detect(telemetry.auth, settings[impossible_travel.RULE.id]),
        *web_scanning.detect(telemetry.web, settings[web_scanning.RULE.id]),
        *outbound_volume.detect(telemetry.firewall, settings[outbound_volume.RULE.id]),
    ]
    alerts.sort(
        key=lambda alert: (alert.detected_at, alert.customer, alert.rule_id, alert.alert_id)
    )
    if output is not None:
        write_json(output, [alert.as_record() for alert in alerts])
    return alerts

from pathlib import Path

import pytest
import yaml

from siem_lab.detect import DEFAULT_CONFIG, REPO_ROOT, RULES, detect, load_settings
from siem_lab.evaluate import matches
from siem_lab.generate import FixtureWriter, Scenario, generate
from siem_lab.parsing import read_stream, read_telemetry
from siem_lab.records import CUSTOMERS, FIXED_START, Alert, Stream
from siem_lab.rules.common import Settings

EXPECTED = {
    "ssh_brute_force": ("T1110.001", "high", Stream.AUTH),
    "password_spraying": ("T1110.003", "high", Stream.AUTH),
    "impossible_travel": ("T1078", "critical", Stream.AUTH),
    "web_scanning": ("T1595", "medium", Stream.WEB),
    "outbound_volume": ("T1048", "critical", Stream.FIREWALL),
}


@pytest.mark.parametrize("rule_id", EXPECTED)
def test_attack_scenario_fires_with_original_evidence(
    rule_id: str, reference: tuple[Path, list[Scenario], list[Alert]]
) -> None:
    directory, labels, alerts = reference
    label = next(item for item in labels if item.expected_rule == rule_id)
    matched = [alert for alert in alerts if matches(alert, label)]
    assert len(matched) == 1
    alert = matched[0]
    technique, severity, stream = EXPECTED[rule_id]
    assert alert.severity == severity
    assert alert.mitre_technique_id == technique
    assert alert.evidence
    raw = (directory / "logs" / label.customer / stream.filename).read_text(encoding="utf-8")
    assert set(alert.evidence) <= set(raw.splitlines())


def test_alert_health_canary_fails_if_any_rule_stops_firing(
    reference: tuple[Path, list[Scenario], list[Alert]],
) -> None:
    """A reference replay exercises the full parser-to-alert path for each rule."""
    _, labels, alerts = reference
    observed = {
        label.expected_rule
        for label in labels
        if label.expected_rule and any(matches(alert, label) for alert in alerts)
    }
    assert observed == set(EXPECTED), f"Dead-man's switch: missing {set(EXPECTED) - observed}"


def test_quiet_admin_and_normal_control_do_not_alert(
    settings: dict[str, Settings],
    reference: tuple[Path, list[Scenario], list[Alert]],
    tmp_path: Path,
) -> None:
    _, labels, alerts = reference
    quiet = next(case for case in labels if case.name == "quiet_admin")
    assert not any(alert.source_ip == quiet.source_ip for alert in alerts)
    generate(tmp_path, profile="control")
    assert detect(tmp_path / "logs", settings) == []


def test_seeded_replays_are_repeatable_and_all_three_streams_parse(tmp_path: Path) -> None:
    for folder, seed in (("first", 42), ("repeat", 42), ("different", 43)):
        generate(tmp_path / folder, seed=seed)
    for customer in CUSTOMERS:
        for stream in Stream:
            path = Path("logs") / customer / stream.filename
            first, repeat, different = (
                tmp_path / folder / path for folder in ("first", "repeat", "different")
            )
            assert first.read_bytes() == repeat.read_bytes()
            assert first.read_bytes() != different.read_bytes()
    parsed = read_telemetry(tmp_path / "first/logs")
    assert {event.action for event in parsed.auth} == {"ssh_success", "ssh_failure", "sudo"}
    assert {event.status for event in parsed.web} == {200, 404}
    assert {event.customer for event in parsed.firewall} == set(CUSTOMERS)


@pytest.mark.parametrize(("last_offset", "alerts_expected"), [(300, 1), (301, 0)])
def test_brute_force_window_boundary(
    last_offset: int, alerts_expected: int, tmp_path: Path, settings: dict[str, Settings]
) -> None:
    writer = FixtureWriter(FIXED_START)
    for offset in (0, 40, 80, 120, 160, 200, 240, last_offset):
        writer.ssh(CUSTOMERS[0], offset, "test-user", "192.0.2.99", success=False)
    writer.write(tmp_path)
    observed = detect(tmp_path, settings)
    assert len(observed) == alerts_expected


def test_windows_and_location_pairs_stay_within_tenant(
    tmp_path: Path, settings: dict[str, Settings]
) -> None:
    writer = FixtureWriter(FIXED_START)
    for customer in CUSTOMERS:
        for offset in range(4):
            writer.ssh(customer, offset, "shared", "192.0.2.99", success=False)
    writer.ssh(CUSTOMERS[0], 50, "shared", "198.51.100.111", success=True)
    writer.ssh(CUSTOMERS[1], 150, "shared", "203.0.113.211", success=True)
    writer.write(tmp_path)
    assert detect(tmp_path, settings) == []


def test_semantically_irrelevant_events_are_excluded(
    tmp_path: Path, settings: dict[str, Settings]
) -> None:
    writer = FixtureWriter(FIXED_START)
    customer = CUSTOMERS[0]
    for offset in range(15):
        writer.web(customer, offset, "192.0.2.99", f"/missing?cache={offset}", 404)
    writer.firewall(customer, 0, "10.1.0.51", "203.0.113.4", 90_000_000, direction="IN")
    writer.firewall(customer, 1, "10.1.0.51", "203.0.113.4", 90_000_000, verdict="DROP")
    writer.firewall(customer, 2, "10.1.0.51", "10.1.0.52", 90_000_000, zone="internal")
    for offset, user in enumerate(("a", "a", "a", "b", "c", "d", "e", "f")):
        writer.ssh(customer, offset, user, "192.0.2.31", success=False)
    writer.write(tmp_path)
    assert detect(tmp_path, settings) == []


def test_cooldown_suppresses_duplicate_alerts_then_allows_new_incident(
    tmp_path: Path, settings: dict[str, Settings]
) -> None:
    writer = FixtureWriter(FIXED_START)
    for start in (0, 450):
        for offset in range(start, start + 20):
            writer.ssh(CUSTOMERS[0], offset, "shared", "192.0.2.91", success=False)
    writer.write(tmp_path)
    alerts = detect(tmp_path, settings)
    assert len(alerts) == 2
    assert alerts[0].alert_id != alerts[1].alert_id
    assert all(alert.observations["failed_logins"] == 8 for alert in alerts)


def test_threshold_override_changes_alerts(
    tmp_path: Path, reference: tuple[Path, list[Scenario], list[Alert]]
) -> None:
    directory, _, _ = reference
    config = tmp_path / "rules.yml"
    raw = yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    raw["ssh_brute_force"]["min_failures"] = 50
    config.write_text(yaml.safe_dump(raw), encoding="utf-8")
    alerts = detect(directory / "logs", load_settings(config))
    assert {alert.rule_id for alert in alerts} == set(EXPECTED) - {"ssh_brute_force"}


@pytest.mark.parametrize("invalid", [-1, True, "8"])
def test_invalid_rule_threshold_fails(tmp_path: Path, invalid: object) -> None:
    path = tmp_path / "rules.yml"
    raw = yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    raw["ssh_brute_force"]["min_failures"] = invalid
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="ssh_brute_force.min_failures"):
        load_settings(path)


def test_bad_log_includes_file_and_line_number(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("\nMalformed entry\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"auth\.log:2: Unrecognized"):
        list(read_stream(path, CUSTOMERS[0], Stream.AUTH))


def test_sigma_descriptions_reference_each_runtime_rule(settings: dict[str, Settings]) -> None:
    for rule in RULES:
        spec = yaml.safe_load((REPO_ROOT / f"sigma/{rule.id}.yml").read_text(encoding="utf-8"))
        assert spec["name"] == rule.id
        assert spec["level"] == settings[rule.id].severity
        assert f"attack.{rule.technique.lower()}" in spec["tags"]

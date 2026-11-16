"""Measure labeled detection performance and event-time latency."""

from collections.abc import Iterable
from pathlib import Path
from statistics import mean, median
from tempfile import TemporaryDirectory
from typing import Any

from siem_lab.detect import RULES, detect
from siem_lab.generate import Scenario, generate
from siem_lab.records import CUSTOMERS, Alert, parse_timestamp, write_json
from siem_lab.rules.common import Settings

BENCHMARK_START = 4100
BENCHMARK_RUNS = 20


def matches(alert: Alert, label: Scenario) -> bool:
    """Require a matching rule, subject, tenant and inclusive event window."""
    return (
        alert.rule_id == label.expected_rule
        and alert.customer == label.customer
        and alert.source_ip == label.source_ip
        and label.starts_at <= alert.detected_at <= label.ends_at
    )


def timing(values: Iterable[int]) -> dict[str, float | int | None]:
    ordered = sorted(values)
    if not ordered:
        return {"mean": None, "median": None, "p95": None}
    nearest_rank_index = (95 * len(ordered) + 99) // 100 - 1
    return {
        "mean": round(mean(ordered), 2),
        "median": median(ordered),
        "p95": ordered[nearest_rank_index],
    }


def evaluate(
    settings: dict[str, Settings],
    *,
    runs: int = BENCHMARK_RUNS,
    seed_start: int = BENCHMARK_START,
) -> dict[str, Any]:
    """Score one variable replay and matched benign control per seed."""
    if runs < 1:
        raise ValueError("The benchmark requires at least one run")
    trials = []
    benign = []
    unmatched = []
    with TemporaryDirectory(prefix="siem-benchmark-") as temp:
        workspace = Path(temp)
        for seed in range(seed_start, seed_start + runs):
            incident = workspace / "incidents"
            control = workspace / "controls"
            labels = generate(incident, seed=seed, profile="variable")
            generate(control, seed=seed, profile="control")
            observed = detect(incident / "logs", settings)
            benign_alerts = detect(control / "logs", settings)
            matched_ids = set()
            for label in labels:
                if label.expected_rule is None:
                    continue
                alert = next((item for item in observed if matches(item, label)), None)
                if alert is not None:
                    matched_ids.add(alert.alert_id)
                latency = (
                    int(
                        (
                            parse_timestamp(alert.detected_at) - parse_timestamp(label.starts_at)
                        ).total_seconds()
                    )
                    if alert is not None
                    else None
                )
                trials.append(
                    {
                        "seed": seed,
                        "rule_id": label.expected_rule,
                        "customer": label.customer,
                        "source_ip": label.source_ip,
                        "variant": label.variant,
                        "scenario_start": label.starts_at,
                        "scenario_end": label.ends_at,
                        "detected_at": alert.detected_at if alert else None,
                        "alert_id": alert.alert_id if alert else None,
                        "time_to_detect_seconds": latency,
                    }
                )
            unmatched.extend(
                {
                    "seed": seed,
                    "alert_id": alert.alert_id,
                    "customer": alert.customer,
                    "rule_id": alert.rule_id,
                    "source_ip": alert.source_ip,
                }
                for alert in observed
                if alert.alert_id not in matched_ids
            )
            for customer in CUSTOMERS:
                ids = [alert.alert_id for alert in benign_alerts if alert.customer == customer]
                benign.append({"seed": seed, "customer": customer, "alert_ids": ids})

    times = [
        trial["time_to_detect_seconds"]
        for trial in trials
        if trial["time_to_detect_seconds"] is not None
    ]
    false_positives = sum(bool(trial["alert_ids"]) for trial in benign)
    by_rule = {}
    for rule in RULES:
        relevant = [trial for trial in trials if trial["rule_id"] == rule.id]
        rule_times = [
            trial["time_to_detect_seconds"]
            for trial in relevant
            if trial["time_to_detect_seconds"] is not None
        ]
        by_rule[rule.id] = {
            "trials": len(relevant),
            "detected": len(rule_times),
            "median_seconds": median(rule_times) if rule_times else None,
        }
    return {
        "summary": {
            "runs": runs,
            "first_seed": seed_start,
            "last_seed": seed_start + runs - 1,
            "attack_trials": len(trials),
            "detected": len(times),
            "missed": len(trials) - len(times),
            "detection_rate": len(times) / len(trials),
            "benign_customer_trials": len(benign),
            "false_positive_trials": false_positives,
            "false_positive_rate": false_positives / len(benign),
            "unmatched_alerts": len(unmatched),
            "time_to_detect_seconds": timing(times),
        },
        "by_rule": by_rule,
        "attack_trials": trials,
        "benign_trials": benign,
        "unmatched_alerts": unmatched,
    }


def write_results(directory: Path, report: dict[str, Any]) -> None:
    """Export a readable summary and all per-trial measurements."""
    write_json(directory / "results.json", report)
    result = report["summary"]
    latency = result["time_to_detect_seconds"]
    lines = [
        "# Detection benchmark",
        "",
        f"Seeded replays: {result['runs']} (seeds {result['first_seed']}–{result['last_seed']}). "
        "Each replay pairs a variable incident mix with a benign control.",
        "",
        "| Metric | Measured |",
        "| --- | ---: |",
        f"| Detection rate | {result['detection_rate']:.2%} "
        f"({result['detected']}/{result['attack_trials']}) |",
        f"| Missed scenarios | {result['missed']} |",
        f"| False-positive rate | {result['false_positive_rate']:.2%} "
        f"({result['false_positive_trials']}/{result['benign_customer_trials']}) |",
        f"| Unmatched alerts in incident replays | {result['unmatched_alerts']} |",
        f"| Mean time to detect, seconds | {display(latency['mean'])} |",
        f"| Median time to detect, seconds | {display(latency['median'])} |",
        f"| P95 time to detect, seconds | {display(latency['p95'])} |",
        "",
        "| Rule | Detected | Trials | Median seconds |",
        "| --- | ---: | ---: | ---: |",
    ]
    for rule in RULES:
        row = report["by_rule"][rule.id]
        lines.append(
            f"| {rule.title} | {row['detected']} | {row['trials']} | "
            f"{display(row['median_seconds'])} |"
        )
    lines.extend(
        [
            "",
            "Detection credit requires the correct rule, tenant, and subject IP inside the labeled "
            "scenario window. False-positive rate uses benign customer-replays with at least one "
            "alert divided by all benign customer-replays. Controls include the quiet admin.",
            "",
            "Time to detect is elapsed event time from the first injected event to the first matching "
            "alert, measured on detections. P95 uses the nearest-rank percentile.",
            "",
            "| Seed | Missed rule | Fixture variant |",
            "| ---: | --- | --- |",
        ]
    )
    for trial in report["attack_trials"]:
        if trial["alert_id"] is None:
            lines.append(f"| {trial['seed']} | {trial['rule_id']} | {trial['variant']} |")
    (directory / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def display(value: float | int | None) -> str:
    return "—" if value is None else f"{value:g}"

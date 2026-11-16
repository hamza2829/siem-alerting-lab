"""CLI for fixture generation, detection, evaluation and reporting."""

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from siem_lab.dashboard import DEFAULT_DASHBOARD, render
from siem_lab.detect import DEFAULT_CONFIG, detect, load_settings
from siem_lab.evaluate import BENCHMARK_RUNS, BENCHMARK_START, evaluate, write_results
from siem_lab.generate import DEFAULT_SEED, generate
from siem_lab.records import FIXED_START, REPLAY_SECONDS


def cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("demo", "generate", "evaluate", "dashboard", "detect"):
        command = commands.add_parser(name)
        command.add_argument("--out", type=Path, required=True)
        if name in {"demo", "detect", "evaluate"}:
            command.add_argument("--rules", type=Path, default=DEFAULT_CONFIG)
        if name in {"demo", "dashboard"}:
            command.add_argument("--dashboard-config", type=Path, default=DEFAULT_DASHBOARD)
        if name in {"demo", "generate"}:
            command.add_argument("--seed", type=int, default=DEFAULT_SEED)
            command.add_argument("--end-now", action="store_true")
        if name in {"demo", "evaluate"}:
            command.add_argument("--runs", type=int, default=BENCHMARK_RUNS)
            command.add_argument("--seed-start", type=int, default=BENCHMARK_START)
        if name == "demo":
            command.add_argument("--skip-evaluation", action="store_true")
        if name == "generate":
            command.add_argument(
                "--profile", choices=("reference", "variable", "control"), default="reference"
            )
        if name == "dashboard":
            command.add_argument("--alerts", type=Path, required=True)
        if name == "detect":
            command.add_argument("--logs", type=Path, required=True)
    return parser


def run(args: argparse.Namespace) -> None:
    if args.command in {"demo", "generate"}:
        start = (
            datetime.now(UTC) - timedelta(seconds=REPLAY_SECONDS) if args.end_now else FIXED_START
        )
        generate(
            args.out, seed=args.seed, profile=getattr(args, "profile", "reference"), start=start
        )
    if args.command in {"demo", "detect"}:
        logs = args.out / "logs" if args.command == "demo" else args.logs
        alerts = detect(logs, load_settings(args.rules), output=args.out / "alerts.json")
        print(f"{len(alerts)} alerts written to {args.out / 'alerts.json'}")
    if args.command in {"demo", "dashboard"}:
        alert_file = args.out / "alerts.json" if args.command == "demo" else args.alerts
        render(alert_file, args.out, args.dashboard_config)
    if args.command == "evaluate" or (args.command == "demo" and not args.skip_evaluation):
        result = evaluate(load_settings(args.rules), runs=args.runs, seed_start=args.seed_start)
        write_results(args.out, result)
        print((args.out / "results.md").read_text(encoding="utf-8").split("| Seed |", 1)[0].strip())


def main() -> int:
    parser = cli()
    args = parser.parse_args()
    try:
        run(args)
    except (ValueError, OSError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

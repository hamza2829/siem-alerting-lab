"""Check the latest parseable event in each customer's expected log streams."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from siem_lab.parsing import read_stream
from siem_lab.records import CUSTOMERS, Stream, parse_timestamp, timestamp_text


def check_freshness(directory: Path, now: datetime, max_age: int) -> tuple[int, dict[str, Any]]:
    """Return 0 for healthy, 1 for a freshness alert, or 2 for a log read error."""
    if max_age < 1:
        raise ValueError("max-age-seconds must be positive")
    streams = []
    exit_code = 0
    for customer in CUSTOMERS:
        for stream in Stream:
            path = directory / customer / stream.filename
            row: dict[str, Any] = {"customer": customer, "stream": stream.value}
            try:
                latest = max(
                    (event.timestamp for event in read_stream(path, customer, stream)), default=None
                )
            except FileNotFoundError:
                row["status"] = "missing"
            except (ValueError, OSError) as exc:
                row.update(status="error", detail=str(exc))
                exit_code = 2
            else:
                if latest is None:
                    row["status"] = "empty"
                else:
                    age = int((now - latest).total_seconds())
                    row.update(latest_event=timestamp_text(latest), age_seconds=age)
                    if age < -60:
                        row["status"] = "future_timestamp"
                    else:
                        row["status"] = "stale" if age > max_age else "fresh"
            if row["status"] != "fresh":
                exit_code = max(exit_code, 1)
            streams.append(row)
    return exit_code, {
        "checked_at": timestamp_text(now),
        "max_age_seconds": max_age,
        "status": ("ok", "alert", "error")[exit_code],
        "streams": streams,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--max-age-seconds", type=int, default=900)
    parser.add_argument("--now", type=parse_timestamp)
    options = parser.parse_args()
    try:
        code, report = check_freshness(
            options.logs, options.now or datetime.now(UTC), options.max_age_seconds
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

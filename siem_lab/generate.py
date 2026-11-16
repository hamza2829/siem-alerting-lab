"""Create a seeded replay as local text files with separate scenario labels."""

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from os import fdopen
from pathlib import Path
from random import Random
from tempfile import mkstemp
from typing import Literal

from siem_lab.records import (
    CUSTOMERS,
    FIXED_START,
    REPLAY_SECONDS,
    Stream,
    timestamp_text,
    write_json,
)

Profile = Literal["reference", "variable", "control"]
DEFAULT_SEED = 42


def replace_stream(path: Path, lines: list[tuple[int, str]]) -> None:
    """Publish a complete snapshot as a new file for readers and log tailers."""
    descriptor, filename = mkstemp(dir=path.parent, prefix=f".{path.name}.")
    pending = Path(filename)
    try:
        with fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.writelines(f"{line}\n" for _, line in lines)
        pending.chmod(0o644)
        pending.replace(path)
    finally:
        pending.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    expected_rule: str | None
    customer: str
    source_ip: str
    starts_at: str
    ends_at: str
    variant: str


class FixtureWriter:
    def __init__(self, start: datetime) -> None:
        self.start = start
        self.lines: dict[tuple[str, Stream], list[tuple[int, str]]] = defaultdict(list)

    def stamp(self, offset: int) -> str:
        return timestamp_text(self.start + timedelta(seconds=offset))

    def ssh(self, customer: str, offset: int, user: str, ip: str, *, success: bool) -> None:
        outcome = "Accepted publickey" if success else "Failed password"
        line = (
            f"{self.stamp(offset)} {customer}-auth sshd[{1000 + offset % 3000}]: "
            f"{outcome} for {user} from {ip} port {41000 + offset % 10000} ssh2"
        )
        self.lines[customer, Stream.AUTH].append((offset, line))

    def sudo(self, customer: str, offset: int, user: str) -> None:
        line = (
            f"{self.stamp(offset)} {customer}-auth sudo[{2000 + offset % 3000}]: "
            f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/true"
        )
        self.lines[customer, Stream.AUTH].append((offset, line))

    def web(self, customer: str, offset: int, ip: str, path: str, status: int) -> None:
        line = (
            f'{ip} - - [{self.stamp(offset)}] "GET {path} HTTP/1.1" {status} 512 "-" "LabClient/1"'
        )
        self.lines[customer, Stream.WEB].append((offset, line))

    def firewall(
        self,
        customer: str,
        offset: int,
        source: str,
        destination: str,
        sent: int,
        *,
        direction: str = "OUT",
        verdict: str = "ACCEPT",
        zone: str = "external",
    ) -> None:
        line = (
            f"{self.stamp(offset)} {customer}-edge firewall: DIR={direction} ACTION={verdict} "
            f"ZONE={zone} SRC={source} DST={destination} BYTES_OUT={sent}"
        )
        self.lines[customer, Stream.FIREWALL].append((offset, line))

    def scenario(
        self,
        name: str,
        rule: str | None,
        customer: str,
        ip: str,
        first: int,
        last: int,
        variant: str,
    ) -> Scenario:
        return Scenario(name, rule, customer, ip, self.stamp(first), self.stamp(last), variant)

    def write(self, directory: Path) -> None:
        for customer in CUSTOMERS:
            target = directory / customer
            target.mkdir(parents=True, exist_ok=True)
            for stream in Stream:
                lines = sorted(self.lines[customer, stream])
                replace_stream(target / stream.filename, lines)


def background(writer: FixtureWriter, rng: Random) -> Scenario:
    """Add ordinary SSH, sudo, web and firewall activity to every tenant."""
    for tenant_number, customer in enumerate(CUSTOMERS, 1):
        for base in range(0, REPLAY_SECONDS - 30, 120):
            offset = base + rng.randrange(5, 41)
            user = rng.choice(("reader", "ops-agent", "deployer"))
            writer.ssh(customer, offset, user, f"192.0.2.{10 + tenant_number}", success=True)
            if rng.random() < 0.3:
                writer.sudo(customer, offset + 1, user)
            if rng.random() < 0.1:
                writer.ssh(
                    customer, offset + 2, user, f"192.0.2.{20 + tenant_number}", success=False
                )
            path = rng.choice(("/home", "/catalog", "/help", "/assets/menu.css", "/missing-logo"))
            writer.web(
                customer,
                offset,
                f"198.51.100.{20 + tenant_number}",
                path,
                404 if path == "/missing-logo" else 200,
            )
            writer.firewall(
                customer,
                offset,
                f"10.{tenant_number}.0.14",
                "203.0.113.75",
                rng.randrange(1000, 180_000),
            )

        last = REPLAY_SECONDS - 1
        writer.ssh(customer, last, "ops-agent", f"192.0.2.{10 + tenant_number}", success=True)
        writer.web(customer, last, f"198.51.100.{20 + tenant_number}", "/home", 200)
        writer.firewall(customer, last, f"10.{tenant_number}.0.14", "203.0.113.75", 6072)

    customer, ip, first = CUSTOMERS[2], "192.0.2.80", 6900
    offsets = (0, 14, 32, 49)
    for offset in offsets:
        writer.ssh(customer, first + offset, "ops-admin", ip, success=offset == offsets[-1])
    writer.sudo(customer, first + 50, "ops-admin")
    return writer.scenario(
        "quiet_admin", None, customer, ip, first, first + 50, "3 failures then success and sudo"
    )


def attack_fixtures(writer: FixtureWriter, rng: Random, *, variable: bool) -> list[Scenario]:
    """Add inert log entries for five labeled incident patterns."""
    alder, cedar, harbor = CUSTOMERS
    brute = rng.choice((6, 7, 8, 9, 10, 12, 14)) if variable else 12
    spray = rng.choice((4, 5, 6, 7, 8, 9, 10, 11)) if variable else 8
    travel_seconds = (
        rng.choice((600, 1200, 1800, 2700, 3600, 5400, 7200, 8400)) if variable else 900
    )
    scan = rng.choice((8, 10, 11, 12, 13, 15, 17, 20)) if variable else 16
    egress = rng.choice((17, 22, 23, 25, 30, 34, 37, 40)) if variable else 35
    labels = []

    ip, first, spacing = "198.51.100.91", 300, rng.randrange(4, 12)
    for index in range(brute):
        writer.ssh(alder, first + index * spacing, "inventory", ip, success=False)
    labels.append(
        writer.scenario(
            "ssh_brute_force",
            "ssh_brute_force",
            alder,
            ip,
            first,
            first + (brute - 1) * spacing,
            f"{brute} failures",
        )
    )

    ip, first, spacing = "198.51.100.92", 900, rng.randrange(17, 31)
    for index in range(spray):
        writer.ssh(cedar, first + index * spacing, f"demo-user-{index}", ip, success=False)
    labels.append(
        writer.scenario(
            "password_spraying",
            "password_spraying",
            cedar,
            ip,
            first,
            first + (spray - 1) * spacing,
            f"{spray} distinct users",
        )
    )

    ip, first = "203.0.113.211", 1500
    writer.ssh(harbor, first, "ops-rover", "198.51.100.111", success=True)
    writer.ssh(harbor, first + travel_seconds, "ops-rover", ip, success=True)
    labels.append(
        writer.scenario(
            "impossible_travel",
            "impossible_travel",
            harbor,
            ip,
            first,
            first + travel_seconds,
            f"{travel_seconds}s between locations",
        )
    )

    ip, first, spacing = "203.0.113.93", 3500, rng.randrange(2, 6)
    for index in range(scan):
        writer.web(alder, first + index * spacing, ip, f"/missing/demo-item-{index:02d}", 404)
    labels.append(
        writer.scenario(
            "web_scanning",
            "web_scanning",
            alder,
            ip,
            first,
            first + (scan - 1) * spacing,
            f"{scan} distinct 404 paths",
        )
    )

    ip, first, spacing = "10.2.0.77", 5000, rng.randrange(20, 50)
    for index in range(5):
        writer.firewall(cedar, first + index * spacing, ip, "203.0.113.205", egress * 200_000)
    labels.append(
        writer.scenario(
            "outbound_volume",
            "outbound_volume",
            cedar,
            ip,
            first,
            first + 4 * spacing,
            f"{egress} MB sent",
        )
    )
    return labels


def generate(
    directory: Path,
    *,
    seed: int = DEFAULT_SEED,
    profile: Profile = "reference",
    start: datetime = FIXED_START,
) -> list[Scenario]:
    """Write a replay under logs/ and separate labels.json beneath directory."""
    writer = FixtureWriter(start)
    quiet = background(writer, Random(seed))
    labels = [quiet]
    if profile != "control":
        labels.extend(
            attack_fixtures(writer, Random(seed + 100_003), variable=profile == "variable")
        )
    writer.write(directory / "logs")
    write_json(directory / "labels.json", [asdict(label) for label in labels])
    return labels

"""Shared types and file formats for synthetic logs and detection output."""

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

CUSTOMERS = ("alder-retail", "cedar-freight", "harbor-studio")
FIXED_START = datetime(2025, 2, 3, 8, tzinfo=UTC)
REPLAY_SECONDS = 3 * 60 * 60


class Stream(StrEnum):
    AUTH = "auth"
    WEB = "access"
    FIREWALL = "firewall"

    @property
    def filename(self) -> str:
        return f"{self.value}.log"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def parse_timestamp(value: str) -> datetime:
    """Accept an ISO timestamp with a timezone and normalize to UTC."""
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        raise ValueError("A timezone is required")
    return timestamp.astimezone(UTC)


def timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_json(path: Path, content: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(content, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


@dataclass(frozen=True, slots=True)
class Event:
    customer: str
    timestamp: datetime
    raw: str
    source_ip: str


@dataclass(frozen=True, slots=True)
class AuthEvent(Event):
    action: str
    user: str


@dataclass(frozen=True, slots=True)
class WebEvent(Event):
    status: int
    path: str


@dataclass(frozen=True, slots=True)
class FirewallEvent(Event):
    direction: str
    verdict: str
    zone: str
    destination_ip: str
    sent_bytes: int


@dataclass(slots=True)
class Telemetry:
    auth: list[AuthEvent] = field(default_factory=list)
    web: list[WebEvent] = field(default_factory=list)
    firewall: list[FirewallEvent] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    severity: Severity
    customer: str
    rule_id: str
    title: str
    mitre_technique_id: str
    detected_at: str
    source_ip: str
    group: tuple[str, ...]
    evidence: tuple[str, ...]
    observations: dict[str, str | int | float]

    def as_record(self) -> dict[str, Any]:
        return asdict(self)

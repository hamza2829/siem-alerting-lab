"""Shared rolling windows and alert construction."""

from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from typing import TypeVar

from siem_lab.records import Alert, Event, Severity, timestamp_text

Observations = dict[str, str | int | float]
EventT = TypeVar("EventT", bound=Event)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    technique: str
    thresholds: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Settings:
    severity: Severity
    window: timedelta
    limits: dict[str, int]


def make_alert(
    rule: Rule,
    settings: Settings,
    group: tuple[str, ...],
    evidence: Sequence[Event],
    observations: Observations,
) -> Alert:
    last = evidence[-1]
    stamp = timestamp_text(last.timestamp)
    key = "|".join((rule.id, *group, stamp))
    return Alert(
        alert_id=sha256(key.encode()).hexdigest()[:16],
        severity=settings.severity,
        customer=last.customer,
        rule_id=rule.id,
        title=rule.title,
        mitre_technique_id=rule.technique,
        detected_at=stamp,
        source_ip=last.source_ip,
        group=group,
        evidence=tuple(event.raw for event in evidence),
        observations=observations,
    )


def threshold_alerts(
    events: Iterable[EventT],
    rule: Rule,
    settings: Settings,
    group_by: Callable[[EventT], tuple[str, ...]],
    qualifies: Callable[[deque[EventT]], Observations | None],
) -> list[Alert]:
    """Emit at threshold crossing, then suppress repeats for one rule window."""
    windows: dict[tuple[str, ...], deque[EventT]] = defaultdict(deque)
    suppressed_until: dict[tuple[str, ...], datetime] = {}
    alerts = []
    for event in sorted(events, key=lambda item: item.timestamp):
        group = group_by(event)
        until = suppressed_until.get(group)
        if until is not None and event.timestamp <= until:
            continue
        window = windows[group]
        earliest = event.timestamp - settings.window
        while window and window[0].timestamp < earliest:
            window.popleft()
        window.append(event)
        if (observations := qualifies(window)) is not None:
            alerts.append(make_alert(rule, settings, group, tuple(window), observations))
            suppressed_until[group] = event.timestamp + settings.window
            window.clear()
    return alerts

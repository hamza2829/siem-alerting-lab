"""Detect unusual outbound byte volume to the synthetic external zone."""

from collections import deque

from siem_lab.records import Alert, FirewallEvent
from siem_lab.rules.common import Observations, Rule, Settings, threshold_alerts

RULE = Rule("outbound_volume", "Outbound volume", "T1048", ("min_bytes",))


def detect(events: list[FirewallEvent], settings: Settings) -> list[Alert]:
    limit = settings.limits["min_bytes"]

    def qualifies(window: deque[FirewallEvent]) -> Observations | None:
        total = sum(event.sent_bytes for event in window)
        return {"outbound_bytes": total} if total >= limit else None

    return threshold_alerts(
        (
            event
            for event in events
            if event.direction == "OUT" and event.verdict == "ACCEPT" and event.zone == "external"
        ),
        RULE,
        settings,
        lambda event: (event.customer, event.source_ip),
        qualifies,
    )

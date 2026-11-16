"""Detect a burst of distinct web paths returning HTTP 404."""

from collections import deque

from siem_lab.records import Alert, WebEvent
from siem_lab.rules.common import Observations, Rule, Settings, threshold_alerts

RULE = Rule("web_scanning", "Web scanning", "T1595", ("min_unique_paths",))


def detect(events: list[WebEvent], settings: Settings) -> list[Alert]:
    limit = settings.limits["min_unique_paths"]

    def qualifies(window: deque[WebEvent]) -> Observations | None:
        paths = {event.path.split("?", 1)[0] for event in window}
        return {"distinct_404_paths": len(paths)} if len(paths) >= limit else None

    return threshold_alerts(
        (event for event in events if event.status == 404),
        RULE,
        settings,
        lambda event: (event.customer, event.source_ip),
        qualifies,
    )

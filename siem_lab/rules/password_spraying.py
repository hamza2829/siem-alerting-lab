"""Detect low-count SSH failures spread across distinct users from one IP."""

from collections import Counter, deque

from siem_lab.records import Alert, AuthEvent
from siem_lab.rules.common import Observations, Rule, Settings, threshold_alerts

RULE = Rule(
    "password_spraying", "Password spraying", "T1110.003", ("min_users", "max_failures_per_user")
)


def detect(events: list[AuthEvent], settings: Settings) -> list[Alert]:
    users = settings.limits["min_users"]
    per_user = settings.limits["max_failures_per_user"]

    def qualifies(window: deque[AuthEvent]) -> Observations | None:
        counts = Counter(event.user for event in window)
        if len(counts) >= users and max(counts.values()) <= per_user:
            return {"distinct_users": len(counts), "max_failures_per_user": max(counts.values())}
        return None

    return threshold_alerts(
        (event for event in events if event.action == "ssh_failure"),
        RULE,
        settings,
        lambda event: (event.customer, event.source_ip),
        qualifies,
    )

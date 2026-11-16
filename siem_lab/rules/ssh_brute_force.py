"""Detect repeated SSH failures against one account from one IP."""

from collections import deque

from siem_lab.records import Alert, AuthEvent
from siem_lab.rules.common import Observations, Rule, Settings, threshold_alerts

RULE = Rule("ssh_brute_force", "SSH brute force", "T1110.001", ("min_failures",))


def detect(events: list[AuthEvent], settings: Settings) -> list[Alert]:
    limit = settings.limits["min_failures"]

    def qualifies(window: deque[AuthEvent]) -> Observations | None:
        if len(window) >= limit:
            return {"failed_logins": len(window), "user": window[-1].user}
        return None

    return threshold_alerts(
        (event for event in events if event.action == "ssh_failure"),
        RULE,
        settings,
        lambda event: (event.customer, event.source_ip, event.user),
        qualifies,
    )

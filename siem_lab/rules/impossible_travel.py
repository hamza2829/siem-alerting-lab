"""Compare consecutive successful SSH events using fixture-only locations."""

from math import asin, cos, radians, sin, sqrt

from siem_lab.records import Alert, AuthEvent
from siem_lab.rules.common import Rule, Settings, make_alert

RULE = Rule("impossible_travel", "Impossible travel", "T1078", ("min_speed_kmh",))
LOCATIONS = {
    "198.51.100.111": ("London", 51.5074, -0.1278),
    "203.0.113.211": ("Toronto", 43.6532, -79.3832),
}


def distance_km(site_a: tuple[str, float, float], site_b: tuple[str, float, float]) -> float:
    _, lat_a, lon_a = site_a
    _, lat_b, lon_b = site_b
    a, b = radians(lat_a), radians(lat_b)
    chord = sin((b - a) / 2) ** 2 + cos(a) * cos(b) * sin(radians(lon_b - lon_a) / 2) ** 2
    return 2 * 6371 * asin(sqrt(min(1.0, chord)))


def detect(events: list[AuthEvent], settings: Settings) -> list[Alert]:
    previous: dict[tuple[str, str], AuthEvent] = {}
    alerts = []
    eligible = (
        event for event in events if event.action == "ssh_success" and event.source_ip in LOCATIONS
    )
    for event in sorted(eligible, key=lambda item: item.timestamp):
        group = (event.customer, event.user)
        earlier = previous.get(group)
        previous[group] = event
        if earlier is None:
            continue
        elapsed = event.timestamp - earlier.timestamp
        if not 0 < elapsed.total_seconds() <= settings.window.total_seconds():
            continue
        start, end = LOCATIONS[earlier.source_ip], LOCATIONS[event.source_ip]
        distance = distance_km(start, end)
        speed = distance * 3600 / elapsed.total_seconds()
        if speed >= settings.limits["min_speed_kmh"]:
            alerts.append(
                make_alert(
                    RULE,
                    settings,
                    group,
                    (earlier, event),
                    {
                        "user": event.user,
                        "from_location": start[0],
                        "to_location": end[0],
                        "distance_km": round(distance),
                        "implied_speed_kmh": round(speed),
                    },
                )
            )
    return alerts

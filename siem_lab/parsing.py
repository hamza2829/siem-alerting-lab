"""Parse the lab's ISO syslog, combined-style web, and key-value firewall logs."""

import re
from collections.abc import Iterator
from ipaddress import ip_address
from pathlib import Path

from siem_lab.records import (
    CUSTOMERS,
    AuthEvent,
    Event,
    FirewallEvent,
    Stream,
    Telemetry,
    WebEvent,
    parse_timestamp,
)

SSH = re.compile(
    r"(?P<stamp>\S+) \S+ sshd\[\d+\]: "
    r"(?P<result>Failed|Accepted) (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>[\w.-]+) from (?P<ip>\S+) port \d+ ssh2"
)
SUDO = re.compile(r"(?P<stamp>\S+) \S+ sudo\[\d+\]: (?P<user>[\w.-]+) : TTY=.+")
ACCESS = re.compile(
    r"(?P<ip>\S+) - - \[(?P<stamp>\S+)\] "
    r'"[A-Z]+ (?P<path>/\S*) HTTP/[\d.]+" (?P<status>[1-5]\d{2}) \d+ "[^"]*" "[^"]*"'
)
FIREWALL = re.compile(
    r"(?P<stamp>\S+) \S+ firewall: DIR=(?P<direction>IN|OUT) "
    r"ACTION=(?P<verdict>ACCEPT|DROP) ZONE=(?P<zone>internal|external) "
    r"SRC=(?P<source>\S+) DST=(?P<destination>\S+) BYTES_OUT=(?P<sent>\d+)"
)


def parse_auth(line: str, customer: str) -> AuthEvent:
    if match := SSH.fullmatch(line):
        return AuthEvent(
            customer,
            parse_timestamp(match["stamp"]),
            line,
            str(ip_address(match["ip"])),
            "ssh_failure" if match["result"] == "Failed" else "ssh_success",
            match["user"],
        )
    if match := SUDO.fullmatch(line):
        return AuthEvent(customer, parse_timestamp(match["stamp"]), line, "", "sudo", match["user"])
    raise ValueError("Unrecognized auth line")


def parse_web(line: str, customer: str) -> WebEvent:
    if match := ACCESS.fullmatch(line):
        return WebEvent(
            customer,
            parse_timestamp(match["stamp"]),
            line,
            str(ip_address(match["ip"])),
            int(match["status"]),
            match["path"],
        )
    raise ValueError("Unrecognized access line")


def parse_firewall(line: str, customer: str) -> FirewallEvent:
    if match := FIREWALL.fullmatch(line):
        return FirewallEvent(
            customer,
            parse_timestamp(match["stamp"]),
            line,
            str(ip_address(match["source"])),
            match["direction"],
            match["verdict"],
            match["zone"],
            str(ip_address(match["destination"])),
            int(match["sent"]),
        )
    raise ValueError("Unrecognized firewall line")


PARSERS = {
    Stream.AUTH: parse_auth,
    Stream.WEB: parse_web,
    Stream.FIREWALL: parse_firewall,
}


def read_stream(path: Path, customer: str, stream: Stream) -> Iterator[Event]:
    """Read a stream and identify malformed records by file and line number."""
    parser = PARSERS[stream]
    with path.open(encoding="utf-8") as source:
        for number, raw in enumerate(source, 1):
            line = raw.rstrip("\r\n")
            if line:
                try:
                    yield parser(line, customer)
                except ValueError as exc:
                    raise ValueError(f"{path}:{number}: {exc}") from exc


def read_telemetry(directory: Path) -> Telemetry:
    """Load every configured customer and retain the original evidence lines."""
    data = Telemetry()
    for customer in CUSTOMERS:
        for stream in Stream:
            for event in read_stream(directory / customer / stream.filename, customer, stream):
                if isinstance(event, AuthEvent):
                    data.auth.append(event)
                elif isinstance(event, WebEvent):
                    data.web.append(event)
                else:
                    assert isinstance(event, FirewallEvent)
                    data.firewall.append(event)
    return data

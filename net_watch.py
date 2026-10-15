#!/usr/bin/env python3
"""net_watch.py -- watch your machine's network connections, live.

One of the first scripts I wrote while teaching myself cybersecurity
(May 2026). It polls the machine's network connections every 3 seconds,
diffs each snapshot against the previous one, and prints -- and logs --
every *new* connection it sees. Each peer is tagged LOCAL or EXTERNAL,
and a running count tracks your top talkers: the addresses your machine
talks to most.

This is the updated version. What changed from the original:

* The original as first committed didn't run at all -- a missing closing
  parenthesis and a misindented ``if``. Fixed, obviously.
* The original tagged the *local* endpoint (the first IP-looking token
  on an ``ss`` line is your own machine, forever). A watcher cares about
  the *peer*. Events are now keyed and tagged on the peer endpoint.
* The original classified LOCAL by string prefix (``10.``, ``192.168.``,
  ``127.``), which quietly misses the whole 172.16.0.0/12 private range.
  Classification now uses the stdlib ``ipaddress`` module: full RFC1918,
  loopback, link-local, IPv6 ULA, and CGNAT shared space (100.64.0.0/10).
* The original shelled out to ``ss`` (Linux-only, text scraping).
  Snapshots now come from ``psutil``, so the same script runs on Linux,
  Windows, and macOS, with clean ``process name (pid)`` labels.
* Structured records instead of raw text diffs, and the first poll is a
  silent baseline instead of a flood of "new" connections that were
  already there when you started.

Usage:
    python3 net_watch.py [--interval 3] [--log soc_network_log.txt]

Stop with Ctrl+C. New connections are appended to the log file
(``soc_network_log.txt`` by default, same as the original).

Requires: Python 3.9+ and psutil (``pip install psutil``). Everything
else is the standard library.

This script grew up into a full desktop app -- see the QuantumCat SOC
Toolkit at https://quantumcatsoc.gumroad.com/l/quantumcat-soc-toolkit
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional

try:
    import psutil
except ImportError:  # pragma: no cover - friendly failure, not a crash
    psutil = None

DEFAULT_INTERVAL = 3.0
DEFAULT_LOG = "soc_network_log.txt"

LOCAL = "LOCAL"
EXTERNAL = "EXTERNAL"

# CPython's ipaddress reports the CGNAT shared address space
# (100.64.0.0/10, RFC 6598) as neither private nor global, so it needs an
# explicit entry -- it is not publicly routable to a unique host.
_EXTRA_LOCAL_NETWORKS = [ipaddress.ip_network("100.64.0.0/10")]


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------


def clean_ip(raw: str) -> str:
    """Normalise an address string: strip brackets, %zone, whitespace."""
    text = (raw or "").strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    if "%" in text:
        text = text.split("%", 1)[0]
    return text


def classify_ip(raw: str) -> str:
    """Return LOCAL for non-publicly-routable addresses, else EXTERNAL.

    LOCAL covers: RFC1918 private ranges (10/8, 172.16/12, 192.168/16),
    loopback, link-local (169.254/16, fe80::/10), IPv6 unique-local
    (fc00::/7), multicast, CGNAT shared space (100.64/10), reserved and
    unspecified addresses -- anything that is not a public unicast
    address on the open internet. Unparseable values count as LOCAL (they
    cannot be an external contact by definition).
    """
    text = clean_ip(raw)
    if not text or text == "*":
        return LOCAL
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return LOCAL
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
        or any(ip in net for net in _EXTRA_LOCAL_NETWORKS if ip.version == net.version)
    ):
        return LOCAL
    return EXTERNAL


# ---------------------------------------------------------------------------
# Connection records
# ---------------------------------------------------------------------------

# psutil reports long status names; the rest of my tooling speaks the
# ss-style abbreviations ("ESTAB", "TIME-WAIT", ...). "LISTEN" is the
# same in both.
_PSUTIL_STATE_MAP = {
    "ESTABLISHED": "ESTAB",
    "SYN_SENT": "SYN-SENT",
    "SYN_RECV": "SYN-RECV",
    "FIN_WAIT1": "FIN-WAIT1",
    "FIN_WAIT2": "FIN-WAIT2",
    "TIME_WAIT": "TIME-WAIT",
    "CLOSE_WAIT": "CLOSE-WAIT",
    "LAST_ACK": "LAST-ACK",
    "LISTEN": "LISTEN",
    "CLOSING": "CLOSING",
    "NONE": "",
}


@dataclass(frozen=True)
class Connection:
    proto: str  # "tcp", "udp", "tcp6", "udp6"
    state: str  # "ESTAB", "LISTEN", "TIME-WAIT", "" for stateless UDP
    local_ip: str
    local_port: str
    peer_ip: Optional[str]  # None for listeners / wildcard peers
    peer_port: Optional[str]
    process: str = ""  # clean "name (pid)" display, best effort

    def key(self) -> tuple:
        return (
            self.proto,
            self.local_ip,
            self.local_port,
            self.peer_ip or "",
            self.peer_port or "",
        )

    def describe(self) -> str:
        peer = f"{self.peer_ip}:{self.peer_port}" if self.peer_ip else "*:*"
        return (
            f"{self.proto} {self.local_ip}:{self.local_port} -> {peer} "
            f"({self.state or '-'})"
        )


def _process_name_map() -> Dict[int, str]:
    """PID -> process name for everything currently running (best effort)."""
    names: Dict[int, str] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info.get("name"):
                names[int(proc.info["pid"])] = proc.info["name"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return names


def snapshot_connections() -> List[Connection]:
    """Take one snapshot of the machine's current connections via psutil."""
    names = _process_name_map()
    conns: List[Connection] = []
    for c in psutil.net_connections(kind="inet"):
        proto = "tcp" if int(c.type) == int(socket.SOCK_STREAM) else "udp"
        if int(c.family) == int(socket.AF_INET6):
            proto += "6"
        raw_state = (c.status or "").upper()
        state = _PSUTIL_STATE_MAP.get(raw_state, raw_state)
        process = ""
        if c.pid and names.get(c.pid):
            process = f"{names[c.pid]} ({c.pid})"
        peer_ip = c.raddr.ip if c.raddr else None
        peer_port = str(c.raddr.port) if c.raddr else None
        if peer_ip in ("0.0.0.0", "::"):
            peer_ip, peer_port = None, None
        conns.append(
            Connection(
                proto=proto,
                state=state,
                local_ip=c.laddr.ip if c.laddr else "",
                local_port=str(c.laddr.port) if c.laddr else "",
                peer_ip=peer_ip,
                peer_port=peer_port,
                process=process,
            )
        )
    return conns


# ---------------------------------------------------------------------------
# Diff / counter engine
# ---------------------------------------------------------------------------


@dataclass
class ConnectionEvent:
    timestamp: str
    connection: Connection
    tag: str  # LOCAL / EXTERNAL, based on the peer address

    def log_line(self) -> str:
        c = self.connection
        return f"{self.timestamp} | {self.tag} | {c.peer_ip or '-'} | {c.describe()}"


class ConnectionTracker:
    """Diffs successive snapshots and counts peer activity.

    Mirrors the original script's counter semantics: a peer IP's counter
    goes up by one each time a *new* connection to it is observed.
    """

    def __init__(self) -> None:
        self._previous: set = set()
        self.counters: Counter = Counter()

    def baseline(self, connections: Iterable[Connection]) -> int:
        """Seed the tracker with the first snapshot (no events for these)."""
        snapshot = list(connections)
        self._previous = {c.key() for c in snapshot}
        return len(snapshot)

    def update(
        self, connections: Iterable[Connection], timestamp: Optional[str] = None
    ) -> List[ConnectionEvent]:
        """Feed a new snapshot; returns the *new* connection events."""
        ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        snapshot = list(connections)
        keys = {c.key() for c in snapshot}
        events: List[ConnectionEvent] = []
        for conn in snapshot:
            if conn.key() in self._previous:
                continue
            tag = classify_ip(conn.peer_ip) if conn.peer_ip else LOCAL
            events.append(ConnectionEvent(timestamp=ts, connection=conn, tag=tag))
            if conn.peer_ip:
                self.counters[conn.peer_ip] += 1
        self._previous = keys
        return events

    def top_talkers(self, limit: int = 5) -> List[tuple]:
        """Most frequently seen peer IPs, like the original's Top Talked IPs."""
        return self.counters.most_common(limit)


# ---------------------------------------------------------------------------
# Console watcher
# ---------------------------------------------------------------------------


def append_log(path: str, events: Iterable[ConnectionEvent]) -> None:
    """Append event lines to the log file. Logging must never kill the watch."""
    try:
        with open(path, "a", encoding="utf-8") as fh:
            for event in events:
                fh.write(event.log_line() + "\n")
    except OSError:
        pass


def watch(interval: float, log_path: Optional[str]) -> None:
    tracker = ConnectionTracker()

    print("=" * 60)
    print(" SOC NETWORK ANALYST")
    print("=" * 60)
    print(f"Polling every {interval:g} seconds. Ctrl+C to stop.")
    if log_path:
        print(f"Logging new connections to {log_path}")
    print("Watching... (first snapshot is the baseline)")

    try:
        first = snapshot_connections()
    except Exception as exc:
        print(f"\nCould not read network connections: {exc}")
        print("On some systems this needs elevated permissions -- try again")
        print("from an administrator / root shell.")
        return

    count = tracker.baseline(first)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] Baseline: {count} connections already open.")

    try:
        while True:
            time.sleep(interval)
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                events = tracker.update(snapshot_connections())
            except Exception as exc:
                print(f"[{stamp}] Poll failed: {exc}")
                continue

            print("\n" + "=" * 60)
            print(f" SOC NETWORK ANALYST - {stamp}")
            print("=" * 60)

            if events:
                for event in events:
                    c = event.connection
                    peer = f"{c.peer_ip}:{c.peer_port}" if c.peer_ip else "-"
                    print(f"[NEW] [{event.tag}] {peer}")
                    detail = f"      {c.describe()}"
                    if c.process:
                        detail += f"  {c.process}"
                    print(detail)
                if log_path:
                    append_log(log_path, events)
            else:
                print("No new connections detected.")

            print("\nTop Talked IPs:")
            top = tracker.top_talkers()
            if top:
                for ip, hits in top:
                    print(f"{ip} -> {hits} events")
            else:
                print("(no connections counted yet)")
    except KeyboardInterrupt:
        print("\nStopped. Stay curious.")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Watch your machine's network connections and log new ones."
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"seconds between polls (default: {DEFAULT_INTERVAL:g})",
    )
    parser.add_argument(
        "--log",
        default=DEFAULT_LOG,
        help=f"log file for new connections (default: {DEFAULT_LOG}; "
        "use --no-log to disable)",
    )
    parser.add_argument(
        "--no-log", action="store_true", help="do not write a log file"
    )
    args = parser.parse_args(argv)

    if psutil is None:
        print("net_watch.py needs the 'psutil' package:  pip install psutil")
        print("(Everything else it uses is the Python standard library.)")
        return 1

    watch(interval=max(1.0, args.interval), log_path=None if args.no_log else args.log)
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Network-Monitor

A small Python script I wrote while teaching myself cybersecurity. It
watches your machine's network connections and tells you when something
new shows up.

## What it does

`net_watch.py` polls your connections every 3 seconds, diffs each
snapshot against the previous one, and prints — and logs — every *new*
connection it sees. Each peer is tagged **LOCAL** or **EXTERNAL**, and
the script keeps a running count of your top talkers: the addresses your
machine talks to most.

```bash
pip install psutil   # the one dependency; everything else is stdlib
python3 net_watch.py
```

Leave it running in a terminal and watch what your machine reaches out
to. New connections are appended to `soc_network_log.txt`. Stop it with
Ctrl+C. Flags: `--interval N` (poll seconds), `--log FILE`, `--no-log`.

## Updated

This started in May 2026 as a 57-line script shelling out to `ss -tun`.
It did its job, but it had real bugs, so I rewrote it to the standard of
the toolkit it grew into (below). What changed:

- **It runs now.** The version I originally committed didn't: there was
  a missing closing parenthesis on line 19 and a misindented `if` a bit
  further down. The history stays as-is because that's the truth of how
  this started.
- **Events are keyed on the peer endpoint.** The original tagged the
  first IP-looking token on the line — the *local* endpoint, i.e. my own
  machine, forever. What a watcher cares about is the peer.
- **Proper IP classification.** The original's LOCAL test was string
  prefixes (`10.`, `192.168.`, `127.`), which quietly misses the
  172.16.0.0/12 private range. Classification now uses the stdlib
  `ipaddress` module: full RFC1918, loopback, link-local, IPv6, and
  CGNAT space (100.64.0.0/10).
- **Cross-platform.** Snapshots come from `psutil` instead of scraping
  `ss` text, so the same script runs on Linux, Windows, and macOS, with
  clean `process name (pid)` labels.
- **A silent baseline.** The first poll used to report every existing
  connection as "new." Now the first snapshot is the baseline; only
  changes after that are events.

## This grew up → the QuantumCat SOC Toolkit

This script is one of three I wrote in May 2026 while learning. I
eventually rebuilt all three properly and combined them into a single
desktop app — the **QuantumCat SOC Toolkit** — for people who want
this kind of watching without living in a terminal.

What the app version of the monitor adds:

- A real GUI tab with a live events table and a Top Talkers panel
- The other two tools built in: a threaded port scanner and a
  one-click snapshot triage report
- An **AI Analyst** tab that reads the findings and explains them in
  plain English — VERDICT → what looks normal → what deserves a
  second look → suggested next steps — running 100% locally via
  Ollama, with a built-in rule engine if you don't have Ollama
- Real installers: a Windows `.msi` that gives you a desktop shortcut
  and a Start Menu entry, plus a Linux `.deb` and a portable
  `.tar.gz`. Click the cat, the app opens — no terminal

It's $12, one-time. And it's honest about what it is: a
beginner-friendly watching and triage tool, not a Wireshark
replacement. 100% local, no accounts, no telemetry. The full Python
source is included in the download.

→ https://quantumcatsoc.gumroad.com/l/quantumcat-soc-toolkit

The other two originals:
[Port_scanner](https://github.com/Quantumcat-py/Port_scanner) ·
[Snapshot-Report](https://github.com/Quantumcat-py/Snapshot-Report)

# Network-Monitor

A small Python script I wrote while teaching myself cybersecurity. It
watches your Linux machine's network connections and tells you when
something new shows up.

## What it does

`net_watch.py` (57 lines) runs `ss -tun` every 3 seconds, diffs the
result against the previous snapshot, and prints — and logs — every
*new* connection it sees. Each peer is tagged **LOCAL** or **EXTERNAL**,
and the script keeps a running count of your top talkers: the addresses
your machine talks to most.

That's it. No GUI, no dependencies beyond Python and the `ss` tool
(iproute2) that ships with basically every Linux distro.

## Run it

```bash
python3 net_watch.py
```

Leave it running in a terminal and watch what your machine reaches out
to. It's a beginner project and it reads like one — that's kind of the
point of keeping it here.

## Honest notes

- The version I originally committed didn't actually run: there's a
  missing closing parenthesis on line 19 and a misindented `if` a bit
  further down. The history stays as-is because that's the truth of how
  this started. (The fixed, rewritten version lives in the toolkit
  below.)
- The LOCAL/EXTERNAL tagging is string-prefix based (`10.`, `192.168.`,
  `127.`), which quietly misses the 172.16.0.0/12 private range. The
  toolkit version classifies addresses properly.

## This grew up → the QuantumCat SOC Toolkit

This script is one of three I wrote in May 2026 while learning. I
eventually rebuilt all three properly and combined them into a single
desktop app — the **QuantumCat SOC Toolkit** — for people who want
this kind of watching without living in a terminal.

What the app version of the monitor adds:

- A real GUI tab with a live events table and a Top Talkers panel
- Structured parsing and proper IP classification (full RFC1918
  including 172.16.0.0/12, loopback, link-local, IPv6, CGNAT)
- Events keyed on the *peer* endpoint — the address that actually
  matters — with clean `process name (pid)` labels
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

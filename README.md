# Splunk
# SOC Analyst Learning Journey — Splunk & Log Analysis Notes

Personal study notes documenting my path toward becoming a SOC (Security Operations Center) Analyst, focused on practical log analysis and Splunk skills using a home lab environment.

## About

These notes are written as I learn — covering log fundamentals, Windows/Linux event analysis, and SPL (Search Processing Language) for Splunk. The focus is on **practical detection logic** (how attacks actually look in logs) rather than pure theory.

## Lab Environment

- **Splunk Enterprise** (Windows) — log indexing & search
- **Kali Linux** — attacker VM
- **Metasploitable 2** — target VM
- **WSL2 / Debian** — CLI & scripting

## Notes Index

| File | Topics Covered |
|---|---|
| [`splunk-day1-2-notes.md`](./splunk-day1-2-notes.md) | Log fundamentals, SSH brute-force patterns, Windows EventCodes (4624/4625), Logon Types, baselining, brute-force vs password-spraying detection logic, SPL pipe basics (`stats count by`) |

## Roadmap

- [x] Log fundamentals (Linux auth logs)
- [x] Windows Security Event basics (EventCode 4624/4625)
- [x] SPL basics (search, stats, pipes)
- [ ] SPL intermediate (eval, where, timechart, lookups)
- [ ] Detection rule writing (correlation searches)
- [ ] BOTS (Boss of the SOC) dataset investigations
- [ ] Splunk Core Certified User prep

## Goal

Working toward a SOC Analyst role, targeting **Splunk Core Certified User → Splunk Core Certified Power User → CySA+** as the certification path.

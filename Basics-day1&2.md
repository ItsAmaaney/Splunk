# Splunk & SOC Analyst — Study Notes

## Day 1: Understanding Logs (Fundamentals)

### What is a log?
- A log = a **timestamped record of an event** that happened on a system
- Every action (login, file access, network connection, error) gets written down somewhere
- Analogy: like a CCTV camera's timestamp log — "At 3:42:15 PM, person entered through door A"
- **Why SOC analysts care**: attacks leave footprints in logs; the job is reading those footprints and spotting normal vs abnormal

### Common log types

| Log Type | What It Records | Example Source |
|---|---|---|
| Authentication logs | Logins, logouts, failed attempts | `/var/log/auth.log`, Windows Security logs |
| Web server logs | HTTP requests to a website | Apache/Nginx access logs |
| Firewall logs | Allowed/blocked network traffic | pfSense, iptables |
| System logs | OS-level events, errors | `/var/log/syslog` |

### Anatomy of a Linux SSH auth log line

```
Jun 13 14:32:07 ubuntu-server sshd[2841]: Failed password for invalid user admin from 192.168.1.105 port 51223 ssh2
```

| Part | Value | Meaning |
|---|---|---|
| Timestamp | `Jun 13 14:32:07` | WHEN it happened |
| Hostname | `ubuntu-server` | WHICH machine logged it |
| Process | `sshd[2841]` | WHAT service (SSH daemon), PID 2841 |
| Event | `Failed password for invalid user admin` | WHAT happened |
| Target user | `admin` | WHO they tried to log in as |
| Source IP | `192.168.1.105` | WHERE the attempt came from |
| Port | `51223` | Source port (usually random, not important) |
| Protocol | `ssh2` | HOW — SSH version 2 |

### Brute-force pattern recognition

Example sequence:
```
14:32:07 — Failed login as admin from 192.168.1.105
14:32:11 — Accepted (success) login as root from 192.168.1.105  (4 seconds later)
```

**Why this is suspicious:**
- 4 seconds is too fast for a human to type a password, switch usernames, and succeed
- This timing = **automated brute-force tool** (e.g., Hydra, Metasploit)
- Result: attacker gained **root access** (full control)

**Key takeaway**: Speed of events + which account succeeds = tells you whether it's human error or automated attack.

---
## Day 2: Splunk + Windows Event Logs

### What is Splunk?

- A **log aggregator + search engine** for machine data
- Collects logs from many systems into one place, indexes them, makes them searchable
- Query language = **SPL** (Search Processing Language) 
- Analogy: Splunk = the central monitoring room where all CCTV feeds from a building show up on one screen, searchable by time/location/event

### Splunk architecture (basics)

| Component | What it does |
|---|---|
| **Forwarder** | Small agent on a machine, sends logs to Splunk |
| **Indexer** | Receives logs, stores & indexes them for searching |
| **Search Head** | The UI/dashboard where searches are run |

For a home lab single-machine setup, one Splunk instance often does all three roles.

### Internal vs regular indexes

- `index=*` searches **all non-internal indexes** — does NOT include Splunk's own internal logs
- Internal indexes start with underscore: `_audit`, `_internal`, `_introspection`
- Must specify explicitly: `index=_audit`, `index=_internal`, or `index=_*` for all internal indexes
- `_audit` = logs who logged into Splunk web UI and what searches were run — useful for "did someone misuse their Splunk access" investigations

### Windows EventCodes

| EventCode | Meaning |
|---|---|
| **4624** | Successful logon |
| **4625** | Failed logon |
| **4798** | A user's local group membership was enumerated (recon activity) |

### Logon Types (the "HOW" of a login)

| Logon Type | Meaning |
|---|---|
| **2** | Interactive — physically at the keyboard |
| **3** | Network — accessing a shared resource over network |
| **4** | Batch — scheduled task running |
| **5** | Service — a Windows service starting up |
| **7** | Unlock — unlocking a locked screen |
| **10** | RemoteInteractive — RDP (Remote Desktop) login |
| **11** | CachedInteractive — logged in using cached credentials |

**SOC relevance:**
- Logon Type 10 (RDP) from an unrecognized IP at odd hours → red flag
- Logon Type 3 (Network) with repeated failed passwords against `\\server\admin$` → lateral movement / share brute-forcing
- Logon Type 2 = most "normal" — someone physically typing their password

### Basic SPL filtering (start broad, narrow down)

```spl
index=*
```
Show everything indexed.

```spl
index=* EventCode=4624
```
Filter to only successful Windows logons.

```spl
index=* EventCode=4624 Logon_Type=2
```
Filter further — only interactive (keyboard) logons.

**Core SOC investigation method**: start broad → filter by event type → filter further by HOW it happened, until you isolate exactly what matters.

### Baselining

- **Baselining = knowing what "normal" looks like on a system BEFORE you can spot what's abnormal**
- Example: 17 failed logon events (EventCode 4625), all Logon_Type=2, all clustered in short bursts on the same machine = likely just normal password typos — this is the "normal" baseline for that machine
- If the SAME pattern showed up with Logon_Type=10 (RDP), unrecognized account, or at 3am → that becomes "investigate this"

### Investigation discipline (lessons learned)

- Always verify timestamps — don't assume "today" without checking the actual date
- Check field VALUES, not just field NAMES — e.g., `Account_Name` had 2 distinct values (`ADIL$` and `-`), neither of which was the actual username expected
- `ADIL$` (with `$`) = the **computer account**, not a personal user account
- Sometimes investigations are inconclusive — that's realistic. Document it and move on.

### Brute Force vs Password Spraying — detection logic

| Attack Type | Pattern | Detection approach |
|---|---|---|
| **Brute force** | Many passwords tried against ONE username, from ONE source IP | `stats count by src_ip, user` → look for HIGH count |
| **Password spraying** | ONE (or few) passwords tried against MANY usernames, from ONE source IP, one attempt each | Drop username from grouping — count DISTINCT usernames per source IP |

**Why this matters**: if you group by `src_ip + username` for a spraying attack, every group has count=1 (looks like 100 unrelated typos). You'd miss it entirely. Must use `dc()` (distinct count) on username instead.

Example spraying detection:
```spl
index=* EventCode=4625 
| stats dc(user) as unique_users count by src_ip 
| where unique_users > 10
```

---

## SPL Basics — The Pipe Concept

### Structure
```
search_terms | command1 | command2 | command3
```

Each `|` (pipe) takes the OUTPUT of the previous stage and feeds it as INPUT to the next — like an assembly line / conveyor belt.

### `stats` command

- `stats count` → ONE total number (no grouping)
- `stats count by <field>` → SEPARATE count for EACH distinct value of that field

**Example (non-log data):**

Grades: A, B, A, C, A, B, B, A, C, A

```
stats count           → 10
stats count by grade  → A: 5, B: 3, C: 2
```

### Practical example — web access logs

```spl
sourcetype=access_* | stats count by status
```

= "Take all web access events, and for EACH different HTTP status code (200, 404, 500...), tell me how many events have that code."

Result tells you: how many requests succeeded (200) vs failed (404, 500) — a real monitoring question answered in one line.

---

.

## Day 3: SPL Intermediate — sort, head, and Web Attack Detection

### HTTP Status Codes (what they mean for security)

| Status Code | Meaning | Security relevance |
|---|---|---|
| **200** | OK — request succeeded | Normal traffic |
| **400** | Bad Request — malformed request | Could be scanner/fuzzer sending garbage |
| **403** | Forbidden — server refused the request | Trying to access restricted areas |
| **404** | Not Found — page doesn't exist | Could be directory scanning/enumeration |
| **406** | Not Acceptable — server can't produce response in requested format | Unusual, could be scanner |
| **408** | Request Timeout | Could indicate slow/scanning tools |
| **500** | Internal Server Error — server crashed processing the request | Could be fuzzing/injection attempts |
| **503** | Service Unavailable | Could indicate DoS or server overload |
| **505** | HTTP Version Not Supported | Unusual — possibly scanner or old tool |

### `sort` command

```spl
sourcetype=access_* | stats count by status | sort -count
```

- `sort -count` = sort by count, **descending** (highest first). The `-` means descending
- `sort count` (no `-`) = ascending (lowest first)

### `head` command

```spl
sourcetype=access_* status=404 | stats count by clientip | sort -count | head 5
```

- `head 5` = show only the TOP 5 rows after sorting
- Useful for quickly seeing the biggest outliers without scrolling through hundreds of IPs

### Real investigation example — 404 scanning detection

**Question being asked:** Which IP is generating the most "Page Not Found" errors? Could someone be scanning for hidden files/pages?

```spl
sourcetype=access_* status=404 | stats count by clientip | sort -count | head 5
```

**Pipeline breakdown:**
1. `sourcetype=access_* status=404` → filter to ONLY 404 events (690 out of 39,532)
2. `| stats count by clientip` → group by source IP, count how many 404s each caused
3. `| sort -count` → sort highest to lowest
4. `| head 5` → show top 5 only

**Finding from real data:** IP `87.194.216.51` caused 40 out of 690 total 404 errors

**How to investigate further:**
- Is 40 a lot? Compare to #2, #3, #4, #5 — if they're all 5-10, then 40 is a clear outlier
- If the top IP is WAY ahead of everyone else → suspicious (possible scanner)
- If all IPs have similar counts → probably normal random 404s from regular visitors

### Key SOC investigation principle — context matters

**40 failed requests could mean:**
- Normal: user with a broken bookmark, hitting the same missing page repeatedly
- Suspicious: automated scanner trying to discover hidden pages/admin panels

**How to tell the difference:**
- Look at WHAT URLs they're requesting (are they trying `/admin`, `/.env`, `/backup.zip`?)
- Look at WHEN they're hitting (all within 2 seconds = automated; spread across hours = probably human)
- Look at HOW MANY different URLs they tried (10 different URLs = suspicious enumeration; same URL 10 times = broken link)

### Accuracy matters in SOC reporting

- Always double-check totals before reporting — a typo'd number can send someone investigating the wrong incident
- Example: "35,532 events" vs actual "39,532 events" — small typo, but misleading in a real report

# Day4
## 🔧 SPL Commands Learned
 
### 1. `stats count by`
Groups and counts events by a field.
```spl
sourcetype=access_* | stats count by clientip | sort -count
```
**Use:** See which IPs are making the most requests → brute force detection.
 
---
 
### 2. `eval` — Field Transformation
Creates or transforms a field on the fly.
 
**Syntax:**
```spl
| eval new_field = expression
```
 
**Example — Convert bytes to kilobytes:**
```spl
| eval kilobytes = bytes / 1024
```
 
**With `round()` for clean decimals:**
```spl
| eval kilobytes = round(bytes / 1024, 2)
```
 
---
 
### 3. `stats sum()` — Aggregate Per Group
Adds up a field's values per group (e.g., per IP).
 
**Why not just `eval`?**  
`eval` works row by row. One IP can make 500 requests — each row has its own `kilobytes`.  
`sum()` collapses all rows for the same IP into **one total**.
 
```spl
| stats sum(kilobytes) as total_kb by clientip
```
 
---
 
### 4. `where` — Filter Results
Filters rows after aggregation (like SQL's `HAVING`).
 
```spl
| where total_kb > 1000
```
 
---
 
### 5. `sort` — Order Results
`-fieldname` = descending (highest first)  
`+fieldname` = ascending (lowest first)
 
```spl
| sort -total_kb
```
 
---
 
### 6. `rename` — Rename a Field
```spl
| rename clientip as Source_IP
```
 
---
 
### 7. `table` — Display Specific Fields Only
```spl
| table clientip, uri_path, kilobytes
```
 
---
 
## 🚨 Real Detection Query — Data Exfiltration by IP
 
**Goal:** Find IPs that transferred the most data — potential exfiltration.
 
```spl
sourcetype=access_* 
| eval kilobytes = round(bytes / 1024, 2) | stats sum(kilobytes) as total_kb by clientip | where total_kb > 1000 | sort -total_kb | rename clientip as Source_IP
```
 
**What it does step by step:**
 
| Step | Command | Purpose |
|------|---------|---------|
| 1 | `eval kilobytes = round(bytes/1024, 2)` | Convert bytes → KB per request |
| 2 | `stats sum(kilobytes) as total_kb by clientip` | Total KB transferred per IP |
| 3 | `where total_kb > 1000` | Keep only high-volume IPs |
| 4 | `sort -total_kb` | Highest first |
| 5 | `rename clientip as Source_IP` | Clean field naming |
 
**SOC Context:** High `total_kb` from a single IP = 🚩 potential data exfiltration. Pivot to check what `uri_path` they were hitting and whether the IP is internal or external.
 
---
 
## ⚠️ Common Mistakes
 
| Mistake | Fix |
|--------|-----|
| `sum (kilobytes)` with a space | `sum(kilobytes)` — no space |
| Using `where` before `stats` | `where` filters **after** aggregation |
| Forgetting `as` in stats | Always name your output field: `sum(x) as total` |
 
---
 
*Training ongoing — updated as new concepts are covered.*
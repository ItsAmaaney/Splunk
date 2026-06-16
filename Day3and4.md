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
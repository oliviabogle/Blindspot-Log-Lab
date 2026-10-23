# CMMC Log Lab

**A regenerating cyber-investigation range for GRC and threat-analyst practice, aligned to NIST SP 800-171 and CMMC Level 2.**

Every run builds a brand-new fictional defense subcontractor — employees, servers, a week of security logs, and the GRC paperwork an assessor would ask for — then quietly plants **active threats** and **compliance failures** in it, along with **decoys** that look bad but are actually authorized. Your job is to find the real problems, prove each one with evidence, and map it to the 800-171 requirement / CMMC practice it violates. The built-in grader scores you and explains everything you missed.

Same seed = same case (so you can share a challenge). No seed = a fresh case every time.

```
$ python -m loglab generate --seed 482913 --difficulty medium

New case generated: cases/CASE-482913
  difficulty=medium  focus=mixed  seed=482913
  window 2026-08-31 -> 2026-09-06  |  3,213 log events
    logs/windows_security.jsonl        282
    logs/vpn.jsonl                     106
    logs/fileshare_audit.jsonl         930
    logs/firewall.log                  862
    logs/email_gateway.jsonl           488
    logs/endpoint_edr.jsonl            545
```

---

## Why this exists

Entry-level GRC and SOC roles in the defense industrial base ask for two skills that are hard to show on a résumé:

1. **Threat analysis** — reading raw telemetry, correlating across sources, and separating attacks from noise.
2. **Compliance analysis** — knowing what NIST SP 800-171 actually requires and recognizing when an environment doesn't meet it.

This lab exercises both at once, the way a real CMMC readiness review or incident investigation does.

> **Standard version:** CMMC Level 2 (32 CFR Part 170) incorporates the 110 requirements of **NIST SP 800-171 Revision 2**, so the lab uses Rev 2 numbering and CMMC practice IDs (e.g. `AC.L2-3.1.8`). NIST has published Rev 3, and DoD has signaled a future transition; the control catalog in `loglab/controls.py` is the single place to update when that happens.

---

## Quick start

Requires **Python 3.10+**. No third-party packages are needed to run the lab.

```bash
git clone https://github.com/<you>/cmmc-log-lab.git
cd cmmc-log-lab

python -m loglab generate                 # new random case (medium, mixed)
python -m loglab brief CASE-482913        # read the assignment + SSP rules
# ...investigate logs/ and evidence/, fill in findings.csv...
python -m loglab grade CASE-482913        # score it (missed items stay hidden)
python -m loglab grade CASE-482913 --reveal
```

Optional: `pip install -e .` gives you a `loglab` command instead of `python -m loglab`.

### All commands

| Command | What it does |
|---|---|
| `generate` / `new` | Build a new case. Options: `--difficulty easy\|medium\|hard`, `--focus mixed\|threat\|compliance`, `--seed N`, `--days 7-14` |
| `list` | Show your cases and which ones are graded |
| `brief CASE` | Print the case briefing |
| `hint CASE [N]` | Get a nudge for finding *N* without spoiling it |
| `grade CASE [--findings file] [--reveal]` | Score your findings; writes `grade_report.md` |
| `reveal CASE` | Full answer key (spoilers) |
| `controls [--family AC]` | Browse the 800-171 / CMMC L2 requirements used in the lab |
| `scenarios` | List every threat, compliance, and decoy scenario |

---

## What's in a case

```
cases/CASE-482913/
├── BRIEFING.md                 # assignment, SSP excerpts (the rules), log field reference
├── findings.csv                # <- your answers go here
├── logs/
│   ├── windows_security.jsonl  # 4624/4625/4634/4728/1102 ...
│   ├── vpn.jsonl               # connects, MFA results, geo
│   ├── fileshare_audit.jsonl   # CUI share and PLM vault access
│   ├── firewall.log            # key=value perimeter + internal firewall
│   ├── email_gateway.jsonl     # inbound/outbound mail, TLS, SPF/DKIM verdicts
│   └── endpoint_edr.jsonl      # processes, USB, file copies, AV health, installs
└── evidence/
    ├── user_roster.csv         # USR-#### — employment vs account status, MFA, owners
    ├── asset_inventory.csv     # AST-#### — OS, patch date, EDR, audit logging, CUI scope
    ├── config_snapshot.csv     # CFG-### — GPO / VPN / SIEM settings
    ├── change_tickets.csv      # approved changes (explains some "suspicious" admin work)
    ├── usb_allowlist.csv       # approved encrypted drives
    └── travel_exceptions.csv   # approved foreign travel
```

Every log line, roster row, asset, and config setting has an ID. Findings cite those IDs.

### Writing findings

```csv
evidence_id,control,notes
VPN-000074,3.14.6,One IP sprayed 14 accounts; last had valid password
USR-0015,IA.L2-3.5.6,No login since January but still enabled
FS-000301;FW-000224,AC.L2-3.1.3,Bulk CUI reads after hours then upload to personal cloud
```

* `evidence_id` — any ID that proves the finding (separate several with `;`).
* `control` — `3.5.6`, `IA.L2-3.5.6`, or several separated by `;`.
* One row per finding.

### Scoring

| | Points |
|---|---|
| Finding detected (valid evidence cited) | **+10** |
| Mapped to an accepted 800-171 / CMMC control | **+5** |
| False positive (benign activity or decoy flagged) | **−3** |

Most findings accept more than one reasonable control, because real assessors map one failure to several requirements.

### Difficulty

| | Findings | Decoys | Log volume | Briefing help |
|---|---|---|---|---|
| **easy** | 4 | 1 + scanner | low | control refs shown next to each SSP rule; finding count given |
| **medium** | 6 | 2 + scanner | normal | finding count given |
| **hard** | 9 | 4 + scanner | high, larger org | nothing — figure it out |

---

## Scenario library

### Threats

| Scenario | What you'll see | Primary controls |
|---|---|---|
| Password spray | One external IP failing against many users, last one hits MFA | 3.14.6, 3.14.7, 3.1.12 |
| MFA fatigue | Repeated push denials, then approval from abroad, then CUI access | 3.1.12, 3.14.7, 3.5.3 |
| Impossible travel | Concurrent sessions in two countries, token reuse | 3.1.12, 3.14.7 |
| Terminated user still active | Roster says terminated; account still logs in | **3.9.2**, 3.1.1 |
| Insider exfiltration | Departing employee bulk-reads CUI, uploads to personal cloud | 3.1.3, 3.14.7, 3.13.1 |
| USB CUI copy | Non-allowlisted, unencrypted drive + CUI file copies | 3.8.7, 3.8.8 |
| Phishing → malware | Look-alike domain macro doc, Office spawns PowerShell, C2 beacon | 3.14.2, 3.14.6 |
| Privilege escalation | Standard user added to Domain Admins with no change ticket | 3.1.5, 3.4.3, 3.1.7 |
| Audit log cleared | Service account RDPs in at 2 a.m., Event 1102 | 3.3.8, 3.3.9 |
| AV tampering | User disables Defender real-time protection | 3.14.2, 3.4.2 |
| Internal recon | Workstation port-scans the server subnet | 3.14.6, 3.14.7 |

### Compliance failures

| Scenario | Where it hides | Primary controls |
|---|---|---|
| Shared account | Roster (no owner) + logons from many hosts | 3.5.1, 3.5.2, 3.3.2 |
| No MFA on remote access | VPN `mfa=none`, exemption group in config | 3.5.3 |
| Cleartext protocols | FTP to a supplier / Telnet to switches | 3.13.8, 3.5.10 |
| Weak password policy | Config snapshot | 3.5.7 |
| Lockout disabled | Config snapshot | 3.1.8 |
| No session lock / VPN idle timeout | Config snapshot | 3.1.10, 3.1.11, 3.13.9 |
| Missing logon banner | Config snapshot | 3.1.9 |
| Audit gaps | Host with logging off / short SIEM retention | 3.3.1, 3.3.2 |
| Unpatched / EOL system | Asset inventory | 3.14.1, 3.11.3 |
| Missing EDR | Asset inventory + no nightly check-in | 3.14.2 |
| CUI to personal email | Email gateway, `tls=false` | 3.1.3, 3.13.8 |
| Privileged account misuse | `adm-` account browsing and emailing | 3.1.6 |
| Unauthorized software | AnyDesk / uTorrent / TeamViewer installs | 3.4.9, 3.4.8 |
| Stale account | Roster `last_login` > 90 days | 3.5.6 |

### Decoys (authorized activity that looks bad)

Approved after-hours change, approved foreign travel, allowlisted encrypted USB, large SFTP transfer to the prime contractor, fat-fingered logins, and the weekly authorized vulnerability scan.

---

## Hunting tips

The logs are plain JSON Lines and text, so use whatever you'd use on the job.

**Python**

```python
import json, collections
vpn = [json.loads(l) for l in open("cases/CASE-482913/logs/vpn.jsonl")]
# failures per source IP
print(collections.Counter(e["src_ip"] for e in vpn if e["action"] == "auth_failure").most_common(5))
# anything not from the US
[print(e) for e in vpn if e.get("geo_country") not in (None, "US")]
```

**jq**

```bash
jq -c 'select(.EventID == 4728 or .EventID == 1102)' logs/windows_security.jsonl
jq -c 'select(.type == "process" and (.parent == "winword.exe" or .parent == "excel.exe"))' logs/endpoint_edr.jsonl
jq -c 'select(.direction == "outbound" and .tls == false)' logs/email_gateway.jsonl
```

**grep / PowerShell**

```bash
grep -E 'dport=(21|23) ' logs/firewall.log
```
```powershell
Get-Content logs\vpn.jsonl | ConvertFrom-Json | Where-Object mfa -eq 'none'
```

You can also load the files into Splunk, Elastic, or a SQLite database and practice real queries.

---

## Project layout

```
loglab/
├── cli.py         # command-line interface
├── generator.py   # builds a case: org -> scenarios -> decoys -> baseline noise -> files
├── org.py         # fictional company, people, assets, IP/domain pools
├── baseline.py    # normal day-to-day activity (the haystack)
├── scenarios.py   # threat, compliance, and decoy scenarios (the needles)
├── briefing.py    # BRIEFING.md / SSP excerpts
├── grader.py      # scoring and report
└── controls.py    # NIST SP 800-171 Rev 2 catalog + CMMC L2 practice IDs
tests/test_lab.py  # every answer is backed by real evidence; perfect score = 100%
```

### Adding a scenario

```python
@scenario("dns_tunneling", "threat")
def dns_tunneling(ctx: Context) -> Issue:
    u = ctx.pick_user()
    day = ctx.workday()
    ev = [ctx.add(ctx.at(day, 14), "firewall", action="allow", src=..., dport=53, ...)
          for _ in range(200)]
    return Issue(key="dns_tunneling", title="DNS tunneling from ...", category="threat",
                 severity="high", controls=["3.14.6", "3.13.1"], evidence=ev,
                 explanation="...", remediation="...", hint="...")
```

It's automatically eligible for new cases, and the test suite will verify its evidence exists.

Run tests with `pip install -r requirements-dev.txt && pytest`.

---

## Notes

* **All data is fictional.** Domains use the reserved `.example` TLD and external IPs come from the RFC 5737 documentation ranges, so nothing points at a real organization.
* The answer key (`.answer_key`) is compressed and encoded to prevent accidental spoilers. It's not encryption — the honor system applies.
* Control titles in the catalog are short paraphrases for training. Use the official NIST SP 800-171 Rev 2 and 800-171A publications for authoritative requirement and assessment-objective text.
* This is a training tool, not an assessment tool, and is not affiliated with DoD, NIST, or the Cyber AB.

## License

MIT

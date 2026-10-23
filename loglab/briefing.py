"""Renders the analyst briefing (BRIEFING.md) for a case."""

from __future__ import annotations

from . import org

# (policy text, related controls) - mirrors an SSP excerpt
POLICIES = [
    ("Business hours are 06:00-19:00 Mon-Fri (local time). Privileged work outside business hours "
     "requires an approved change ticket (`change_tickets.csv`).", ["3.4.3"]),
    ("Security group membership changes (especially admin groups) require an approved change ticket.",
     ["3.1.5", "3.4.3"]),
    ("Remote access is permitted only through VPN-GW with MFA for every user. Connections from outside the "
     "US are not allowed unless listed in `travel_exceptions.csv`.", ["3.1.12", "3.5.3"]),
    ("Accounts lock after 5 invalid logon attempts for 30 minutes.", ["3.1.8"]),
    ("Passwords: minimum 14 characters, complexity enabled, 24 remembered.", ["3.5.7"]),
    ("Workstations lock after 15 minutes (900 s) of inactivity; idle VPN sessions end after 30 minutes.",
     ["3.1.10", "3.1.11", "3.13.9"]),
    ("An approved system-use / CUI notification banner is displayed at logon.", ["3.1.9"]),
    ("Audit logging is enabled on every in-scope system and forwarded to SIEM01; retention is 365 days. "
     "Only Security Admins may manage or clear logs.", ["3.3.1", "3.3.8", "3.3.9"]),
    ("Every account has exactly one accountable named owner. Shared/generic accounts are prohibited. "
     "Service accounts are non-interactive.", ["3.5.1", "3.3.2"]),
    ("Accounts inactive for 90 days are disabled. Access is revoked on an employee's termination date.",
     ["3.5.6", "3.9.2"]),
    ("Privileged `adm-` accounts are used only for administration - never for web browsing or email.",
     ["3.1.6"]),
    ("Removable media: only FIPS-encrypted devices listed in `usb_allowlist.csv`, used by their assigned owner.",
     ["3.8.7", "3.8.8"]),
    (f"CUI may be emailed only to @{org.PRIME_DOMAIN} (TLS enforced) and transferred via "
     f"{org.PRIME_SFTP}. Personal email and personal cloud storage are prohibited for CUI.",
     ["3.1.3", "3.13.8"]),
    ("Cleartext protocols (FTP, Telnet, unencrypted HTTP logins) are prohibited.", ["3.13.8", "3.5.10"]),
    ("Only approved software may run (list below). Standard users cannot install software.",
     ["3.4.8", "3.4.9"]),
    ("Security patches are applied within 30 days. End-of-life operating systems are not permitted in scope.",
     ["3.14.1", "3.11.3"]),
    ("EDR/antivirus runs on every Windows workstation and server with real-time and tamper protection ON, "
     "checking in nightly (Linux hosts and vendor appliances are covered by separate controls).",
     ["3.14.2"]),
    ("Only VULNSCAN01 (svc-scan) may scan the network - weekly, Sunday 02:00.", ["3.11.2", "3.14.6"]),
]

LOG_REFERENCE = """\
| File | What it contains | Useful fields |
|---|---|---|
| `logs/windows_security.jsonl` | Windows Security events from workstations, servers and DCs | `EventID` (4624 logon OK, 4625 logon failed, 4634 logoff, 4728 added to security group, 1102 audit log cleared), `LogonType` (2 interactive, 3 network, 4 batch, 10 RDP), `TargetUserName`, `SubjectUserName`, `Computer`, `IpAddress` |
| `logs/vpn.jsonl` | Remote-access gateway | `action` (connect, disconnect, auth_failure, mfa_denied), `mfa`, `src_ip`, `geo_city`, `geo_country`, `assigned_ip` (the user's internal VPN address) |
| `logs/fileshare_audit.jsonl` | File access on file servers / PLM vault | `user`, `src_ip`, `path`, `action`, `bytes`, `classification` (CUI or Internal) |
| `logs/firewall.log` | Perimeter + internal firewall (key=value text) | `action`, `src`, `dst`, `dport`, `app`, `host`, `bytes_out` |
| `logs/email_gateway.jsonl` | Mail security gateway | `direction`, `sender`, `recipient`, `attachment`, `tls`, `verdict`, `spf`, `dkim` |
| `logs/endpoint_edr.jsonl` | EDR telemetry | `type` (process, usb, file_copy, av_status, software_install), `host`, `user`, `image`, `parent`, `cmdline` |

Static evidence lives in `evidence/`: `user_roster.csv` (IDs `USR-####`), `asset_inventory.csv`
(`AST-####`), `config_snapshot.csv` (`CFG-###`), plus `change_tickets.csv`, `usb_allowlist.csv`, and
`travel_exceptions.csv` for context.
"""


def render_briefing(case_id: str, meta: dict, issues) -> str:
    show = meta["show"]
    lines = [
        f"# {case_id} - CUI Environment Investigation",
        "",
        f"**Client:** {org.COMPANY} (fictional) - a small defense subcontractor that machines precision "
        f"components and holds Controlled Unclassified Information (CUI) for its prime, {org.PRIME_DOMAIN}.  ",
        f"**Review window:** {meta['window_start']} through {meta['window_end']} (all times local).  ",
        f"**Difficulty:** {meta['difficulty']}  |  **Focus:** {meta['focus']}  |  **Seed:** {meta['seed']}",
        "",
        "## Your assignment",
        "",
        "The company is preparing for a CMMC Level 2 assessment (NIST SP 800-171 Rev 2, 110 requirements). "
        "The ISSM has asked you to review one week of security telemetry and the supporting GRC records, and to "
        "identify **active threats** and **compliance failures** in the CUI enclave.",
        "",
        "For each finding:",
        "1. Cite at least one **evidence ID** that proves it (`WIN-000123`, `USR-0007`, `AST-0012`, `CFG-004`...).",
        "2. Map it to the **NIST SP 800-171 requirement / CMMC practice** it violates (e.g. `3.1.8` or `AC.L2-3.1.8`).",
        "3. Record it as a row in `findings.csv`, then run `python -m loglab grade " + case_id + "`.",
        "",
        "Beware: some activity *looks* suspicious but is authorized. False positives cost points - "
        "check the change tickets, allowlists, and travel exceptions before you flag something.",
        "",
    ]
    if show["show_count"]:
        n_t = sum(1 for i in issues if i.category == "threat")
        n_c = len(issues) - n_t
        lines += [f"> Intel: the ISSM believes there are **{n_t} threat(s)** and **{n_c} compliance failure(s)** "
                  "to find.", ""]
    else:
        lines += ["> Intel: unknown number of findings. Hard mode - you're on your own.", ""]

    lines += ["## System Security Plan (SSP) excerpts - the rules you are auditing against", ""]
    for n, (text, ctrls) in enumerate(POLICIES, 1):
        ref = f"  *(ref: {', '.join(ctrls)})*" if show["show_refs"] else ""
        lines.append(f"{n}. {text}{ref}")
    lines += ["", "**Approved software:** " + ", ".join(f"`{s}`" for s in org.APPROVED_SOFTWARE), "",
              "**CUI locations:** " + ", ".join(f"`{s}`" for s in org.CUI_SHARES) + ", plus systems marked "
              "`stores_cui=True` in the asset inventory.", "",
              "## Log & evidence reference", "", LOG_REFERENCE, "",
              "## Suggested workflow", "",
              "1. Read the SSP excerpts and the evidence CSVs first - know what 'normal' is supposed to be.",
              "2. Audit the static records: roster vs. policy, asset inventory, config snapshot.",
              "3. Hunt through the logs for each policy: who, what, when, from where, and was it authorized?",
              "4. Correlate across sources (VPN `assigned_ip` -> fileshare `src_ip`, workstation IP -> firewall `src`).",
              "5. Write findings, grade, read the report, and regenerate a new case to practice again.",
              ""]
    return "\n".join(lines)

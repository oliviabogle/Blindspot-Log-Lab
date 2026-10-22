

# Blindspot Log Lab

A Python training lab for **threat analysts** and **GRC analysts**, aligned to **NIST SP 800-171** and **CMMC Level 2**.

Each run creates a new fictional defense contractor with a week of security logs and compliance records. Hidden inside are real threats, compliance failures, and a few decoys that look bad but are actually allowed. Your job: find the real problems, prove them with evidence, and map each one to the control it violates. The lab grades you and explains what you missed.

---

## Quick start

Requires Python 3.10 or newer. Nothing else to install.

```bash
python -m loglab generate          # create a new case
python -m loglab brief CASE-12345  # read your assignment
python -m loglab grade CASE-12345  # grade your findings
```

Run `generate` again any time for a fresh case. Add `--seed 12345` to recreate the same case.

---

## How it works

1. **Generate a case.** Choose `--difficulty easy | medium | hard` and `--focus mixed | threat | compliance`.
2. **Read the briefing.** `BRIEFING.md` lists the company's security rules you're auditing against.
3. **Investigate.** Search the logs and records for anything that breaks the rules.
4. **Record findings** in `findings.csv`:

   ```csv
   evidence_id,control,notes
   VPN-000074,3.14.6,One IP tried 14 accounts
   USR-0015,IA.L2-3.5.6,No login in 6 months but still enabled
   ```

5. **Grade it.** You earn points for each real finding and correct control, and lose points for false alarms.

Stuck? Run `python -m loglab hint CASE-12345` for a nudge, or `reveal` to see the answers.

---

## What's in a case

| Folder | Contents |
|---|---|
| `logs/` | Windows security, VPN, file share, firewall, email, and endpoint (EDR) logs |
| `evidence/` | User roster, asset inventory, config settings, change tickets, USB allowlist, travel approvals |

Every log line and record has an ID (like `WIN-000123` or `USR-0007`) that you cite as evidence.

---

## What you might find

**Threats:** password spraying, MFA fatigue attacks, impossible travel, fired employees still logging in, insider data theft, unapproved USB drives, phishing and malware, unauthorized admin access, cleared audit logs, disabled antivirus, internal network scanning.

**Compliance failures:** shared accounts, missing MFA, unencrypted protocols, weak password rules, no account lockout, no screen lock, missing logon banner, logging gaps, unpatched systems, missing antivirus, CUI emailed to personal accounts, admin accounts used for everyday work, unapproved software, inactive accounts left on.

**Decoys:** activity that looks suspicious but is authorized, like after-hours work with an approved change ticket.

---

## Tips for investigating

The logs are plain text and JSON, so use any tool you like: Python, `jq`, `grep`, PowerShell, Splunk, or Elastic.

```bash
jq -c 'select(.EventID == 1102)' logs/windows_security.jsonl   # cleared audit logs
grep -E 'dport=(21|23) ' logs/firewall.log                      # FTP and Telnet
```

---

## Notes

- **All data is fictional.** Domains and IP addresses use reserved example ranges.
- **Uses NIST SP 800-171 Rev 2**, which is what CMMC Level 2 currently assesses against.
- This is a training tool, not affiliated with DoD, NIST, or the Cyber AB.

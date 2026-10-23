"""Assembles a full investigation case: org + planted issues + decoys + baseline noise."""

from __future__ import annotations

import base64
import csv
import json
import random
import zlib
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from . import baseline, org
from .controls import cmmc_id
from .model import LOG_PREFIX, Context, Decoy, Event, Issue
from .scenarios import DECOYS, SCENARIOS

DIFFICULTY = {
    #          issues decoys noise  show control refs / count in briefing
    "easy":   dict(issues=4, decoys=1, noise=0.6, show_refs=True,  show_count=True,  size="small"),
    "medium": dict(issues=6, decoys=2, noise=1.0, show_refs=False, show_count=True,  size="medium"),
    "hard":   dict(issues=9, decoys=4, noise=1.4, show_refs=False, show_count=False, size="large"),
}

LOG_FILES = {
    "windows": "windows_security.jsonl",
    "vpn": "vpn.jsonl",
    "fileshare": "fileshare_audit.jsonl",
    "firewall": "firewall.log",
    "email": "email_gateway.jsonl",
    "endpoint": "endpoint_edr.jsonl",
}

DEFAULT_CONFIG = {
    # key: (system, setting, compliant value)
    "min_password_length": ("Default Domain Policy (GPO)", "MinimumPasswordLength", "14"),
    "password_complexity": ("Default Domain Policy (GPO)", "PasswordComplexity", "Enabled"),
    "password_history": ("Default Domain Policy (GPO)", "PasswordHistorySize", "24"),
    "lockout_threshold": ("Default Domain Policy (GPO)", "LockoutBadCount", "5"),
    "lockout_duration": ("Default Domain Policy (GPO)", "LockoutDuration", "30 minutes"),
    "inactivity_limit": ("Workstation Baseline (GPO)", "InactivityTimeoutSecs", "900 seconds"),
    "logon_banner": ("Workstation Baseline (GPO)", "LegalNoticeText",
                     "\"You are accessing a system containing CUI. Use is monitored...\""),
    "usb_policy": ("Workstation Baseline (GPO)", "RemovableStorage_DenyAll", "Enabled (allowlist exceptions)"),
    "applocker": ("Workstation Baseline (GPO)", "AppLocker_EnforcementMode", "Enforced"),
    "vpn_mfa": ("VPN-GW", "require_mfa_all_groups", "true (all groups)"),
    "vpn_idle_timeout": ("VPN-GW", "idle_session_timeout", "30 minutes"),
    "vpn_geo": ("VPN-GW", "geo_policy", "alert on non-US source (SOC review)"),
    "siem_retention_days": ("SIEM01", "retention_days", "365"),
    "audit_logon": ("Domain Controllers Policy (GPO)", "Audit Logon", "Success, Failure"),
    "audit_group_mgmt": ("Domain Controllers Policy (GPO)", "Audit Security Group Management", "Success"),
    "mail_tls_partner": ("MAIL-GW", "enforced_tls_domains", org.PRIME_DOMAIN),
    "fips_mode": ("Domain Controllers Policy (GPO)", "FIPSAlgorithmPolicy", "Enabled"),
}


# ---------------------------------------------------------------------------
def _encode_key(obj) -> str:
    return base64.b85encode(zlib.compress(json.dumps(obj).encode())).decode()


def decode_key(text: str):
    return json.loads(zlib.decompress(base64.b85decode(text.encode())))


def _choose(rng: random.Random, n: int, focus: str) -> list[str]:
    threats = [k for k, (c, _) in SCENARIOS.items() if c == "threat"]
    comp = [k for k, (c, _) in SCENARIOS.items() if c == "compliance"]
    if focus == "threat":
        return rng.sample(threats, k=min(n, len(threats)))
    if focus == "compliance":
        return rng.sample(comp, k=min(n, len(comp)))
    n_t = max(1, min(len(threats), n // 2 + rng.choice([-1, 0, 0, 1])))
    n_c = min(len(comp), n - n_t)
    return rng.sample(threats, k=n_t) + rng.sample(comp, k=n_c)


def build_case(seed: int, difficulty: str = "medium", focus: str = "mixed", days: int = 7):
    """Pure function: same inputs -> identical case. Returns (ctx, issues, decoys, meta)."""
    rng = random.Random(seed)
    cfg = DIFFICULTY[difficulty]
    start = datetime(2026, 1, 5) + timedelta(weeks=rng.randint(0, 38))  # always a Monday
    users, assets = org.build_org(rng, start, cfg["size"])
    ctx = Context(rng=rng, start=start, days=days, users=users, assets=assets, ips=org.IPPool(rng))
    ctx.config = {k: {"system": s, "setting": n, "value": v} for k, (s, n, v) in DEFAULT_CONFIG.items()}

    # legitimate paperwork that makes the environment feel real
    for u in rng.sample([u for u in users if u.department in ("Engineering", "Quality") and u.status == "active"], k=2):
        ctx.usb_allowlist.append({"serial": "".join(rng.choice("0123456789ABCDEF") for _ in range(16)),
                                  "model": "SecureVault FIPS 140-3 encrypted drive", "assigned_to": u.username,
                                  "encrypted": True})
    for _ in range(rng.randint(3, 6)):
        ws = start + timedelta(days=rng.randint(0, days - 1), hours=rng.choice([10, 13, 20]))
        ctx.change_tickets.append({"ticket": f"CHG-{rng.randint(10000, 99999)}", "status": "Approved",
                                   "requested_by": rng.choice([u.username for u in users if u.department == "IT"]),
                                   "approved_by": "IT Manager", "window_start": ws.isoformat(),
                                   "window_end": (ws + timedelta(hours=2)).isoformat(),
                                   "description": rng.choice(["Monthly patching - workstations ring 1",
                                                              "Firewall rule cleanup", "Replace UPS battery",
                                                              "Renew TLS certificate on MAIL-GW",
                                                              "PLM01 application update"])})

    keys = _choose(rng, cfg["issues"], focus)
    issues: list[Issue] = [SCENARIOS[k][1](ctx) for k in keys]
    decoys: list[Decoy] = [DECOYS[k](ctx) for k in rng.sample(sorted(DECOYS), k=cfg["decoys"])]

    baseline.generate_baseline(ctx, noise=cfg["noise"])
    scan_events = baseline.generate_scanner_activity(ctx)
    decoys.append(Decoy("authorized_vuln_scan", scan_events,
                        "Port-scan pattern, but the source is VULNSCAN01 (svc-scan), the only authorized "
                        "scanner, during its scheduled Sunday 02:00 window."))

    # ---- post-processing so the data stays internally consistent ----------
    evidence_events = {id(e) for x in issues + decoys for e in x.evidence if isinstance(e, Event)}
    no_audit = ctx.state.get("audit_disabled_hosts", set())
    no_edr = ctx.state.get("no_edr_hosts", set())
    ctx.events = [e for e in ctx.events if id(e) in evidence_events or not (
        (e.log == "windows" and e.data.get("Computer") in no_audit) or
        (e.log == "endpoint" and e.data.get("host") in no_edr))]
    for uname in ctx.state.get("collect_vpn_no_mfa", set()):
        issue = next(i for i in issues if i.key == "no_mfa_remote")
        have = {id(e) for e in issue.evidence if isinstance(e, Event)}
        issue.evidence += [e for e in ctx.events if e.log == "vpn" and e.data.get("user") == uname
                           and e.data.get("mfa") == "none" and id(e) not in have]

    # roster last_login reflects actual activity in the window
    last_seen: dict[str, datetime] = {}
    for e in ctx.events:
        who = e.data.get("TargetUserName") if e.data.get("EventID") == 4624 else (
            e.data.get("user") if e.log == "vpn" and e.data.get("action") == "connect" else None)
        if who and (who not in last_seen or e.ts > last_seen[who]):
            last_seen[who] = e.ts
    for u in ctx.users:
        if u.username in last_seen:
            u.last_login = last_seen[u.username].date().isoformat()

    # ---- assign stable IDs ---------------------------------------------------
    ctx.events.sort(key=lambda e: (e.ts, e.log))
    counters = {k: 0 for k in LOG_PREFIX}
    for e in ctx.events:
        counters[e.log] += 1
        e.eid = f"{LOG_PREFIX[e.log]}-{counters[e.log]:06d}"
    cfg_keys = list(ctx.config)
    rng.shuffle(cfg_keys)
    cfg_ids = {k: f"CFG-{i + 1:03d}" for i, k in enumerate(cfg_keys)}
    for x in issues + decoys:
        x.evidence = [cfg_ids[e[4:]] if isinstance(e, str) and e.startswith("cfg:") else e for e in x.evidence]

    meta = dict(seed=seed, difficulty=difficulty, focus=focus, days=days,
                window_start=start.date().isoformat(),
                window_end=(start + timedelta(days=days - 1)).date().isoformat(),
                cfg_ids=cfg_ids, cfg_order=cfg_keys, show=cfg)
    return ctx, issues, decoys, meta


# ---------------------------------------------------------------------------
def _write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _kv(v) -> str:
    s = str(v)
    return f'"{s}"' if " " in s else s


def write_case(ctx: Context, issues: list[Issue], decoys: list[Decoy], meta: dict, out_dir: Path) -> Path:
    case_id = f"CASE-{meta['seed']}"
    root = out_dir / case_id
    (root / "logs").mkdir(parents=True, exist_ok=True)
    (root / "evidence").mkdir(parents=True, exist_ok=True)

    # logs
    handles = {log: (root / "logs" / fn).open("w", encoding="utf-8") for log, fn in LOG_FILES.items()}
    try:
        for e in ctx.events:
            ts = e.ts.isoformat(timespec="seconds")
            if e.log == "firewall":
                fields = " ".join(f"{k}={_kv(v)}" for k, v in e.data.items())
                handles["firewall"].write(f"{ts} id={e.eid} {fields}\n")
            else:
                handles[e.log].write(json.dumps({"event_id": e.eid, "timestamp": ts, **e.data}) + "\n")
    finally:
        for h in handles.values():
            h.close()

    # evidence / GRC artifacts
    roster = []
    for u in ctx.users:
        d = asdict(u)
        d["employment_status"] = d.pop("status")
        d["account_status"] = "enabled" if d.pop("account_enabled") else "disabled"
        roster.append(d)
    _write_csv(root / "evidence" / "user_roster.csv", roster,
               ["user_id", "username", "full_name", "department", "title", "account_type", "owner",
                "privileged", "mfa_enrolled", "employment_status", "account_status", "hire_date",
                "term_date", "last_login", "workstation", "notes"])
    _write_csv(root / "evidence" / "asset_inventory.csv", [asdict(a) for a in ctx.assets],
               ["asset_id", "hostname", "ip", "os", "role", "stores_cui", "last_patched",
                "edr_installed", "audit_logging", "owner"])
    cfg_rows = [{"setting_id": meta["cfg_ids"][k], **ctx.config[k]} for k in meta["cfg_order"]]
    cfg_rows.sort(key=lambda r: r["setting_id"])
    _write_csv(root / "evidence" / "config_snapshot.csv", cfg_rows, ["setting_id", "system", "setting", "value"])
    _write_csv(root / "evidence" / "change_tickets.csv", sorted(ctx.change_tickets, key=lambda r: r["window_start"]),
               ["ticket", "status", "requested_by", "approved_by", "window_start", "window_end", "description"])
    _write_csv(root / "evidence" / "usb_allowlist.csv", ctx.usb_allowlist,
               ["serial", "model", "assigned_to", "encrypted"])
    _write_csv(root / "evidence" / "travel_exceptions.csv", ctx.travel_exceptions,
               ["username", "destination", "start", "end", "approved_by", "conditions"])

    from .briefing import render_briefing
    (root / "BRIEFING.md").write_text(render_briefing(case_id, meta, issues), encoding="utf-8")
    (root / "findings.csv").write_text(
        "evidence_id,control,notes\n"
        "# One finding per row. evidence_id = any event/roster/asset/config ID that proves it.\n"
        "# control = NIST 800-171 / CMMC ID, e.g. 3.1.8 or AC.L2-3.1.8. Lines starting with # are ignored.\n",
        encoding="utf-8")

    key = {
        "case_id": case_id, "meta": {k: v for k, v in meta.items() if k not in ("cfg_ids", "cfg_order", "show")},
        "issues": [{"key": i.key, "title": i.title, "category": i.category, "severity": i.severity,
                    "controls": i.controls, "cmmc": [cmmc_id(c) for c in i.controls],
                    "evidence": i.evidence_ids(), "explanation": i.explanation,
                    "remediation": i.remediation, "hint": i.hint} for i in issues],
        "decoys": [{"key": d.key, "evidence": d.evidence_ids(), "reason": d.reason} for d in decoys],
    }
    (root / ".answer_key").write_text(_encode_key(key), encoding="utf-8")
    (root / "case.json").write_text(json.dumps(
        {"case_id": case_id, "seed": meta["seed"], "difficulty": meta["difficulty"], "focus": meta["focus"],
         "window_start": meta["window_start"], "window_end": meta["window_end"],
         "event_counts": {LOG_FILES[k]: sum(1 for e in ctx.events if e.log == k) for k in LOG_FILES},
         "generated_at": datetime.now().isoformat(timespec="seconds")}, indent=2), encoding="utf-8")
    return root


def generate(seed: int | None = None, difficulty: str = "medium", focus: str = "mixed",
             days: int = 7, out_dir: str | Path = "cases") -> Path:
    if seed is None:
        seed = random.SystemRandom().randint(1000, 999999)
    ctx, issues, decoys, meta = build_case(seed, difficulty, focus, days)
    return write_case(ctx, issues, decoys, meta, Path(out_dir))


def load_key(case_dir: str | Path) -> dict:
    return decode_key((Path(case_dir) / ".answer_key").read_text(encoding="utf-8"))

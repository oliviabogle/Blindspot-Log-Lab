"""Scores an analyst's findings.csv against the case answer key."""

from __future__ import annotations

import csv
from pathlib import Path

from .controls import cmmc_id, describe, normalize
from .generator import load_key

POINTS_DETECT = 10      # found the issue (cited valid evidence)
POINTS_MAP = 5          # mapped it to an accepted control
PENALTY_FP = 3          # flagged something that isn't an issue


def read_findings(path: Path) -> list[dict]:
    rows = []
    with path.open(newline="", encoding="utf-8-sig") as f:
        lines = [ln for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    for r in csv.DictReader(lines):
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
        ids = [x.strip().upper() for x in r.get("evidence_id", "").replace(",", ";").split(";") if x.strip()]
        if ids:
            rows.append({"ids": ids, "controls": normalize(r.get("control", "")), "notes": r.get("notes", "")})
    return rows


def grade(case_dir: str | Path, findings_path: str | Path | None = None) -> dict:
    case_dir = Path(case_dir)
    key = load_key(case_dir)
    findings_path = Path(findings_path) if findings_path else case_dir / "findings.csv"
    rows = read_findings(findings_path)

    evidence_to_issue = {}
    for idx, issue in enumerate(key["issues"]):
        for eid in issue["evidence"]:
            evidence_to_issue.setdefault(eid, idx)
    evidence_to_decoy = {eid: d for d in key["decoys"] for eid in d["evidence"]}

    results = [{"issue": i, "found": False, "mapped": False, "submitted_controls": set()} for i in key["issues"]]
    false_pos = []
    for r in rows:
        hit = {evidence_to_issue[e] for e in r["ids"] if e in evidence_to_issue}
        if not hit:
            decoy = next((evidence_to_decoy[e] for e in r["ids"] if e in evidence_to_decoy), None)
            false_pos.append({"row": r, "decoy": decoy})
            continue
        for idx in hit:
            res = results[idx]
            res["found"] = True
            res["submitted_controls"].update(r["controls"])
            if set(r["controls"]) & set(res["issue"]["controls"]):
                res["mapped"] = True

    max_pts = len(results) * (POINTS_DETECT + POINTS_MAP)
    earned = sum(POINTS_DETECT * r["found"] + POINTS_MAP * r["mapped"] for r in results)
    earned -= PENALTY_FP * len(false_pos)
    pct = max(0.0, earned / max_pts * 100) if max_pts else 0.0
    return {"key": key, "results": results, "false_positives": false_pos, "earned": earned,
            "max": max_pts, "percent": pct, "rows": len(rows)}


def _rank(pct: float) -> str:
    for cutoff, name in [(95, "Lead Assessor"), (80, "Senior Threat Analyst"), (65, "GRC Analyst"),
                         (45, "Junior Analyst"), (0, "Analyst in Training")]:
        if pct >= cutoff:
            return name
    return ""


def render_report(g: dict, reveal: bool = True) -> str:
    key = g["key"]
    found = sum(r["found"] for r in g["results"])
    mapped = sum(r["mapped"] for r in g["results"])
    out = [f"# Grade report - {key['case_id']}", "",
           f"**Score:** {g['percent']:.0f}%  ({g['earned']} / {g['max']} pts)  -  **Rank:** {_rank(g['percent'])}",
           f"**Detected:** {found}/{len(g['results'])}   **Correctly mapped:** {mapped}/{len(g['results'])}   "
           f"**False positives:** {len(g['false_positives'])}", "",
           f"Scoring: +{POINTS_DETECT} per issue detected, +{POINTS_MAP} for a correct 800-171/CMMC mapping, "
           f"-{PENALTY_FP} per false-positive row.", ""]

    for r in g["results"]:
        i = r["issue"]
        mark = "FOUND" if r["found"] else "MISSED"
        if r["found"]:
            mark += " + mapped" if r["mapped"] else " - wrong/missing control"
        out.append(f"## [{mark}] {i['title'] if (r['found'] or reveal) else '(hidden - keep hunting)'}")
        if not (r["found"] or reveal):
            out += [f"- Category: {i['category']} | Hint: {i['hint']}", ""]
            continue
        out += [f"- **Category / severity:** {i['category']} / {i['severity']}",
                f"- **Accepted controls:** " + "; ".join(describe(c) for c in i["controls"])]
        if r["found"] and not r["mapped"]:
            got = ", ".join(cmmc_id(c) for c in sorted(r["submitted_controls"])) or "none"
            out.append(f"- **You mapped:** {got}")
        ev = i["evidence"]
        out += [f"- **Evidence:** {', '.join(ev[:8])}{' ...(+%d more)' % (len(ev) - 8) if len(ev) > 8 else ''}",
                f"- **What happened:** {i['explanation']}",
                f"- **Remediation / POA&M:** {i['remediation']}", ""]

    if g["false_positives"]:
        out += ["## False positives", ""]
        for fp in g["false_positives"]:
            ids = ", ".join(fp["row"]["ids"])
            if fp["decoy"]:
                out.append(f"- `{ids}` - **decoy**: {fp['decoy']['reason']}")
            else:
                out.append(f"- `{ids}` - normal baseline activity (or an ID that doesn't exist).")
        out.append("")
    return "\n".join(out)

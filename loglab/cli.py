"""Command-line interface:  python -m loglab <command> ..."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .controls import CONTROLS, FAMILIES, describe, family_of
from .generator import DIFFICULTY, generate, load_key
from .grader import grade, render_report
from .scenarios import DECOYS, SCENARIOS

DEFAULT_OUT = Path("cases")


def _case_dir(arg: str, out: Path) -> Path:
    p = Path(arg)
    if p.is_dir():
        return p
    for cand in (out / arg, out / f"CASE-{arg}"):
        if cand.is_dir():
            return cand
    sys.exit(f"Case not found: {arg}  (try `python -m loglab list`)")


def cmd_generate(a) -> None:
    root = generate(seed=a.seed, difficulty=a.difficulty, focus=a.focus, days=a.days, out_dir=a.out)
    meta = json.loads((root / "case.json").read_text())
    total = sum(meta["event_counts"].values())
    print(f"\nNew case generated: {root}")
    print(f"  difficulty={meta['difficulty']}  focus={meta['focus']}  seed={meta['seed']}")
    print(f"  window {meta['window_start']} -> {meta['window_end']}  |  {total:,} log events")
    for fn, n in meta["event_counts"].items():
        print(f"    logs/{fn:<26} {n:>6,}")
    print(f"\nNext: read {root / 'BRIEFING.md'}, hunt, fill in findings.csv, then:")
    print(f"  python -m loglab grade {root.name}\n")


def cmd_list(a) -> None:
    if not a.out.is_dir():
        print("No cases yet. Run: python -m loglab generate")
        return
    for d in sorted(a.out.iterdir()):
        if (d / "case.json").exists():
            m = json.loads((d / "case.json").read_text())
            graded = " (graded)" if (d / "grade_report.md").exists() else ""
            print(f"{d.name:<16} {m['difficulty']:<7} {m['focus']:<11} {m['window_start']}{graded}")


def cmd_brief(a) -> None:
    print((_case_dir(a.case, a.out) / "BRIEFING.md").read_text())


def cmd_grade(a) -> None:
    case = _case_dir(a.case, a.out)
    g = grade(case, a.findings)
    report = render_report(g, reveal=a.reveal)
    (case / "grade_report.md").write_text(report, encoding="utf-8")
    print(report)
    if not a.reveal:
        print("Missed findings are hidden. Keep hunting, or re-run with --reveal to see the full answer key.")
    print(f"\nReport saved to {case / 'grade_report.md'}")


def cmd_hint(a) -> None:
    case = _case_dir(a.case, a.out)
    key = load_key(case)
    issues = key["issues"]
    if a.number is None:
        print(f"{len(issues)} hints available. Use `hint {case.name} N` (1-{len(issues)}).")
        for n, i in enumerate(issues, 1):
            print(f"  {n}. [{i['category']}]")
        return
    i = issues[a.number - 1]
    print(f"Hint {a.number} [{i['category']}]: {i['hint']}")


def cmd_reveal(a) -> None:
    case = _case_dir(a.case, a.out)
    key = load_key(case)
    for i in key["issues"]:
        print(f"\n[{i['category'].upper()} / {i['severity']}] {i['title']}")
        print("  controls: " + ", ".join(i["cmmc"]))
        print("  evidence: " + ", ".join(i["evidence"][:10]) + (" ..." if len(i["evidence"]) > 10 else ""))
        print("  " + i["explanation"])
    print("\nDecoys (legitimate activity):")
    for d in key["decoys"]:
        print(f"  - {d['key']}: {d['reason']}")


def cmd_controls(a) -> None:
    fam = a.family.upper() if a.family else None
    current = None
    for cid in sorted(CONTROLS, key=lambda c: tuple(int(x) for x in c.split("."))):
        f = family_of(cid)
        if fam and f != fam:
            continue
        if f != current:
            print(f"\n{f} - {FAMILIES[f]}")
            current = f
        print("  " + describe(cid))


def cmd_scenarios(a) -> None:
    for cat in ("threat", "compliance"):
        print(f"\n{cat.upper()} scenarios:")
        for k, (c, fn) in SCENARIOS.items():
            if c == cat:
                print(f"  - {k}")
    print("\nDECOYS:")
    for k in DECOYS:
        print(f"  - {k}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="loglab", description="CMMC / NIST SP 800-171 log investigation lab")
    p.add_argument("--version", action="version", version=f"loglab {__version__}")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT, help="cases directory (default: ./cases)")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", aliases=["new"], help="generate a fresh case (random unless --seed)")
    g.add_argument("--seed", type=int, help="reproduce a specific case")
    g.add_argument("--difficulty", choices=list(DIFFICULTY), default="medium")
    g.add_argument("--focus", choices=["mixed", "threat", "compliance"], default="mixed")
    g.add_argument("--days", type=int, default=7, choices=range(7, 15), metavar="7-14")
    g.set_defaults(func=cmd_generate)

    sub.add_parser("list", help="list generated cases").set_defaults(func=cmd_list)

    b = sub.add_parser("brief", help="print a case briefing")
    b.add_argument("case")
    b.set_defaults(func=cmd_brief)

    gr = sub.add_parser("grade", help="grade findings.csv for a case")
    gr.add_argument("case")
    gr.add_argument("--findings", help="path to findings CSV (default: <case>/findings.csv)")
    gr.add_argument("--reveal", action="store_true", help="show details for missed findings")
    gr.set_defaults(func=cmd_grade)

    h = sub.add_parser("hint", help="get a hint for a finding")
    h.add_argument("case")
    h.add_argument("number", nargs="?", type=int)
    h.set_defaults(func=cmd_hint)

    r = sub.add_parser("reveal", help="show the full answer key (spoilers!)")
    r.add_argument("case")
    r.set_defaults(func=cmd_reveal)

    c = sub.add_parser("controls", help="list NIST 800-171 / CMMC L2 controls used in the lab")
    c.add_argument("--family", help="filter by family, e.g. AC, IA, AU")
    c.set_defaults(func=cmd_controls)

    sub.add_parser("scenarios", help="list available scenarios").set_defaults(func=cmd_scenarios)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)

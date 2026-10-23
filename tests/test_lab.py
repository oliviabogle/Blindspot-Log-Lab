import csv
import json
from pathlib import Path

import pytest

from loglab.controls import CONTROLS, cmmc_id, normalize
from loglab.generator import build_case, generate, load_key
from loglab.grader import grade
from loglab.scenarios import DECOYS, SCENARIOS


def _all_ids(case: Path) -> set[str]:
    ids = set()
    for f in (case / "logs").glob("*.jsonl"):
        ids |= {json.loads(line)["event_id"] for line in f.open()}
    for line in (case / "logs" / "firewall.log").open():
        ids.add(line.split()[1].split("=")[1])
    for name, col in [("user_roster.csv", "user_id"), ("asset_inventory.csv", "asset_id"),
                      ("config_snapshot.csv", "setting_id")]:
        ids |= {r[col] for r in csv.DictReader((case / "evidence" / name).open())}
    return ids


def _write_findings(path: Path, rows: list[tuple[str, str]]) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["evidence_id", "control", "notes"])
        w.writerows([(e, c, "") for e, c in rows])


@pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
@pytest.mark.parametrize("seed", [1, 77, 2024, 99999])
def test_every_answer_is_backed_by_real_evidence(tmp_path, seed, difficulty):
    case = generate(seed=seed, difficulty=difficulty, out_dir=tmp_path)
    ids = _all_ids(case)
    key = load_key(case)
    assert key["issues"], "case should contain issues"
    for issue in key["issues"]:
        assert issue["evidence"], issue["key"]
        missing = [e for e in issue["evidence"] if e not in ids]
        assert not missing, f"{issue['key']} cites nonexistent evidence {missing}"
        for c in issue["controls"]:
            assert c in CONTROLS, f"{issue['key']} maps to uncatalogued control {c}"


def test_same_seed_is_reproducible():
    _, i1, d1, m1 = build_case(555, "medium")
    _, i2, d2, m2 = build_case(555, "medium")
    assert [i.key for i in i1] == [i.key for i in i2]
    assert [i.evidence_ids() for i in i1] == [i.evidence_ids() for i in i2]
    assert m1["window_start"] == m2["window_start"]


def test_different_seeds_differ():
    keys = {tuple(sorted(i.key for i in build_case(s, "hard")[1])) for s in range(10)}
    assert len(keys) > 3


def test_perfect_submission_scores_100(tmp_path):
    case = generate(seed=31337, difficulty="hard", out_dir=tmp_path)
    key = load_key(case)
    _write_findings(case / "findings.csv", [(i["evidence"][0], i["controls"][0]) for i in key["issues"]])
    g = grade(case)
    assert g["percent"] == 100
    assert not g["false_positives"]


def test_decoys_and_wrong_controls_cost_points(tmp_path):
    case = generate(seed=8080, difficulty="hard", out_dir=tmp_path)
    key = load_key(case)
    first = key["issues"][0]
    rows = [(first["evidence"][0], "3.2.1" if "3.2.1" not in first["controls"] else "3.4.1")]
    rows += [(d["evidence"][0], "3.14.7") for d in key["decoys"]]
    _write_findings(case / "findings.csv", rows)
    g = grade(case)
    assert g["results"][0]["found"] and not g["results"][0]["mapped"]
    assert len(g["false_positives"]) == len(key["decoys"])
    assert all(fp["decoy"] for fp in g["false_positives"])


def test_control_normalization():
    assert normalize("AC.L2-3.1.8") == ["3.1.8"]
    assert normalize("3.5.3; ia.l2-3.5.7") == ["3.5.3", "3.5.7"]
    assert cmmc_id("3.14.2") == "SI.L2-3.14.2"
    assert cmmc_id("3.9.2") == "PS.L2-3.9.2"


def test_focus_modes():
    for focus, cat in [("threat", "threat"), ("compliance", "compliance")]:
        _, issues, _, _ = build_case(42, "medium", focus)
        assert all(i.category == cat for i in issues)


def test_registry_has_both_categories():
    cats = {c for c, _ in SCENARIOS.values()}
    assert cats == {"threat", "compliance"}
    assert len(DECOYS) >= 4

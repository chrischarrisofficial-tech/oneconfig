"""DISA STIG Viewer 3 checklists (.cklb): every catalog rule has DISA's text, statuses and findings carry over, and
STIG Manager's own parser reads the file (when fetched: tests/build_stigmanager.sh)."""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from oneconfig.cklb import _text, checklist
from oneconfig.render import context, render
from oneconfig.stig import BENCH, stig_audit
from platforms import example

SM = Path(os.environ.get("ONECONFIG_STIGMANAGER", Path.home() / ".cache" / "oneconfig-stigmanager"))
NOW = datetime(2026, 10, 22, tzinfo=timezone.utc)


def _result(platform):
    n = example(platform)
    d = next(x for x in n.devices if x.platform == platform)
    return d, stig_audit(render(d, n), d.role, context(d, n), platform)


def test_rule_text_matches_the_catalog():
    t = _text()
    for bid, b in BENCH.items():
        assert sorted(t[bid]["rules"]) == sorted(r[2] for r in b["rules"]), bid
        assert t[bid]["release_info"].startswith(f"Release: {b['release']} Benchmark Date: ")
    assert t["Switch_NDM"]["benchmark_id"] == "Cisco_IOS_XE_Switch_NDM_STIG" and t["EOS_NDM"]["benchmark_id"] == "Arista_MLS_EOS_4-2x_NDM_STIG"


@pytest.mark.parametrize("platform", ["ios-xe", "fortios"])
def test_checklist_carries_status_findings_and_disa_text(platform):
    d, r = _result(platform)
    c = checklist(r, d.hostname, "10.99.0.5", "the generated configuration", now=NOW)
    rules = [x for s in c["stigs"] for x in s["rules"]]
    assert [x["status"] for x in rules] == [x["status"] for x in r["results"]]
    assert all(x["check_content"] and x["fix_text"] and x["ccis"] and x["rule_id_src"].endswith("_rule") for x in rules)
    assert [s["stig_id"] for s in c["stigs"]] == [_text()[b["id"]]["benchmark_id"] for b in r["benchmarks"]]
    opened = [x for x in rules if x["status"] == "open"]
    assert all("\n\nFix:\n" in x["finding_details"] for x in opened) and (opened or platform == "ios-xe")
    assert c == checklist(r, d.hostname, "10.99.0.5", "the generated configuration", now=NOW)  # stable IDs: re-exports update, not duplicate
    assert c["target_data"]["host_name"] == d.hostname and "generated configuration" in rules[0]["comments"]


@pytest.mark.skipif(not (shutil.which("node") and (SM / "ReviewParser.js").exists()), reason="needs Node.js and tests/build_stigmanager.sh")
def test_stig_manager_reads_the_checklist(tmp_path):
    d, r = _result("fortios")
    f = tmp_path / "fw.cklb"
    f.write_text(json.dumps(checklist(r, d.hostname, "10.99.0.5", now=NOW)))
    js = tmp_path / "read.mjs"
    js.write_text(f"""import {{ reviewsFromCklb }} from {json.dumps(str(SM / 'ReviewParser.js'))}
import {{ readFileSync }} from 'fs'
const o = {{autoStatus: {{fail: 'submitted', notapplicable: 'submitted', pass: 'submitted'}}, unreviewed: 'always',
  unreviewedCommented: 'informational', emptyDetail: 'import', emptyComment: 'import', allowCustom: true}}
const fs = {{detail: {{enabled: 'always', required: 'always'}}, comment: {{enabled: 'findings', required: 'optional'}}}}
const r = reviewsFromCklb({{data: readFileSync(process.argv[2], 'utf8'), fieldSettings: fs, allowAccept: true, importOptions: o, sourceRef: 'x'}})
console.log(JSON.stringify({{target: r.target, checklists: r.checklists.map(c => [c.benchmarkId, c.revisionStr, c.stats])}}))""")
    out = json.loads(subprocess.run(["node", str(js), str(f)], capture_output=True, text=True, check=True).stdout)
    assert out["target"]["name"] == d.hostname and out["target"]["ip"] == "10.99.0.5" and out["target"]["noncomputing"]
    assert [c[:2] for c in out["checklists"]] == [["FN_FortiGate_Firewall_NDM_STIG", "V1R6"], ["FN_FortiGate_Firewall_STIG", "V1R5"]]
    count = lambda k: sum(c[2][k] for c in out["checklists"])  # noqa: E731
    st = [x["status"] for x in r["results"]]
    assert (count("pass"), count("fail"), count("notapplicable"), count("informational")) == \
        (st.count("not_a_finding"), st.count("open"), st.count("not_applicable"), st.count("not_reviewed"))


def test_cli_writes_a_checklist(tmp_path):
    d, _ = _result("fortios")
    n = example("fortios")
    cfg = tmp_path / "fw1.conf"
    cfg.write_text(render(d, n))
    out = tmp_path / "fw1.cklb"
    p = subprocess.run([sys.executable, "-m", "oneconfig", "stig", str(cfg), "--os", "fortios", "--platform", "firewall", "--cklb", str(out)],
                       capture_output=True, text=True)
    c = json.loads(out.read_text())
    assert p.returncode == 1 and c["target_data"]["host_name"] == "fw1" and len(c["stigs"]) == 2  # exit 1: open findings

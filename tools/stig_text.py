"""Build oneconfig/stig/rules.json.gz from DISA's XCCDF files: per benchmark its XCCDF id and release info, and per
rule the text a STIG Viewer checklist carries (discussion, check, fix, CCIs, legacy IDs). The catalog's rule list must
match exactly, so the text always belongs to the release OneConfig checks against.

    python3 tools/stig_text.py <folder with the *-xccdf.xml files>...
"""
import gzip
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}
OUT = Path(__file__).parents[1] / "oneconfig" / "stig" / "rules.json.gz"
# Fields DISA keeps inside each rule's <description> as escaped pseudo-XML
DESC = {"VulnDiscussion": "discussion", "FalsePositives": "false_positives", "FalseNegatives": "false_negatives",
        "Documentable": "documentable", "Mitigations": "mitigations", "SeverityOverrideGuidance": "security_override_guidance",
        "PotentialImpacts": "potential_impacts", "ThirdPartyTools": "third_party_tools", "MitigationControl": "mitigation_control",
        "Responsibility": "responsibility", "IAControls": "ia_controls"}


def parse(path: Path) -> dict:
    root = ET.parse(path).getroot()
    rules = {}
    for g in root.findall("x:Group", NS):
        r = g.find("x:Rule", NS)
        desc = r.findtext("x:description", namespaces=NS) or ""
        ref = r.find("x:check/x:check-content-ref", NS)
        rule = {"group_title": g.findtext("x:title", namespaces=NS) or "", "weight": r.get("weight") or "10.0",
                "check": r.findtext("x:check/x:check-content", namespaces=NS) or "", "fix": r.findtext("x:fixtext", namespaces=NS) or "",
                "ccis": [i.text for i in r.findall("x:ident", NS) if i.get("system", "").endswith("/cci")],
                "legacy": [i.text for i in r.findall("x:ident", NS) if i.get("system", "").endswith("/legacy")],
                "check_ref": {"href": ref.get("href"), "name": ref.get("name")} if ref is not None else {}}
        for tag, key in DESC.items():
            m = re.search(rf"<{tag}>(.*?)</{tag}>", desc, re.S)
            if m and m[1].strip():
                rule[key] = m[1]
        rules[r.get("id")] = rule
    return {"benchmark_id": root.get("id"), "title": root.findtext("x:title", namespaces=NS),
            "release_info": root.findtext("x:plain-text[@id='release-info']", namespaces=NS), "rules": rules}


if __name__ == "__main__":
    sys.path.insert(0, str(OUT.parents[2]))
    from oneconfig.stig import BENCH
    found = {p.name: p for d in sys.argv[1:] for p in Path(d).rglob("*-xccdf.xml")}
    out = {}
    for bid, b in BENCH.items():
        data = parse(found[b["file"]])
        want = [r[2] for r in b["rules"]]
        assert sorted(data["rules"]) == sorted(want), f"{bid}: {b['file']} has different rules than the catalog"
        assert f"Release: {b['release']} " in data["release_info"], (bid, data["release_info"])
        out[bid] = data
        print(f"{bid:16} {data['benchmark_id']:45} {data['release_info']}  {len(want)} rules")
    OUT.write_bytes(gzip.compress(json.dumps(out, sort_keys=True, separators=(",", ":")).encode(), mtime=0))
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")

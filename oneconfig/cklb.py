"""DISA STIG Viewer 3 checklists (.cklb, JSON) from OneConfig's STIG results. Rule text, CCIs and benchmark IDs come
from DISA's XCCDF files (stig/rules.json.gz, built by tools/stig_text.py). OneConfig's status names are STIG Viewer's,
so they carry over as they are; each result's detail goes in finding_details and its fix, when open, after it."""
import gzip
import json
import uuid
from datetime import datetime, timezone
from functools import cache
from pathlib import Path

from .stig import BENCH

TEXT = Path(__file__).parent / "stig" / "rules.json.gz"
_NS = uuid.UUID("6f1c0b7e-8a43-4f0e-9d1a-0ec0f19a2c01")  # stable UUIDs: the same device and rule always get the same ID


@cache
def _text() -> dict:
    return json.loads(gzip.decompress(TEXT.read_bytes()))


def _id(*parts) -> str:
    return str(uuid.uuid5(_NS, "/".join(map(str, parts))))


def checklist(result: dict, host: str, ip: str = "", source: str = "the running configuration", now: datetime | None = None) -> dict:
    """result is what stig.stig_audit returns; source says what was checked (shown in every rule's comments)."""
    stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    note = f"OneConfig automated check of {source} ({stamp[:10]})."
    stigs = []
    for b in result["benchmarks"]:
        t, sid = _text()[b["id"]], _id(host, b["id"])
        rules = []
        for x in (r for r in result["results"] if r["stig"] == b["id"]):
            rt = t["rules"][x["rule"]]
            rules.append({
                "uuid": _id(host, b["id"], x["rule"]), "stig_uuid": sid, "target_key": None, "stig_ref": None,
                "group_id": x["vuln"], "rule_id": x["rule"].removesuffix("_rule"), "rule_id_src": x["rule"],
                "weight": rt["weight"], "classification": "UNCLASSIFIED", "severity": {"CAT I": "high", "CAT II": "medium", "CAT III": "low"}[x["cat"]],
                "rule_version": x["id"], "group_title": rt["group_title"], "rule_title": x["title"],
                "fix_text": rt["fix"], "check_content": rt["check"], "check_content_ref": rt["check_ref"],
                **{k: rt.get(k, "") for k in ("discussion", "false_positives", "false_negatives", "mitigations", "potential_impacts",
                                              "third_party_tools", "mitigation_control", "responsibility", "security_override_guidance",
                                              "ia_controls")},
                "documentable": rt.get("documentable", "false"), "legacy_ids": rt["legacy"], "ccis": rt["ccis"],
                "group_tree": [{"id": x["vuln"], "title": rt["group_title"], "description": "<GroupDescription></GroupDescription>"}],
                "createdAt": stamp, "updatedAt": stamp, "STIGUuid": sid, "status": x["status"], "overrides": {},
                "comments": note, "finding_details": x["detail"] + (f"\n\nFix:\n{x['fix']}" if x.get("fix") else "")})
        stigs.append({"stig_name": t["title"], "display_name": t["title"].removesuffix(" Security Technical Implementation Guide"),
                      "stig_id": t["benchmark_id"], "version": str(BENCH[b["id"]]["version"]), "release_info": t["release_info"],
                      "uuid": sid, "reference_identifier": "", "size": len(rules), "rules": rules})
    return {"title": f"{host} ({', '.join(s['display_name'] for s in stigs)})", "id": _id(host), "active": False, "mode": 1,
            "has_path": True, "cklb_version": "1.0",
            "target_data": {"target_type": "Non-Computing", "host_name": host, "ip_address": ip, "mac_address": "", "fqdn": "",
                            "comments": "", "role": "None", "is_web_database": False, "technology_area": "", "web_db_site": "",
                            "web_db_instance": ""},
            "stigs": stigs}

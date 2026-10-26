"""Check PAN-OS `set` lines against Palo Alto's own configuration specs (github.com/PaloAltoNetworks/pan-os-codegen,
MIT; fetched by build_panspec.sh). A `set` path is the XML path of the setting, so each spec says which words may
follow which, and what kind of value each leaf takes. Sections the specs don't cover are reported as unknown."""
import os
import re
import shlex
from pathlib import Path

SPECS = Path(os.environ.get("ONECONFIG_PANSPEC", Path.home() / ".cache" / "oneconfig-panspec" / "specs"))
ENTRY = "<entry>"
_LEAF = {"string", "int64", "float64", "bool", "enum"}


def available() -> bool:
    return (SPECS / "network" / "zone.yaml").exists()


def _node():
    return {"kids": {}, "leaf": None, "values": None, "list": False}


def _at(node, words):
    for w in words:
        node = node["kids"].setdefault(w, _node())
    return node


def _params(node, spec):
    for p in (spec or {}).get("params", []) + (spec or {}).get("variants", []):
        xp = p.get("profiles", [{}])[0].get("xpath") or [p["name"]]
        t = p.get("type")
        n = _at(node, [ENTRY if x == "entry" else x for x in xp])
        if t in _LEAF:
            n["leaf"] = t
            vals = [str(v) for val in p.get("validators", []) if isinstance(val, dict) for v in (val.get("spec") or {}).get("values", [])]
            n["values"] = (n["values"] or []) + vals if vals else n["values"]
        elif t == "list":
            items = (p.get("spec") or {}).get("items") or {}
            if items.get("type") == "object" or xp[-1] == "entry":  # a list of entries: <name> <entry-name> <params>
                _params(n if xp[-1] == "entry" else _at(n, [ENTRY]), items.get("spec"))
            else:
                n["leaf"], n["list"] = "string", True
        else:
            _params(n, p.get("spec"))


def _prefix(loc_path):
    """CLI words in front of a spec's own path, for a single-vsys firewall."""
    p = "/".join(loc_path)
    if "template" in p or "panorama" in p or "$rulebase" in p:
        return []
    if p == "config/shared/post-rulebase":
        return [["rulebase"]]  # default security rules: the firewall keeps them in its own rulebase
    p = re.sub(r"^config/devices/\$\w+(/vsys/\$\w+)?/?", "", p)
    words = [x for x in p.split("/") if x and x != "config"]
    return [words, []] if words == ["shared"] else [words]  # a single-vsys firewall also takes shared objects in vsys1


def build(root=SPECS):
    import yaml
    tree = _node()
    for f in sorted(root.rglob("*.yaml")):
        if f.parts[-2] in ("predefined", "panorama", "actions"):
            continue
        d = yaml.safe_load(f.read_text())
        if "panos_xpath" not in d:
            continue
        own = [ENTRY if x.startswith("$") else x for x in d["panos_xpath"]["path"]]
        for loc in d.get("locations", []):
            for pre in _prefix(loc["xpath"]["path"]):
                base = _at(tree, pre + own + ([ENTRY] if d.get("entries") and own[-1:] != [ENTRY] else []))
                _params(base, d.get("spec"))
    return tree


def _value_ok(node, v):
    t = node["leaf"]
    if node["values"] and t == "enum":
        return v in node["values"]
    if t == "bool":
        return v in ("yes", "no")
    if t == "int64":
        return v.isdigit()
    return True


def check(tree, line: str) -> str | None:
    """None if the spec accepts the line, else why not."""
    try:
        words = shlex.split(line)
    except ValueError as e:
        return f"unbalanced quotes ({e})"
    if not words or words[0] != "set":
        return "not a set line"
    node, i, words = tree, 0, words[1:]
    while i < len(words):
        w = words[i]
        if node["leaf"]:
            rest = words[i:]
            if node["list"]:
                return None if rest and (rest[0] != "[" or rest[-1] == "]") else "list value expected"
            return None if len(rest) == 1 and _value_ok(node, rest[0]) else f"bad value {' '.join(rest)!r}"
        if w in node["kids"]:
            node = node["kids"][w]
        elif ENTRY in node["kids"]:
            node = node["kids"][ENTRY]
        else:
            return f"unknown word {w!r} (expected one of: {', '.join(sorted(node['kids'])[:12])})"
        i += 1
    return None if node["leaf"] is None or node["list"] else "value missing"

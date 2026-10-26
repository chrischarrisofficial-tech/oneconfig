"""Check FortiOS CLI against Fortinet's own configuration schema (the `versioned_schema` in each module of
github.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection, fetched by build_fosspec.sh). Each module is one
CLI table (`config system global`); the schema lists its fields, their allowed values and the FortiOS versions that
have them. Modules are read with `ast`, never imported or run. A line is accepted only if the field exists on every
version in VERSIONS."""
import ast
import json
import os
import re
import shlex
import sys
from pathlib import Path

SPEC = Path(os.environ.get("ONECONFIG_FOSSPEC", Path.home() / ".cache" / "oneconfig-fosspec" / "spec.json"))
VERSIONS = ("v7.4.4", "v7.6.0")  # plus the newest 7.6 release the schema knows, added in load()


def available() -> bool:
    return SPEC.exists()


def _v(s):
    return tuple(int(x) for x in s.lstrip("v").split("."))


def extract(modules: Path, out: Path):
    spec = {}
    for f in sorted(modules.glob("fortios_*.py")):
        tree = ast.parse(f.read_text())
        schema = path = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "versioned_schema" for t in node.targets):
                schema = ast.literal_eval(node.value)
            if (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "set" and len(node.args) >= 2
                    and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in node.args[:2])):
                path = node.args[0].value.replace(".", " ") + " " + node.args[1].value
        if schema and path:
            spec[path] = schema
    out.write_text(json.dumps(spec, separators=(",", ":")))


def load():
    spec = json.loads(SPEC.read_text())
    seen = set(re.findall(r'"(v7\.6\.\d+)"', SPEC.read_text()))
    return {"tables": spec, "versions": VERSIONS + (max(seen, key=_v),)}


def _ok(node, versions):
    """Present on every version we target."""
    ranges = node.get("v_range") or [["v6.0.0", ""]]
    return all(any(_v(a) <= _v(v) and (not b or _v(v) <= _v(b)) for a, b in ranges) for v in versions)


def _value(node, vals, versions):
    t, opts = node.get("type"), [o["value"] for o in node.get("options", []) if _ok(o, versions)]
    if not vals:
        return "no value"
    if t == "list" and node.get("children"):  # a list of names: set srcintf "port1" "port2"
        return None
    if opts:
        if not (node.get("multiple_values") or t == "list") and len(vals) > 1:
            return f"one value expected, got {vals}"
        bad = [v for v in vals if v not in opts]
        return f"{bad} not in {opts}" if bad else None
    if t == "integer" and not all(re.fullmatch(r"-?\d+", v) for v in vals):
        return f"{vals} is not a number"
    return None


def check(spec, text: str, allow=()) -> list[str]:
    """Problems in a FortiOS config, one string per bad line (empty when every line is known). `allow` holds top-level
    `config ...` headers (as written) whose whole block a cited source vouches for instead."""
    tables, versions, out = spec["tables"], spec["versions"], []
    stack = []  # (node, kind) where kind is "table" (expects edit), "entry" or "dict"
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = shlex.split(line)
        cmd, args = words[0], words[1:]

        def bad(why):
            out.append(f"line {n}: {line}: {why}")
        if cmd == "config":
            if not stack:
                node = tables.get(" ".join(args))
                if node is None:
                    if line not in allow:
                        bad("no such table")
                    stack.append(({}, "unknown"))
                    continue
            else:
                parent, kind = stack[-1]
                node = (parent.get("children") or {}).get(args[0].replace("-", "_")) if kind in ("entry", "dict") and len(args) == 1 else None
                if kind == "unknown":
                    stack.append(({}, "unknown"))
                    continue
                if node is None or not _ok(node, versions):
                    bad("no such sub-table here")
                    stack.append(({}, "unknown"))
                    continue
            stack.append((node, "table" if node.get("type") == "list" else "dict"))
        elif cmd == "edit":
            if not stack or stack[-1][1] not in ("table", "unknown"):
                bad("edit outside a table")
                continue
            stack.append((stack[-1][0], "entry" if stack[-1][1] == "table" else "unknown"))
        elif cmd == "next":
            if stack and stack[-1][1] in ("entry", "unknown"):
                stack.pop()
            else:
                bad("next outside an entry")
        elif cmd == "end":
            if not stack:
                bad("end without config")
                continue
            if stack[-1][1] in ("entry",):  # FortiOS lets `end` close an open edit as well
                stack.pop()
            stack.pop()
        elif cmd in ("set", "unset", "append", "select", "unselect"):
            if not stack or stack[-1][1] == "unknown":
                continue  # already reported
            node, kind = stack[-1]
            if kind == "table":
                bad(f"{cmd} in a table needs an edit first")
                continue
            field = (node.get("children") or {}).get(args[0].replace("-", "_")) if args else None
            if field is None or not _ok(field, versions):
                bad("no such field" if field is None else f"not on every FortiOS version {versions}")
            elif cmd in ("set", "append", "select") and (why := _value(field, args[1:], versions)):
                bad(why)
        else:
            bad("unknown command")
    if stack:
        out.append("config block not closed with end")
    return out


if __name__ == "__main__" and sys.argv[1:2] == ["--extract"]:
    extract(Path(sys.argv[2]), Path(sys.argv[3]))

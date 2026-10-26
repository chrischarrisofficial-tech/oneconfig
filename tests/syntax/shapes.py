"""Reduce config lines to 'shapes' (keywords kept, values replaced) so generated configs can be checked
against lines a real parser accepts. The reference shapes come from Batfish's NX-OS and Arista EOS parser
test configs (github.com/batfish/batfish, Apache-2.0); see NOTICE in this folder."""
import re

FREE_TEXT = ("description", "remark", "name", "banner", "msg", "location", "contact", "pattern")
_VALUE = re.compile(r"""^(
      <[A-Z0-9][A-Z0-9.-]*>            # OneConfig placeholder
    | ".*"                             # quoted string
    | \d+([:./-]\d+)*[a-zA-Z]?         # numbers, versions, times, ranges, 1/1
    | [\d.]+/\d+                       # prefixes
    | [0-9a-fA-F:.]+                   # MACs, hex, IPv6-ish
    | .*[A-Z0-9_.@$/].*                # any token with capitals, digits, dots, slashes: a name or value
)$""", re.X)


def shape(line: str) -> str:
    words, out = line.strip().split(), []
    for i, w in enumerate(words):
        if out and out[-1] in FREE_TEXT and w not in ("vlan",):
            out.append("V*")  # free text: the rest of the line is one value
            break
        out.append("V" if _VALUE.match(w) else w.lower())
    if len(out) > 1 and out[0] == "V" and out[1] in ("permit", "deny", "remark"):
        out.pop(0)  # ACL sequence numbers are optional
    while len(out) > 1 and out[-1] == "V" and out[-2] == "V":
        out.pop()  # value lists of any length
    return " ".join(out)


def shapes_of(text: str) -> set:
    out = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith(("!", "#", "end")) or s in ("exit",):
            continue
        out.add(shape(s))
    return out

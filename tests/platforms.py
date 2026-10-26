"""The example campus network rewritten for another platform (interface names in that OS's style)."""
import json
import re
from pathlib import Path

from oneconfig.model import Network

EXAMPLE = Path(__file__).parents[1] / "oneconfig" / "examples" / "campus.json"


def rename(name: str, platform: str) -> str:
    m = re.match(r"GigabitEthernet(\d+)/0/(\d+)$", name)
    if platform == "junos":  # Junos counts from 0: router Gi0/0/1 -> ge-0/0/1, switch Gi1/0/1 -> ge-0/0/0
        if m:
            return f"ge-0/0/{m.group(2)}" if m.group(1) == "0" else f"ge-{int(m.group(1)) - 1}/0/{int(m.group(2)) - 1}"
        for ios, jun in (("Port-channel", "ae"), ("Loopback0", "lo0"), ("Vlan", "irb.")):
            if name.startswith(ios):
                return jun + name[len(ios):] if ios != "Loopback0" else jun
        return name
    if m:
        port = int(m.group(2)) + (1 if m.group(1) == "0" else 0)  # router ports start at 0
        return f"Ethernet1/{port}" if platform == "nx-os" else f"Ethernet{port}"
    if name.startswith("Port-channel"):
        return ("port-channel" if platform == "nx-os" else "Port-Channel") + name[len("Port-channel"):]
    if name.startswith("Loopback") and platform == "nx-os":
        return "loopback" + name[len("Loopback"):]
    return name


def example(platform: str) -> Network:
    if platform in ("asa", "panos", "fortios"):  # firewalls have their own example: an edge pair in front of a core switch
        data = json.loads((EXAMPLE.parent / "edge.json").read_text())
        if platform != "asa":  # same design: data ports only (the management port isn't one), shared HA addresses
            fw = data["devices"][0]
            names = {f"GigabitEthernet0/{n}": (f"ethernet1/{n + 1}" if platform == "panos" else f"port{n + 1}") for n in range(8)}
            fw["platform"] = platform
            if platform == "fortios":  # every FortiGate has a predefined DNS service, so a group can't take that name
                for g in fw["service_groups"]:
                    g["name"] = "DNS-ALL" if g["name"] == "DNS" else g["name"]
                for r in fw["rules"]:
                    r["service"] = ["DNS-ALL" if x == "DNS" else x for x in r["service"]]
            fw["interfaces"] = [{k: v for k, v in dict(i, name=names[i["name"]]).items() if k != "standby_ip"}
                                for i in fw["interfaces"] if i["name"] in names]
            fw["zones"] = [z for z in fw["zones"] if z["name"] != "MANAGEMENT"]
            fw["failover"]["interface"] = names[fw["failover"]["interface"]]
            for l in data["links"]:
                l["a_if"] = names.get(l["a_if"], l["a_if"])
        return Network.model_validate(data)
    data = json.loads(EXAMPLE.read_text())
    if platform != "ios-xe":
        for d in data["devices"]:
            d["platform"] = platform
            for i in d["interfaces"]:
                i["name"] = rename(i["name"], platform)
                i.pop("voice_vlan", None)
            for n in (d.get("bgp") or {}).get("neighbors", []):
                if n.get("update_source"):
                    n["update_source"] = rename(n["update_source"], platform)
        for l in data["links"]:
            l["a_if"], l["b_if"] = rename(l["a_if"], platform), rename(l["b_if"], platform)
    return Network.model_validate(data)

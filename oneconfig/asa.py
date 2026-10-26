"""Cisco ASA helpers: zone-based rules as per-interface access lists, NAT, and which interface reaches a server.

ASA filters on the interface a packet arrives on and has no "to zone". A rule from zone A to zone B goes in A's
access list; its destination "any" means "whatever lies behind B". For a zone with known networks (its subnet and
static routes) that is those networks. For an open zone (default route, OSPF or BGP) it is everything else, so open
zone rules come after a deny of every known network. Rules toward different zones never match the same packet, so
this reordering keeps the meaning the user wrote."""
from ipaddress import IPv4Address, IPv4Network, collapse_addresses

MGMT_PORTS = (("udp", "snmp"), ("udp", "snmptrap"), ("udp", "ntp"), ("udp", "syslog"), ("tcp", "ssh"), ("tcp", "tacacs"))


def net(n: IPv4Network) -> str:
    return f"host {n.network_address}" if n.prefixlen == 32 else f"{n.network_address} {n.netmask}"


def zone_ifs(dev):
    """zone -> interface carrying traffic (ASA: one each; management-only interfaces carry none)."""
    return {i.zone: i for i in dev.interfaces if i.zone and not i.name.lower().startswith("management")}


def _via(dev, hop):
    return next((i.zone for i in dev.interfaces if i.zone and i.ip and hop in i.ip.network), None)


def open_zones(dev) -> set:
    zones = {_via(dev, r.next_hop) for r in dev.static_routes if r.prefix.prefixlen == 0}
    zones |= {i.zone for i in dev.interfaces if i.zone and i.ospf_area is not None}
    if dev.bgp:
        zones |= {_via(dev, n.ip) for n in dev.bgp.neighbors}
    return (zones - {None}) & set(zone_ifs(dev))


def zone_nets(dev) -> dict:
    """Known networks behind each closed zone: its subnet plus static routes through it."""
    out = {z: [i.ip.network] for z, i in zone_ifs(dev).items()}
    for r in dev.static_routes:
        z = _via(dev, r.next_hop)
        if r.prefix.prefixlen and z in out:
            out[z].append(r.prefix)
    return {z: list(collapse_addresses(n)) for z, n in out.items() if z not in open_zones(dev)}


def zone_for(dev, ip: IPv4Address) -> str:
    """The nameif to reach a server: connected subnet, then the longest static route, then an open zone."""
    hit = next((i.zone for i in dev.interfaces if i.zone and i.ip and ip in i.ip.network), None)
    routes = sorted((r for r in dev.static_routes if ip in r.prefix), key=lambda r: -r.prefix.prefixlen)
    hit = hit or next((_via(dev, r.next_hop) for r in routes), None)
    inside = [z.name for z in sorted(dev.zones, key=lambda z: -z.security_level)] + ["inside"]  # a new firewall may have no interfaces yet
    return hit or next(iter(sorted(open_zones(dev))), None) or inside[0]


def acl_name(zone: str) -> str:
    return f"{zone.upper()}_IN"  # DISA's naming (OUTSIDE_IN, INSIDE_IN)


def policy(dev) -> tuple[list[str], list[str]]:
    """(object-group lines for multi-object rule fields and zone networks, access-list and access-group lines)."""
    kinds = {a.name: "object" for a in dev.addresses} | {g.name: "object-group" for g in dev.address_groups}
    skinds = {s.name: "object" for s in dev.services} | {g.name: "object-group" for g in dev.service_groups}
    groups, acls = [], []
    taken = set(kinds) | set(skinds)

    def group(name, kind, members):
        if name in taken:
            raise ValueError(f"{dev.hostname}: object {name} clashes with a group OneConfig generates; rename it")
        taken.add(name)
        groups.append(f"object-group {kind} {name}")
        groups.extend(members)
        return f"object-group {name}"

    def addr(names, rule, end):
        if names == ["any"]:
            return "any4"
        if len(names) == 1:
            return f"{kinds[names[0]]} {names[0]}"
        return group(f"{rule}-{end}", "network", [f" {'network-object object' if kinds[n] == 'object' else 'group-object'} {n}" for n in names])

    def svc(names, rule):
        if names == ["any"]:
            return "ip"
        if len(names) == 1:
            return f"{skinds[names[0]]} {names[0]}"
        return group(f"{rule}-SVC", "service", [f" {'service-object object' if skinds[n] == 'object' else 'group-object'} {n}" for n in names])

    known, opened = zone_nets(dev), open_zones(dev)
    nets = {z: group(f"ZONE-{z}-NETS", "network", [f" network-object {net(n)}" for n in ns]) for z, ns in sorted(known.items())}
    external = {i.zone for i in dev.interfaces if i.zone and i.external}
    for z, i in zone_ifs(dev).items():
        name, mine = acl_name(z), [r for r in dev.rules if r.from_zone == z]

        def emit(r, dst):
            acls.append(f"access-list {name} remark {r.name}")
            src = addr(r.source, r.name, "SRC")
            acls.append(f"access-list {name} extended {'permit' if r.action == 'allow' else 'deny'} {svc(r.service, r.name)} {src} {dst}"
                        + (" log" if r.log else ""))
        for r in mine:
            if r.to_zone not in opened:
                emit(r, nets[r.to_zone] if r.destination == ["any"] and r.to_zone in nets else addr(r.destination, r.name, "DST"))
        if any(r.to_zone in opened for r in mine):
            acls += [f"access-list {name} extended deny ip any4 {g} log" for k, g in nets.items() if k != z]
            if z not in external and external & opened:  # STIG CASA-FW-000250: no management traffic out of the enclave
                acls += [f"access-list {name} extended deny {p} any4 any4 eq {port} log" for p, port in MGMT_PORTS]
            for r in mine:
                if r.to_zone in opened:
                    emit(r, addr(r.destination, r.name, "DST"))
        acls += [f"access-list {name} extended deny ip any any log", f"access-group {name} in interface {z}"]
    return groups, acls


def nat(dev) -> list[str]:
    """Twice NAT: static entries first (section 1), dynamic PAT after the automatic rules (section 3)."""
    out = []
    for n in sorted(dev.nat, key=lambda n: n.kind != "static"):
        pair = f"nat ({n.from_zone},{n.to_zone})"
        if n.kind == "static":
            out.append(f"{pair} source static {n.source} {n.translated}" + (f" service {n.service} {n.service}" if n.service else ""))
        else:
            out.append(f"{pair} after-auto source dynamic {n.source} {n.translated}")
    return out

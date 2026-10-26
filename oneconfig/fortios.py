"""FortiOS helpers: OneConfig's zone rules and NAT in FortiOS terms.

OneConfig turns on central NAT, which matches its own model: NAT rules are separate from security policies, and
policies match real (untranslated) addresses. Source NAT becomes central SNAT entries; publishing a server
becomes a virtual IP (destination NAT) plus, for one-to-one NAT, a one-to-one IP pool for its outbound traffic."""
from ipaddress import IPv4Network


def _ifs(dev, zone):
    return [i.name for i in dev.interfaces if i.zone == zone]


def _range(net: IPv4Network) -> str:
    return str(net.network_address) if net.prefixlen == 32 else f"{net.network_address}-{net.broadcast_address}"


def nat(dev):
    """(vips, pools, snat): dicts for `firewall vip`, `firewall ippool` and `firewall central-snat-map`."""
    addr = {a.name: a.value for a in dev.addresses}
    svc = {s.name: s for s in dev.services}
    vips, pools, snat = [], [], []
    for n in sorted(dev.nat, key=lambda n: n.kind != "static"):  # first match wins: one-to-one entries before PAT
        out_ifs = _ifs(dev, n.to_zone)
        out_ip = next(i.ip.ip for i in dev.interfaces if i.zone == n.to_zone)
        pub = addr[n.translated] if n.translated != "interface" else IPv4Network(f"{out_ip}/32")
        entry = {"srcintf": n.from_zone, "dstintf": n.to_zone, "orig": n.source, "comment": n.name}
        if n.kind == "dynamic":
            if n.translated != "interface":
                pools.append({"name": n.name, "type": "overload", "start": pub.network_address, "end": pub.broadcast_address})
            snat.append({**entry, "pool": n.name if n.translated != "interface" else None})
            continue
        if n.source not in addr:
            raise ValueError(f"{dev.hostname} NAT {n.name}: FortiOS publishes an address, not a group; use an address as the source")
        real = addr[n.source]
        if real.num_addresses != pub.num_addresses:
            raise ValueError(f"{dev.hostname} NAT {n.name}: {n.source} and {n.translated} must be the same size for one-to-one NAT")
        vip = {"name": n.name, "extip": _range(pub), "mappedip": _range(real), "extintf": out_ifs[0] if len(out_ifs) == 1 else "any"}
        if n.service:  # port forward: inbound only, on the service's ports
            s = svc[n.service]
            vips.append({**vip, "protocol": s.protocol, "port": s.ports})
        else:  # one-to-one both ways: the VIP for inbound, a one-to-one pool for the server's own outbound traffic
            vips.append(vip)
            pools.append({"name": n.name, "type": "one-to-one", "start": pub.network_address, "end": pub.broadcast_address})
            snat.append({**entry, "pool": n.name})
    return vips, pools, snat


def policies(dev):
    """Security policies in FortiOS form, in OneConfig's order (FortiOS matches top to bottom)."""
    return [{"id": k, "name": r.name, "srcintf": r.from_zone, "dstintf": r.to_zone,
             "srcaddr": ["all" if a == "any" else a for a in r.source], "dstaddr": ["all" if a == "any" else a for a in r.destination],
             "service": ["ALL" if s == "any" else s for s in r.service], "action": "accept" if r.action == "allow" else "deny",
             "log": r.log} for k, r in enumerate(dev.rules, 1)]

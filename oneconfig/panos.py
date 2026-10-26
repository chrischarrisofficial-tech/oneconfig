"""PAN-OS helpers: OneConfig's zone rules and NAT in PAN-OS terms.

PAN-OS services are TCP/UDP ports only; ICMP is an application. So a rule's ICMP services become a second rule
(<name>-ICMP) that matches the ICMP applications. PAN-OS security rules also match the destination address before
NAT, so a rule toward a server published by static NAT uses its public address."""


def leaf_services(dev, names, seen=None):
    """Service objects behind names (groups expanded)."""
    svc = {s.name: s for s in dev.services}
    grp = {g.name: g.members for g in dev.service_groups}
    out = []
    for n in names:
        out += [svc[n]] if n in svc else leaf_services(dev, grp.get(n, []))
    return out


def has_icmp(dev, name):
    return any(s.protocol == "icmp" for s in leaf_services(dev, [name]))


def l4(dev, name):
    return any(s.protocol != "icmp" for s in leaf_services(dev, [name]))


def service_groups(dev):
    """Service groups as PAN-OS sees them: TCP/UDP members only; groups left empty are dropped."""
    svc = {s.name for s in dev.services if s.protocol != "icmp"}
    out, kept = [], set()
    for g in dev.service_groups:
        members = [m for m in g.members if m in svc or m in kept]
        if members:
            out.append((g.name, members))
            kept.add(g.name)
    return out


def _published(dev):
    """(outside zone, inside zone, real address name) -> public destination, from static NAT."""
    out = {}
    for n in dev.nat:
        if n.kind == "static":
            pub = n.translated if n.translated != "interface" else str(_iface(dev, n.to_zone).ip.ip)
            out[(n.to_zone, n.from_zone, n.source)] = pub
    return out


def _iface(dev, zone):
    return next(i for i in dev.interfaces if i.zone == zone)


def rules(dev):
    """Security rules in PAN-OS form: dicts with name, from, to, source, destination, service, application, action, log."""
    pub = _published(dev)
    out = []
    for r in dev.rules:
        dst = [pub.get((r.from_zone, r.to_zone, d), d) for d in r.destination]
        base = {"from": r.from_zone, "to": r.to_zone, "source": r.source, "destination": dst,
                "action": "allow" if r.action == "allow" else "deny", "log": r.log}
        if r.service == ["any"]:
            out.append({**base, "name": r.name, "service": ["any"], "application": ["any"]})
            continue
        ports = [s for s in r.service if l4(dev, s)]
        if ports:
            out.append({**base, "name": r.name, "service": ports, "application": ["any"]})
        if any(has_icmp(dev, s) for s in r.service):
            out.append({**base, "name": f"{r.name}-ICMP", "service": ["application-default"], "application": ["icmp", "ping", "traceroute"]})
    names = [x["name"] for x in out]
    clash = {n for n in names if names.count(n) > 1}
    if clash:
        raise ValueError(f"{dev.hostname}: rule names {', '.join(sorted(clash))} clash with the -ICMP rules OneConfig generates")
    return out


def nat(dev):
    """NAT rules in PAN-OS form: dicts with name, from, to, source, destination, service and the translation lines."""
    svc = {s.name: s for s in dev.services}
    out = []
    for n in sorted(dev.nat, key=lambda n: n.kind != "static"):  # first match wins: one-to-one entries before PAT
        out_if = _iface(dev, n.to_zone)
        if n.kind == "dynamic":
            xlate = (f"source-translation dynamic-ip-and-port interface-address interface {out_if.name}" if n.translated == "interface"
                     else f"source-translation dynamic-ip-and-port translated-address {n.translated}")
            out.append({"name": n.name, "from": n.from_zone, "to": n.to_zone, "source": n.source, "destination": "any",
                        "service": "any", "xlate": [xlate]})
        elif n.service:  # port forward: destination NAT, matched in the outside zone on the public address
            pub = n.translated if n.translated != "interface" else str(out_if.ip.ip)
            port = svc[n.service].ports.split("-")[0]
            out.append({"name": n.name, "from": n.to_zone, "to": n.to_zone, "source": "any", "destination": pub, "service": n.service,
                        "xlate": [f"destination-translation translated-address {n.source}", f"destination-translation translated-port {port}"]})
        else:
            pub = n.translated if n.translated != "interface" else str(out_if.ip.ip)
            out.append({"name": n.name, "from": n.from_zone, "to": n.to_zone, "source": n.source, "destination": "any", "service": "any",
                        "xlate": [f"source-translation static-ip translated-address {pub}", "source-translation static-ip bi-directional yes"]})
    return out

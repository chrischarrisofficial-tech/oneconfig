from datetime import date, timedelta
from ipaddress import IPv4Address, IPv4Network, collapse_addresses
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .model import Device, Network, Vlan

_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    trim_blocks=True,
    lstrip_blocks=True,
    undefined=StrictUndefined,
)
_LOGICAL = ("vlan", "loopback", "tunnel", "null", "mgmt", "management", "lo0", "irb", "em", "fxp", "me0", "vme")
TEMPLATES = {"ios-xe": "ios_xe.j2", "nx-os": "nx_os.j2", "eos": "eos.j2", "junos": "junos.j2", "asa": "asa.j2", "panos": "panos.j2", "fortios": "fortios.j2"}
# DISA RTR STIG bogon lists (CISC-RT-000270 ACL, CISC-RT-000490 BGP)
BOGONS = [IPv4Network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")]
DOD_BANNER = (
    "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n"
    "By using this IS (which includes any device attached to this IS), you consent to the following conditions:\n"
    "-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, "
    "penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), "
    "and counterintelligence (CI) investigations.\n"
    "-At any time, the USG may inspect and seize data stored on this IS.\n"
    "-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, "
    "and search, and may be disclosed or used for any USG-authorized purpose.\n"
    "-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your "
    "personal benefit or privacy.\n"
    "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or "
    "monitoring of the content of privileged communications, or work product, related to personal representation or services "
    "by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and "
    "confidential. See User Agreement for details.")


def _lifetime(today=None):
    """Key lifetime string for 180 days from today (STIG CISC-RT-000050)."""
    t = today or date.today()
    f = lambda d: f"00:00:00 {d:%b} {d.day} {d.year}"  # noqa: E731
    return f"{f(t)} {f(t + timedelta(days=180))}"


def _peer_role(net, dev, ifname):
    roles = {d.hostname: d.role for d in net.devices}
    for l in net.links:
        if l.a == dev.hostname and l.a_if == ifname:
            return roles.get(l.b)
        if l.b == dev.hostname and l.b_if == ifname:
            return roles.get(l.a)


def context(dev: Device, net: Network) -> dict:
    """Facts about this device's place in the network that a config file alone can't show."""
    external = [i.name for i in dev.interfaces if i.external]
    perimeter = bool(external)
    internal = [i.name for i in dev.interfaces if perimeter and i.mode == "routed" and i.ip and not i.external
                and not i.name.lower().startswith(_LOGICAL)]
    downlinks = [i.name for i in dev.interfaces if dev.role == "l3switch" and i.mode == "trunk"
                 and not i.channel_group and _peer_role(net, dev, i.name) == "switch"]
    return {"role": dev.role, "external": external, "internal": internal, "downlinks": downlinks, "generated": True}


def render(dev: Device, net: Network, today=None) -> str:
    s = net.security
    ctx = context(dev, net)
    vlans = list(net.vlans)
    if dev.role != "router":
        for vid, name in ((s.native_vlan, "NATIVE-UNUSED"), (s.parking_vlan, "PARKING")):
            if vid and vid not in {v.id for v in vlans}:
                vlans.append(Vlan(id=vid, name=name))
    user_vlans = sorted({i.access_vlan or 1 for i in dev.interfaces if i.mode == "access" and not i.shutdown}
                        | {i.voice_vlan for i in dev.interfaces if i.voice_vlan})
    default_trunk = ",".join(str(v.id) for v in net.vlans if v.id not in (1, s.parking_vlan, s.native_vlan))
    routed = [i for i in dev.interfaces if i.mode == "routed" and not i.routing_passive
              and not i.name.lower().startswith(("loopback", "lo0"))]
    loopback = next((i.name for i in dev.interfaces if i.name.lower().startswith(("loopback", "lo0"))), None)
    bgp = dev.bgp
    ebgp = [n for n in bgp.neighbors if n.remote_as != bgp.asn] if bgp else []
    internal_nets = list(collapse_addresses(i.ip.network for d in net.devices for i in d.interfaces
                                            if i.ip and not i.external))

    def acl_in(i):
        return i.acl_in or ("EXTERNAL-IN" if i.external else "EGRESS-FILTER" if i.name in ctx["internal"] else None)

    return _env.get_template(TEMPLATES[dev.platform]).render(
        net=net, d=dev, s=s, ctx=ctx, vlans=sorted(vlans, key=lambda v: v.id),
        user_vlans=",".join(map(str, user_vlans)),
        trunk_vlans=lambda i: i.trunk_vlans or default_trunk,
        ospf_active=[i.name for i in routed if i.ospf_area is not None],
        eigrp_active=[i.name for i in routed if dev.eigrp and i.ip and any(i.ip.ip in n for n in dev.eigrp.networks)],
        no_switchport=lambda i: dev.role != "router" and not i.name.lower().startswith(_LOGICAL),
        acl_in=acl_in, acl_out=lambda i: i.acl_out or ("EXTERNAL-OUT" if i.external else None),
        needs_external_in=any(i.external and not i.acl_in for i in dev.interfaces),
        needs_external_out=any(i.external and not i.acl_out for i in dev.interfaces),
        needs_egress=any(acl_in(i) == "EGRESS-FILTER" for i in dev.interfaces),
        internal_nets=internal_nets, bogons=BOGONS, ebgp=ebgp, ebgp_as=sorted({n.remote_as for n in ebgp}),
        bgp_as=sorted({n.remote_as for n in bgp.neighbors if n.authenticate}) if bgp else [],
        update_source=lambda n: n.update_source or (loopback if bgp and n.remote_as == bgp.asn else None),
        null0=any(str(r.next_hop).lower() == "null0" for r in dev.static_routes),
        lifetime=_lifetime(today), dod_banner=DOD_BANNER, today=today or date.today(),
        # Junos OSPF key chains only do HMAC-SHA-1 (RFC 5709), so every vendor uses it when a Junos device runs OSPF
        ospf_sha1=any(x.platform == "junos" and x.ospf and x.ospf.authenticate for x in net.devices),
        login_group="group TACACS-SERVERS " if s.tacacs_servers else "group RADIUS-SERVERS " if s.radius_servers else "",
        area_id=lambda a: str(IPv4Address(a)),  # NX-OS and EOS show areas dotted
        mgmt_vrf=" use-vrf management" if any(i.name.lower() == "mgmt0" for i in dev.interfaces) else "",
        uses={"svi": any(i.name.lower().startswith("vlan") for i in dev.interfaces),
              "lacp": any(i.channel_group for i in dev.interfaces),
              "access": any(i.mode == "access" for i in dev.interfaces),
              "relay": any(i.dhcp_helper for i in dev.interfaces)},
        **(_junos(dev, net) if dev.platform == "junos" else {}),
        **(_asa(dev) if dev.platform == "asa" else {}),
        **(_panos(dev) if dev.platform == "panos" else {}),
        **(_fortios(dev) if dev.platform == "fortios" else {}),
    )


def _asa(dev: Device) -> dict:
    from . import asa
    groups, acls = asa.policy(dev)
    return {"level": {z.name: z.security_level for z in dev.zones}, "zone_ifs": asa.zone_ifs(dev),
            "group_names": {g.name for g in (*dev.address_groups, *dev.service_groups)},
            "policy_groups": groups, "policy_acls": acls, "nat_lines": asa.nat(dev),
            "zone_for": lambda ip: asa.zone_for(dev, ip)}


def _junos(dev: Device, net: Network) -> dict:
    """Junos-only helpers: logical units, VLAN names, interface IPs, and user ACLs as filter terms."""
    from .junos import acl_terms
    names = {v.id: v.name for v in net.vlans} | {1: "default"}
    s = net.security
    if s.native_vlan:
        names.setdefault(s.native_vlan, "NATIVE-UNUSED")
    names.setdefault(s.parking_vlan, "PARKING")
    ip_of = {i.name: i.ip.ip for i in dev.interfaces if i.ip}
    return {"unit": lambda n: n if "." in n else n + ".0",
            "phys": lambda n: n.split(".")[0], "unit_no": lambda n: n.split(".")[1] if "." in n else "0",
            "vlan_name": names, "ip_of": ip_of,
            "irb_vlans": {int(i.name.split(".")[1]) for i in dev.interfaces if i.name.startswith("irb.")},
            "acl_lines": [x for a in dev.acls for x in acl_terms(a.name, a.entries)],
            "q": lambda t: '"' + str(t).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"',
            "ae_count": max([i.channel_group for i in dev.interfaces if i.channel_group] or [0]),
            "is_junos_mgmt": lambda n: n.startswith(("em", "fxp", "me", "vme"))}


def _panos(dev: Device) -> dict:
    from . import panos
    ext = [z.name for z in dev.zones if any(i.zone == z.name and i.external for i in dev.interfaces)]
    return {"sec_rules": panos.rules(dev), "nat_rules": panos.nat(dev), "svc_groups": panos.service_groups(dev),
            "svc_objects": [x for x in dev.services if x.protocol != "icmp"],
            "external_zones": ext, "internal_zones": [z.name for z in dev.zones if z.name not in ext],
            "src_if": lambda ip: next((i for i in dev.interfaces if i.ip and ip in i.ip.network), None),
            "lst": lambda xs: xs[0] if len(xs) == 1 else "[ " + " ".join(map(str, xs)) + " ]",
            "q": lambda t: '"' + str(t).replace('"', "'") + '"'}


def _fortios(dev: Device) -> dict:
    from . import fortios
    vips, pools, snat = fortios.nat(dev)
    q = lambda t: '"' + str(t).replace("\\", "\\\\").replace('"', '\\"') + '"'
    return {"fw_policies": fortios.policies(dev), "nat_vips": vips, "nat_pools": pools, "nat_snat": snat,
            "src_if": lambda ip: next((i for i in dev.interfaces if i.ip and ip in i.ip.network), None),
            "q": q, "lst": lambda xs: " ".join(q(x) for x in xs),
            # Fortinet's anomaly names; thresholds are packets (floods) or sessions per second, FortiOS's own defaults
            "dos_anomalies": [("tcp_syn_flood", 2000), ("tcp_port_scan", 1000), ("udp_flood", 2000), ("udp_scan", 2000),
                              ("icmp_flood", 250), ("icmp_sweep", 100)]}


def render_all(net: Network) -> dict[str, str]:
    return {d.hostname: render(d, net) for d in net.devices}

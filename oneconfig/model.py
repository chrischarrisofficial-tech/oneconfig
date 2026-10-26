"""Vendor-neutral network model. Every string that lands in a config is pattern-checked
so a field can never smuggle a newline (and with it, extra commands) into the output."""
import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Line = Annotated[str, StringConstraints(pattern=r"^[ -$&-\]_-~]*$", max_length=200)]  # printable ASCII minus % and ^ (banner delimiters)
Name = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")]
IfName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z-]*\d+(/\d+)*(\.\d+)?$|^(irb|loopback|tunnel)\.\d+$|^(dmz|mgmt|ha|internal|lan|wan|a|b)$")]  # irb.N: Junos; loopback.N: PAN-OS; dmz, a: FortiGate ports
VlanList = Annotated[str, StringConstraints(pattern=r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$|^$")]
AclEntry = Annotated[str, StringConstraints(pattern=r"^(permit|deny|remark) [ -~]{1,180}$")]
VlanId = Annotated[int, Field(ge=1, le=4094)]
# Interface types each OS's config uses; catches IOS names left behind after switching a device's platform.
IF_KINDS = {"nx-os": r"(ethernet|loopback|port-channel|vlan|mgmt|tunnel|nve)\d",
            "eos": r"(ethernet|management|loopback|port-channel|vlan|tunnel|vxlan)\d",
            "junos": r"((ge|xe|et|mge)-\d+/\d+/\d+$|ae\d+$|lo0$|irb\.\d+$|(em|fxp|me|vme)\d+$)",
            "asa": r"(gigabitethernet|tengigabitethernet|ethernet|management|port-channel|redundant|vlan)\d",  # Ethernet1/1: Firepower hardware
            "panos": r"(ethernet\d+/\d+(\.\d+)?$|ae\d+(\.\d+)?$|loopback\.\d+$|tunnel\.\d+$)",
            "fortios": r"(port\d+|wan\d*|lan\d*|internal\d*|dmz\d*|mgmt\d*|ha\d*|x\d+|a|b|agg\d+|loop\d+)$"}  # FortiGate hardware port names
EXAMPLE_IF = {"nx-os": "Ethernet1/1", "eos": "Ethernet1", "junos": "ge-0/0/0", "asa": "GigabitEthernet0/0", "panos": "ethernet1/1", "fortios": "port1"}
PO_NAME = {"ios-xe": "Port-channel", "nx-os": "port-channel", "eos": "Port-Channel", "junos": "ae", "asa": "Port-channel", "panos": "ae", "fortios": "agg"}  # each OS's own spelling
FIREWALLS = ("asa", "panos", "fortios")  # platforms that take the firewall role
Ports = Annotated[str, StringConstraints(pattern=r"^$|^\d{1,5}(-\d{1,5})?$")]  # "443" or "8000-8080"


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Vlan(Base):
    id: VlanId
    name: Name


class Interface(Base):
    name: IfName
    description: Line = ""
    mode: Literal["access", "trunk", "routed"] = "routed"
    access_vlan: VlanId | None = None
    voice_vlan: VlanId | None = None
    trunk_vlans: VlanList = ""
    ip: IPv4Interface | None = None
    dhcp_helper: IPv4Address | None = None
    ospf_area: int | None = Field(None, ge=0)
    routing_passive: bool = False
    channel_group: int | None = Field(None, ge=1, le=128)
    acl_in: Name | None = None
    acl_out: Name | None = None
    external: bool = False  # faces an untrusted network; turns on STIG perimeter rules
    shutdown: bool = False
    zone: Name | None = None  # firewalls: the security zone (on ASA, the nameif)
    standby_ip: IPv4Address | None = None  # firewalls in a failover pair: the secondary unit's address


class Ospf(Base):
    process_id: int = Field(1, ge=1, le=65535)
    router_id: IPv4Address | None = None
    reference_bw: int = Field(100000, ge=1)
    authenticate: bool = True


class Eigrp(Base):
    asn: int = Field(100, ge=1, le=65535)
    router_id: IPv4Address | None = None
    networks: list[IPv4Network] = []
    authenticate: bool = True


class BgpNeighbor(Base):
    ip: IPv4Address
    remote_as: int = Field(ge=1, le=4294967295)
    description: Line = ""
    update_source: IfName | None = None
    authenticate: bool = True
    max_prefix: int | None = Field(1000, ge=1)


class Bgp(Base):
    asn: int = Field(65000, ge=1, le=4294967295)
    router_id: IPv4Address | None = None
    neighbors: list[BgpNeighbor] = []
    networks: list[IPv4Network] = []


class StaticRoute(Base):
    prefix: IPv4Network
    next_hop: IPv4Address | IfName
    name: Name | None = None


class Acl(Base):
    name: Name
    entries: list[AclEntry] = []


class Zone(Base):
    name: Name
    security_level: int = Field(0, ge=0, le=100)  # ASA: traffic from higher to lower is the default direction


class Address(Base):
    name: Name
    value: IPv4Network  # a host is a /32


class Service(Base):
    name: Name
    protocol: Literal["tcp", "udp", "icmp"]
    ports: Ports = ""  # destination port or range; empty for ICMP

    @model_validator(mode="after")
    def _check(self):
        if (self.protocol == "icmp") == bool(self.ports):
            raise ValueError(f"service {self.name}: {'ICMP takes no ports' if self.ports else 'TCP and UDP need a port or range'}")
        if self.ports and not all(1 <= int(x) <= 65535 for x in self.ports.split("-")):
            raise ValueError(f"service {self.name}: ports must be 1-65535")
        return self


class Group(Base):
    name: Name
    members: list[Name] = Field(min_length=1)


class Rule(Base):
    name: Name
    from_zone: Name
    to_zone: Name
    source: list[Name] = ["any"]
    destination: list[Name] = ["any"]
    service: list[Name] = ["any"]
    action: Literal["allow", "deny"] = "allow"
    log: bool = True


class Nat(Base):
    name: Name
    kind: Literal["dynamic", "static"]  # dynamic: many-to-one PAT outbound; static: one-to-one or a port forward
    from_zone: Name  # where the real addresses live
    to_zone: Name
    source: Name  # real addresses: an address or address group
    translated: Name = "interface"  # an address, or the to_zone interface's own address
    service: Name | None = None  # static only: forward just this TCP/UDP service


class Failover(Base):
    interface: IfName  # dedicated link to the peer, carrying both failover and state
    ip: IPv4Interface | None = None  # ASA and PAN-OS address the link; a FortiGate heartbeat link needs no addresses
    peer_ip: IPv4Address | None = None
    unit: Literal["primary", "secondary"] = "primary"


class Device(Base):
    hostname: Name
    role: Literal["router", "switch", "l3switch", "firewall"] = "switch"
    platform: Literal["ios-xe", "nx-os", "eos", "junos", "asa", "panos", "fortios"] = "ios-xe"
    mgmt_ip: IPv4Address | None = None
    os_version: Line = ""
    model: Line = ""  # hardware model, e.g. "Catalyst 9300": shown in the UI, not used to render
    x: float = 0
    y: float = 0
    interfaces: list[Interface] = []
    ospf: Ospf | None = None
    eigrp: Eigrp | None = None
    bgp: Bgp | None = None
    static_routes: list[StaticRoute] = []
    acls: list[Acl] = []
    zones: list[Zone] = []
    addresses: list[Address] = []
    address_groups: list[Group] = []
    services: list[Service] = []
    service_groups: list[Group] = []
    rules: list[Rule] = []
    nat: list[Nat] = []
    failover: Failover | None = None

    @model_validator(mode="after")
    def _check(self):
        names = {i.name for i in self.interfaces}
        if len(names) != len(self.interfaces):
            raise ValueError(f"{self.hostname}: duplicate interface names")
        acls = {a.name for a in self.acls}
        for i in self.interfaces:
            if self.platform in IF_KINDS and not re.match(IF_KINDS[self.platform], i.name, re.I):
                raise ValueError(f"{self.hostname} {i.name}: not a {self.platform} interface name (e.g. {EXAMPLE_IF[self.platform]})")
            if i.external and i.mode != "routed":
                raise ValueError(f"{self.hostname} {i.name}: only routed interfaces can be external")
            if i.mode != "routed" and self.role == "router":
                raise ValueError(f"{self.hostname} {i.name}: routers only take routed interfaces")
            if i.channel_group and f"{PO_NAME[self.platform]}{i.channel_group}".lower() not in {n.lower() for n in names}:
                raise ValueError(f"{self.hostname} {i.name}: add interface {PO_NAME[self.platform]}{i.channel_group} first")
            if i.voice_vlan and self.platform != "ios-xe":
                raise ValueError(f"{self.hostname} {i.name}: OneConfig generates voice VLANs for IOS-XE only")
            for acl in (i.acl_in, i.acl_out):
                if acl and acl not in acls:
                    raise ValueError(f"{self.hostname} {i.name}: ACL {acl} is not defined")
        if self.eigrp and self.platform in ("eos", "junos"):
            raise ValueError(f"{self.hostname}: {'Arista EOS' if self.platform == 'eos' else 'Junos'} does not run EIGRP; use OSPF or BGP")
        if self.platform == "junos":
            from .junos import acl_terms
            for a in self.acls:
                acl_terms(a.name, a.entries)  # raises with the entry Junos can't express
        if (self.role == "firewall") != (self.platform in FIREWALLS):
            raise ValueError(f"{self.hostname}: {'a firewall needs a firewall platform (' + ', '.join(FIREWALLS) + ')' if self.role == 'firewall' else self.platform + ' is a firewall platform; set the role to firewall'}")
        if self.role == "firewall":
            self._check_firewall()
        elif self.zones or self.rules or self.nat or self.failover or any(i.zone or i.standby_ip for i in self.interfaces):
            raise ValueError(f"{self.hostname}: zones, rules, NAT and failover are for firewalls")
        return self

    def _check_firewall(self):
        h = self.hostname
        zones = {z.name for z in self.zones}
        if len({z.lower() for z in zones}) != len(self.zones):
            raise ValueError(f"{h}: duplicate zone names")
        if self.eigrp or self.acls:
            raise ValueError(f"{h}: firewalls take security rules, not {'EIGRP' if self.eigrp else 'ACLs'}")
        objs = [o.name for o in (*self.addresses, *self.address_groups, *self.services, *self.service_groups)]
        if len(set(objs)) != len(objs) or "any" in objs or "interface" in objs:
            raise ValueError(f"{h}: object names must be unique and not 'any' or 'interface'")
        nets = {a.name for a in self.addresses}
        svcs = {s.name for s in self.services}
        for groups, known, what in ((self.address_groups, nets, "address"), (self.service_groups, svcs, "service")):
            for g in groups:  # members must be defined earlier, so groups can nest but never loop
                for m in g.members:
                    if m not in known:
                        raise ValueError(f"{h} group {g.name}: {m} is not an {what} or an earlier {what} group")
                known.add(g.name)
        used = {}
        for i in self.interfaces:
            if i.mode != "routed":
                raise ValueError(f"{h} {i.name}: firewall interfaces are routed")
            if i.zone and i.zone not in zones:
                raise ValueError(f"{h} {i.name}: zone {i.zone} is not defined")
            if i.zone and used.setdefault(i.zone, i.name) != i.name and self.platform == "asa":
                raise ValueError(f"{h}: ASA puts one interface in each zone (nameif); {i.zone} is on {used[i.zone]} and {i.name}")
            if bool(i.zone) != bool(i.ip):
                raise ValueError(f"{h} {i.name}: {'give the zone interface an IP address' if i.zone else 'put the interface in a zone (firewall interfaces with an IP need one)'}")
            if i.standby_ip and self.platform in ("panos", "fortios"):
                raise ValueError(f"{h} {i.name}: a {'PAN-OS' if self.platform == 'panos' else 'FortiGate'} active/passive pair shares its addresses; leave the standby IP empty")
            if i.standby_ip and not (self.failover and i.ip and i.standby_ip in i.ip.network and i.standby_ip != i.ip.ip):
                raise ValueError(f"{h} {i.name}: standby IP needs failover and another address in {i.ip.network if i.ip else 'the interface subnet'}")
        for r in self.rules:
            for z in (r.from_zone, r.to_zone):
                if z not in zones:
                    raise ValueError(f"{h} rule {r.name}: zone {z} is not defined")
            if r.from_zone == r.to_zone:
                raise ValueError(f"{h} rule {r.name}: traffic within one zone doesn't cross the firewall")
            for ref, known in ((r.source, nets), (r.destination, nets), (r.service, svcs)):
                for n in ref:
                    if n != "any" and n not in known:
                        raise ValueError(f"{h} rule {r.name}: {n} is not defined")
                if "any" in ref and len(ref) > 1:
                    raise ValueError(f"{h} rule {r.name}: 'any' can't be combined with other objects")
        if len({r.name for r in self.rules}) != len(self.rules) or len({n.name for n in self.nat}) != len(self.nat):
            raise ValueError(f"{h}: rule and NAT names must be unique")
        addr = {a.name for a in self.addresses}
        if self.platform == "fortios" and {n.name for n in self.nat} & set(objs):
            raise ValueError(f"{h}: on FortiOS a NAT rule becomes a virtual IP or IP pool named after it, so NAT names can't match object names")
        for n in self.nat:
            for z in (n.from_zone, n.to_zone):
                if z not in used:
                    raise ValueError(f"{h} NAT {n.name}: zone {z} has no interface")
            if n.source not in nets or (n.translated != "interface" and n.translated not in addr):
                raise ValueError(f"{h} NAT {n.name}: source must be an address or group, translated an address or 'interface'")
            if n.service and (n.kind != "static" or n.service not in {s.name for s in self.services if s.protocol != "icmp"}):
                raise ValueError(f"{h} NAT {n.name}: only static NAT forwards a service, and it must be a TCP or UDP service")
        f = self.failover
        if f:
            fi = next((i for i in self.interfaces if i.name == f.interface), None)
            if not fi or fi.ip or fi.zone:
                raise ValueError(f"{h}: the failover link must be an interface with no IP or zone")
            if self.platform != "fortios" and not (f.ip and f.peer_ip and f.peer_ip in f.ip.network and f.peer_ip != f.ip.ip):
                raise ValueError(f"{h}: the failover link needs its own address and the peer's, in the same subnet")
        for r in self.static_routes:
            if not isinstance(r.next_hop, IPv4Address) or not any(i.zone and r.next_hop in i.ip.network for i in self.interfaces):
                raise ValueError(f"{h} route {r.prefix}: on a firewall the next hop must be an address on a zone's subnet")
        if self.platform == "asa":
            mgmt = {i.zone for i in self.interfaces if i.zone and i.name.lower().startswith("management")}
            for x in (*self.rules, *self.nat):
                if {x.from_zone, x.to_zone} & mgmt:
                    raise ValueError(f"{h} {x.name}: zone {', '.join({x.from_zone, x.to_zone} & mgmt)} is management-only and carries no traffic")


class Security(Base):
    domain: Name = "corp.local"
    mgmt_subnet: IPv4Network | None = None
    ntp_servers: list[IPv4Address] = []
    syslog_servers: list[IPv4Address] = []
    banner: Line = "Authorized access only. Activity is monitored and logged."
    snmpv3: bool = True
    native_vlan: VlanId | None = 999
    dhcp_snooping: bool = True
    arp_inspection: bool = False  # breaks static-IP hosts without ARP ACLs, so opt-in
    port_security: bool = True
    storm_control: bool = True
    ip_source_guard: bool = False  # needs DHCP snooping bindings, so opt-in
    parking_vlan: VlanId = 998
    dod_banner: bool = False
    tacacs_servers: list[IPv4Address] = []
    radius_servers: list[IPv4Address] = []
    dot1x: bool = False
    backup_server: IPv4Address | None = None
    copp: bool = True

    @model_validator(mode="after")
    def _check(self):
        if self.dot1x and not self.radius_servers:
            raise ValueError("802.1X needs at least one RADIUS server")
        if self.parking_vlan == self.native_vlan:
            raise ValueError("parking VLAN and native VLAN must differ")
        return self


class Link(Base):
    a: Name
    a_if: IfName
    b: Name
    b_if: IfName


class Network(Base):
    id: Annotated[str, StringConstraints(pattern=r"^$|^[0-9a-f-]{36}$")] = ""  # random per network: keys its saved secrets
    name: Line = "My Network"
    vlans: list[Vlan] = []
    security: Security = Security()
    devices: list[Device] = []
    links: list[Link] = []

    @model_validator(mode="after")
    def _check(self):
        hosts = {d.hostname: {i.name for i in d.interfaces} for d in self.devices}
        if len(hosts) != len(self.devices):
            raise ValueError("duplicate hostnames")
        for l in self.links:
            for dev, ifn in ((l.a, l.a_if), (l.b, l.b_if)):
                if ifn not in hosts.get(dev, ()):
                    raise ValueError(f"link endpoint {dev} {ifn} does not exist")
        return self

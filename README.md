# OneConfig

Draw your network, click a device, and get a hardened Cisco IOS-XE, Cisco NX-OS, Arista EOS or Juniper Junos config, or a Cisco ASA, Palo Alto PAN-OS or Fortinet FortiGate firewall config, with a live security score.

## Run it

```bash
pip install -e .          # Python 3.10+, installs jinja2 + pydantic
oneconfig serve           # opens OneConfig in your browser (http://127.0.0.1:8470)
```

Works the same on Windows, macOS and Linux. The server only listens on 127.0.0.1 and rejects requests from any other host name. Each launch also makes a random access key that every request must carry. The browser gets it from `~/.oneconfig/open.html`, a page only your account can read, so another account or program on the same computer (a shared jump host, say) can't use the server or your saved logins. With `--no-browser`, open the `file://` link it prints. A tab opened at the plain address has no key and says so.

### Mac app

`OneConfig.app` runs the same server and shows it in its own window, so there's no browser tab or launch link. Your data stays in `~/.oneconfig` and the Keychain, shared with `oneconfig serve`. To build it:

```bash
pip install -e ".[app]"
pyinstaller packaging/OneConfig.spec --noconfirm   # makes dist/OneConfig.app
dist/OneConfig.app/Contents/MacOS/OneConfig --selfcheck   # checks the packed app has its templates, parsers and keychain access
```

The app isn't signed, so the first time you open it, right-click it and choose **Open**. macOS asks once for Local Network access: allow it, or discovery and pushes can't reach your devices. An app built on an Intel Mac runs on Apple Silicon through Rosetta.

## Using the builder

- **Command rail** (left edge): Build places a router, L3 switch, switch or firewall. Connect links two devices, picks the next free ports, and can auto-assign a /30 or /31. Audit checks any pasted `show running-config`. File saves, opens and exports.
  Arrow keys and Enter drive the rail; Esc cancels; Delete removes the selected device.
- **Click a device** to edit it. Targeting brackets mark it on the map, and the header shows which device you are editing.
- **Basic / Intermediate / Expert** controls how many options are shown, not what gets generated.
- Each device's faceplate shows its STIG score as a row of lights: the accent color when it's 80 or better, amber from 50, the alert color below that. The Config tab lists findings with the reason and the exact fix commands.
- **Dashboard.** Panels around the map show network health (average STIG compliance), open findings, CAT I counts, CVEs, the selected device, the devices that need attention, routing in the design, links and this session's activity. Every number comes from the model or the last build; nothing is sampled from devices.
  **Customize** (top right) lets you remove, add, resize (⤢) and reorder panels (drag, or ‹ ›), switch between the Overview, Security, Change window and Minimal layouts, and save your own. The map always stays.
- **Themes:** Ember ops (default), Neon grid, Arctic NOC and Synthwave. The layout and theme are saved in `~/.oneconfig/ui.json`, readable by your account only.
- Work is autosaved in the browser. Use File → Save network to keep a `.oneconfig.json` file.

## What it generates

Pick each device's **Platform** on its General tab: Cisco IOS-XE, Cisco NX-OS, Arista EOS or Juniper Junos. New devices take the platform of the device you have selected, and interface and port-channel names follow that OS's style. Switching an existing device's platform renames its ports (for example `GigabitEthernet1/0/1` becomes `Ethernet1/1` on NX-OS or `ge-0/0/0` on Junos, `Vlan10` becomes `irb.10`) along with its links; any name the app can't map is flagged.

| Area | Included |
|---|---|
| Switching | VLANs, access/voice ports, trunks with pruning, LACP EtherChannel, Rapid PVST+, SVIs, DHCP relay |
| Routing | OSPF (interface mode, passive-by-default, HMAC-SHA key chain with 180-day keys), EIGRP named mode (HMAC-SHA; DISA still counts EIGRP as a permanent finding), BGP (TCP-AO with 180-day keys, GTSM, max-prefix, bogon and prefix-length filters), static routes |
| Security | SSH-only VTY with management ACL, AAA, scrypt secrets, login lockout, SNMPv3 authPriv, NTP, syslog, config archive logging, BPDU Guard, port security, storm control, DHCP snooping, optional DAI, unused native VLAN, extended ACLs |

NX-OS and EOS get the same design in their own syntax, with each OS's DISA-recommended commands: for example `password strength-check`, `ssh macs`/`ssh ciphers` and `copp profile strict` on NX-OS, and `management ssh` (cipher, MAC, FIPS restrictions, ACL), `aaa authentication policy lockout` and configuration sessions on EOS. Differences:

- **Voice VLANs** are generated for IOS-XE only. OneConfig says so instead of guessing NX-OS/EOS voice syntax.
- **EIGRP** isn't available on EOS (Arista doesn't run it). On NX-OS it uses MD5, the only option there.
- **NX-OS 802.1X ports** get 802.1X without port security: NX-OS doesn't allow both on one port.
- **BGP authentication** is TCP-AO on IOS-XE and an MD5 password on NX-OS and EOS (see the STIG notes below). Junos uses a key chain with HMAC-SHA-1-96, DISA's example. BGP between two OneConfig devices of different vendors therefore needs one side's authentication changed by hand.

**Junos** is generated in `set` form, the same form `show configuration | display set` prints, so the diff against a device is a line comparison. The design is the same, in Junos terms:
- **Routing engine filter.** One input filter on `lo0` (PROTECT-RE) is the management ACL and the control-plane policer: SSH and SNMP only from the management subnet, BGP only from configured peers, NTP and RADIUS only from their servers, fragmented ICMP and mask requests dropped, everything else logged and dropped.
- **Login classes.** ENGINEER (used by TACACS+/RADIUS logins) can't change logging, delete files or install software. AUDITOR may only change logging. The local account of last resort has full rights. Every class times out after 5 minutes.
- **Local passwords** are stored by Junos as crypt hashes, and Junos asks for a plain-text password interactively. So the template writes `<ADMIN-SECRET.SHA512>`, and OneConfig fills in the SHA-512 crypt hash of the secret you entered (Python's own implementation, checked against `openssl passwd -6`).
- **ACLs you write** in the ACL tab (IOS-style entries) are translated into firewall filter terms; an entry Junos can't express (`gt`/`lt` ports, `reflect`) is flagged when you type it.
- **OSPF authentication** uses a key chain with HMAC-SHA-1 (RFC 5709), the only HMAC Junos OSPF key chains offer, from Junos 23.4R1. So that mixed networks still form adjacencies, every vendor's OSPF uses HMAC-SHA-1 whenever a Junos device in the network runs OSPF. That is still FIPS 198-1, which is what DISA requires. Networks without Junos keep SHA-256.
- **EIGRP** isn't available (Junos doesn't run it), and voice VLANs stay IOS-XE only.

**Firewalls (Cisco ASA).** Build > Firewall adds one, or File > Load firewall example opens an edge ASA pair in front of a core switch. A firewall has its own tabs:
- **Zones**: each interface joins a zone with a security level. On the ASA a zone is the interface's `nameif`, so there is one interface per zone. The management interface becomes `management-only`.
- **Objects**: addresses, services (TCP/UDP port or range, ICMP) and groups of either. Groups can include earlier groups.
- **Rules**: from zone, to zone, source, destination, service, allow or deny, log. Anything no rule allows is denied and logged.
- **NAT**: dynamic PAT to the interface or an address, and static one-to-one or port forwards, as twice NAT (static first, PAT `after-auto`).
- **High availability** (Zones tab): an active/standby failover pair with one link for failover and state. Interfaces get a standby IP; the config ends with the few lines to type on the other unit.
- **Routing**: static routes, OSPF (MD5, the only OSPF authentication the ASA has) and BGP with bogon and own-prefix filters toward eBGP peers.

The ASA filters on the interface a packet arrives on and has no "to zone". OneConfig turns each zone's rules into one access list on that zone's interface (`INSIDE_IN` and so on, DISA's naming). A destination of `any` toward a zone means the networks behind it: its subnet plus static routes through it. A zone with a default route, OSPF or BGP is open-ended, so its rules come after a deny of every known zone's networks. Rules toward different zones never match the same packet, so this keeps the meaning you wrote. Inward-facing access lists also drop outbound SNMP, NTP, syslog, SSH and TACACS+ before the rules toward the outside (STIG CASA-FW-000250).

**Firewalls (Palo Alto PAN-OS).** Pick Palo Alto PAN-OS as a firewall's platform (switching from ASA renames `GigabitEthernet0/N` to `ethernet1/N+1`, drops the dedicated management interface and its zone, and removes standby addresses). OneConfig writes `set` commands for a single vsys and the `default` virtual router.
- **Zones** hold any number of layer 3 interfaces. Each gets the zone protection profile ONECONFIG-ZP (floods, spoofing, scans).
- **Rules** become security rules with log-at-end, log forwarding and the ONECONFIG profile group (antivirus, anti-spyware with DNS sinkhole, vulnerability protection) on every allow rule. PAN-OS matches the address before NAT, so a rule toward a published server uses its public address. ICMP isn't a port service on PAN-OS, so a rule with ICMP gets a second `<name>-ICMP` rule using the `icmp`, `ping` and `traceroute` applications. The interzone default is deny and logged.
- **NAT**: statics first; a port forward is destination NAT; PAT uses the interface address.
- **HA** is active/passive over HA1 on the interface you name. A PAN-OS pair shares its addresses, so standby addresses are refused.
- The last-resort admin's password is a SHA-256 crypt `phash`, filled at push time from `<ADMIN-SECRET.SHA256>`.

**Firewalls (Fortinet FortiGate).** Pick Fortinet FortiGate as a firewall's platform (from ASA, `GigabitEthernet0/N` becomes `portN+1`; the management interface and its zone are dropped and standby addresses removed). OneConfig writes FortiOS `config` blocks for FortiOS 7.4.4 and later, single VDOM.
- **Zones** (`system zone`, intrazone traffic denied) hold any number of interfaces; policies name zones, not ports.
- **Policies** match top to bottom, log all sessions, and every accept policy gets the built-in `default` IPS sensor and antivirus profile with certificate inspection. Traffic no policy accepts hits the implicit deny, which is logged. ICMP services are native.
- **NAT**: OneConfig turns on **central NAT**, which matches its own model: NAT rules sit apart from policies, and policies use real addresses. PAT becomes a central SNAT entry; publishing a server becomes a virtual IP (a port forward for one service), plus a one-to-one IP pool for its own outbound traffic when the NAT is one-to-one.
- **DoS policies** on every zone block SYN, UDP and ICMP floods, port scans and sweeps.
- **HA** is FGCP active/passive over the heartbeat port you name; the heartbeat needs no addresses, and the pair shares its interface addresses.
- Service groups can't use a name FortiGates already give a predefined service (`DNS`, `HTTP`, …); the push plan reads the firewall and says so.

FTD runs the same ASA engine underneath, so pasted or discovered FTD configs are audited with the ASA checks (DISA has no FTD STIG). OneConfig doesn't generate FTD configs: FTD is normally managed from FMC, which doesn't take CLI config.

**How the NX-OS, EOS, Junos and ASA syntax is checked.** There's no lab hardware here, so every generated line must pass one of three tests (`tests/test_syntax.py`):
1. Batfish's own NX-OS, Arista, flat-Junos or ASA grammar (compiled from its ANTLR source by `tests/syntax/build_parser.sh`) accepts it.
   - On Junos, Batfish's grammar doesn't model a few STIG commands: `system archival`, `rstp bpdu-block-on-edge`, `bpdu-timeout-action block`, 802.1X `supplicant single-secure` and `mac-radius`, and `system rng hmac-drbg`. They pass test 2.
   - Batfish's ASA grammar is inherited from IOS and misses some ASA commands (`failover key`, `ospf message-digest-key`, `aaa accounting ssh console`, `logging host … 6/1514`). They pass test 2 or 3.
2. It matches a command in DISA's fix text for that vendor.
3. It's on a short list in `tests/syntax/allow_*.txt`, each with the Cisco, Arista or CIS document that shows it.

**How the PAN-OS syntax is checked.** Batfish's Palo Alto grammar skips whole sections, so it can't vouch for a line. Instead each PAN-OS line must pass one of:
1. Palo Alto's own config schema: the YAML specs in [pan-os-codegen](https://github.com/PaloAltoNetworks/pan-os-codegen) (the source of their Terraform provider), pinned to a commit and fetched by `tests/syntax/build_panspec.sh`. `tests/syntax/panspec.py` walks each `set` line through them.
2. The same command shape in Palo Alto's [Iron-Skillet](https://github.com/PaloAltoNetworks/iron-skillet) day-one configs, PAN-OS 8.0 to 11.0 (`tests/syntax/vendor_panos_shapes.txt`).
3. `tests/syntax/allow_panos.txt`, each line with its Palo Alto source (shared authentication profiles, HA).

**How the FortiOS syntax is checked.** Every generated line must pass Fortinet's own configuration schema: the per-version `versioned_schema` in each module of Fortinet's Ansible collection ([ansible-galaxy-fortios-collection](https://github.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection)), pinned to a commit and condensed by `tests/syntax/build_fosspec.sh`. `tests/syntax/fosspec.py` walks the `config` / `edit` / `set` blocks and requires each table, field and value to exist on FortiOS 7.4.4, 7.6.0 and the newest 7.6 release the schema knows. That check caught two things a 7.4-only config would get wrong: the TCP/UDP service protocol keyword was renamed between 7.4 and 7.6 (so OneConfig leaves it at its default), and OSPF wants `message-digest`, not `md5`. The one block the schema doesn't list after 7.2, the admin login banner (`config system replacemsg admin "pre_admin-disclaimer-text"`), is in `tests/syntax/allow_fortios.txt` with its source: DISA's current fix text.

Golden files for all seven platforms catch unintended changes.

Text fields (descriptions, banners, ACL entries) accept printable ASCII only, which is what IOS uses. That also means no hidden line break can turn a field into an extra command.

Passwords are never stored. Configs contain `<ANGLE-BRACKET>` placeholders for every secret, and the audit reminds you until they are replaced.

## DISA STIG compliance

Every device is checked against the official DISA STIGs for its OS:

| OS | Package | Benchmarks | Rules |
|---|---|---|---|
| Cisco IOS-XE router | Y26M04 | Router NDM V3R7, Router RTR V3R5 | 139 |
| Cisco IOS-XE switch | Y26M04 | Switch NDM V3R6, Switch L2S V3R2, Switch RTR V3R4 | 152 |
| Cisco NX-OS | Y26M07 | NX-OS Switch NDM V3R6, L2S V3R4, RTR V3R4 | 142 |
| Arista EOS | Y25M07 (latest) | Arista MLS EOS 4.X NDM V2R2, L2S V2R3, Router V2R2 | 114 |
| Juniper Junos router | Juniper Router Y25M01 (latest) | Router NDM V3R2, RTR V3R2 | 145 |
| Juniper Junos switch | Juniper EX Switches Y26M07 (latest) | EX NDM V2R5, L2S V2R5, RTR V2R1 | 181 |
| Cisco ASA (and FTD) | Cisco ASA Y26M07 | ASA NDM V2R5, Firewall V2R1, IPS V2R1, VPN V2R2 | 132 |
| Palo Alto PAN-OS | Palo Alto Y26M07 (final: DISA sunset this STIG on 2026-07-10) | PAN NDM V3R4, ALG V3R4, IDPS V3R2 | 114 |

| Fortinet FortiGate | FortiGate Firewall Y26M10 | FortiGate Firewall NDM V1R6, Firewall V1R5 | 89 |

DISA no longer maintains the Palo Alto STIG. OneConfig checks against its final release because it is still the published DoD baseline for these firewalls; expect no further updates.

Layer 2 switches get the routing rules marked not applicable.

`oneconfig/stig/catalog.json` holds the rule IDs, Vuln IDs, severities and titles, taken verbatim from DISA's XCCDF files (SHA-256 of the source zips is recorded in the file). For IOS-XE, 169 of the 291 rules have automated pass/fail checks, and another 94 (MPLS, PE, multicast, MSDP, IPv6 perimeter, PKI) are marked not applicable automatically when those features are absent. NX-OS has 100 checks plus 34 automatic N/A of 142, EOS has 70 plus 28 of 114, Junos has 82 plus 44 of 145 (router) and 111 plus 47 of 181 (EX switch), ASA has 63 checks of 132, and PAN-OS has 71 checks plus 11 automatic N/A of 114 (TLS decryption, GlobalProtect and IKE rules wait until those are configured), and FortiGate has 64 checks plus 3 automatic N/A of 89. FortiGate checks read `show full-configuration`: settings left at their defaults only appear there, and a rule is only passed when the configuration shows the setting. The ASA's 41 VPN rules and 23 IPS rules (FirePOWER module, checked in its GUI) are not applicable until the config has a VPN or sends traffic to an IPS module; then they are listed for manual review. Junos checks read `display set`; a pasted `show configuration` with braces is flattened first. The key-lifetime rule (JUNI-RT-000030) opens once a key chain's newest key is more than 180 days old, which is DISA's rotation rule. Most NX-OS rule IDs mean the same as IOS-XE's, so those checks are shared. The rest are reported as **Not reviewed** with the reason, because they depend on organization policy, network role or `show` output a config can't reveal. A rule is only marked **Not a finding** when the config proves it.

**STIG Viewer checklists.** Every STIG result (a device's Config tab, or a pasted config under Audit) has **Download checklist (.cklb)**: a DISA STIG Viewer 3 checklist with each rule's status, OneConfig's finding (and the fix, when open), and DISA's own check text, fix text, discussion and CCIs, so eMASS and STIG Manager can map findings to controls. `oneconfig stig … --cklb fw1.cklb` writes the same from the command line. The rule text and XCCDF benchmark IDs come from DISA's XCCDF files (`oneconfig/stig/rules.json.gz`, built by `tools/stig_text.py`, which refuses to build unless every rule matches the catalog). Rule and checklist IDs are stable, so exporting the same device again updates its checklist instead of duplicating it. Not-reviewed rules keep OneConfig's reason in their finding details for the reviewer. `tests/test_cklb.py` reads the files back with STIG Manager's own parser.

Generated configs pass every automated rule except:
- **CISC-L2-000040** (IOS-XE switch QoS), which needs your organization's QoS policy.
- **CASA-FW-000210** and **CASA-FW-000300** on ASA: e-mail alerts need your SMTP server and addresses (`logging mail`, `logging recipient-address`, `smtp-server`).
- On PAN-OS: **PANW-AG-000052** (TCP session timeout) — set it in the web interface under Device > Setup > Session; no Palo Alto source showed its CLI path. **PANW-AG-000111** and **PANW-IP-000045** need your NetFlow collector. The best-practice audit also notes that management isn't limited to a subnet: add Permitted IP Addresses on the management interface in the web interface, for the same reason.
- On FortiGate: **FGFW-ND-000115** and **FNFG-FW-000105** need your mail server and the SA's and ISSO's addresses (an automation stitch with an e-mail action). **FGFW-ND-000255** and **FGFW-ND-000280** need FIPS-CC mode, which reboots the FortiGate and resets its configuration, so OneConfig never turns it on. **FGFW-ND-000311** (a new password changes 8 characters) has no CLI setting on FortiOS 7.6.3 and later; on 7.4 to 7.6.2 it's `set min-change-characters 8` under `config system password-policy`. FGFW-ND-000165 (LDAP) is left for review when administrators use TACACS+ or RADIUS.
- **ARST-RT-000280** on EOS routers with BGP. DISA wants a BGP shared-secret profile; OneConfig generates an MD5 password and leaves the finding open with DISA's fix, because the shared-secret syntax couldn't be verified here. Toggling a control off in the Security tab shows the finding immediately.

Mark an interface **External** to make the device a perimeter router. You get generated EXTERNAL-IN (default deny, DISA bogons, IP options dropped), EXTERNAL-OUT (management traffic blocked), and uRPF plus an egress filter on the inside interfaces.

Note: EXTERNAL-IN is stateless and default-deny, so it allows TCP replies (`established`) but not UDP replies such as DNS from the internet. Add the permits your site needs via a custom ACL.

## Discovery

Install the extras first: `pip install -e ".[discover]"` (netmiko, pysnmp, pyserial, keyring). They power Discover and Push.

Choose **Discover** in the command menu:

| Method | What it does |
|---|---|
| Scan a subnet | TCP-connect probe of 22, 23, 80, 161, 443, 830 (no admin rights needed). Hosts with SSH open can be handed straight to the SSH walk. On macOS, OneConfig raises its open-file limit for the scan, and fails with an error rather than reporting hosts as closed if it runs out. |
| SSH walk | Logs into seed devices, reads `show version`, CDP, LLDP and the running config, then follows neighbors' management addresses. |
| SNMP | v2c or v3 (SHA + AES-128/256). Reads sysName, sysDescr, ipForwarding, interface names and the CDP-MIB neighbor table. |
| Console cable | Logs in over a USB/serial console and reads the same commands as SSH. |

- **Scope.** Discovery never contacts an address outside the **Stay within** networks you enter, capped at 4,096 addresses. Neighbors outside the scope still appear on the map, marked as seen-only.
- **Credentials.** Used for that run only. They're never saved, logged or returned to the browser.
- **Endpoints.** Phones, printers and access points are recognized from CDP/LLDP capabilities and left off the map.
- **Firewalls.** An ASA or FTD answers neither CDP nor LLDP, so list it as a seed. OneConfig sends `terminal pager 0`, reads `show version` and `show running-config`, and draws it with its zones, addresses, standby addresses and failover link.
- **Palo Alto.** Also a seed. When `show version` is an unknown command, OneConfig sends `set cli pager off` and `set cli config-output-format set`, reads `show system info` and `show config running`, and draws the layer 3 interfaces, zones and HA1 link. Interfaces without a zone are shown in UNASSIGNED.
- **FortiGate.** Also a seed. FortiOS answers `show version` with an error, so OneConfig logs in again with netmiko's FortiGate driver (it turns paging off for the session and back on at logout), reads `get system status` and `show full-configuration`, and draws the interfaces with addresses, their zones and the FGCP heartbeat link. Interfaces OneConfig doesn't model, such as VLAN interfaces (`VLAN10`) or named loopbacks, are left off the map. That driver normally offers only old SHA-1 key exchanges, which a FortiGate with `strong-crypto` refuses; OneConfig allows the modern ones and drops only group1.
- **Mixed vendors.** Each device's OS (IOS-XE, NX-OS, Arista EOS, Junos or ASA) is detected from `show version` or the SNMP description, and its output is parsed with that OS's templates. On Junos, OneConfig reads `show lldp neighbors` and `show configuration | display set` (with `| no-more`). Junos's LLDP summary has no management addresses or capabilities, so the walk can't hop from a Junos device: list Junos devices as seeds. A neighbor whose port is named slot/port is drawn as a network device; one reporting `eth0` (an access point, a phone) is not. Arista neighbors are recognized from their LLDP description, because EOS's LLDP output doesn't list capabilities. Discovered devices land on the map with the right platform, and their configs are audited against that OS's STIGs.
- **Results.** Every config pulled is STIG-audited in the results list. **Add to map** merges devices, interfaces, management IPs, OS versions and links into your network; **Replace map** starts fresh.
- **Local server.** It only accepts requests with a JSON content type from a local origin, so a malicious web page can't make it scan your network.

```bash
oneconfig discover ssh --seeds 10.99.0.1 --scope 10.99.0.0/24 --username admin -o discovered.json
oneconfig discover snmp --seeds 10.99.0.1,10.99.0.2 --scope 10.99.0.0/24
oneconfig discover serial --port /dev/ttyUSB0 --username admin
```

## Pushing configs to devices

Choose **Push** in the command menu. Devices need a management IP (set by Discover or on the General tab).

1. **Plan (read-only).**
   - **Diff.** OneConfig reads each running config and shows exactly what it will add. Settings it doesn't manage (licenses, certificates, platform defaults, unused ports) are never touched.
   - **Stale settings.** Old SNMP communities, extra users, retired servers, routes and unused ACLs are listed in red, each with its own checkbox, and only the ones you tick are removed. The account you're logged in with is never removed, and an ACL still referenced anywhere (NAT, a route-map, an interface) is never offered.
   - **Blockers.** OneConfig blocks a push that would lock you out: a management ACL that excludes the computer you're pushing from, or a switch managed through Vlan1 (the STIG config shuts Vlan1 down).
2. **Push.** For each device, one at a time:
   - save a local backup (`~/.oneconfig/backups/`) and an on-device snapshot
   - apply the change under the OS's own auto-rollback (table below), so if OneConfig loses contact the device rolls back by itself
   - log in again on a new session, then compare interfaces up, OSPF neighbors and BGP sessions before and after
   - only if all is well, confirm (and save). Otherwise roll back.
   - It refuses to push if the running config changed since the plan (ignoring what changes on every read: IOS change stamps, the time NX-OS and EOS print, FortiOS's re-encrypted secrets), and by default stops at the first failed device.
3. **Roll back** any pushed device later from the results.

**Cisco ASA is plan only.** The ASA has no commit-confirm or revert timer, so if a change cut OneConfig off nothing would undo it. Push reads the ASA and shows the plan (access lists that differ are cleared and written again, with their `access-group`; group members the device has and the plan doesn't are removed), warns when a `nameif` change would delete the commands that name it or when failover settings change, and offers **Copy plan** (secrets masked). Apply it yourself in a maintenance window with console access to both units.

| OS | Snapshot | Applied under | Confirm | Manual rollback |
|---|---|---|---|---|
| IOS-XE | `archive config` | `configure terminal revert timer N` | `configure confirm` | `configure replace <archive> force` |
| EOS | `copy running-config flash:…` | `configure session X`, then `commit timer`. A rejected line aborts the session, so nothing changes | `configure session X commit` | `configure replace flash:…` |
| NX-OS | `checkpoint …` | `configure replace … commit-timeout` (see below) | `configure replace commit` | `rollback running-config checkpoint …` |
| PAN-OS | `save config to oneconfig-<time>.xml` | the candidate config, then `commit`. A rejected line runs `revert config`, so nothing changes. **No timer** (see below) | — | `load config from oneconfig-<time>.xml` + `commit` |
| FortiOS | `execute backup config flash` (a revision) | `cfg-save revert` with the timer, then the change as one `execute config-transaction`. A rejected line aborts the transaction, so nothing changes | `execute cfg save`, then `cfg-save automatic` | `execute restore config flash <revision>` (reboots) |
| Junos | `show configuration \| save /var/tmp/…` | `configure exclusive`, the `set` lines, `commit check`, then `commit confirmed N`. A rejected line or failed check is discarded (`rollback 0`), so nothing changes | `commit` | `load override /var/tmp/…` + `commit` |

NX-OS has a commit timer only for `configure replace`, which needs a complete config. So the switch builds it itself:
1. apply the change and copy the running config to bootflash;
2. roll back to the checkpoint;
3. replace with that file under the commit timeout.

For those few seconds the change is live without a timer; the plan says so. NX-OS's `copp profile strict` asks for confirmation, so push leaves it for you to set by hand. If verification fails on NX-OS or EOS, the device rolls back when its timer ends.

**FortiOS rolls back by rebooting.** Its revert timer undoes unsaved changes by rebooting to the saved configuration (an HA pair reboots both units), so a failed health check or a lost session costs an outage, but the firewall comes back as it was. FortiOS saves revert mode itself, so after such a reboot OneConfig logs in again and, once it sees the change is gone, turns it off (`cfg-save automatic`). It never does that while the change is still live, because that would save it; if the reload didn't run, the revert timer reboots the firewall and OneConfig tells you to switch it off afterwards. Entries in numbered tables (policies, central SNAT, routes, DoS policies) are matched by name or prefix, so OneConfig's policy 1 never overwrites yours; its policies are then moved into its order. Optional removals read like `delete firewall policy 7 (allow-all)`. The plan warns when the firewall uses policy NAT (OneConfig turns on central NAT; policies that name a virtual IP must go first) or when HA settings change, and leaves out disk logging on models without a log disk.

**PAN-OS has no commit-confirm timer**, so the plan warns: if a commit cuts OneConfig off, nothing undoes it by itself; load the named snapshot from the console. Before it starts, OneConfig refuses to push if the candidate already has someone else's uncommitted changes (`show config diff`), because a commit would publish them too. Rules OneConfig owns are deleted and rewritten whole when they differ, then moved into OneConfig's order. A failed verification loads the snapshot back and commits. A commit is persistent, so there's no separate save.

On Junos a failed verification is undone at once with `rollback 1` + `commit`; if the session is lost, `commit confirmed` rolls back by itself. A Junos commit is already persistent, so there's no separate save. OneConfig warns that Junos OSPF key chains need Junos 23.4R1 or later.

After a confirmed push, OneConfig deletes its own older snapshots on NX-OS, EOS and Junos (`oneconfig-*` checkpoints, flash files, `/var/tmp` files), keeping the newest 3. NX-OS caps the number of checkpoints, and flash fills up. IOS-XE does the same through `archive maximum 14`.

**SSH host keys.** The first time OneConfig connects to a device it remembers the device's SSH host key in `~/.oneconfig/known_hosts`. If the key later changes, it refuses to connect, so an impostor never receives your login or secrets. After a legitimate change (a replaced device), delete that device's line from the file.

**Backups** in `~/.oneconfig/backups/` are readable by your user account only, because running configs hold reversible type-7 passwords.

**Secrets.** Every `<PLACEHOLDER>` (enable secret, AAA keys, OSPF/BGP keys, SNMPv3 passwords) is filled at push time.
- **Keychain.** Values can be remembered in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service), along with the device login. They're kept per network, under an id each network gets when it's created (saved in its file), so two networks that share a name never share secrets. Values are checked before they're remembered.
- **Never shown.** They never reach the web page: the diff shows `<ENABLE-SECRET>`, not the value (also when FortiOS needs a quote or backslash in it escaped). Secrets must be at least 8 characters, so they can be masked reliably; usernames (`<ADMIN-USER>`, `<SNMP-USER>`, `<BACKUP-USER>`) are shown as typed.
- **Set once.** Secrets already on a device are left alone unless something else on the line changes.

## Known vulnerabilities (CVE)

Each device's Config tab has a **Known vulnerabilities** section for its OS version (Discover fills it in, or set it on the General tab). **Check now** looks the release up:

- **Cisco PSIRT openVuln** when you've added a Cisco API key (free at apiconsole.cisco.com). Cisco's own per-release answer, with the first fixed release for each advisory.
- **NVD** otherwise, and always for NX-OS (`cisco:nx-os`, versions like `10.3(4a)`) EOS (`arista:eos`; NVD often lists `4.31.2F` as `4.31.2`, so OneConfig tries both) and Junos (`juniper:junos`; NVD splits the release and drops the build, so `21.4R3-S5.4` is looked up as `21.4:r3-s5` and `15.1X53-D33.3` as `15.1x53:d33`, checked against NVD's CPE dictionary). PAN-OS versions (`10.2.9-h1`) are looked up in Palo Alto's own advisory feed (security.paloaltonetworks.com, no account), with the fixed release from the same train; if that fails, NVD's `paloaltonetworks:pan-os` with the hotfix as the update field. FortiOS (`7.4.4`) is looked up in NVD as `fortinet:fortios`. Both CPE formats are checked against NVD's CPE dictionary. No account needed. ASA versions shown as `9.18(4)22` are looked up as `9.18.4.22`, Cisco's and NVD's form, with Cisco's ASA feed when you have a key and NVD's `cisco:adaptive_security_appliance_software` otherwise. NVD matches on version only, so it can list flaws in features you don't run (wireless controller, web UI). Where NVD has both, Cisco's CVSS score is shown, so severities match Cisco's advisories.

Results are cached for 24 hours in `~/.oneconfig/cve-cache.json` and shown without a new lookup.

## Advisor (AI)

Choose **Advisor** in the command menu, then pick a provider for each run:

| Provider | Where your network data goes |
|---|---|
| Local model: Ollama, LM Studio, vLLM or any OpenAI-compatible server | Only to the server URL you enter (default `http://localhost:11434/v1`) |

**Local model context.** Prompts run about 2,500 tokens for one device and 8,500 for the 4-device example. Many local models start with a 4,096-token context and silently drop the start of a longer prompt. Start Ollama with `OLLAMA_CONTEXT_LENGTH=32768 ollama serve` (or raise the context length in LM Studio). The preview shows the estimated token count.
| Claude API (Sonnet, Opus or Haiku) | Anthropic's API, with your own API key |

Tasks: **Explain findings** (STIG, best-practice and CVE, worst first), **Review the design**, **Ask a question**, and **Draft changes**. Scope it to the whole network or one device.

- **What's sent.** The network model, findings, cached CVEs and the generated configs: hostnames, addresses and topology included. Secrets are never included, since generated configs hold `<PLACEHOLDER>` names, and a masking pass also scrubs passwords, keys, hashes and SNMP communities if real config text ever gets in. **Preview what's sent** shows the exact text before anything leaves your computer.
- **Drafts are text only.** Nothing is applied to any device. To deploy a change, make it in OneConfig so it's generated, audited and pushed with the diff and auto-rollback.

**API keys** live under File → API keys and go into the OS keychain. Only their names ever come back to the page. With no keychain, keys are held for that page session only.

## Command line

```bash
pip install -e ".[dev]" && playwright install chromium && pytest   # tests, incl. browser tests of the UI
oneconfig build network.json -o configs/   # write one .cfg per device
oneconfig audit router1.txt                 # audit a saved running config; exits 1 on high/critical
oneconfig audit --os nx-os nexus1.txt       # same for NX-OS, ASA, PAN-OS, FortiOS, Arista EOS or Junos (--os asa|panos|fortios|eos|junos)
oneconfig stig router1.txt --platform router --external GigabitEthernet0/0/0   # STIG report; exits 1 on any open finding
oneconfig stig leaf1.txt --os eos --platform l3switch                           # NX-OS, Arista EOS or Junos (--os nx-os|eos|junos)
oneconfig stig fw1.txt --os asa --platform firewall                             # Cisco ASA or FTD
oneconfig stig pa1.txt --os panos --platform firewall                           # Palo Alto (set or brace format)
oneconfig stig fg1.txt --os fortios --platform firewall                         # FortiGate (show full-configuration)
tests/syntax/build_parser.sh   # once: builds Batfish's NX-OS/EOS/Junos/ASA parsers so tests/test_syntax.py runs (needs a JDK, ANTLR 4, Guava; a custom ONECONFIG_BATFISH_PARSER must end in oneconfig-bfparse/classes)
tests/syntax/build_panspec.sh  # once: fetches Palo Alto's pan-os-codegen specs (pinned commit) for the PAN-OS syntax test
tests/syntax/build_fosspec.sh  # once: fetches Fortinet's FortiOS schema (pinned commit) for the FortiOS syntax test
tests/build_stigmanager.sh     # once: fetches STIG Manager's checklist parser (pinned commit; runs with Node.js) for tests/test_cklb.py
oneconfig stig fw1.conf --os fortios --platform firewall --cklb fw1.cklb      # also write a STIG Viewer 3 checklist
```

Third-party notices: see `NOTICE`.

## Layout

```
oneconfig/model.py          network data model + validation (blocks newline/command injection)
oneconfig/templates/*.j2    one template per platform
oneconfig/render.py         model -> config text
oneconfig/audit.py          best-practice rules: severity, why, fix, score
oneconfig/stig.py           DISA STIG checks over the official rule catalog (IOS-XE), plus the shared helpers
oneconfig/stig_nxos.py      NX-OS checks (reuses IOS-XE checks where DISA's rule IDs mean the same)
oneconfig/stig_eos.py       Arista EOS checks
oneconfig/stig_junos.py     Junos checks (Juniper Router and EX switch STIGs) and the display-set parser
oneconfig/junos.py          SHA-512 crypt for local passwords, IOS-style ACL entries -> Junos filter terms
oneconfig/stig_asa.py       Cisco ASA checks (NDM, Firewall; IPS and VPN gated)
oneconfig/asa.py            zone rules -> per-interface access lists, NAT, which interface reaches a server
oneconfig/stig_panos.py     Palo Alto checks (NDM, ALG, IDPS; TLS/VPN gated) and the set/brace parser
oneconfig/panos.py          rules and NAT in PAN-OS terms (ICMP as applications, pre-NAT addresses)
oneconfig/stig_fortios.py   FortiGate checks (NDM, Firewall) and the config-block parser
oneconfig/fortios.py        NAT as central SNAT, virtual IPs and IP pools; policies in FortiOS terms
oneconfig/stig/catalog.json DISA rule IDs, severities, titles (public domain)
oneconfig/stig/rules.json.gz DISA check/fix text, CCIs, benchmark IDs for checklists (public domain; tools/stig_text.py)
oneconfig/cklb.py           STIG Viewer 3 checklists (.cklb) from STIG results
oneconfig/discover.py       sweep, SSH/serial (netmiko), SNMP (pysnmp), CDP/LLDP parsing (ntc-templates)
oneconfig/diff.py           hierarchy-aware, merge-safe config diff (and a set-line diff for Junos, list-aware for ASA and PAN-OS, block-aware for FortiOS)
oneconfig/push.py           plan, revert-timer push, verify, confirm/rollback
oneconfig/vault.py          OS keychain storage for secrets and logins
oneconfig/cve.py            CVE lookup: Cisco PSIRT openVuln, NVD fallback, 24 h cache
oneconfig/ai.py             Advisor prompts, secret masking, Claude API + OpenAI-compatible clients
oneconfig/server.py         localhost API for the UI, background discovery and push jobs
oneconfig/ui/index.html     the visual builder (no build step)
tests/                      pytest suite, incl. simulated IOS-XE / NX-OS / EOS / Junos / ASA / PAN-OS / FortiGate devices (SSH, console, config state, each OS's
                            rollback mechanism), an SNMP agent, a recorded NVD response, fake Claude / OpenAI-compatible APIs,
                            golden configs and the Batfish syntax check (tests/syntax)
```

Adding a vendor means adding a template plus its interface naming. The model stays the same.

## Roadmap

1. ~~Generator core + rules audit + visual builder~~
2. ~~DISA STIG checks~~, ~~STIG Viewer .cklb export~~
3. ~~Discovery: subnet sweep, SSH + CDP/LLDP walk, SNMP, console/serial~~
4. ~~Diff, push, verify, roll back (credentials in the OS keychain)~~
5. ~~CVE lookup (Cisco PSIRT / NVD) and AI advisor, local or cloud~~
6. ~~Cisco NX-OS and Arista EOS~~ (generate, audit, STIG, discover, push)
7. ~~Juniper Junos~~ (generate, audit, STIG, discover, CVE, push)
8. Firewalls: ~~Cisco ASA~~ (generate, audit, STIG, discover, CVE, plan-only push; FTD audited), ~~Palo Alto~~ (generate, audit, sunset STIG, discover, CVE, push), ~~FortiGate~~ (generate, audit, STIG, discover, CVE, push under the revert timer). VPN deferred
9. ~~Desktop app~~ (macOS, `packaging/OneConfig.spec`); Windows build next

## Security

OneConfig changes live network devices. Try it against lab equipment before production. To report a vulnerability, see [SECURITY.md](SECURITY.md); please don't open a public issue for one.

## License

MIT, see [LICENSE](LICENSE). Third-party material and its licenses are listed in [NOTICE](NOTICE).

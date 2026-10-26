"""What a broken or hostile device can send back must neither crash the parsers nor stall them.
Each case below took seconds to minutes before its fix; the limits leave room for a slow machine."""
import time
from pathlib import Path

from oneconfig import ai, audit, push, stig
from oneconfig.stig_junos import flatten

FIX = Path(__file__).parent / "fixtures"


class _Device:  # answers every show command with the same text
    def __init__(self, text):
        self.text = text

    def send_command(self, *a, **kw):
        return self.text


def _quick(fn, *args, limit=2.0):
    t = time.perf_counter()
    out = fn(*args)
    assert time.perf_counter() - t < limit, f"{fn.__name__} took {time.perf_counter() - t:.1f}s"
    return out


def test_one_long_line_in_show_output_doesnt_stall_the_health_check():
    for nos in ("ios-xe", "eos"):  # 4 KB of digits: 24 s in the OSPF and BGP templates
        assert _quick(push.health, _Device("1" * 4000), nos) == {"interfaces up": 0, "OSPF neighbors": 0, "BGP sessions": 0}


def test_an_unclosed_quote_ends_at_its_line():
    _quick(audit.audit, 'edit "' + '\\"' * 20000, "junos")  # 40 KB: quadratic before, about a minute
    # the broken statement ends at its own ; and the next line still counts (a missing domain-name would be a false finding)
    assert flatten('system {\n  host-name "EX1;\n  domain-name corp.local;\n  login { message "a \\"q\\" b"; }\n}\n') == [
        'system host-name "EX1', "system domain-name corp.local", 'system login message "a \\"q\\" b"']


def test_runs_of_blank_lines_stay_linear():
    cfg = "\n" * 20000 + (FIX / "brownfield_acc1.cfg").read_text()
    _quick(stig.stig_audit, cfg, "l3switch", None, "ios-xe")  # about a minute before
    _quick(stig.stig_audit, "\n" * 20000 + (FIX / "dc/nxos_running.txt").read_text(), "l3switch", None, "nx-os")
    _quick(ai.mask, "\n" * 20000 + " key-string 7 0822455D0A16\n")
    assert _quick(push.latest_archive, "\n" * 20000) is None


def test_odd_asa_security_level_doesnt_crash_the_stig_audit():
    cfg = (FIX / "asa/running_config.txt").read_text().replace(" security-level 100", " security-level 100%:", 1)
    assert stig.stig_audit(cfg, "firewall", None, "asa")["results"]


def test_odd_values_in_pasted_configs_dont_crash_the_stig_audit():
    eos = (FIX / "dc/eos_running.txt").read_text() + "\ninterface Ethernet48\n   switchport mode access\n   switchport access vlan }\n"
    assert stig.stig_audit(eos, "l3switch", None, "eos")["results"]
    pan = (FIX / "panos/running_set.txt").read_text() + (
        "\nset network virtual-router default routing-table ip static-route D destination 0.0.0.0/0"
        "\nset network virtual-router default routing-table ip static-route D nexthop ip-address 198.51.1\n")
    assert stig.stig_audit(pan, "firewall", None, "panos")["results"]
    _quick(stig.stig_audit, "\n" * 20000 + (FIX / "dc/eos_running.txt").read_text(), "l3switch", None, "eos")

import json
import urllib.error
from pathlib import Path

import pytest

from oneconfig import cve

FIX = Path(__file__).parent / "fixtures" / "cve"
NVD_REAL = json.loads((FIX / "nvd_iosxe_17.9.4a.json").read_text())  # recorded from services.nvd.nist.gov, Oct 2026
# Built from the field names in Cisco's openVuln OSType docs (a live response needs an API key).
CISCO_DOCS = {"advisories": [
    {"advisoryId": "cisco-sa-iosxe-webui-privesc-j22SaA4z", "advisoryTitle": "Cisco IOS XE Software Web UI Privilege Escalation",
     "sir": "Critical", "cvssBaseScore": "10.0", "cves": ["CVE-2023-20198"], "publicationUrl": "https://sec.cloudapps.cisco.com/x",
     "firstPublished": "2023-10-16T15:00:00", "firstFixed": ["17.9.4a"]},
    {"advisoryId": "cisco-sa-snmp-dos", "advisoryTitle": "SNMP DoS", "sir": "Medium", "cvssBaseScore": "6.5", "cves": ["CVE-2025-1"],
     "publicationUrl": "https://sec.cloudapps.cisco.com/y", "firstPublished": "2025-01-01T00:00:00", "firstFixed": ["17.9.6"]}]}


@pytest.fixture(autouse=True)
def tmp_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cve, "CACHE", tmp_path / "cache.json")


class Fake:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, url, data=None, headers=None):
        self.calls.append((url, data, headers))
        for prefix, resp in self.routes.items():
            if url.startswith(prefix):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise AssertionError(f"unexpected call {url}")


@pytest.mark.parametrize("raw,norm", [("17.09.04a", "17.9.4a"), ("17.9.4a", "17.9.4a"), ("16.12.10", "16.12.10"), (" 17.3.1W ", "17.3.1w")])
def test_normalize_version(raw, norm):
    assert cve.normalize_version(raw) == norm


def test_nvd_real_response_parsed():
    get = Fake({cve.NVD_API: NVD_REAL})
    r = cve.lookup("17.09.04a", get=get)
    assert r["source"] == "NVD" and len(r["items"]) == 66
    assert r["counts"] == {"Critical": 3, "High": 39, "Medium": 24}
    top = r["items"][0]
    assert top["severity"] == "Critical" and top["cvss"] == 9.8 and top["id"] == "CVE-2026-20272"
    assert "cpeName=cpe%3A2.3%3Ao%3Acisco%3Aios_xe%3A17.9.4a" in get.calls[0][0]
    assert any("sec.cloudapps.cisco.com" in i["url"] for i in r["items"])  # links to Cisco's advisory when NVD has it
    assert "features you don't use" in r["note"]


def test_cisco_preferred_with_key():
    get = Fake({cve.CISCO_TOKEN: {"access_token": "tok", "expires_in": 3600}, cve.CISCO_API: CISCO_DOCS})
    r = cve.lookup("17.9.4", {"cisco_client_id": "id", "cisco_client_secret": "sec"}, get=get)
    assert r["source"] == "Cisco PSIRT openVuln" and r["items"][0]["cvss"] == 10.0 and r["items"][0]["fixed_in"] == ["17.9.4a"]
    token_call, api_call = get.calls
    assert token_call[1] == {"client_id": "id", "client_secret": "sec", "grant_type": "client_credentials"}
    assert api_call[2]["Authorization"] == "Bearer tok" and "version=17.9.4" in api_call[0]


def test_cisco_none_found_and_bad_version():
    ok = Fake({cve.CISCO_TOKEN: {"access_token": "t"}, cve.CISCO_API: {"_status": 404, "errorCode": "NO_IOS_AFFECTING_ADVISORIES_FOUND"}})
    assert cve.cisco("17.15.1", "i", "s", ok) == []
    bad = Fake({cve.CISCO_TOKEN: {"access_token": "t"}, cve.CISCO_API: {"_status": 406, "errorCode": "INVALID_IOS_VERSION",
                                                                          "errorMessage": "Invalid version"}})
    with pytest.raises(ValueError, match="Invalid version"):
        cve.cisco("99.1.1", "i", "s", bad)
    with pytest.raises(PermissionError):
        cve.cisco("17.9.4", "i", "s", Fake({cve.CISCO_TOKEN: {"_status": 401, "error": "invalid_client"}}))


def test_falls_back_to_nvd_when_cisco_unreachable():
    get = Fake({cve.CISCO_TOKEN: urllib.error.URLError("timed out"), cve.NVD_API: NVD_REAL})
    r = cve.lookup("17.9.4a", {"cisco_client_id": "i", "cisco_client_secret": "s"}, get=get)
    assert r["source"] == "NVD" and "couldn't be reached" in r["note"]


def test_cache_avoids_second_call():
    get = Fake({cve.NVD_API: NVD_REAL})
    cve.lookup("17.9.4a", get=get)
    cve.lookup("17.09.04a", get=get)
    assert len(get.calls) == 1 and cve.cached("17.9.4a")["counts"]["Critical"] == 3
    cve.lookup("17.9.4a", refresh=True, get=get)
    assert len(get.calls) == 2


def test_rejects_garbage_version():
    with pytest.raises(ValueError, match="doesn't look like"):
        cve.lookup("latest", get=Fake({}))


def test_nxos_and_eos_use_their_own_nvd_products():
    assert cve.cpe("10.3(4a)", "nx-os") == r"cpe:2.3:o:cisco:nx-os:10.3\(4a\)"  # NVD escapes the parentheses
    get = Fake({cve.NVD_API: NVD_REAL})
    r = cve.lookup("10.3(4A)", get=get, nos="nx-os")
    assert r["os"] == "nx-os" and "cpeName=cpe%3A2.3%3Ao%3Acisco%3Anx-os%3A10.3%5C%28" in get.calls[0][0]
    assert cve.cached("10.3(4a)", "nx-os")["source"] == "NVD" and cve.cached("10.3(4a)") is None  # separate from IOS-XE
    with pytest.raises(ValueError, match="NX-OS release"):
        cve.lookup("17.9.4a", nos="nx-os", get=get)


def test_eos_falls_back_to_the_version_without_its_train_letter():
    calls = []

    def get(url, data=None, headers=None):
        calls.append(url)
        return NVD_REAL if "4.31.2%3A" in url or url.endswith("4.31.2&resultsPerPage=2000") else {"vulnerabilities": []}
    r = cve.lookup("4.31.2F", get=get, nos="eos", keys={"cisco_client_id": "i", "cisco_client_secret": "s"})
    assert "arista%3Aeos%3A4.31.2f" in calls[0] and "arista%3Aeos%3A4.31.2&" in calls[1] and len(r["items"]) == 66
    assert r["source"] == "NVD"  # Cisco's API is IOS-XE only here


@pytest.mark.parametrize("shown,cpe_name", [("21.4R3-S5.4", "cpe:2.3:o:juniper:junos:21.4:r3-s5:*:*:*:*:*:*"),
                                            ("22.4R3.25", "cpe:2.3:o:juniper:junos:22.4:r3:*:*:*:*:*:*"),
                                            ("15.1X53-D33.3", "cpe:2.3:o:juniper:junos:15.1x53:d33:*:*:*:*:*:*")])
def test_junos_cpe_matches_nvd(shown, cpe_name):
    """Formats checked against NVD's CPE dictionary (services.nvd.nist.gov/rest/json/cpes/2.0)."""
    assert cve.cpe(cve.check_version(shown, "junos"), "junos") == cpe_name


def test_junos_rejects_non_releases():
    with pytest.raises(ValueError, match="Junos release"):
        cve.check_version("17.9.4a", "junos")


@pytest.mark.parametrize("shown,norm", [("9.18(4)22", "9.18.4.22"), ("9.20(2)", "9.20.2"), ("9.16.4.18", "9.16.4.18")])
def test_asa_versions_are_dotted_like_cisco_and_nvd(shown, norm):
    v = cve.check_version(shown, "asa")
    assert v == norm and cve.cpe(v, "asa") == f"cpe:2.3:a:cisco:adaptive_security_appliance_software:{norm}:*:*:*:*:*:*:*"
    with pytest.raises(ValueError, match="ASA release"):
        cve.check_version("17.9.4a", "asa")


def test_asa_uses_ciscos_asa_feed_with_a_key():
    get = Fake({cve.CISCO_TOKEN: {"access_token": "tok"}, cve.CISCO_OSTYPE["asa"]: CISCO_DOCS})
    r = cve.lookup("9.18(4)22", keys={"cisco_client_id": "i", "cisco_client_secret": "s"}, get=get, nos="asa")
    assert r["source"] == "Cisco PSIRT openVuln" and r["version"] == "9.18.4.22"


# Shaped like Palo Alto's feed: CVE JSON 5 records (security.paloaltonetworks.com/api; schema at apis.io).
PAN_FEED = [{"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2026-0101", "state": "PUBLISHED", "datePublished": "2026-09-10T16:00:00Z"},
             "containers": {"cna": {"title": "PAN-OS: Authentication Bypass in the Management Web Interface",
                                    "metrics": [{"cvssV4_0": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}],
                                    "affected": [{"vendor": "Palo Alto Networks", "product": "PAN-OS", "versions": [
                                        {"version": "11.1.0", "lessThan": "11.1.6-h1", "status": "affected", "versionType": "custom"},
                                        {"version": "10.2.0", "lessThan": "10.2.14", "status": "affected", "versionType": "custom"}]}],
                                    "descriptions": [{"lang": "en", "value": "x"}], "references": [{"url": "https://security.paloaltonetworks.com/CVE-2026-0101"}]}}},
            {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": "CVE-2026-0077", "datePublished": "2026-08-01T00:00:00Z"},
             "containers": {"cna": {"title": "PAN-OS: Denial of Service in DNS Security",
                                    "metrics": [{"cvssV3_1": {"version": "3.1", "vectorString": "x", "baseScore": 5.3, "baseSeverity": "MEDIUM"}}],
                                    "affected": [], "descriptions": [], "references": []}}}]


def test_panos_uses_palo_altos_feed_without_a_key():
    get = Fake({cve.PAN_API: PAN_FEED})
    r = cve.lookup("11.1.4-H7", get=get, nos="panos")
    assert r["source"] == "Palo Alto Networks security advisories" and r["version"] == "11.1.4-h7"
    assert "version=PAN-OS+11.1.4-h7&product=PAN-OS" in get.calls[0][0]
    top = r["items"][0]
    assert (top["id"], top["severity"], top["cvss"], top["fixed_in"]) == ("CVE-2026-0101", "Critical", 9.3, ["11.1.6-h1"])
    assert top["url"] == "https://security.paloaltonetworks.com/CVE-2026-0101" and r["counts"] == {"Critical": 1, "Medium": 1}


def test_panos_falls_back_to_nvd_and_names_the_hotfix_as_the_update():
    assert cve.cpe("11.1.4-h7", "panos") == "cpe:2.3:o:paloaltonetworks:pan-os:11.1.4:h7:*:*:*:*:*:*"
    assert cve.cpe("10.2.9", "panos") == "cpe:2.3:o:paloaltonetworks:pan-os:10.2.9:-:*:*:*:*:*:*"
    r = cve.lookup("10.2.9", get=Fake({cve.PAN_API: OSError("offline"), cve.NVD_API: {"vulnerabilities": []}}), nos="panos")
    assert r["source"] == "NVD" and "couldn't be reached" in r["note"]
    with pytest.raises(ValueError, match="PAN-OS release"):
        cve.check_version("9.18(4)22", "panos")


@pytest.mark.parametrize("nos,shown,cpe_name", [("fortios", "7.4.4", "cpe:2.3:o:fortinet:fortios:7.4.4:*:*:*:*:*:*:*"),
                                                ("panos", "11.1.4-h7", "cpe:2.3:o:paloaltonetworks:pan-os:11.1.4:h7:*:*:*:*:*:*"),
                                                ("panos", "11.1.4", "cpe:2.3:o:paloaltonetworks:pan-os:11.1.4:-:*:*:*:*:*:*")])
def test_firewall_cpes_match_nvd(nos, shown, cpe_name):
    """Formats checked against NVD's CPE dictionary (services.nvd.nist.gov/rest/json/cpes/2.0, 2026-10-22)."""
    assert cve.cpe(cve.check_version(shown, nos), nos) == cpe_name


def test_fortios_uses_nvd():
    get = Fake({cve.NVD_API: NVD_REAL})
    r = cve.lookup("7.4.4", get=get, nos="fortios")
    assert r["os"] == "fortios" and r["source"] == "NVD" and "fortinet%3Afortios%3A7.4.4" in get.calls[0][0]
    with pytest.raises(ValueError, match="FortiOS release"):
        cve.check_version("v7.4.4,build2662", "fortios")

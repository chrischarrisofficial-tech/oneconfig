"""Known vulnerabilities for a Cisco IOS-XE, Cisco NX-OS, Cisco ASA, Palo Alto PAN-OS, Arista EOS or Juniper Junos release.

Cisco PSIRT openVuln first (IOS-XE and ASA): Cisco's own per-release answer, including first-fixed releases (free API key).
NVD as fallback: no account needed, but it matches on version alone, so it can list flaws in features
you don't run (wireless controller, web UI...)."""
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CISCO_TOKEN = "https://id.cisco.com/oauth2/default/v1/token"
CISCO_API = "https://apix.cisco.com/security/advisories/v2/OSType/iosxe"
CISCO_OSTYPE = {"ios-xe": CISCO_API, "asa": CISCO_API.replace("iosxe", "asa")}
PAN_API = "https://security.paloaltonetworks.com/json"  # Palo Alto's own per-version advisories (no account needed)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = Path.home() / ".oneconfig" / "cve-cache.json"
TTL = 24 * 3600
_CACHE_LOCK = threading.Lock()
RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "None": 5}


def normalize_version(v: str) -> str:
    """'17.09.04a' (show version banner) -> '17.9.4a' (what Cisco and NVD use)."""
    m = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)([a-z]*)\s*$", v or "", re.I)
    return f"{int(m[1])}.{int(m[2])}.{int(m[3])}{m[4].lower()}" if m else (v or "").strip()


VERSION = {"ios-xe": (r"^\d+\.\d+\.\d+[a-z]*$", "an IOS-XE release (like 17.9.4a)"),
           "nx-os": (r"^\d+\.\d+\(\d+[a-z]?\)[\w.()]*$", "an NX-OS release (like 10.3(4a))"),
           "eos": (r"^\d+\.\d+\.\d+[a-z]*$", "an EOS release (like 4.31.2F)"),
           "junos": (r"^\d+\.\d+(r\d+(-s\d+)?|x\d+-d\d+)(\.\d+)?$", "a Junos release (like 21.4R3-S5.4)"),
           "asa": (r"^\d+\.\d+\.\d+(\.\d+)?$", "an ASA release (like 9.18(4)22)"),
           "panos": (r"^\d+\.\d+\.\d+(-h\d+)?$", "a PAN-OS release (like 11.1.4-h7)"),
           "fortios": (r"^\d+\.\d+\.\d+$", "a FortiOS release (like 7.4.4)")}
VENDOR = {"ios-xe": "cisco", "nx-os": "cisco", "eos": "arista", "junos": "juniper", "asa": "cisco", "panos": "paloaltonetworks", "fortios": "fortinet"}


def check_version(v: str, nos: str = "ios-xe") -> str:
    v = normalize_version(v) if nos == "ios-xe" else (v or "").strip().lower()  # NVD writes suffix letters in lower case
    if nos == "asa":  # show version prints 9.18(4)22; Cisco and NVD write 9.18.4.22
        v = re.sub(r"^(\d+\.\d+)\((\d+)\)(\d*)$", lambda m: f"{m[1]}.{m[2]}" + (f".{m[3]}" if m[3] else ""), v)
    pattern, what = VERSION[nos]
    if not re.match(pattern, v):
        raise ValueError(f"'{v}' doesn't look like {what}")
    return v


def cpe(version: str, nos: str = "ios-xe") -> str:
    """NVD's CPE name. NX-OS versions keep their parentheses, escaped: cpe:2.3:o:cisco:nx-os:10.3\\(4a\\)."""
    if nos == "nx-os":
        return "cpe:2.3:o:cisco:nx-os:" + version.replace("(", "\\(").replace(")", "\\)")
    if nos == "asa":
        return f"cpe:2.3:a:cisco:adaptive_security_appliance_software:{version}:*:*:*:*:*:*:*"
    if nos == "panos":  # NVD puts the hotfix in the update field: 11.1.4-h7 -> 11.1.4:h7
        base, _, hot = version.partition("-")
        return f"cpe:2.3:o:paloaltonetworks:pan-os:{base}:{hot or '-'}:*:*:*:*:*:*"
    if nos == "fortios":
        return f"cpe:2.3:o:fortinet:fortios:{version}:*:*:*:*:*:*:*"
    if nos == "junos":  # NVD splits release and update and drops the build: 21.4R3-S5.4 -> 21.4:r3-s5, 15.1X53-D33 -> 15.1x53:d33
        m = re.match(r"^(\d+\.\d+)(r\d+(?:-s\d+)?)(?:\.\d+)?$", version) or re.match(r"^(\d+\.\d+x\d+)-(d\d+)(?:\.\d+)?$", version)
        return f"cpe:2.3:o:juniper:junos:{m[1]}:{m[2]}:*:*:*:*:*:*"
    return f"cpe:2.3:o:{'arista:eos' if nos == 'eos' else 'cisco:ios_xe'}:{version}"


def http(url, data=None, headers=None, timeout=25):
    """JSON over HTTPS. Returns the decoded body for 2xx and for JSON error bodies (APIs put error codes there)."""
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return {"_status": e.code, **json.loads(raw)}
        except ValueError:
            raise ConnectionError(f"HTTP {e.code} from {urllib.parse.urlsplit(url).netloc}") from None


def cisco(version: str, client_id: str, client_secret: str, get=None, nos: str = "ios-xe") -> list[dict]:
    get = get or http
    tok = get(CISCO_TOKEN, {"client_id": client_id, "client_secret": client_secret, "grant_type": "client_credentials"},
              {"Content-Type": "application/x-www-form-urlencoded"})
    if "access_token" not in tok:
        raise PermissionError("Cisco rejected the API key: " + str(tok.get("error_description") or tok.get("error") or tok))
    items, page = [], 1
    while True:
        q = urllib.parse.urlencode({"version": version, "pageIndex": page, "pageSize": 100})
        data = get(f"{CISCO_OSTYPE[nos]}?{q}", None, {"Authorization": f"Bearer {tok['access_token']}", "Accept": "application/json"})
        if isinstance(data, dict) and data.get("errorCode"):
            if "NO_" in data["errorCode"]:  # e.g. NO_IOS_AFFECTING_ADVISORIES_FOUND
                break
            raise ValueError(f"Cisco: {data.get('errorMessage') or data['errorCode']} (version {version})")
        batch = data.get("advisories", []) if isinstance(data, dict) else data
        items += batch
        if len(batch) < 100:
            break
        page += 1
    return [{"id": a.get("advisoryId"), "title": a.get("advisoryTitle", ""), "severity": (a.get("sir") or "None").title(),
             "cvss": _num(a.get("cvssBaseScore")), "cves": a.get("cves") or [], "url": a.get("publicationUrl"),
             "published": str(a.get("firstPublished") or "")[:10], "fixed_in": a.get("firstFixed") or [], "source": "cisco"}
            for a in items]


def paloalto(version: str, get=None) -> list[dict]:
    """Palo Alto's advisory feed for one PAN-OS release: CVE JSON 5 records (the feed's own format)."""
    get = get or http
    data = get(f"{PAN_API}?{urllib.parse.urlencode({'version': 'PAN-OS ' + version, 'product': 'PAN-OS'})}", None, {"Accept": "application/json"})
    if isinstance(data, dict) and data.get("_status"):
        raise ConnectionError(f"Palo Alto returned HTTP {data['_status']}")
    out = []
    for r in data if isinstance(data, list) else data.get("data", []):
        cna = (r.get("containers") or {}).get("cna") or {}
        cid = (r.get("cveMetadata") or {}).get("cveId") or r.get("ID") or ""
        best = next((m[k] for k in ("cvssV4_0", "cvssV3_1") for m in cna.get("metrics", []) if k in m), {})
        fixed = sorted({v["lessThan"] for a in cna.get("affected", []) for v in a.get("versions", [])
                        if v.get("status") == "affected" and v.get("lessThan") and v["lessThan"].split(".")[:2] == version.split(".")[:2]})
        out.append({"id": cid, "title": cna.get("title") or "", "severity": (best.get("baseSeverity") or "None").title(),
                    "cvss": best.get("baseScore"), "cves": [cid] if cid.startswith("CVE-") else [],
                    "url": f"https://security.paloaltonetworks.com/{cid}" if cid else None,
                    "published": str((r.get("cveMetadata") or {}).get("datePublished") or "")[:10], "fixed_in": fixed, "source": "paloalto"})
    return out


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def nvd(version: str, api_key: str = "", get=None, nos: str = "ios-xe") -> list[dict]:
    get = get or http
    q = urllib.parse.urlencode({"cpeName": cpe(version, nos), "resultsPerPage": 2000})
    data = get(f"{NVD_API}?{q}", None, {"apiKey": api_key} if api_key else {})
    if data.get("_status"):
        raise ConnectionError(f"NVD returned HTTP {data['_status']}")
    if nos == "eos" and not data.get("vulnerabilities") and re.search(r"[a-z]+$", version):
        return nvd(re.sub(r"[a-z]+$", "", version), api_key, get, nos)  # NVD often lists EOS 4.31.2F as 4.31.2
    vendor = VENDOR[nos]
    out = []
    for v in data.get("vulnerabilities", []):
        c = v["cve"]
        m = c.get("metrics", {})
        # Prefer Cisco's own score (it matches Cisco's advisories); otherwise NVD's primary score.
        best = next((sorted(m[k], key=lambda x: (vendor not in (x.get("source") or ""), x.get("type") != "Primary"))[0]["cvssData"]
                     for k in ("cvssMetricV31", "cvssMetricV30") if m.get(k)), {})
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        advisory = next((r["url"] for r in c.get("references", []) if re.search(r"CiscoSecurityAdvisory/|arista\.com/.*advisor|juniper\.net/(s/article/)?JSA|security\.paloaltonetworks\.com/|fortiguard\.(com|fortinet\.com)/psirt/FG-IR", r.get("url", ""))), None)
        out.append({"id": c["id"], "title": desc[:220], "severity": (best.get("baseSeverity") or "None").title(),
                    "cvss": best.get("baseScore"), "cves": [c["id"]],
                    "url": advisory or f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                    "published": c.get("published", "")[:10], "fixed_in": [], "source": "nvd"})
    return out


def _cache():
    try:
        return json.loads(CACHE.read_text())
    except (OSError, ValueError):
        return {}


def _key(version, nos):
    return version if nos == "ios-xe" else f"{nos}:{version}"  # IOS-XE keeps its original cache key


def cached(version: str, nos: str = "ios-xe"):
    """Last lookup for a version, if any (no network)."""
    try:
        return _cache().get(_key(check_version(version, nos), nos))
    except ValueError:
        return None


def lookup(version: str, keys: dict | None = None, refresh=False, get=None, nos: str = "ios-xe") -> dict:
    version, keys = check_version(version, nos), keys or {}
    hit = _cache().get(_key(version, nos))
    if hit and not refresh and time.time() - hit["fetched"] < TTL:
        return hit
    note = ""
    if nos == "panos":
        try:
            items, source = paloalto(version, get), "Palo Alto Networks security advisories"
        except (OSError, ConnectionError, ValueError) as e:
            items, source = nvd(version, keys.get("nvd_api_key", ""), get, nos), "NVD"
            note = f"Palo Alto's advisory feed couldn't be reached ({e}); showing NVD results instead."
    elif nos in CISCO_OSTYPE and keys.get("cisco_client_id") and keys.get("cisco_client_secret"):
        try:
            items, source = cisco(version, keys["cisco_client_id"], keys["cisco_client_secret"], get, nos), "Cisco PSIRT openVuln"
        except (OSError, ConnectionError) as e:  # Cisco unreachable: still give an answer
            items, source = nvd(version, keys.get("nvd_api_key", ""), get, nos), "NVD"
            note = f"Cisco's API couldn't be reached ({e}); showing NVD results instead."
    else:
        items, source = nvd(version, keys.get("nvd_api_key", ""), get, nos), "NVD"
        note = "From NVD by version only, so some may affect features you don't use." + (
            " Add a Cisco API key for exact results." if nos in CISCO_OSTYPE else "")
    items.sort(key=lambda a: (RANK.get(a["severity"], 9), -(a["cvss"] or 0)))
    counts = {}
    for a in items:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    result = {"version": version, "os": nos, "source": source, "note": note, "fetched": time.time(), "counts": counts, "items": items}
    with _CACHE_LOCK:  # re-read so a parallel lookup's entry isn't lost; replace atomically so a crash can't empty it
        store = _cache()
        store[_key(version, nos)] = result
        from . import private
        private.write(CACHE, json.dumps(store))  # which releases this network runs: this account's business only
    return result

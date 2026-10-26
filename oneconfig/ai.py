"""AI advisor: explain findings, review the design, answer questions, draft changes.

Providers: any OpenAI-compatible server (Ollama, LM Studio, vLLM) or Anthropic's Claude API.
What gets sent is built from OneConfig's own model and generated configs, which hold <PLACEHOLDER>
names instead of secrets. mask() also scrubs real secrets in case device config text ever ends up
in the prompt. Hostnames, addresses and topology are sent; the UI can preview the exact text first."""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import cve
from .audit import audit
from .render import context as dev_context
from .render import render
from .stig import stig_audit

CLAUDE_URL = "https://api.anthropic.com/v1/messages"
OS_NAME = {"ios-xe": "IOS-XE", "nx-os": "NX-OS", "eos": "Arista EOS", "junos": "Juniper Junos", "asa": "Cisco ASA", "panos": "Palo Alto PAN-OS", "fortios": "Fortinet FortiOS"}
CUT = "\n\n(Answer cut off at the length limit. Narrow the scope to one device or ask a narrower question.)"
MAX_CHARS = 120_000
_MASKS = [(re.compile(p, re.I | re.M), r) for p, r in (
    (r"\b(secret|password)(\s+\d)?\s+\S+", r"\1 <redacted>"),
    (r"^([ \t]*key-string)(\s+\d)?\s+\S.*$", r"\1 <redacted>"),
    (r"(\bkey)([ \t]+[0-9])?[ \t]+(?!chain\b)(?!\d+[ \t]*$)\S.*$", r"\1 <redacted>"),  # line-start and inline keys
    (r"(snmp-server community|\bsnmp community|snmp-community-string)[ \t]+\S+", r"\1 <redacted>"),
    (r"(\bauth\s+(?:sha\d*|md5|sha-\d+))\s+\S+", r"\1 <redacted>"),  # sha, sha256 (ASA), sha-256
    (r"(\bpriv\s+(?:aes(?:\s+\d+)?|des|3des))\s+\S+", r"\1 <redacted>"),
    (r"(authentication-key\s+\d+\s+\S+)(\s+\d)?\s+\S+", r"\1 <redacted>"),
    (r"(\bauthentication-key)(\s+\d)?\s+\S+", r"\1 <redacted>"),
    (r"(authentication mode hmac-sha-256)\s+\S+", r"\1 <redacted>"),
    (r"(message-digest-key\s+\d+\s+md5)(\s+\d)?\s+\S+", r"\1 <redacted>"),
    (r"(pre-shared-key|isakmp key)(\s+\d)?\s+\S+", r"\1 <redacted>"),
    (r"\b(ascii-text|hexadecimal)\s+\S+", r"\1 <redacted>"),  # Junos IPsec / key strings
    (r"\$\d\$\S+", "<redacted>"),
    (r"(://[^:/\s@]+:)[^@\s]+@", r"\1<redacted>@"),  # user:password@ in copy URLs (ASA backup applet)
    (r"^[ \t]+[0-9A-F]{8}( [0-9A-F]{8})+\s*$\n?", ""),  # certificate hex blobs: no value to a reviewer
    # FortiOS: quoted values and ENC hashes, whole rest of the line
    (r"^([ \t]*set (?:password|passwd|key|key-string|secret|auth-pwd|priv-pwd|psksecret|secondary-key|secondary-secret))\s+\S.*$", r"\1 <redacted>"),
)]
# FortiOS SNMP communities are named on a `set name` line inside their own block.
_FOS_COMMUNITY = re.compile(r"^config system snmp community\n.*?^end$", re.M | re.S)

SYSTEM = ("You are a senior network engineer reviewing a network (Cisco IOS-XE, Cisco NX-OS, Cisco ASA, Palo Alto PAN-OS, Fortinet FortiOS, Arista EOS and/or Juniper Junos) built with OneConfig. The facts below come "
          "from the tool: the network model, generated configs, DISA STIG results, best-practice findings and known CVEs. "
          "Be specific and cite device names and config lines. Only suggest commands that exist on each device's own OS; say "
          "when you're unsure. Secrets are shown as <PLACEHOLDER> or <redacted>; never ask for them.")
MODES = {
    "explain": "Explain the open findings (STIG, best-practice and CVE) in plain English: what each means, the real-world "
               "risk, and the exact fix. Put CAT I and Critical first and group duplicates across devices.",
    "design": "Review the network design: single points of failure and redundancy, spanning-tree root placement, routing "
              "design, addressing, management-plane protection and segmentation. Give a prioritized list of improvements "
              "with the reason for each.",
    "ask": "Answer the user's question about this network using only the facts provided. If the facts don't contain the "
           "answer, say exactly what's missing.",
    "draft": "Draft the configuration changes, in each device's own OS syntax, for the user's request. For each device, write '### HOSTNAME' and then "
             "one fenced code block with only the lines to add or change. Keep changes minimal and list the risks. These are "
             "suggestions for an engineer to review, not something that will be applied automatically. Use <PLACEHOLDER> "
             "names for any secret.",
}


_PLACEHOLDER = re.compile(r"<[A-Z0-9][A-Z0-9.-]*>\s*$")


def mask(text: str) -> str:
    """Scrub secret values; keep <PLACEHOLDER> names (they're labels, not secrets)."""
    for rx, rep in _MASKS:
        text = rx.sub(lambda m: m[0] if _PLACEHOLDER.search(m[0]) else m.expand(rep), text)
    return _FOS_COMMUNITY.sub(lambda m: re.sub(r"^([ \t]*set name)\s+.*$", r"\1 <redacted>", m[0], flags=re.M), text)


def build_prompt(net, mode: str, question: str = "", focus: str | None = None) -> tuple[str, str]:
    """(system, user) text. Pure function of the network, so the UI can preview it exactly."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    if mode in ("ask", "draft") and not question.strip():
        raise ValueError("Type a question or the change you want")
    devices = [d for d in net.devices if not focus or d.hostname == focus]
    if focus and not devices:
        raise ValueError(f"No device named {focus}")
    summary = {"name": net.name, "vlans": [v.model_dump() for v in net.vlans],
               "security": net.security.model_dump(mode="json"), "links": [l.model_dump() for l in net.links],
               "devices": [{"hostname": d.hostname, "role": d.role, "mgmt_ip": str(d.mgmt_ip or ""), "os_version": d.os_version}
                           for d in net.devices]}
    parts = [f"## Network\n```json\n{json.dumps(summary, indent=1)}\n```"]
    for d in devices:
        cfg = render(d, net)
        st = stig_audit(cfg, d.role, dev_context(d, net), d.platform)
        opened = [f"- [{r['cat']}] {r['id']} {r['title']} -> {r['detail']}" for r in st["results"] if r["status"] == "open"]
        bp = [f"- [{f['severity']}] {f['title']} {f['where']}".rstrip() for f in audit(cfg, d.platform)["findings"] if f["severity"] != "info"]
        vul = cve.cached(d.os_version, d.platform) if d.os_version else None
        cves = [f"- [{a['severity']} {a['cvss'] or '-'}] {a['id']} {a['title'][:160]}" + (f" (fixed in {', '.join(a['fixed_in'][:4])})" if a["fixed_in"] else "")
                for a in (vul or {}).get("items", [])[:15]]
        parts.append("\n".join([
            f"## {d.hostname} ({d.role}, {OS_NAME[d.platform]} {d.os_version or 'version unknown'})",
            f"STIG compliance {st['summary']['compliance']}%; open findings:", *(opened or ["- none"]),
            "Best-practice findings:", *(bp or ["- none"]),
            f"Known vulnerabilities ({vul['source']}, {sum(vul['counts'].values())} total, top 15):" if vul else
            "Known vulnerabilities: not checked yet.", *cves,
            "Generated config:", "```", mask(cfg), "```"]))
    user = "\n\n".join(parts)
    if len(user) > MAX_CHARS:  # keep the prompt bounded: drop configs, keep findings
        user = re.sub(r"Generated config:\n```.*?```", "Generated config: (omitted to fit the model's context)", user, flags=re.S)
    task = MODES[mode] + (f"\n\nUser request: {question.strip()}" if question.strip() else "")
    return SYSTEM + "\n\n" + task, user


def _post(url, body, headers, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        try:
            err = json.loads(detail).get("error", {})
            detail = err.get("message", detail) if isinstance(err, dict) else str(err)
        except ValueError:
            pass
        raise ConnectionError(f"HTTP {e.code} from {urllib.parse.urlparse(url).netloc}: {detail}") from None
    except urllib.error.URLError as e:
        raise ConnectionError(f"Can't reach {urllib.parse.urlparse(url).netloc}: {e.reason}") from None


def is_loopback(url: str) -> bool:
    return (urllib.parse.urlparse(url).hostname or "") in ("localhost", "127.0.0.1", "::1")


def check_base_url(url: str, has_key: bool):
    """http(s) only. A key travels only over https, or plain http to this computer (a local model server)."""
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("The model server address must start with http:// or https://")
    if has_key and u.scheme == "http" and not is_loopback(url):
        raise ValueError("An API key is only sent over https (or plain http to this computer). Use https:// for "
                         + u.hostname)


def complete(provider: dict, system: str, user: str, timeout=300) -> str:
    kind = provider.get("kind")
    if kind == "claude":
        if not provider.get("api_key"):
            raise ValueError("Add a Claude API key first")
        r = _post(provider.get("url") or CLAUDE_URL,
                  {"model": provider.get("model") or "claude-sonnet-5-5", "max_tokens": 4096, "system": system,
                   "messages": [{"role": "user", "content": user}]},
                  {"x-api-key": provider["api_key"], "anthropic-version": "2023-06-01"}, timeout)
        text = "".join(b.get("text", "") for b in r.get("content", []) if b.get("type") == "text")
        return text + (CUT if r.get("stop_reason") == "max_tokens" else "")
    if kind == "openai":
        base = (provider.get("base_url") or "http://localhost:11434/v1").rstrip("/")
        check_base_url(base, bool(provider.get("api_key")))
        r = _post(base + "/chat/completions",
                  {"model": provider.get("model") or "llama3.1", "temperature": 0.2, "stream": False,
                   "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
                  {"Authorization": f"Bearer {provider['api_key']}"} if provider.get("api_key") else {}, timeout)
        choice = r["choices"][0]
        return choice["message"]["content"] + (CUT if choice.get("finish_reason") == "length" else "")
    raise ValueError("provider kind must be 'claude' or 'openai'")

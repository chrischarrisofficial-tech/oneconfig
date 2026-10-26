"use strict";
const $ = s => document.querySelector(s);
const svg = $("#topo");
// The server's per-launch token arrives in the URL fragment from the launch file; every API call carries it.
const TOKEN = (() => { const m = location.hash.match(/^#t=([\w-]+)/); try { if (m) sessionStorage.setItem("oneconfig.t", m[1]); } catch {}
  if (m) history.replaceState(null, "", location.pathname);
  try { return m?.[1] || sessionStorage.getItem("oneconfig.t") || ""; } catch { return m?.[1] || ""; } })();
const _fetch = window.fetch.bind(window);
const SESSION = () => { try { return sessionStorage.getItem("oneconfig.s") || ""; } catch { return ""; } };  // signed-in session, this tab only
window.fetch = (u, o = {}) => _fetch(u, {...o, headers:{...(o.headers || {}), "X-OneConfig-Token":TOKEN, "X-OneConfig-Session":SESSION()}}).then(r => {
  if (r.status === 401 && r.headers.get("X-OneConfig-Login")) { signIn(); return r; }  // accounts are on and this tab isn't signed in
  if (r.status === 401 && !document.querySelector("#stale")) {  // the server restarted with a new key: say so instead of looking empty
    const p = document.createElement("p");
    p.id = "stale"; p.className = "errors"; p.style.margin = "8px"; p.setAttribute("role", "alert");
    p.textContent = "OneConfig was restarted, so this tab's access key no longer works. Open it again from the link that `oneconfig serve` printed (or ~/.oneconfig/open.html).";
    document.body.prepend(p);
  }
  return r;
});
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k.startsWith("aria-")) e.setAttribute(k, String(v));
    else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c);
  return e;
};
const add = (el, ...kids) => el.append(...kids.flat(Infinity).filter(k => k != null && k !== false));
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const short = n => n.replace(/^TenGigabitEthernet/i,"Te").replace(/^TwentyFiveGigE/i,"Twe").replace(/^GigabitEthernet/i,"Gi")
  .replace(/^FastEthernet/i,"Fa").replace(/^Port-channel/i,"Po").replace(/^Loopback/i,"Lo");
const store = {
  get(k){ try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set(k,v){ try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

let net, sel = null, tab = null, level = store.get("oneconfig.level") || 1;
let built = {}, errors = [], mode = null, linkA = null, drag = null, timer = null;
const openCards = new WeakSet();
const dev = name => net.devices.find(d => d.hostname === name);
const ROLE = {router:"ROUTER", switch:"SWITCH", l3switch:"L3 SWITCH", firewall:"FIREWALL"};
const OSN = {"ios-xe":"IOS-XE", "nx-os":"NX-OS", "eos":"EOS", "junos":"Junos", "asa":"ASA", "panos":"PAN-OS", "fortios":"FortiOS"};
const FW = d => d.role === "firewall";
const FW_OS = ["asa", "panos", "fortios"];
const roleOs = d => ROLE[d.role] + (d.platform && d.platform !== "ios-xe" ? " · " + OSN[d.platform] : "");

/* ---------- persistence + build loop ---------- */
let histAt = 0, histTimer = null;
function keepVersion(reason = "edited") {  // a saved version of the network, on this computer (File > History)
  if (!net?.id || !net.devices) return Promise.resolve();
  histAt = Date.now();
  return post("/api/history/save", {network:net, reason}).catch(() => {});
}
function changed(redraw) {
  store.set("oneconfig.net", net);
  clearTimeout(histTimer); histTimer = setTimeout(() => keepVersion(), Math.max(2000, 20000 - (Date.now() - histAt)));
  if (redraw) renderPanel();
  drawCanvas(); renderHeader();
  clearTimeout(timer); timer = setTimeout(rebuild, 250);
}
async function rebuild() {
  try {
    const r = await fetch("/api/build", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(net)});
    const j = await r.json();
    if (r.ok) { built = j; errors = []; } else errors = j.errors || ["Build failed"];
  } catch { errors = ["Can't reach the OneConfig engine. Is `python -m oneconfig serve` running?"]; }
  drawCanvas(); renderErrors(); renderDash();
  if (["config","overview"].includes(tab)) renderPanel();
  refreshSide();
}

/* ---------- form helpers ---------- */
function field(label, obj, key, o = {}) {
  let inp;
  const cur = obj[key] ?? o.def;
  const set = v => {
    const old = obj[key];
    if (v === "" || v == null || (Array.isArray(v) && !v.length)) delete obj[key]; else obj[key] = v;
    o.after?.(old, obj[key]);
    (o.onchange || changed)(o.redraw);
  };
  if (o.type === "bool") {
    inp = h("input", {type:"checkbox"}); inp.checked = !!cur;
    inp.addEventListener("change", () => set(inp.checked));
  } else if (o.type === "select") {
    inp = h("select", {}, o.options.map(([v, t]) => h("option", {value:v}, t)));
    inp.value = cur ?? "";
    inp.addEventListener("change", () => set(inp.value));
  } else {
    const max = o.type === "list" || o.type === "password" ? null : o.max ?? (["hostname", "domain"].includes(key) || (key === "name" && obj !== net) ? 63 : 200);
    inp = h("input", {placeholder:o.placeholder || "", spellcheck:"false", type:o.type === "password" ? "password" : "text", maxlength:max,
      autocomplete:o.type === "password" ? "off" : null});
    inp.value = o.type === "list" ? (cur || []).join(", ") : (cur ?? "");
    inp.addEventListener("change", () => {
      const v = inp.value.trim();
      set(o.type === "num" ? (v === "" || isNaN(v) ? "" : Number(v))
        : o.type === "list" ? v.split(/[,\s]+/).filter(Boolean) : v);
    });
  }
  return h("label", {class:"fld", "data-lvl":o.lvl || 1}, h("span", {}, label), inp);
}
function card(obj, title, sub, body, onDelete, lvl) {  // body: the fields, or a function that makes them on first open
  const inner = h("div");
  const fill = () => inner.childNodes.length || add(inner, typeof body === "function" ? body() : body,
    h("div", {class:"row"}, h("button", {class:"btn danger", onclick:onDelete}, "Remove")));
  const d = h("details", {class:"card", "data-lvl":lvl || 1}, h("summary", {}, h("span", {}, title), h("small", {}, sub)), inner);
  d.open = openCards.has(obj);
  if (d.open) fill();
  d.addEventListener("toggle", () => { if (d.open) { fill(); openCards.add(obj); } else openCards.delete(obj); });
  return d;
}
const addBtn = (label, fn, lvl) => h("div", {class:"row", "data-lvl":lvl || 1}, h("button", {class:"btn", onclick:fn}, "+ " + label));
// Number Ticker (after Magic UI's): a score that changes counts there from the value on screen in 280ms, and onFrame
// moves its bar or ring in step. A re-render mid-count hands the count to the new element; a new value mid-count turns
// around from where it is. The first sighting just shows the number, so opening a tab doesn't replay anything.
const nums = new Map();  // key -> {shown, target, el, onFrame, run}
function ticker(el, key, v, onFrame) {
  let s = nums.get(key);
  if (!s || typeof v !== "number" || typeof s.shown !== "number" || REDUCED.matches) {
    if (s) cancelAnimationFrame(s.run);
    nums.set(key, s = {shown:v, target:v});
  } else if (v !== s.target) {
    cancelAnimationFrame(s.run);
    const from = s.shown, t0 = performance.now();
    s.target = v;
    const step = t => { const k = Math.min(1, (t - t0) / 280);
      s.shown = k < 1 ? from + (v - from) * (1 - (1 - k) ** 4) : v;
      s.el.textContent = Math.round(s.shown); s.onFrame?.(s.shown);
      s.run = k < 1 ? requestAnimationFrame(step) : 0; };
    s.run = requestAnimationFrame(step);
  }
  s.el = el; s.onFrame = onFrame;
  el.textContent = typeof s.shown === "number" ? Math.round(s.shown) : v ?? "—";
  if (typeof s.shown === "number") onFrame?.(s.shown);
  return el;
}
const hp = (score, label = "SECURITY", key) => {
  const band = score >= 80 ? "good" : score >= 50 ? "mid" : "low";
  const fill = h("div", {class:"hp-fill", "data-band":band}), show = v => fill.style.clipPath = `inset(0 ${100 - v}% 0 0)`;  // clipped, so the LED segments don't stretch
  show(score);
  return h("div", {class:"hp", role:"meter", "aria-valuenow":score, "aria-valuemin":0, "aria-valuemax":100, "aria-label":"Security score"},
    fill, h("span", {class:"hp-label"}, label), key ? ticker(h("span", {class:"hp-num"}, score), key, score, show) : h("span", {class:"hp-num"}, score));
};
const findings = (r, host) => [hp(r.score, undefined, host && "audit:" + host), ...(r.findings.length ? r.findings.map(f =>
  h("details", {class:"finding sev-" + f.severity},
    h("summary", {}, h("span", {class:"chip"}, f.severity), f.title, f.where ? h("span", {class:"muted"}, "  " + f.where) : null),
    h("p", {}, f.why), f.fix ? h("pre", {}, f.fix) : null)) : [h("p", {class:"muted"}, "No findings. This config is clean.")])];

const STATUS = {open:"Open", not_reviewed:"Not reviewed", not_a_finding:"Not a finding", not_applicable:"N/A"};
const CATCLS = {"CAT I":"sev-critical", "CAT II":"sev-medium", "CAT III":"sev-low"};
let stigFilter = "open";
function stigView(r, target) {
  const s = r.summary, wrap = h("div");
  const cklb = async () => {  // DISA STIG Viewer 3 checklist, built by the server from DISA's rule text
    const res = await fetch("/api/cklb", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({stig:r, ...target})});
    if (res.ok) download(target.host + ".cklb", await res.text(), "application/json");
  };
  const count = k => k === "open" ? s.open["CAT I"] + s.open["CAT II"] + s.open["CAT III"] : s[k];
  const draw = () => {
    const rows = r.results.filter(x => x.status === stigFilter);
    wrap.replaceChildren(hp(s.compliance, "STIG", "stig:" + target.host),
      h("p", {class:"muted"}, r.benchmarks.map(b => `${b.id.replaceAll("_", " ")} V${b.version}R${b.release}`).join(" · ") + " · DISA"),
      h("div", {class:"row"}, h("button", {class:"btn ghost", onclick:cklb}, "Download checklist (.cklb)")),
      h("div", {class:"cats"}, Object.keys(CATCLS).map(c => h("span", {class:CATCLS[c]}, h("span", {class:"chip"}, `${c} open: ${s.open[c]}`)))),
      h("div", {class:"tabs stigtabs", role:"tablist"}, Object.entries(STATUS).map(([k, t]) =>
        h("button", {role:"tab", "aria-selected":k === stigFilter, onclick:() => { stigFilter = k; draw(); }}, `${t} (${count(k)})`))),
      ...(rows.length ? rows.map(x => h("details", {class:"finding " + (x.status === "open" ? CATCLS[x.cat] : x.status === "not_a_finding" ? "sev-pass" : "sev-info")},
        h("summary", {}, h("span", {class:"chip"}, x.cat), x.id + " ", h("span", {class:"muted"}, x.title)),
        h("p", {}, x.detail), x.fix ? h("pre", {}, x.fix) : null, h("p", {class:"muted"}, `${x.vuln} · ${x.rule}`)))
        : [h("p", {class:"muted"}, stigFilter === "open" ? "No open findings." : "Nothing in this group.")]));
  };
  draw(); return wrap;
}

const SEVCLS = {Critical:"sev-critical", High:"sev-high", Medium:"sev-medium", Low:"sev-low"};
const appKeys = {};  // typed in File > API keys when there's no OS keychain: this page session only, never stored
function cveView(d, v) {
  const wrap = h("div"), log = h("pre", {style:"max-height:90px;display:none"});
  if (!d.os_version) return h("p", {class:"muted"}, "Set the OS version on the General tab (Discover fills it in) to check this release for known vulnerabilities.");
  const check = async () => {
    log.style.display = "block"; log.textContent = "Starting…";
    try {
      const job = await pollJob((await post("/api/cve", {version:d.os_version, os:d.platform || "ios-xe", refresh:true, keys:appKeys})).job, log);
      if (!job.error && built[d.hostname]) { built[d.hostname].cve = job.result; renderPanel();
        logEvent(`${d.hostname} CVE check: ${job.result.items.length} advisor${job.result.items.length === 1 ? "y" : "ies"}`, job.result.counts.Critical > 0); }
    } catch (e) { log.textContent = e.message; }
  };
  let all = false;
  const draw = () => wrap.replaceChildren(
    h("div", {class:"row"}, h("button", {class:"btn", onclick:check}, v ? "Check again" : "Check now"),
      h("span", {class:"muted", style:"align-self:center"}, v ? `${v.source} · ${new Date(v.fetched * 1000).toLocaleString()}` : `${OSN[d.platform || "ios-xe"]} ${d.os_version} not checked yet`)),
    log,
    ...(v ? [
      v.note ? h("p", {class:"muted"}, v.note) : null,
      h("div", {class:"cats"}, Object.keys(SEVCLS).filter(k => v.counts[k]).map(k => h("span", {class:SEVCLS[k]}, h("span", {class:"chip"}, `${k}: ${v.counts[k]}`))),
        v.items.length ? null : h("span", {class:"sev-pass"}, h("span", {class:"chip"}, "None found"))),
      ...(all ? v.items : v.items.slice(0, 10)).map(a => h("details", {class:"finding " + (SEVCLS[a.severity] || "sev-info")},
        h("summary", {}, h("span", {class:"chip"}, a.severity + (a.cvss ? " " + a.cvss : "")), a.id + " ", h("span", {class:"muted"}, a.title.slice(0, 120))),
        h("p", {}, a.title), a.cves.length > 1 || a.cves[0] !== a.id ? h("p", {class:"muted"}, a.cves.join(", ")) : null,
        h("p", {class:"muted"}, `Published ${a.published || "?"}` + (a.fixed_in.length ? ` · First fixed in ${a.fixed_in.join(", ")}` : "")),
        /^https:\/\//.test(a.url || "") ? h("p", {}, h("a", {href:a.url, target:"_blank", rel:"noopener noreferrer"}, "Read the advisory")) : null)),
      v.items.length > 10 && !all ? h("button", {class:"btn ghost", onclick:() => { all = true; draw(); }}, `Show all ${v.items.length}`) : null] : []));
  draw(); return wrap;
}

/* ---------- header ---------- */
function renderHeader() {
  $("#netname").value = net.name || "";
  document.body.dataset.level = level;
  document.querySelectorAll(".levels button").forEach(b => b.setAttribute("aria-pressed", +b.dataset.l === level));
  const d = sel && dev(sel);
  const now = d ? `${d.hostname} · ${roleOs(d)}` : "Whole network";
  $("#editing").replaceChildren(h("small", {}, "Now editing"), h("span", {title:now}, now));
  renderDash();
}
$("#netname").addEventListener("change", e => { net.name = e.target.value; changed(); });
document.querySelectorAll(".levels button").forEach(b => b.addEventListener("click", () => {
  level = +b.dataset.l; store.set("oneconfig.level", level); renderHeader();
}));

/* ---------- canvas ---------- */
const band = s => s == null ? "none" : s >= 80 ? "good" : s >= 50 ? "mid" : "bad";
const BANDC = {good:"var(--a)", mid:"var(--warn)", bad:"var(--t)", none:"var(--dim)"};
// Each role gets the faceplate its hardware has: router = a few copper ports + SFPs + console, switch = a row of
// copper, L3 switch = SFP cages, firewall = a status screen + a handful of ports.
function face(role, c, bad) {
  const port = (x, w = 5) => `<rect class="port" x="${x}" y="-4" width="${w}" height="8" rx="1"/>`;
  const led = (x, on, cls = "") => `<circle class="${cls}" cx="${x}" cy="-9" r="1.4" fill="${on ? c : "var(--dim)"}"/>`;
  let f = "";
  if (role === "router") { for (let i = 0; i < 4; i++) f += port(-22 + i * 8) + led(-19.5 + i * 8, i < 2, i === 0 ? "blink" : "");
    f += port(12, 9) + port(23, 9) + `<rect x="36" y="-4" width="6" height="8" rx="1" fill="none" stroke="var(--a)" stroke-width=".8"/>`; }
  else if (role === "firewall") { f += `<rect x="-28" y="-7" width="30" height="14" rx="2" fill="rgba(0,0,0,.55)" stroke="var(--line)"/>`
    + `<text x="-13" y="2.5" text-anchor="middle" style="font:500 6px var(--mono);fill:${c}">${bad ? "ALERT" : "SECURE"}</text>`;
    for (let i = 0; i < 4; i++) f += port(8 + i * 8) + led(10.5 + i * 8, i < 3, i === 1 ? "blink" : ""); }
  else if (role === "l3switch") for (let i = 0; i < 7; i++) f += port(-24 + i * 10, 8) + led(-20 + i * 10, i < 5, i === 2 ? "blink" : "");
  else for (let i = 0; i < 10; i++) f += port(-25 + i * 6.6) + led(-22.5 + i * 6.6, i % 3 !== 2, i === 4 ? "blink" : "");
  return f;
}
let view = {k:1, ox:0, oy:0}, userView = null, pan = null;  // userView: set once the user pans or zooms
const ZMIN = .2, ZMAX = 3;
function setView(v) {  // move the world group only (cheap enough for every wheel tick and pan frame)
  view = userView = v;
  $("#world")?.setAttribute("transform", `translate(${v.ox},${v.oy}) scale(${v.k})`);
}
function zoomAt(f, sx, sy) {  // zoom by f keeping the map point under (sx, sy) (map-tile pixels) where it is
  const k = Math.min(ZMAX, Math.max(ZMIN, view.k * f)), mx = (sx - view.ox) / view.k, my = (sy - view.oy) / view.k;
  setView({k, ox:sx - mx * k, oy:sy - my * k});
}
function zoomBy(f) { const m = mapSize(); zoomAt(f, m.width / 2, m.height / 2); }
function fitMap() { userView = null; drawCanvas(); }
const mapName = n => { const s = n.split(".")[0]; return s.length > 24 ? s.slice(0, 11) + "…" + s.slice(-12) : s; };
const labelHalf = d => Math.max(70, mapName(d.hostname).length * 4.6);  // half the label's width in map units, about
function fitView(w, ht) {  // shrink (never grow) a map that doesn't fit the tile, centered
  if (!net.devices.length) return {k:1, ox:0, oy:0};
  const ys = net.devices.map(d => d.y);
  const x0 = Math.min(...net.devices.map(d => d.x - labelHalf(d))), x1 = Math.max(...net.devices.map(d => d.x + labelHalf(d))), y0 = Math.min(...ys) - 50, y1 = Math.max(...ys) + 60;
  if (x0 >= 0 && y0 >= 0 && x1 <= w && y1 <= ht) return {k:1, ox:0, oy:0};
  const k = Math.min(1, w / (x1 - x0), ht / (y1 - y0));
  return {k, ox:(w - (x1 - x0) * k) / 2 - x0 * k, oy:(ht - (y1 - y0) * k) / 2 - y0 * k};
}
// Animated Beam (after Magic UI's), played once: when a device is selected, a bright head with a fading tail runs out
// along each of its links, 50ms apart, showing what it connects to. Each run is pinned to a time on the SVG's own clock,
// so a redraw while it plays (a build, a drag) picks it up mid-run, and once it's over it isn't drawn at all.
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)");
const BEAM_S = .6, BEAM_GAP = .05;
let beamAt = null;  // {host, t}: the device whose links run, and when (SVG clock seconds)
function beam(a, b, n, ln, begin) {
  const len = Math.hypot(b.x - a.x, b.y - a.y) || 1, ux = (b.x - a.x) / len, uy = (b.y - a.y) / len, L = Math.min(90, len * .45);
  const p = d => [+(a.x + ux * d).toFixed(1), +(a.y + uy * d).toFixed(1)];
  const [hx0, hy0] = p(0), [tx0, ty0] = p(-L), [hx1, hy1] = p(len + L), [tx1, ty1] = p(len);  // head from a to past b; tail follows
  const an = (at, v0, v1) => `<animate attributeName="${at}" values="${v0};${v1}" dur="${BEAM_S}s" begin="${begin.toFixed(3)}s" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines=".77 0 .175 1"/>`;
  return `<linearGradient id="beam${n}" gradientUnits="userSpaceOnUse" x1="${hx0}" y1="${hy0}" x2="${tx0}" y2="${ty0}">`
    + an("x1", hx0, hx1) + an("y1", hy0, hy1) + an("x2", tx0, tx1) + an("y2", ty0, ty1)
    + `<stop offset="0" style="stop-color:var(--tx);stop-opacity:0"/><stop offset=".04" style="stop-color:var(--tx)"/><stop offset=".325" style="stop-color:var(--a)"/><stop offset="1" style="stop-color:var(--a);stop-opacity:0"/></linearGradient>`
    + `<line class="beam" ${ln} stroke="url(#beam${n})"/>`;
}
function linksMarkup() {
  const pos = Object.fromEntries(net.devices.map(d => [d.hostname, d]));
  let out = "", j = 0;
  const now = svg.getCurrentTime(), run = beamAt && !REDUCED.matches ? beamAt.host : null;
  const pairKey = l => [l.a, l.b].sort().join("~"), pairs = {}, seenPair = {};
  for (const l of net.links) pairs[pairKey(l)] = (pairs[pairKey(l)] || 0) + 1;
  for (const l of net.links) {
    let a = pos[l.a], b = pos[l.b];
    if (!a || !b) continue;
    const k = pairKey(l), i = seenPair[k] = (seenPair[k] ?? -1) + 1, off = (i - (pairs[k] - 1) / 2) * 14;
    if (off) {  // fan out parallel links between the same two devices
      const flip = l.a > l.b ? -1 : 1, len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
      const ox = -(b.y - a.y) / len * off * flip, oy = (b.x - a.x) / len * off * flip;
      a = {x:a.x + ox, y:a.y + oy}; b = {x:b.x + ox, y:b.y + oy};
    }
    const lab = (p, q, t) => {  // out past the faceplate, nudged off the line so text never sits on a device
      const dx = q.x - p.x, dy = q.y - p.y, len = Math.hypot(dx, dy) || 1, k = Math.min(Math.abs(dx / len) > .7 ? 72 : 62, len / 3) + i * 28;
      return `<text class="iflabel" x="${p.x + dx / len * k - dy / len * 12}" y="${p.y + dy / len * k + dx / len * 12 + 4}" text-anchor="middle">${esc(short(t))}</text>`;
    };
    const ln = `x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"`;
    out += `<line class="link ${/^(port-channel|ae|agg)/i.test(l.a_if) ? "po" : ""}" ${ln}/>`;
    if (run && (l.a === run || l.b === run)) {  // outward from the selected device
      const begin = beamAt.t + j * BEAM_GAP;
      if (now < begin + BEAM_S) out += l.a === run ? beam(a, b, j, ln, begin) : beam(b, a, j, ln, begin);
      j++;
    }
    out += lab(a, b, l.a_if) + lab(b, a, l.b_if);
  }
  return out;
}
// The map's own size, before any CSS transform (a theme may tilt the map in 3D; its on-screen box is then a projection).
const mapSize = () => ({width:svg.clientWidth || svg.getBoundingClientRect().width, height:svg.clientHeight || svg.getBoundingClientRect().height});
function drawCanvas() {
  const r = mapSize(), W = r.width || 800, H = r.height || 600;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  if (!drag) view = userView || fitView(W, H);
  const vx = W / 2, vy = H * .56;  // the floor's vanishing point
  let floor = "";
  for (let i = -6; i <= 6; i++) floor += `M${vx} ${vy}L${vx + i * W / 5} ${H}`;
  for (const f of [.04, .12, .26, .5]) floor += `M0 ${vy + (H - vy) * f}H${W}`;
  let out = `<defs><filter id="soft" x="-50%" y="-200%" width="200%" height="500%"><feGaussianBlur stdDeviation="7"/></filter>
    <radialGradient id="halo" cx="50%" cy="40%" r="60%"><stop offset="0" style="stop-color:var(--a);stop-opacity:.12"/><stop offset="1" style="stop-color:var(--a);stop-opacity:0"/></radialGradient></defs>
    <rect width="${W}" height="${H}" fill="url(#halo)"/><path d="${floor}" style="stroke:rgba(var(--floor),.08)" fill="none"/>
    <g id="world" transform="translate(${view.ox},${view.oy}) scale(${view.k})">`;
  out += `<g class="links">${linksMarkup()}</g>`;
  for (const d of net.devices) {
    const rs = built[d.hostname], s = rs?.stig?.summary?.compliance ?? rs?.score, bd = band(s), c = BANDC[bd], seg = Math.round((s ?? 0) / 10);
    out += `<g class="node ${d.hostname === sel ? "sel" : ""} ${d.hostname === linkA ? "linkA" : ""} ${bd === "bad" ? "bad" : ""}" data-h="${esc(d.hostname)}" transform="translate(${d.x},${d.y})" tabindex="0" role="button" aria-label="${esc(d.hostname)}">
      <ellipse class="halo" cx="0" cy="20" rx="50" ry="7" style="fill:var(--t)" filter="url(#soft)"/>
      <path class="ring" d="M-58 -12V-23H-47M58 -12V-23H47M-58 12V23H-47M58 12V23H47"/>
      <rect class="slab" x="-48" y="-15" width="96" height="30" rx="${d.role === "router" ? 9 : 5}"/>
      <path class="shine" d="M-40 -14.4H40"/>${d.role === "firewall" ? `<rect x="-48" y="-12" width="3" height="24" style="fill:${bd === "bad" ? "var(--t)" : "var(--a)"}"/>` : ""}
      <circle class="${bd === "bad" ? "blink" : ""}" cx="-40" cy="0" r="2.6" style="fill:${c};filter:drop-shadow(0 0 3px ${c})"/>
      ${face(d.role, c, bd === "bad")}
      <title>${esc(d.hostname)}</title><text class="host" y="-30" text-anchor="middle">${esc(mapName(d.hostname))}</text>
      <text class="role" y="36" text-anchor="middle">${roleOs(d)}</text>
      ${s == null ? "" : Array.from({length:10}, (_, k) => `<rect x="${-39 + k * 8}" y="42" width="6" height="3" rx=".5" style="fill:${k < seg ? c : "rgba(255,255,255,.08)"}"/>`).join("")}
    </g>`;
  }
  svg.innerHTML = out + "</g>";
  $("#empty").style.display = net.devices.length ? "none" : "grid";
}
svg.addEventListener("pointerdown", e => {
  const g = e.target.closest(".node");
  if (!g) { pan = {sx:e.clientX, sy:e.clientY, ox:view.ox, oy:view.oy, k:view.k, moved:false}; svg.setPointerCapture(e.pointerId); return; }
  const d = dev(g.dataset.h);
  const b = g.querySelector(".slab").getBoundingClientRect();  // the faceplate is 96 x 30 map units: its size on screen gives
  drag = {d, sx:e.clientX, sy:e.clientY, ox:d.x, oy:d.y, moved:false,  // the local scale where the device stands (a theme may tilt the map)
    fx:b.width / (96 * view.k) || 1, fy:b.height / (30 * view.k) || 1};
  svg.setPointerCapture(e.pointerId);
});
const overTrash = e => { const r = $("#trash").getBoundingClientRect(); return e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom; };
svg.addEventListener("pointermove", e => {
  if (pan) {
    const dx = e.clientX - pan.sx, dy = e.clientY - pan.sy;
    if (Math.abs(dx) + Math.abs(dy) > 4) { pan.moved = true; svg.classList.add("panning"); }
    if (pan.moved) setView({k:pan.k, ox:pan.ox + dx, oy:pan.oy + dy});
    return;
  }
  if (!drag) return;
  const dx = (e.clientX - drag.sx) / (view.k * drag.fx), dy = (e.clientY - drag.sy) / (view.k * drag.fy);  // screen pixels to map units
  if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true;
  if (drag.moved) { document.body.classList.add("dragging"); $("#trash").classList.toggle("hot", overTrash(e)); }
  if (drag.moved) { drag.d.x = Math.round(drag.ox + dx); drag.d.y = Math.round(drag.oy + dy);
    drag.raf ||= requestAnimationFrame(() => {  // once a frame: move this node and redraw the links, not the whole map
      if (!drag) return;
      drag.raf = 0;
      svg.querySelector(`.node[data-h="${CSS.escape(drag.d.hostname)}"]`)?.setAttribute("transform", `translate(${drag.d.x},${drag.d.y})`);
      svg.querySelector("g.links").innerHTML = linksMarkup();
    }); }
});
svg.addEventListener("pointerup", e => {
  if (pan) {
    const moved = pan.moved; pan = null; svg.classList.remove("panning");
    if (!moved && !mode) { sel = null; tab = null; renderPanel(); drawCanvas(); renderHeader(); openPanel(false); }  // a plain click: deselect, as before
    return;
  }
  if (!drag) return;
  const {d, moved, ox, oy} = drag; drag = null;
  document.body.classList.remove("dragging"); $("#trash").classList.remove("hot");
  if (moved && overTrash(e)) {  // dropped on the trash: put it back where it was, then ask (Cancel leaves it there)
    d.x = ox; d.y = oy; drawCanvas();
    return deleteDevice(d);
  }
  moved ? (store.set("oneconfig.net", net), drawCanvas()) : nodeClick(d.hostname);
});
svg.addEventListener("wheel", e => {  // mouse wheel or trackpad: zoom around the pointer
  e.preventDefault();
  const r = svg.getBoundingClientRect();
  zoomAt(Math.exp(-e.deltaY * (e.deltaMode === 1 ? .05 : .0015)), e.clientX - r.left, e.clientY - r.top);
}, {passive:false});
$("#zoomctl").addEventListener("click", e => { const b = e.target.closest("button"); if (b) ({in:() => zoomBy(1.25), out:() => zoomBy(1 / 1.25), fit:fitMap})[b.dataset.z](); });
$("#trash").addEventListener("click", () => {
  if (sel && dev(sel)) return deleteDevice(dev(sel));
  const t = "Drag a device onto the trash to delete it, or select one first";
  hint(t); setTimeout(() => $("#hint").textContent === t && hint(), 3000);
});
svg.addEventListener("keydown", e => { if (e.key === "Enter" && e.target.closest(".node")) nodeClick(e.target.closest(".node").dataset.h); });
window.addEventListener("resize", () => { fitScreen(); drawCanvas(); });

function openPanel(on = true) { document.body.classList.toggle("panel-open", on); }  // only matters when the panel is a drawer
function nodeClick(name) {
  if (mode === "link") {
    if (!linkA) { linkA = name; hint(`Now pick the device to connect ${name} to`); drawCanvas(); }
    else if (name !== linkA) openLinkModal(dev(linkA), dev(name));
    return;
  }
  if (name !== sel) beamAt = {host:name, t:svg.getCurrentTime()};
  sel = name; if (!["general","interfaces","routing","acls","zones","objects","rules","nat","config"].includes(tab)) tab = "general";
  renderPanel(); drawCanvas(); renderHeader(); openPanel();
}
function hint(text) { const e = $("#hint"); e.textContent = text || ""; e.style.display = text ? "block" : "none"; }

/* ---------- side panel ---------- */
function renderErrors() {
  $("#panel .errors")?.remove();
  if (errors.length) $("#panel").insertBefore(h("div", {class:"errors", role:"alert"},
    h("b", {}, `⚠ ${errors.length} problem${errors.length > 1 ? "s" : ""} — configs are not updated until fixed`),
    h("ul", {}, errors.slice(0, 6).map(x => h("li", {}, x)))), $("#panel .tabs"));
}
function renderPanel() {
  const d = sel && dev(sel);
  if (sel && !d) sel = null;
  const tabs = d ? (FW(d) ? [["general","General"],["interfaces","Interfaces"],["zones","Zones"],["objects","Objects"],["rules","Rules"],["nat","NAT",2],["routing","Routing",2],["config","Config"]]
                          : [["general","General"],["interfaces","Interfaces"],["routing","Routing"],["acls","ACLs",2],["config","Config"]])
                 : [["network","Network"],["security","Security"],["overview","Overview"]];
  if (!tabs.some(t => t[0] === tab)) tab = tabs[0][0];
  const body = h("div", {class:"pbody"});
  ({general:tGeneral, interfaces:tInterfaces, routing:tRouting, acls:tAcls, config:tConfig, zones:tZones, objects:tObjects, rules:tRules, nat:tNat,
    network:tNetwork, security:tSecurity, overview:tOverview})[tab](body, d);
  $("#panel").replaceChildren(
    h("div", {class:"ptitle"}, h("h2", {}, d ? d.hostname : net.name || "Network"), h("small", {}, d ? roleOs(d) + (d.model ? " · " + d.model : "") : "Network settings"),
      h("button", {class:"btn ghost pclose", title:"Close the panel", "aria-label":"Close the panel", onclick:() => openPanel(false)}, "×")),
    h("div", {class:"tabs", role:"tablist"}, tabs.map(([k, t, lvl]) =>
      h("button", {role:"tab", "aria-selected":k === tab, "data-lvl":lvl || 1, onclick:() => { tab = k; renderPanel(); }}, t))),
    body);
  renderErrors();
}

function tGeneral(b, d) {
  add(b, h("h3", {}, "Identity"),
    field("Hostname", d, "hostname", {redraw:true, after(old, nu) {
      for (const l of net.links) { if (l.a === old) l.a = nu; if (l.b === old) l.b = nu; }
      if (sel === old) sel = nu;
    }}),
    field("Role", d, "role", {type:"select", redraw:true, after:() => { if (FW(d) !== FW_OS.includes(d.platform)) { d.platform = FW(d) ? "asa" : "ios-xe"; renameIfs(d); } },
      options:[["router","Router"],["l3switch","Layer 3 switch"],["switch","Layer 2 switch"],["firewall","Firewall"]]}),
    field("Platform", d, "platform", {type:"select", redraw:true, def:"ios-xe", after:() => { if (FW(d) !== FW_OS.includes(d.platform)) d.role = FW_OS.includes(d.platform) ? "firewall" : "router"; fwPlatform(d); renameIfs(d); },
      options:FW(d) ? [["asa","Cisco ASA"],["panos","Palo Alto PAN-OS"],["fortios","Fortinet FortiGate"]]
        : [["ios-xe","Cisco IOS-XE"],["nx-os","Cisco NX-OS"],["eos","Arista EOS"],["junos","Juniper Junos"],["asa","Cisco ASA (firewall)"],["panos","Palo Alto PAN-OS (firewall)"],["fortios","Fortinet FortiGate (firewall)"]]}),
    field("Management IP", d, "mgmt_ip", {placeholder:"10.99.0.1", lvl:2}),
    field("Model", d, "model", {placeholder:"e.g. Catalyst 9300 (Discover fills it in)", redraw:true}),
    PORTS[d.model] ? h("p", {class:"muted"}, `Ports: ${portSummary(PORTS[d.model])}. Connect uses the uplinks first; Add interface uses the front-panel ports.`) : null,
    field("OS version", d, "os_version", {placeholder:"filled in by Discover", lvl:2}),
    h("h3", {}, "At a glance"),
    h("p", {class:"muted"}, `${plural((d.interfaces || []).length, "interface")} · ${plural(net.links.filter(l => l.a === d.hostname || l.b === d.hostname).length, "link")} · `
      + (["ospf","eigrp","bgp"].filter(p => d[p]).map(p => p.toUpperCase()).join(", ") || "no dynamic routing")),
    h("div", {class:"row"}, h("button", {class:"btn danger", onclick:() => deleteDevice(d)}, "Delete device")));
}

// Interface names in the device's OS style after a platform switch (unit u, port p, both from 1; IOS routers
// and Junos count ports from 0).
const PO = {"nx-os":"port-channel", "eos":"Port-Channel", "junos":"ae", "panos":"ae", "fortios":"agg"};
// ASA -> PAN-OS or FortiGate: no management-only zone (the management port is separate) and HA pairs share addresses.
function fwPlatform(d) {
  if (d.platform !== "panos" && d.platform !== "fortios") return;
  const mgmt = (d.interfaces || []).filter(i => /^management/i.test(i.name)).map(i => i.zone);
  d.interfaces = (d.interfaces || []).filter(i => !/^management/i.test(i.name));
  d.interfaces.forEach(i => delete i.standby_ip);
  d.zones = (d.zones || []).filter(z => !mgmt.includes(z.name));
  for (const k of ["rules", "nat"]) d[k] = (d[k] || []).filter(x => !mgmt.includes(x.from_zone) && !mgmt.includes(x.to_zone));
  net.links = net.links.filter(l => !((l.a === d.hostname && /^management/i.test(l.a_if)) || (l.b === d.hostname && /^management/i.test(l.b_if))));
}
function ifName(name, d) {
  const os = d.platform || "ios-xe";
  let m, u, p;
  if ((m = name.match(/^\w*Ethernet(\d+)\/0\/(\d+)$/))) [u, p] = +m[1] ? [+m[1], +m[2]] : [1, +m[2] + 1];
  else if ((m = name.match(/^GigabitEthernet0\/(\d+)$/))) [u, p] = [1, +m[1] + 1];  // ASA
  else if ((m = name.match(/^ethernet1\/(\d+)$/))) [u, p] = [1, +m[1]];  // PAN-OS
  else if ((m = name.match(/^port(\d+)$/))) [u, p] = [1, +m[1]];  // FortiGate
  else if ((m = name.match(/^Ethernet(\d+)(?:\/(\d+))?$/))) [u, p] = m[2] ? [+m[1], +m[2]] : [1, +m[1]];
  else if ((m = name.match(/^(?:ge|xe|et|mge)-(\d+)\/\d+\/(\d+)$/))) [u, p] = [+m[1] + 1, +m[2] + 1];
  if (p && os === "asa") return `GigabitEthernet0/${p - 1}`;
  if (p && os === "panos") return `ethernet1/${p}`;
  if (p && os === "fortios") return `port${p}`;
  if (p) return os === "nx-os" ? `Ethernet${u}/${p}` : os === "eos" ? (u > 1 ? `Ethernet${u}/${p}` : `Ethernet${p}`)
    : os === "junos" ? `ge-${d.role === "router" ? 0 : u - 1}/0/${p - 1}`
    : d.role === "router" ? `GigabitEthernet0/0/${p - 1}` : `GigabitEthernet${u}/0/${p}`;
  if ((m = name.match(/^(?:port-channel|ae)(\d+)$/i))) return (PO[os] || "Port-channel") + m[1];
  if ((m = name.match(/^(?:loopback(\d+)|lo0)$/i))) return os === "junos" ? "lo0" : (os === "nx-os" ? "loopback" : "Loopback") + (m[1] || 0);
  if ((m = name.match(/^(?:vlan(\d+)|irb\.(\d+))$/i))) return os === "junos" ? `irb.${m[1] || m[2]}` : `Vlan${m[1] || m[2]}`;
  return name;  // anything else: the server's check names the problem
}

function renameIfs(d) {
  const map = Object.fromEntries(d.interfaces.map(i => [i.name, ifName(i.name, d)]));
  for (const i of d.interfaces) i.name = map[i.name];
  for (const l of net.links) { if (l.a === d.hostname) l.a_if = map[l.a_if] || l.a_if; if (l.b === d.hostname) l.b_if = map[l.b_if] || l.b_if; }
  for (const n of d.bgp?.neighbors || []) if (n.update_source) n.update_source = map[n.update_source] || ifName(n.update_source, d);
  if (d.failover?.interface) d.failover.interface = map[d.failover.interface] || ifName(d.failover.interface, d);
}

function ifaceFields(d, i) {
  const m = i.mode || "routed";
  const f = [
    field("Name", i, "name", {placeholder:"GigabitEthernet1/0/1", redraw:true, after(old, nu) {
      for (const l of net.links) { if (l.a === d.hostname && l.a_if === old) l.a_if = nu; if (l.b === d.hostname && l.b_if === old) l.b_if = nu; }
    }}),
    field("Description", i, "description"),
    field("Mode", i, "mode", {type:"select", def:"routed", redraw:true, options: d.role === "router" || FW(d)
      ? [["routed","Routed (L3)"]] : [["access","Access"],["trunk","Trunk"],["routed","Routed (L3)"]]}),
  ];
  if (m === "access") f.push(field("Access VLAN", i, "access_vlan", {type:"num"}), field("Voice VLAN", i, "voice_vlan", {type:"num", lvl:2}));
  if (m === "trunk") f.push(field("Allowed VLANs", i, "trunk_vlans", {placeholder:"10,20,30-40"}));
  if (FW(d)) {
    f.push(field("Zone", i, "zone", {type:"select", redraw:true, options:[["","none (unused or failover link)"], ...(d.zones || []).map(z => [z.name, `${z.name} (level ${z.security_level ?? 0})`])]}),
      field("IP / prefix", i, "ip", {placeholder:"10.0.0.1/24"}));
    if (d.failover && d.platform === "asa") f.push(field("Standby IP", i, "standby_ip", {placeholder:"10.0.0.2"}));
    f.push(field("External (untrusted)", i, "external", {type:"bool", lvl:2}));
    if (d.ospf) f.push(field("OSPF area", i, "ospf_area", {type:"num", placeholder:"0"}));
    return f;
  }
  if (m === "routed") {
    f.push(field("IP / prefix", i, "ip", {placeholder:"10.0.0.1/30"}), field("DHCP helper", i, "dhcp_helper", {lvl:2, placeholder:"10.99.0.30"}),
      field("External (untrusted)", i, "external", {type:"bool", lvl:2, redraw:true}));
    if (i.external) f.push(h("p", {class:"muted", "data-lvl":2}, "Gets perimeter hardening: EXTERNAL-IN/OUT ACLs, no CDP/LLDP, uRPF and egress filtering inside."));
    if (d.ospf) f.push(field("OSPF area", i, "ospf_area", {type:"num", placeholder:"0"}));
    if (d.ospf || d.eigrp) f.push(field("Passive (no neighbors)", i, "routing_passive", {type:"bool", lvl:2}));
    if (d.acls?.length) {
      const opts = [["","none"], ...d.acls.map(a => [a.name, a.name])];
      f.push(field("ACL inbound", i, "acl_in", {type:"select", options:opts, lvl:3}), field("ACL outbound", i, "acl_out", {type:"select", options:opts, lvl:3}));
    }
  }
  if (!/^(vlan|loopback|port-channel|tunnel|ae\d|lo0|irb\.)/i.test(i.name))
    f.push(field("EtherChannel group", i, "channel_group", {type:"num", lvl:2, redraw:true, after(_, n) {
      const po = (PO[d.platform] || "Port-channel") + n;
      if (n && !d.interfaces.some(x => x.name.toLowerCase() === po.toLowerCase()))
        d.interfaces.push({name:po, mode:i.mode || "routed", ...(i.trunk_vlans ? {trunk_vlans:i.trunk_vlans} : {})});
    }}));
  f.push(field("Shutdown", i, "shutdown", {type:"bool", lvl:2}));
  return f;
}
let ifFilter = {host:null, q:""};
function tInterfaces(b, d) {
  d.interfaces ??= [];
  if (ifFilter.host !== d.hostname) ifFilter = {host:d.hostname, q:""};
  const cards = d.interfaces.map(i => [i, card(i, short(i.name), " " + (i.mode || "routed") + (i.ip ? " " + i.ip : i.access_vlan ? " vlan " + i.access_vlan : i.trunk_vlans ? " " + i.trunk_vlans : ""),
      () => ifaceFields(d, i), () => {
        d.interfaces.splice(d.interfaces.indexOf(i), 1);
        net.links = net.links.filter(l => !((l.a === d.hostname && l.a_if === i.name) || (l.b === d.hostname && l.b_if === i.name)));
        changed(true);
      })]);
  const show = () => { const q = ifFilter.q.trim().toLowerCase();
    for (const [i, c] of cards) c.hidden = !!q && ![i.name, short(i.name), i.description, i.ip, i.mode].join(" ").toLowerCase().includes(q); };
  show();
  add(b, h("h3", {}, "Interfaces"),
    h("p", {class:"muted"}, "Links you draw with Connect create interfaces automatically. SVIs are interfaces named Vlan10, Vlan20…"),
    d.interfaces.length > 24 ? h("input", {class:"filter", type:"search", value:ifFilter.q, "aria-label":"Filter interfaces",
      placeholder:`Filter ${d.interfaces.length} interfaces by name, description or IP`, oninput:e => { ifFilter.q = e.target.value; show(); }}) : null,
    cards.map(c => c[1]),
    addBtn("Add interface", () => { const i = {name:nextIf(d), mode:d.role === "router" ? "routed" : "access"}; openCards.add(i); d.interfaces.push(i); changed(true); }),
    addBtn("Add VLAN interface (SVI)", () => { const i = {name:"Vlan" + (net.vlans[0]?.id || 10), mode:"routed"}; openCards.add(i); d.interfaces.push(i); changed(true); }, 1));
  if (d.role === "router") b.lastChild.remove();
}
function protoToggle(d, key, label, lvl, mk) {
  const on = h("input", {type:"checkbox"}); on.checked = !!d[key];
  on.addEventListener("change", () => { on.checked ? d[key] = mk() : delete d[key]; changed(true); });
  return h("label", {class:"fld", "data-lvl":lvl}, h("span", {}, label), on);
}
function tRouting(b, d) {
  add(b, h("h3", {}, "OSPF"), protoToggle(d, "ospf", "Enable OSPF", 1, () => ({})));
  if (d.ospf) add(b, 
    field("Router ID", d.ospf, "router_id", {placeholder:"10.255.0.1"}),
    field("Process ID", d.ospf, "process_id", {type:"num", def:1, lvl:2}),
    field("Reference BW (Mbps)", d.ospf, "reference_bw", {type:"num", def:100000, lvl:3}),
    field("HMAC-SHA auth", d.ospf, "authenticate", {type:"bool", def:true, lvl:3}),
    h("p", {class:"muted"}, "Put interfaces into OSPF by setting their area on the Interfaces tab. Only non-passive ones form neighbors."));
  if (!FW(d)) add(b, h("h3", {"data-lvl":2}, "EIGRP (named mode)"), protoToggle(d, "eigrp", "Enable EIGRP", 2, () => ({})));
  if (d.eigrp) add(b, 
    field("AS number", d.eigrp, "asn", {type:"num", def:100, lvl:2}),
    field("Router ID", d.eigrp, "router_id", {lvl:2}),
    field("Networks", d.eigrp, "networks", {type:"list", placeholder:"10.0.0.0/8, 172.16.1.0/24", lvl:2}),
    field("HMAC-SHA auth", d.eigrp, "authenticate", {type:"bool", def:true, lvl:3}));
  add(b, h("h3", {"data-lvl":3}, "BGP"), protoToggle(d, "bgp", "Enable BGP", 3, () => ({neighbors:[]})));
  if (d.bgp) {
    const bg = d.bgp; bg.neighbors ??= [];
    add(b, field("Local AS", bg, "asn", {type:"num", def:65000, lvl:3}), field("Router ID", bg, "router_id", {lvl:3}),
      field("Advertise", bg, "networks", {type:"list", placeholder:"198.51.100.0/24", lvl:3}),
      bg.neighbors.map(n => card(n, n.ip || "new neighbor", " AS " + (n.remote_as ?? "?"), [
        field("Neighbor IP", n, "ip", {redraw:true}), field("Remote AS", n, "remote_as", {type:"num", redraw:true}),
        field("Description", n, "description"), field("Update source", n, "update_source", {placeholder:"Loopback0"}),
        field("MD5 password", n, "authenticate", {type:"bool", def:true}), field("Max prefixes (eBGP)", n, "max_prefix", {type:"num", def:1000}),
      ], () => { bg.neighbors.splice(bg.neighbors.indexOf(n), 1); changed(true); }, 3)),
      addBtn("Add neighbor", () => { const n = {ip:"", remote_as:65001}; openCards.add(n); bg.neighbors.push(n); changed(true); }, 3));
  }
  d.static_routes ??= [];
  add(b, h("h3", {"data-lvl":2}, "Static routes"),
    d.static_routes.map(r => card(r, r.prefix || "new route", " via " + (r.next_hop || "?"), [
      field("Prefix", r, "prefix", {placeholder:"0.0.0.0/0", redraw:true}), field("Next hop", r, "next_hop", {placeholder:"10.0.0.1 or Null0", redraw:true}),
      field("Name", r, "name"),
    ], () => { d.static_routes.splice(d.static_routes.indexOf(r), 1); changed(true); }, 2)),
    addBtn("Add static route", () => { const r = {prefix:"0.0.0.0/0", next_hop:""}; openCards.add(r); d.static_routes.push(r); changed(true); }, 2));
}
/* ---------- firewall tabs ---------- */
const listCards = (b, d, key, title, make, fields, sub, help) => {
  d[key] ??= [];
  add(b, h("h3", {}, title), help ? h("p", {class:"muted"}, help) : null,
    d[key].map(x => card(x, x.name || "new", " " + sub(x), () => fields(x), () => { d[key].splice(d[key].indexOf(x), 1); changed(true); })),
    addBtn("Add " + title.toLowerCase().replace(/s$/, ""), () => { const x = make(d[key].length + 1); openCards.add(x); d[key].push(x); changed(true); }));
};
const names = (d, ...keys) => keys.flatMap(k => (d[k] || []).map(x => x.name));
function tZones(b, d) {
  listCards(b, d, "zones", "Zones", n => ({name:"ZONE" + n, security_level:50}),
    z => [field("Name", z, "name", {redraw:true}), field("Security level (0-100)", z, "security_level", {type:"num", def:0})],
    z => "level " + (z.security_level ?? 0), d.platform !== "asa"
      ? "Each interface joins a zone; a zone can hold several. Traffic between zones is denied unless a rule allows it."
      : "Each interface joins one zone (on the ASA, its nameif). Traffic is denied unless a rule allows it.");
  add(b, h("h3", {"data-lvl":2}, "High availability"), protoToggle(d, "failover", "Failover pair (active/standby)", 2, () => ({interface:"", ip:"10.255.255.1/30", peer_ip:"10.255.255.2"})));
  if (d.failover) add(b, field("Failover link interface", d.failover, "interface", {placeholder:"GigabitEthernet0/7", lvl:2}),
    ...(d.platform === "fortios" ? [] : [field("This unit's link IP", d.failover, "ip", {lvl:2}), field("Peer's link IP", d.failover, "peer_ip", {lvl:2})]),
    field("This unit is", d.failover, "unit", {type:"select", def:"primary", lvl:2, options:[["primary","Primary"],["secondary","Secondary"]]}),
    h("p", {class:"muted", "data-lvl":2}, d.platform === "fortios" ? "FGCP: the pair shares its addresses and the heartbeat link needs none; the config shows the peer's priority."
      : d.platform === "panos" ? "The pair shares its addresses; the config shows what to change on the peer."
      : "Give every zone interface a standby IP. The config shows the few lines to type on the other unit."));
}
function tObjects(b, d) {
  listCards(b, d, "addresses", "Addresses", n => ({name:"HOST-" + n, value:"10.0.0.10/32"}),
    a => [field("Name", a, "name", {redraw:true}), field("Network (host = /32)", a, "value", {redraw:true})], a => a.value || "");
  listCards(b, d, "address_groups", "Address groups", n => ({name:"GROUP-" + n, members:[]}),
    g => [field("Name", g, "name", {redraw:true}), field("Members", g, "members", {type:"list", placeholder:names(d, "addresses").join(", ")})],
    g => plural((g.members || []).length, "member"));
  listCards(b, d, "services", "Services", n => ({name:"SVC-" + n, protocol:"tcp", ports:"443"}),
    x => [field("Name", x, "name", {redraw:true}), field("Protocol", x, "protocol", {type:"select", redraw:true, options:[["tcp","TCP"],["udp","UDP"],["icmp","ICMP"]]}),
      x.protocol === "icmp" ? null : field("Port or range", x, "ports", {placeholder:"443 or 8000-8080", redraw:true})].filter(Boolean),
    x => x.protocol + (x.ports ? "/" + x.ports : ""));
  listCards(b, d, "service_groups", "Service groups", n => ({name:"SVCGRP-" + n, members:[]}),
    g => [field("Name", g, "name", {redraw:true}), field("Members", g, "members", {type:"list", placeholder:names(d, "services").join(", ")})],
    g => plural((g.members || []).length, "member"));
}
function tRules(b, d) {
  const zones = [["",""], ...names(d, "zones").map(z => [z, z])];
  listCards(b, d, "rules", "Rules", n => ({name:"RULE-" + n, from_zone:"", to_zone:"", source:["any"], destination:["any"], service:["any"], action:"allow", log:true}),
    r => [field("Name", r, "name", {redraw:true}), field("From zone", r, "from_zone", {type:"select", options:zones, redraw:true}),
      field("To zone", r, "to_zone", {type:"select", options:zones, redraw:true}),
      field("Source", r, "source", {type:"list", def:["any"], placeholder:"any, or " + names(d, "addresses", "address_groups").slice(0, 3).join(", ")}),
      field("Destination", r, "destination", {type:"list", def:["any"], placeholder:"any"}),
      field("Service", r, "service", {type:"list", def:["any"], placeholder:"any, or " + names(d, "services", "service_groups").slice(0, 3).join(", ")}),
      field("Action", r, "action", {type:"select", def:"allow", redraw:true, options:[["allow","Allow"],["deny","Deny"]]}), field("Log", r, "log", {type:"bool", def:true})],
    r => `${r.from_zone || "?"} → ${r.to_zone || "?"} · ${r.action || "allow"}`,
    "Checked top to bottom; anything no rule allows is denied and logged. 'any' toward a zone means the networks behind it.");
}
function tNat(b, d) {
  const zones = [["",""], ...names(d, "zones").map(z => [z, z])];
  listCards(b, d, "nat", "NAT rules", n => ({name:"NAT-" + n, kind:"dynamic", from_zone:"", to_zone:"", source:""}),
    x => [field("Name", x, "name", {redraw:true}), field("Kind", x, "kind", {type:"select", redraw:true, options:[["dynamic","Dynamic PAT (many to one)"],["static","Static (one to one / port forward)"]]}),
      field("Real addresses in zone", x, "from_zone", {type:"select", options:zones}), field("Translated toward zone", x, "to_zone", {type:"select", options:zones}),
      field("Real source (address or group)", x, "source", {max:63}), field("Translated to", x, "translated", {def:"interface", placeholder:"interface, or an address", max:63}),
      x.kind === "static" ? field("Only this service", x, "service", {placeholder:"HTTPS (optional)", max:63}) : null].filter(Boolean),
    x => `${x.kind} ${x.from_zone || "?"} → ${x.to_zone || "?"}`);
}
function tAcls(b, d) {
  d.acls ??= [];
  add(b, h("h3", {}, "Extended ACLs"), h("p", {class:"muted"}, "One entry per line: permit / deny / remark. Apply them on routed interfaces (Expert level)."),
    d.acls.map(a => {
      const ta = h("textarea", {class:"lines", spellcheck:"false"}); ta.value = (a.entries || []).join("\n");
      ta.addEventListener("change", () => { a.entries = ta.value.split("\n").map(s => s.trim()).filter(Boolean); changed(); });
      return card(a, a.name, (a.entries || []).length === 1 ? " 1 entry" : ` ${(a.entries || []).length} entries`, [field("Name", a, "name", {redraw:true}), ta],
        () => { d.acls.splice(d.acls.indexOf(a), 1); changed(true); });
    }),
    addBtn("Add ACL", () => { const a = {name:"ACL-" + (d.acls.length + 1), entries:["deny ip any any log"]}; openCards.add(a); d.acls.push(a); changed(true); }));
}
function tConfig(b, d) {
  const r = built[d.hostname];
  if (!r) return add(b, h("p", {class:"muted"}, errors.length ? "Fix the problems above to generate this config." : "Building…"));
  add(b, h("h3", {}, "DISA STIG"), stigView(r.stig, {host:d.hostname, ip:d.mgmt_ip || "", source:"the generated configuration"}),
    h("h3", {}, "Known vulnerabilities"), cveView(d, r.cve),
    h("h3", {}, "Best-practice review"), ...findings(r, d.hostname),
    h("h3", {}, "Generated config"),
    h("div", {class:"row"},
      h("button", {class:"btn", onclick:e => { navigator.clipboard?.writeText(r.config); e.target.textContent = "Copied"; }}, "Copy"),
      h("button", {class:"btn ghost", onclick:() => download(d.hostname + ".cfg", r.config)}, "Download .cfg")),
    h("pre", {class:"config"}, r.config));
}
function tNetwork(b) {
  net.vlans ??= [];
  add(b, h("h3", {}, "Network"), field("Name", net, "name"),
    h("h3", {}, "VLANs"), h("p", {class:"muted"}, "Created on every switch. The native VLAN from Security is added automatically."),
    net.vlans.map(v => card(v, "VLAN " + v.id, " " + v.name, [field("ID", v, "id", {type:"num", redraw:true}), field("Name", v, "name", {redraw:true})],
      () => { net.vlans.splice(net.vlans.indexOf(v), 1); changed(true); })),
    addBtn("Add VLAN", () => {
      const id = Math.max(0, ...net.vlans.map(v => v.id)) + 10; const v = {id, name:"VLAN" + id}; openCards.add(v); net.vlans.push(v); changed(true);
    }));
}
function tSecurity(b) {
  const s = net.security ??= {};
  add(b, h("h3", {}, "Management plane"),
    field("Domain name", s, "domain", {def:"corp.local"}),
    field("Mgmt subnet", s, "mgmt_subnet", {placeholder:"10.99.0.0/24"}),
    h("p", {class:"muted"}, "Only this subnet may SSH or poll SNMP. Leave empty and the audit will flag open VTY lines."),
    field("NTP servers", s, "ntp_servers", {type:"list", placeholder:"10.99.0.10"}),
    field("Syslog servers", s, "syslog_servers", {type:"list", placeholder:"10.99.0.20"}),
    field("DoD notice banner", s, "dod_banner", {type:"bool", def:false, lvl:2, redraw:true}),
    s.dod_banner ? null : field("Login banner", s, "banner", {def:"Authorized access only. Activity is monitored and logged."}),
    field("TACACS+ servers", s, "tacacs_servers", {type:"list", placeholder:"10.99.0.40, 10.99.0.41", lvl:2}),
    field("RADIUS servers", s, "radius_servers", {type:"list", placeholder:"10.99.0.50, 10.99.0.51", lvl:2}),
    field("Config backup (SCP)", s, "backup_server", {placeholder:"10.99.0.60", lvl:2}),
    h("p", {class:"muted", "data-lvl":2}, "The STIG needs two NTP, two syslog and two AAA servers. Login uses TACACS+ first (RADIUS if no TACACS+), then the local account."),
    field("Control-plane policing", s, "copp", {type:"bool", def:true, lvl:3}),
    field("SNMPv3 (authPriv)", s, "snmpv3", {type:"bool", def:true, lvl:2}),
    h("h3", {"data-lvl":2}, "Layer 2 protection"),
    field("Trunk native VLAN", s, "native_vlan", {type:"num", def:999, lvl:2}),
    field("DHCP snooping", s, "dhcp_snooping", {type:"bool", def:true, lvl:2}),
    field("Port security", s, "port_security", {type:"bool", def:true, lvl:2}),
    field("Storm control", s, "storm_control", {type:"bool", def:true, lvl:3}),
    field("Parking VLAN (unused ports)", s, "parking_vlan", {type:"num", def:998, lvl:2}),
    field("Dynamic ARP inspection", s, "arp_inspection", {type:"bool", def:false, lvl:3}),
    field("IP Source Guard", s, "ip_source_guard", {type:"bool", def:false, lvl:3}),
    field("802.1X + MAB on access ports", s, "dot1x", {type:"bool", def:false, lvl:3}),
    h("p", {class:"muted", "data-lvl":3}, "DAI and IP Source Guard drop traffic from static-IP hosts that DHCP snooping hasn't seen, and 802.1X needs RADIUS, so all three are off by default. The STIG requires them on user ports."));
}
function showHealth() { sel = null; tab = "overview"; renderPanel(); drawCanvas(); renderHeader(); openPanel(); }
const RISK = [["CAT I", "High"], ["CAT II", "Medium"], ["CAT III", "Low"]];
let riskCat = "CAT I";
function showRisk(cat) { riskCat = cat; showHealth(); $("#risk")?.scrollIntoView({block:"start"}); }
function riskView() {
  const wrap = h("div", {id:"risk"});
  const draw = () => {
    const hits = net.devices.map(d => [d, (built[d.hostname]?.stig.results || []).filter(x => x.status === "open" && x.cat === riskCat)]).filter(x => x[1].length);
    wrap.replaceChildren(h("h3", {}, "Open STIG findings"),
      h("div", {class:"tabs stigtabs", role:"tablist"}, RISK.map(([c, word]) => h("button", {role:"tab", "aria-selected":c === riskCat,
        onclick:() => { riskCat = c; draw(); }}, `${word} · ${c} (${net.devices.reduce((a, d) => a + (built[d.hostname]?.stig.summary.open[c] || 0), 0)})`))),
      ...(hits.length ? hits.flatMap(([d, rows]) => [
        h("div", {class:"row", style:"align-items:center;margin:12px 0 4px"}, h("b", {}, d.hostname), h("span", {class:"muted"}, plural(rows.length, "finding")),
          h("button", {class:"btn ghost", style:"margin-left:auto", onclick:() => openDevice(d.hostname, "config")}, "Open device")),
        ...rows.map(x => h("details", {class:"finding " + CATCLS[x.cat]},
          h("summary", {}, h("span", {class:"chip"}, x.cat), x.id + " ", h("span", {class:"muted"}, x.title)),
          h("p", {}, x.detail), x.fix ? h("pre", {}, x.fix) : null, h("p", {class:"muted"}, `${x.vuln} · ${x.rule}`)))])
        : [h("p", {class:"muted"}, `No open ${RISK.find(r => r[0] === riskCat)[1].toLowerCase()}-risk findings on any device.`)]));
  };
  draw(); return wrap;
}
function tOverview(b) {
  const rs = Object.values(built), avg = rs.length ? Math.round(rs.reduce((a, r) => a + r.stig.summary.compliance, 0) / rs.length) : null;
  const open = c => rs.reduce((a, r) => a + r.stig.summary.open[c], 0);
  if (avg != null) add(b, h("h3", {}, "STIG compliance"), hp(avg, "AVERAGE", "health-avg"),
    h("p", {class:"muted"}, `${plural(rs.length, "device")} built of ${net.devices.length} · checked against DISA STIGs`),
    h("div", {class:"cats"}, Object.keys(CATCLS).map(c => h("span", {class:CATCLS[c]}, h("span", {class:"chip"}, `${c} open: ${open(c)}`)))));
  if (avg != null) add(b, riskView());
  add(b, h("h3", {}, "Devices"));
  if (!net.devices.length) add(b, h("p", {class:"muted"}, "No devices yet."));
  for (const d of net.devices) {
    const r = built[d.hostname];
    add(b, h("div", {class:"devrow", tabindex:0, onclick:() => nodeClick(d.hostname), onkeydown:e => e.key === "Enter" && nodeClick(d.hostname)},
      h("b", {}, d.hostname), r ? hp(r.stig.summary.compliance, "STIG", "stig:" + d.hostname) : h("span", {class:"muted"}, "—")));
  }
  const all = Object.values(built).flatMap(r => r.findings).filter(f => f.severity !== "info");
  add(b, h("h3", {}, "Network health"), h("p", {class:"muted"}, all.length ? `${all.length} findings across all devices. Open a device's Config tab for fixes.` : "Every device passes the security review."));
}

/* ---------- actions ---------- */
// Port layouts per model: [prefix, first, count, suffix, kind]. kind "up" = uplinks (links to other devices use these
// first), "acc" = front-panel ports (Add interface uses these first). Names are the ones each OS shows.
const PORTS = {
  "ISR 1100":[["GigabitEthernet0/0/", 0, 2, "", "up"], ["GigabitEthernet0/1/", 0, 8, "", "acc"]],
  "ISR 4331":[["GigabitEthernet0/0/", 0, 3, "", "up"]], "ISR 4451":[["GigabitEthernet0/0/", 0, 4, "", "up"]],
  "Catalyst 8200":[["GigabitEthernet0/0/", 0, 4, "", "up"]], "Catalyst 8300":[["GigabitEthernet0/0/", 0, 6, "", "up"]],
  "Catalyst 8500":[["TenGigabitEthernet0/0/", 0, 12, "", "up"]], "ASR 1001-X":[["TenGigabitEthernet0/0/", 0, 2, "", "up"], ["GigabitEthernet0/0/", 0, 6, "", "acc"]],
  "Catalyst 9300":[["TenGigabitEthernet1/1/", 1, 4, "", "up"], ["GigabitEthernet1/0/", 1, 48, "", "acc"]],
  "Catalyst 9400":[["TenGigabitEthernet1/1/", 1, 8, "", "up"], ["GigabitEthernet2/0/", 1, 48, "", "acc"]],
  "Catalyst 9500":[["HundredGigE1/0/", 49, 4, "", "up"], ["TwentyFiveGigE1/0/", 1, 48, "", "acc"]],
  "Catalyst 9600":[["HundredGigE1/0/", 1, 24, "", "up"]],
  "Catalyst 9200":[["GigabitEthernet1/1/", 1, 4, "", "up"], ["GigabitEthernet1/0/", 1, 48, "", "acc"]],
  "Catalyst 9200L":[["GigabitEthernet1/1/", 1, 4, "", "up"], ["GigabitEthernet1/0/", 1, 48, "", "acc"]],
  "Catalyst 1000":[["GigabitEthernet1/0/", 49, 4, "", "up"], ["GigabitEthernet1/0/", 1, 48, "", "acc"]],
  "Catalyst IE3300":[["GigabitEthernet1/0/", 9, 2, "", "up"], ["GigabitEthernet1/0/", 1, 8, "", "acc"]],
  "Nexus 93180YC-FX":[["Ethernet1/", 49, 6, "", "up"], ["Ethernet1/", 1, 48, "", "acc"]], "Nexus 9336C-FX2":[["Ethernet1/", 1, 36, "", "up"]],
  "Nexus 9364C":[["Ethernet1/", 1, 64, "", "up"]], "Nexus 9508":[["Ethernet1/", 1, 36, "", "up"]],
  "ASA 5506-X":[["GigabitEthernet1/", 1, 8, "", "up"]], "ASA 5516-X":[["GigabitEthernet1/", 1, 8, "", "up"]],
  "Firepower 1120":[["Ethernet1/", 1, 12, "", "up"]], "Firepower 2130":[["Ethernet1/", 1, 12, "", "up"]], "Firepower 4115":[["Ethernet1/", 1, 8, "", "up"]],
  "7050X3":[["Ethernet", 49, 8, "/1", "up"], ["Ethernet", 1, 48, "", "acc"]], "7280R3":[["Ethernet", 1, 32, "/1", "up"]],
  "7060X5":[["Ethernet", 1, 32, "/1", "up"]], "7300X3":[["Ethernet3/", 1, 32, "/1", "up"]],
  "720XP":[["Ethernet", 49, 6, "", "up"], ["Ethernet", 1, 48, "", "acc"]], "722XPM":[["Ethernet", 49, 4, "", "up"], ["Ethernet", 1, 48, "", "acc"]],
  "750X":[["Ethernet1/", 1, 4, "", "up"], ["Ethernet3/", 1, 48, "", "acc"]], "7280R3 (edge)":[["Ethernet", 1, 32, "/1", "up"]], "7500R3":[["Ethernet3/", 1, 36, "/1", "up"]],
  "MX204":[["et-0/0/", 0, 4, "", "up"], ["xe-0/1/", 0, 8, "", "acc"]], "MX304":[["et-0/0/", 0, 16, "", "up"]], "MX480":[["xe-1/0/", 0, 20, "", "up"]],
  "ACX7100":[["et-0/0/", 0, 32, "", "up"]], "EX4400":[["xe-0/2/", 0, 4, "", "up"], ["ge-0/0/", 0, 48, "", "acc"]],
  "EX4650":[["et-0/0/", 48, 8, "", "up"], ["xe-0/0/", 0, 48, "", "acc"]], "QFX5120":[["et-0/0/", 48, 8, "", "up"], ["xe-0/0/", 0, 48, "", "acc"]],
  "QFX5130":[["et-0/0/", 0, 32, "", "up"]], "EX2300":[["xe-0/1/", 0, 4, "", "up"], ["ge-0/0/", 0, 48, "", "acc"]],
  "EX3400":[["xe-0/2/", 0, 4, "", "up"], ["ge-0/0/", 0, 48, "", "acc"]], "EX4100":[["xe-0/2/", 0, 4, "", "up"], ["ge-0/0/", 0, 48, "", "acc"]],
  "PA-440":[["ethernet1/", 1, 8, "", "up"]], "PA-450":[["ethernet1/", 1, 8, "", "up"]], "PA-1410":[["ethernet1/", 1, 14, "", "up"]],
  "PA-3220":[["ethernet1/", 1, 20, "", "up"]], "PA-5220":[["ethernet1/", 1, 24, "", "up"]], "PA-5430":[["ethernet1/", 1, 24, "", "up"]], "VM-Series":[["ethernet1/", 1, 8, "", "up"]],
  "FortiGate 40F":[["wan", 1, 1, "", "up"], ["lan", 1, 3, "", "acc"]], "FortiGate 60F":[["wan", 1, 2, "", "up"], ["internal", 1, 5, "", "acc"]],
  "FortiGate 100F":[["x", 1, 2, "", "up"], ["port", 1, 16, "", "acc"]], "FortiGate 200F":[["x", 1, 8, "", "up"], ["port", 1, 16, "", "acc"]],
  "FortiGate 600F":[["x", 1, 8, "", "up"], ["port", 1, 16, "", "acc"]], "FortiGate VM":[["port", 1, 10, "", "up"]],
};
const portNames = (prof, kind) => prof.filter(g => !kind || g[4] === kind).flatMap(([pre, first, n, suf]) => Array.from({length:n}, (_, k) => `${pre}${first + k}${suf}`));
const portSummary = prof => prof.map(([pre, first, n, suf]) => `${n} × ${short(pre + first + suf)}${n > 1 ? "–" + (first + n - 1) + suf : ""}`).join(" · ");
function nextIf(d, forLink = false) {  // a known model: its real port names (links take uplinks first); otherwise the OS default
  const prof = PORTS[d.model], used = new Set((d.interfaces || []).map(i => i.name));
  if (prof) { const free = [...portNames(prof, forLink ? "up" : "acc"), ...portNames(prof, forLink ? "acc" : "up")].find(n => !used.has(n)); if (free) return free; }
  const base = {"nx-os":"Ethernet1/", "eos":"Ethernet", "junos":"ge-0/0/", "asa":"GigabitEthernet0/", "panos":"ethernet1/", "fortios":"port"}[d.platform] || (d.role === "router" ? "GigabitEthernet0/0/" : "GigabitEthernet1/0/");
  for (let n = (base.startsWith("Gig") && (d.role === "router" || FW(d))) || base.startsWith("ge-") ? 0 : 1; ; n++) if (!used.has(base + n)) return base + n;
}
function freeSpot() {  // first grid spot (in map units) at least 140 from every device
  const r = mapSize(), w = Math.max(r.width, 600) / view.k, ht = Math.max(r.height, 500) / view.k;
  for (let y = 90; y < ht - 70; y += 120)
    for (let x = 100; x < w - 80; x += 150)
      if (net.devices.every(o => Math.hypot(o.x - x, o.y - y) > 140)) return {x, y};
  return {x:120 + net.devices.length * 20, y:110};
}
const nextName = role => { const pre = {router:"R", switch:"SW", l3switch:"CORE", firewall:"FW"}[role]; let n = 1; while (dev(pre + n)) n++; return pre + n; };
function addDevice(role, o = {}) {  // o: platform, model and hostname from the Add device dialog
  const os = o.platform || (role === "firewall" ? "asa" : dev(sel)?.platform === "asa" ? "ios-xe" : dev(sel)?.platform || "ios-xe");  // same OS as the selected device
  const d = {hostname:o.hostname || nextName(role), role, platform:os, ...(o.model ? {model:o.model} : {}), ...freeSpot(), interfaces:[],
    ...(role === "firewall" ? {zones:[{name:"OUTSIDE", security_level:0}, {name:"INSIDE", security_level:100}]} : {})};
  net.devices.push(d); sel = d.hostname; tab = "general"; changed(true); openPanel();
}
// Brands and models people put on a map, each with the role and OS OneConfig builds it as. A model is a label on the
// device (shown, and filled in by Discover); the role and OS are what decide the generated config.
const CATALOG = {
  "Cisco":[
    ["Routers", "router", "ios-xe", ["ISR 1100", "ISR 4331", "ISR 4451", "Catalyst 8200", "Catalyst 8300", "Catalyst 8500", "ASR 1001-X"]],
    ["Layer 3 switches", "l3switch", "ios-xe", ["Catalyst 9300", "Catalyst 9400", "Catalyst 9500", "Catalyst 9600"]],
    ["Access switches", "switch", "ios-xe", ["Catalyst 9200", "Catalyst 9200L", "Catalyst 1000", "Catalyst IE3300"]],
    ["Data center switches (NX-OS)", "l3switch", "nx-os", ["Nexus 93180YC-FX", "Nexus 9336C-FX2", "Nexus 9364C", "Nexus 9508"]],
    ["Firewalls (ASA)", "firewall", "asa", ["ASA 5506-X", "ASA 5516-X", "Firepower 1120", "Firepower 2130", "Firepower 4115"]]],
  "Arista":[
    ["Layer 3 switches", "l3switch", "eos", ["7050X3", "7280R3", "7060X5", "7300X3"]],
    ["Access switches", "switch", "eos", ["720XP", "722XPM", "750X"]],
    ["Routers", "router", "eos", ["7280R3 (edge)", "7500R3"]]],
  "Juniper":[
    ["Routers", "router", "junos", ["MX204", "MX304", "MX480", "ACX7100"]],
    ["Layer 3 switches", "l3switch", "junos", ["EX4400", "EX4650", "QFX5120", "QFX5130"]],
    ["Access switches", "switch", "junos", ["EX2300", "EX3400", "EX4100"]]],
  "Palo Alto Networks":[["Firewalls", "firewall", "panos", ["PA-440", "PA-450", "PA-1410", "PA-3220", "PA-5220", "PA-5430", "VM-Series"]]],
  "Fortinet":[["Firewalls", "firewall", "fortios", ["FortiGate 40F", "FortiGate 60F", "FortiGate 100F", "FortiGate 200F", "FortiGate 600F", "FortiGate VM"]]],
};
function openAddDevice() {
  const st = {brand:"Cisco", model:"", hostname:""};
  const brandSel = h("select", {"aria-label":"Brand"}, Object.keys(CATALOG).map(b => h("option", {value:b}, b)));
  const modelSel = h("select", {"aria-label":"Model"}), nameIn = h("input", {"aria-label":"Hostname", maxlength:63, spellcheck:"false"}), info = h("p", {class:"muted"});
  const pick = () => { for (const [, role, os, models] of CATALOG[st.brand]) if (models.includes(st.model)) return {role, os}; };
  const fillModels = () => {
    modelSel.replaceChildren(...CATALOG[st.brand].map(([group, , , models]) => h("optgroup", {label:group}, models.map(m => h("option", {value:m}, m)))));
    st.model = modelSel.value = CATALOG[st.brand][0][3][0]; describe();
  };
  const describe = () => { const p = pick(); nameIn.placeholder = nextName(p.role); info.textContent = `Added as ${{router:"a router", l3switch:"a layer 3 switch", switch:"a layer 2 switch", firewall:"a firewall"}[p.role]} running ${OSN[p.os]}.`; };
  brandSel.addEventListener("change", () => { st.brand = brandSel.value; fillModels(); });
  modelSel.addEventListener("change", () => { st.model = modelSel.value; describe(); });
  const row = (label, el) => h("label", {class:"fld"}, h("span", {}, label), el);
  fillModels();
  modal("Add a device", [row("Brand", brandSel), row("Model", modelSel), row("Hostname", nameIn), info], [["Add to map", () => {
    const p = pick(), name = nameIn.value.trim() || nextName(p.role);
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(name)) return "A hostname is letters, digits, dot, dash or underscore, up to 63 characters, starting with a letter or digit.";
    if (dev(name)) return `There is already a device called ${name}.`;
    addDevice(p.role, {platform:p.os, model:st.model, hostname:name});
  }]]);
  brandSel.focus();
}
async function deleteDevice(d) {
  if (!await ask(`Delete ${d.hostname} and its links?`, "Delete", true)) return;
  await keepVersion(`before deleting ${d.hostname}`);
  net.devices = net.devices.filter(x => x !== d);
  net.links = net.links.filter(l => l.a !== d.hostname && l.b !== d.hostname);
  sel = null; changed(true);
}
function notice(t) { hint(t); setTimeout(() => $("#hint").textContent === t && hint(), 3500); }  // in-page: some browsers block alert()
function startLink() { if (net.devices.length < 2) return notice("Add at least two devices first."); mode = "link"; linkA = null; hint("Connect: pick the first device  (Esc to cancel)"); }
function endLink() { mode = null; linkA = null; hint(); drawCanvas(); }
const ipAdd = (cidr, k) => {
  const [ip, p] = cidr.split("/"); const n = ip.split(".").reduce((a, o) => a * 256 + +o, 0) + k;
  return [24, 16, 8, 0].map(s => Math.floor(n / 2 ** s) % 256).join(".") + "/" + p;
};
function openLinkModal(A, B) {
  const routerInvolved = [A.role, B.role].some(r => r === "router" || r === "firewall");
  const st = {aif:nextIf(A, true), bif:nextIf(B, true), kind:routerInvolved ? "routed" : "trunk", subnet:"", area:A.ospf && B.ospf ? 0 : ""};
  const noop = {onchange:() => {}};
  modal("Connect", [
    h("p", {}, `${A.hostname}  ⟷  ${B.hostname}`),
    field(A.hostname + " port", st, "aif", noop), field(B.hostname + " port", st, "bif", noop),
    field("Link type", st, "kind", {...noop, type:"select", options:routerInvolved ? [["routed","Routed (L3)"]] : [["trunk","Trunk"],["routed","Routed (L3)"],["access","Access"]]}),
    field("Subnet (routed)", st, "subnet", {...noop, placeholder:"10.0.0.0/30 — assigns .1 and .2"}),
    field("OSPF area (routed)", st, "area", {...noop, type:"num"}),
  ], [["Connect", () => {
    if (!st.aif || !st.bif) return "Both ports are required.";
    if (st.subnet && !/^\d+\.\d+\.\d+\.\d+\/(3[01]|[12]?\d)$/.test(st.subnet)) return "Subnet must look like 10.0.0.0/30.";
    const p31 = st.subnet.endsWith("/31");
    [[A, st.aif, p31 ? 0 : 1], [B, st.bif, p31 ? 1 : 2]].forEach(([d, name, k]) => {
      d.interfaces ??= [];
      let i = d.interfaces.find(x => x.name === name);
      if (!i) d.interfaces.push(i = {name});
      i.description ||= "to " + (d === A ? B : A).hostname;
      i.mode = st.kind;
      if (st.kind === "routed" && st.subnet) i.ip = ipAdd(st.subnet, k);
      if (st.kind === "routed" && st.area !== "" && st.area != null && d.ospf) i.ospf_area = st.area;
      if (st.kind === "trunk" && net.vlans.length) i.trunk_vlans = net.vlans.map(v => v.id).join(",");
      if (st.kind === "access") i.access_vlan = net.vlans[0]?.id || 1;
    });
    net.links.push({a:A.hostname, a_if:st.aif, b:B.hostname, b_if:st.bif});
    endLink(); changed(true);
  }]], endLink);
}
async function openAudit() {
  const ta = h("textarea", {placeholder:"Paste output of: show running-config", spellcheck:"false", style:"min-height:220px"});
  const st = {os:"ios-xe", platform:"router", external:""}, out = h("div"), noop = {onchange:() => {}};
  modal("Audit a live config", [h("p", {class:"muted"}, "Paste a running config from a Cisco IOS-XE, NX-OS, ASA (or FTD), Palo Alto PAN-OS, Fortinet FortiGate (show full-configuration), Arista EOS or Juniper Junos device. Nothing leaves this computer."),
    field("Operating system", st, "os", {...noop, type:"select", options:[["ios-xe","Cisco IOS-XE"],["nx-os","Cisco NX-OS"],["asa","Cisco ASA / FTD"],["panos","Palo Alto PAN-OS"],["fortios","Fortinet FortiGate"],["eos","Arista EOS"],["junos","Juniper Junos"]]}),
    field("STIG platform", st, "platform", {...noop, type:"select", options:[["router","Router"],["l3switch","Layer 3 switch"],["switch","Layer 2 switch"],["firewall","Firewall"]]}),
    field("External interfaces", st, "external", {...noop, placeholder:"GigabitEthernet0/0/0 (optional, enables perimeter checks)"}), ta, out],
    [["Run audit", async () => {
      const r = await fetch("/api/audit", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({config:ta.value, ...st})});
      const j = await r.json();
      if (!r.ok) return (j.errors || ["Audit failed"]).join("; ");
      const host = (ta.value.match(/^\s*(?:hostname|set system host-name|set deviceconfig system hostname|set hostname)\s+"?([\w.-]+)/m) || [])[1] || "device";
      out.replaceChildren(h("h3", {}, "DISA STIG"), stigView(j.stig, {host, source:"a pasted running configuration"}), h("h3", {}, "Best-practice review"), ...findings(j));
      logEvent(`Audited ${host}: STIG ${j.stig.summary.compliance}%`, j.stig.summary.open["CAT I"] > 0);
      return false;
    }]]);
}
const DISC = {method:"ssh", scope:"", seeds:"", username:"", password:"", secret:"", targets:"", version:"2c",
  community:"", user:"", auth_key:"", priv_key:"", priv:"aes256", port:"", baud:9600};
async function openDiscover() {
  const st = DISC, noop = {onchange:() => {}}, body = h("div"), out = h("div"), redraw = {onchange:() => draw()};
  let ports = [];
  try { ports = await (await fetch("/api/serial-ports")).json(); } catch {}
  const draw = () => {
    const f = (l, k, o = {}) => field(l, st, k, {...noop, ...o});
    const scope = f("Stay within", "scope", {placeholder:"10.99.0.0/24, 10.0.0.0/30"});
    const creds = [f("Username", "username"), f("Password", "password", {type:"password"}), f("Enable secret", "secret", {type:"password"})];
    body.replaceChildren(
      f("Method", "method", {...redraw, type:"select", options:[["sweep","Scan a subnet (TCP)"],["ssh","SSH walk (CDP/LLDP)"],["snmp","SNMP (CDP-MIB)"],["serial","Console cable"]]}),
      ...({
        sweep: [scope, h("p", {class:"muted"}, "Checks TCP 22, 23, 80, 161, 443 and 830 on every address. Up to 4,096 addresses.")],
        ssh: [f("Seed devices", "seeds", {placeholder:"10.99.0.1"}), scope, ...creds,
              h("p", {class:"muted"}, "Logs into each seed, reads CDP and LLDP, and follows neighbors' management addresses. Nothing outside 'Stay within' is contacted."),
              h("p", {class:"muted"}, "Use a read-only account. The first time OneConfig reaches a device it trusts that device's SSH key, so any device answering inside 'Stay within' sees this login once.")],
        snmp: [f("Targets", "targets", {placeholder:"10.99.0.1, 10.99.0.0/28"}), scope,
               f("SNMP version", "version", {...redraw, type:"select", options:[["2c","v2c"],["3","v3 (authPriv, SHA)"]]}),
               ...(st.version === "3" ? [f("User", "user"), f("Auth password", "auth_key", {type:"password"}), f("Priv password", "priv_key", {type:"password"}),
                 f("Privacy", "priv", {type:"select", options:[["aes256","AES-256"],["aes128","AES-128"]]})]
                 : [f("Community", "community", {type:"password"})])],
        serial: [f("Port", "port", {type:"select", options:ports.length ? ports.map(p => [p.device, `${p.device} ${p.description || ""}`]) : [["", "No serial ports found"]]}),
                 f("Baud", "baud", {type:"select", options:[["9600","9600"],["115200","115200"]]}), ...creds],
      })[st.method]);
    if (st.method === "serial" && !st.port && ports[0]) st.port = ports[0].device;
  };
  draw();
  modal("Discover", [h("p", {class:"muted"}, "Credentials are used for this run only. They are never saved or sent anywhere but your devices."), body, out],
    [["Run", async () => {
      const r = await fetch("/api/discover", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(st)});
      const j = await r.json();
      if (!r.ok) return (j.errors || [j.error]).join("; ");
      const log = h("pre", {style:"max-height:180px"}, "Starting…");
      out.replaceChildren(h("h3", {}, "Progress"), log);
      const job = await pollJob(j.job, log);
      if (!job.error) { out.append(...discoveryResults(job.result, st, draw));
        logEvent(job.result.hosts ? `Subnet scan: ${plural(job.result.hosts.length, "host")} answered` : `Discovery reached ${plural(job.result.rows.filter(r => r.reached).length, "device")}`); }
      return false;
    }]]);
}
const post = (url, body) => fetch(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)})
  .then(async r => { const j = await r.json(); if (!r.ok) throw new Error((j.errors || [j.error]).join("; ")); return j; });
async function pollJob(id, logEl) {
  for (;;) {
    await new Promise(res => setTimeout(res, 600));
    const job = await (await fetch("/api/jobs/" + id)).json();
    logEl.textContent = job.log.join("\n") || "Working…"; logEl.scrollTop = logEl.scrollHeight;
    if (!job.done) continue;
    if (job.error) logEl.textContent += "\n" + job.error;
    return job;
  }
}

/* ---------- push ---------- */
async function openPush() {
  const devs = net.devices, st = {login:{username:"", password:"", secret:"", remember:false}, values:{}, remember:false,
    hosts:new Set(devs.filter(d => d.mgmt_ip).map(d => d.hostname)), removals:{}, save:true, revert_minutes:5, stop_on_failure:true};
  const body = h("div"), noop = {onchange:() => {}};
  const err = msg => h("p", {class:"errors"}, msg);
  const chk = (label, get, set, disabled) => {
    const i = h("input", {type:"checkbox", disabled:!!disabled}); i.checked = get();
    i.addEventListener("change", () => set(i.checked));
    return h("label", {class:"chk"}, i, label);
  };
  const step1 = () => body.replaceChildren(
    h("h3", {}, "1. Devices"),
    ...devs.map(d => chk(`${d.hostname}  ${d.mgmt_ip ? "· " + d.mgmt_ip : "· no management IP (set it on the General tab)"}`,
      () => st.hosts.has(d.hostname), v => v ? st.hosts.add(d.hostname) : st.hosts.delete(d.hostname), !d.mgmt_ip)),
    h("h3", {}, "2. Device login"),
    field("Username", st.login, "username", noop), field("Password", st.login, "password", {...noop, type:"password", placeholder:"blank = use the saved login"}),
    field("Enable secret", st.login, "secret", {...noop, type:"password"}),
    chk("Remember this login in the OS keychain", () => st.login.remember, v => st.login.remember = v),
    h("div", {class:"row"}, h("button", {class:"btn", onclick:step2}, "Next: secrets")));
  async function step2() {
    if (!st.hosts.size) return body.append(err("Pick at least one device."));
    let n;
    try { n = await post("/api/push/needs", {network:net, hostnames:[...st.hosts]}); } catch (e) { return body.append(err(e.message)); }
    const ids = new Set(["ADMIN-USER", "SNMP-USER"]);
    body.replaceChildren(h("h3", {}, "3. Secrets for these configs"),
      h("p", {class:"muted"}, n.keychain ? "Saved values come from your OS keychain and are never shown or sent to this page."
        : "No OS keychain on this computer: values are used for this push only."),
      ...n.needs.map(k => field(k, st.values, k, {...noop, type:ids.has(k) ? "text" : "password",
        placeholder:n.saved.includes(k) ? "saved in keychain" : ids.has(k) ? "e.g. admin" : "required"})),
      n.keychain ? chk("Remember new values in the OS keychain", () => st.remember, v => st.remember = v) : null,
      h("div", {class:"row"}, h("button", {class:"btn ghost", onclick:step1}, "Back"), h("button", {class:"btn", onclick:() => plan(n)}, "Plan (read-only)")));
  }
  async function plan() {
    const log = h("pre", {style:"max-height:140px"}, "Starting…");
    let j;
    try { j = await post("/api/push/plan", {network:net, hostnames:[...st.hosts], login:st.login, values:st.values, remember:st.remember}); }
    catch (e) { return body.append(err(e.message)); }
    body.replaceChildren(h("h3", {}, "Reading running configs (nothing is changed)"), log);
    const job = await pollJob(j.job, log);
    if (job.error) return body.append(h("div", {class:"row"}, h("button", {class:"btn ghost", onclick:step1}, "Start over")));
    review(job.result);
  }
  function review(res) {
    const pushable = res.devices.filter(d => !d.plan_only && !(d.blockers || []).length && (d.add_shown.length || d.remove_shown.length));
    const picked = d => st.removals[d.hostname] ??= new Set();
    body.replaceChildren(h("h3", {}, "4. Review"),
      ...res.devices.map(d => h("details", {class:"finding " + ((d.blockers || []).length ? "sev-high" : (d.add_shown || []).length ? "sev-medium" : "sev-pass"), open:true},
        h("summary", {}, h("span", {class:"chip"}, (d.blockers || []).length ? "blocked" : (d.add_shown || []).length ? `${d.add_shown.length} lines` : "in sync"), d.hostname),
        ...(d.blockers || []).map(b => h("div", {class:"block"}, b)), ...(d.warnings || []).map(w => h("div", {class:"warn"}, w)),
        (d.add_shown || []).length ? h("pre", {class:"diff"}, ...d.add_shown.map(l => h("div", {class:"add"}, "+ " + l))) : null,
        d.plan_only && (d.add_shown || []).length ? h("div", {class:"row"}, h("button", {class:"btn ghost", onclick:e => {
          navigator.clipboard?.writeText(d.add_shown.join("\n")); e.target.textContent = "Copied (secrets masked)"; }}, "Copy plan")) : null,
        (d.remove_shown || []).length ? h("div", {class:"rmlist"}, h("p", {class:"muted"}, "Settings OneConfig doesn't manage. Tick only the ones you're sure are stale; nothing here is removed otherwise. Secrets show as <redacted> with a short fingerprint (#…) to tell lines apart."),
          ...d.remove_shown.map((l, k) => chk("− " + l, () => picked(d).has(k), v => v ? picked(d).add(k) : picked(d).delete(k)))) : null)),
      field("Auto-rollback timer (minutes)", st, "revert_minutes", {...noop, type:"num"}),
      chk("Save to startup-config after a successful push", () => st.save, v => st.save = v),
      chk("Stop at the first failed device", () => st.stop_on_failure, v => st.stop_on_failure = v),
      h("p", {class:"muted"}, "Each device: backup, snapshot, apply under configure terminal revert timer, log in again, compare health, then confirm, or roll back automatically."),
      h("div", {class:"row"}, h("button", {class:"btn ghost", onclick:step1}, "Start over"),
        pushable.length ? h("button", {class:"btn", onclick:() => apply(res, pushable)}, `Push to ${pushable.length} device${pushable.length > 1 ? "s" : ""}`)
          : h("span", {class:"muted"}, "Nothing to push.")));
  }
  async function apply(res, pushable) {
    if (!await ask(`Change ${pushable.length} live device(s) now? Each one rolls back automatically if anything goes wrong.`, "Push now")) return;
    const log = h("pre", {style:"max-height:220px"}, "Starting…");
    let j;
    try { j = await post("/api/push/apply", {plan:res.plan, hostnames:pushable.map(d => d.hostname), removals:Object.fromEntries(Object.entries(st.removals).map(([k, v]) => [k, [...v]])),
      save:st.save, revert_minutes:st.revert_minutes, stop_on_failure:st.stop_on_failure}); } catch (e) { return body.append(err(e.message)); }
    body.replaceChildren(h("h3", {}, "5. Pushing"), log);
    const job = await pollJob(j.job, log);
    if (job.error) return logEvent("Push failed: " + job.error, true);
    job.result.results.forEach(r => logEvent(`${r.hostname}: push ${r.status}`, r.status === "failed"));
    body.append(h("h3", {}, "Results"), ...job.result.results.map(r => h("div", {class:"finding " + (r.status === "pushed" ? "sev-pass" : r.status === "failed" ? "sev-high" : "sev-info")},
      h("p", {}, h("span", {class:"chip"}, r.status), " ", h("b", {}, r.hostname), r.error ? " " + r.error : ""),
      r.health ? h("p", {class:"muted"}, Object.keys(r.health.before).map(k => `${k}: ${r.health.before[k]} → ${r.health.after[k]}`).join(" · ")) : null,
      r.snapshot ? h("p", {class:"muted"}, `Snapshot ${r.snapshot} · backup ${r.backup}`) : null,
      (r.not_applied || []).length ? h("div", {class:"warn"}, `${r.not_applied.length} lines still differ after the push (the device may display them differently): ${r.not_applied.slice(0, 3).join(" | ")}`) : null,
      r.snapshot ? h("div", {class:"row"}, h("button", {class:"btn danger", onclick:async e => {
        if (!await ask(`Roll ${r.hostname} back to ${r.snapshot}?`, "Roll back", true)) return;
        e.target.disabled = true;
        const l2 = h("pre", {}, "Rolling back…"); e.target.parentNode.after(l2);
        try { const jj = await post("/api/push/rollback", {plan:res.plan, hostname:r.hostname, save:st.save}); const rj = await pollJob(jj.job, l2);
          logEvent(`${r.hostname}: rolled back to ${r.snapshot}`, !!rj.error); }
        catch (x) { l2.textContent = x.message; }
      }}, "Roll back")) : null)));
  }
  step1();
  modal("Push to devices", [h("p", {class:"muted"}, "OneConfig only adds or changes what it manages, and asks before removing anything."), body], []);
}
function discoveryResults(res, st, draw) {
  if (res.hosts) return [h("h3", {}, `${res.hosts.length} hosts answered`),
    h("pre", {}, res.hosts.map(x => `${x.ip.padEnd(16)} ${x.ports.join(", ")}`).join("\n") || "Nothing answered."),
    res.hosts.some(x => x.ports.includes(22)) ? h("div", {class:"row"}, h("button", {class:"btn", onclick:() => {
      st.method = "ssh"; st.seeds = res.hosts.filter(x => x.ports.includes(22)).map(x => x.ip).join(", "); draw();
    }}, "SSH walk the hosts with port 22 open")) : null];
  const rows = res.rows;
  return [h("h3", {}, `${rows.filter(r => r.reached).length} devices reached, ${rows.filter(r => !r.reached).length} seen as neighbors`),
    ...rows.map(r => h("details", {class:"finding " + (r.reached ? "sev-pass" : "sev-info")},
      h("summary", {}, h("span", {class:"chip"}, r.reached ? "reached" : "neighbor"), `${r.hostname} `,
        h("span", {class:"muted"}, [ROLE[r.role], OSN[r.os], r.mgmt_ip, r.platform, r.version].filter(Boolean).join(" · ")),
        r.stig ? h("span", {class:"muted"}, `  STIG ${r.stig.summary.compliance}%`) : null),
      r.stig ? stigView(r.stig) : h("p", {class:"muted"}, r.reached ? "No running config was read." : "Not logged into: outside scope, unreachable, or no credentials."))),
    h("div", {class:"row"},
      h("button", {class:"btn", onclick:() => { mergeFragment(res.fragment, false); $("#modal")._close(); }}, "Add to map"),
      h("button", {class:"btn ghost", onclick:async () => { if (await ask("Replace the whole map with what was discovered?", "Replace map", true)) { mergeFragment(res.fragment, true); $("#modal")._close(); } }}, "Replace map"))];
}
function mergeFragment(frag, replace) {
  if (replace) {
    keepVersion("before replacing the map with discovered devices");
    net.devices = []; net.links = []; sel = null;
    const r = mapSize(), xs = frag.devices.map(d => d.x);
    const shift = Math.max(0, (r.width - (Math.max(...xs) - Math.min(...xs))) / 2 - Math.min(...xs));  // center the discovered layout
    frag.devices.forEach(d => d.x += shift);
  }
  for (const d of frag.devices) {
    const cur = dev(d.hostname);
    if (!cur) { net.devices.push(replace ? d : {...d, ...freeSpot()}); continue; }
    if (d.mgmt_ip) cur.mgmt_ip = d.mgmt_ip;
    if (d.os_version) cur.os_version = d.os_version;
    cur.interfaces ??= [];
    for (const i of d.interfaces) if (!cur.interfaces.some(x => x.name === i.name)) cur.interfaces.push(i);
  }
  const key = l => [l.a + "|" + l.a_if, l.b + "|" + l.b_if].sort().join("~"), have = new Set(net.links.map(key));
  for (const l of frag.links) if (!have.has(key(l))) { net.links.push(l); have.add(key(l)); }
  changed(true);
}
function download(name, text, type = "text/plain") {
  const a = h("a", {href:URL.createObjectURL(new Blob([text], {type})), download:name});
  document.body.append(a); a.click(); a.remove();
}
const fileName = () => (net.name || "network").replace(/[^\w-]+/g, "_");
function saveFile() { download(fileName() + ".oneconfig.json", JSON.stringify(net, null, 2), "application/json"); }
function openFile() { $("#filein").click(); }
$("#filein").addEventListener("change", async e => {
  const f = e.target.files[0]; if (!f) return;
  try { setNet(JSON.parse(await f.text())); } catch { notice("That file isn't a OneConfig network."); }
  e.target.value = "";
});
function exportAll() {
  if (!Object.keys(built).length) return notice("Nothing built yet.");
  download(fileName() + "-configs.txt", Object.entries(built).map(([h, r]) => `!!!!!!!!!! ${h} !!!!!!!!!!\n${r.config}`).join("\n\n"));
}
async function loadExample(name) {
  if (await ask(`Replace the current network with the ${name === "edge" ? "edge firewall" : "campus"} example?`, "Replace", true))
    setNet(await (await fetch(name ? "/api/example/" + name : "/api/example")).json());
}
async function newNet() { if (await ask("Start a new empty network? The current one is replaced.", "Start new", true)) setNet({name:"My Network", vlans:[{id:10, name:"USERS"}], security:{}, devices:[], links:[]}); }
function setNet(n, why = "before replacing the network") {
  if (net?.devices?.length) keepVersion(why);  // whatever was there can be brought back from File > History
  net = {devices:[], links:[], vlans:[], security:{}, ...n};
  if (!/^[0-9a-f-]{36}$/.test(net.id || "")) net.id = crypto.randomUUID();  // keys this network's saved secrets
  for (const d of net.devices) { d.x = +d.x || 0; d.y = +d.y || 0; }  // drawn into SVG markup: a shared file must not inject attributes
  sel = null; tab = null; built = {}; userView = null; changed(true);
}

/* ---------- AI advisor ---------- */
const AI = {kind:"openai", base_url:"", model:"", claude_model:"claude-sonnet-5-5", api_key:"", mode:"explain", focus:"", question:"",
  ...(store.get("oneconfig.ai") || {})};
const AIMODES = [["explain","Explain findings"],["design","Review the design"],["ask","Ask a question"],["draft","Draft changes"]];
function answerView(text) {  // fenced code becomes copyable blocks; everything else stays plain text
  return h("div", {class:"answer"}, text.split(/```[^\n]*\n?/).map((part, k) => !part.trim() ? null : k % 2
    ? h("div", {}, h("pre", {}, part.replace(/\n$/, "")), h("button", {class:"btn ghost", onclick:e => { navigator.clipboard?.writeText(part); e.target.textContent = "Copied"; }}, "Copy"))
    : h("p", {}, part.trim())));
}
function openAdvisor() {
  if (PREF.local_only !== false) AI.kind = "openai";
  const st = AI, noop = {onchange:() => store.set("oneconfig.ai", {...st, api_key:""})}, body = h("div"), out = h("div");
  const redraw = {onchange:() => { noop.onchange(); draw(); }};
  const q = h("textarea", {placeholder:"e.g. Which switch should be the spanning-tree root, and why?"});
  q.value = st.question; q.addEventListener("input", () => { st.question = q.value; noop.onchange(); });
  const req = () => ({network:net, mode:st.mode, question:st.question, focus:st.focus || null,
    provider:st.kind === "claude" ? {kind:"claude", model:st.claude_model, api_key:st.api_key || appKeys.claude_api_key || ""}
      : {kind:"openai", base_url:st.base_url, model:st.model, api_key:appKeys.local_api_key || ""}});
  const local = h("input", {type:"checkbox"}); local.checked = PREF.local_only !== false;
  local.addEventListener("change", async () => {  // saved straight away: the server enforces it, so it must know before Ask
    PREF.local_only = local.checked; if (local.checked) st.kind = "openai";
    try { await post("/api/prefs", PREF); } catch {}
    draw();
  });
  const draw = () => body.replaceChildren(
    h("label", {class:"fld"}, h("span", {}, "Keep my network data on this computer"), local),
    PREF.local_only !== false ? h("p", {class:"muted"}, "On: the Advisor can use only an AI server running on this computer (localhost), so nothing about your network leaves it. Turn it off to use the Claude API or a server on another machine.") : null,
    field("Provider", st, "kind", {...redraw, type:"select", options:PREF.local_only !== false ? [["openai","Local model (Ollama, LM Studio…)"]]
      : [["openai","Local model (Ollama, LM Studio…)"],["claude","Claude API"]]}),
    ...(st.kind === "claude" ? [
      field("Model", st, "claude_model", {...noop, type:"select", options:[["claude-sonnet-5-5","Claude Sonnet 5.5"],["claude-opus-5-5","Claude Opus 5.5"],["claude-haiku-5-5","Claude Haiku 5.5"]]}),
      field("API key", st, "api_key", {onchange:() => {}, type:"password", placeholder:"blank = saved key (File > API keys)"})]
    : [field("Server URL", st, "base_url", {...noop, placeholder:"http://localhost:11434/v1"}), field("Model", st, "model", {...noop, placeholder:"llama3.1"}),
       h("div", {class:"warn"}, "Local models often start with a 4,096-token context and silently drop the start of longer prompts. Start Ollama with OLLAMA_CONTEXT_LENGTH=32768 (or raise the context length in LM Studio), or narrow the scope to one device.")]),
    field("Task", st, "mode", {...redraw, type:"select", options:AIMODES}),
    field("Scope", st, "focus", {...noop, type:"select", options:[["","Whole network"], ...net.devices.map(d => [d.hostname, d.hostname])]}),
    ["ask","draft"].includes(st.mode) ? h("label", {class:"fld"}, h("span", {}, st.mode === "ask" ? "Question" : "Change you want"), q) : null,
    h("p", {class:"muted"}, (st.kind === "claude" ? "Sent to Anthropic's API. " : "Sent only to the server URL above. ") +
      "It includes hostnames, addresses, topology, findings and configs. Secrets are never included: they're <PLACEHOLDER> names. Use Preview to see the exact text." +
      (st.mode === "draft" ? " Drafts are text for you to review; nothing is applied to any device." : "")));
  draw();
  modal("Advisor", [body, out], [
    ["Preview what's sent", async () => {
      try {
        const pv = await post("/api/ai/preview", req());
        out.replaceChildren(h("h3", {}, `Exactly what's sent (${pv.chars.toLocaleString()} characters, ~${pv.tokens.toLocaleString()} tokens)`),
          st.kind === "openai" && pv.tokens > 4000 ? h("div", {class:"warn"}, "Bigger than a default 4,096-token local context: raise the model's context length or the start of this prompt is lost.") : null, h("pre", {style:"max-height:300px;white-space:pre-wrap"}, pv.system + "\n\n---\n\n" + pv.user));
      } catch (e) { return e.message; }
      return false;
    }],
    ["Ask", async () => {
      const log = h("pre", {style:"max-height:90px"}, "Starting…");
      try {
        const j = await post("/api/ai/ask", req());
        out.replaceChildren(h("h3", {}, "Answer"), log);
        const job = await pollJob(j.job, log);
        if (!job.error) out.replaceChildren(h("h3", {}, "Answer"), answerView(job.result.answer || "(empty answer)"));
      } catch (e) { return e.message; }
      return false;
    }]]);
}
const KEYS = [["cisco_client_id","Cisco openVuln client ID"],["cisco_client_secret","Cisco openVuln client secret"],["nvd_api_key","NVD API key (optional, raises rate limits)"],
  ["claude_api_key","Claude API key"],["local_api_key","Local model API key (if your server needs one)"]];
async function openKeys() {
  let s = {keychain:false, saved:[]};
  try { s = await (await fetch("/api/settings")).json(); } catch {}
  const vals = {}, forget = new Set(), body = h("div");
  const draw = () => body.replaceChildren(
    h("p", {class:"muted"}, s.keychain ? "Saved in your OS keychain. They never come back to this page; only the names do."
      : "No OS keychain on this computer: keys are kept in this page until you close it, then forgotten."),
    ...KEYS.map(([k, label]) => h("div", {}, field(label, vals, k, {onchange:() => {}, type:k === "cisco_client_id" ? "text" : "password",
      placeholder:s.saved.includes(k) && !forget.has(k) ? "saved" : appKeys[k] ? "set for this session" : ""}),
      s.saved.includes(k) && !forget.has(k) ? h("button", {class:"btn ghost", onclick:() => { forget.add(k); draw(); }}, "Forget") : null)),
    h("p", {class:"muted"}, "Cisco keys are free: apiconsole.cisco.com, app type Service, API 'Cisco PSIRT openVuln API'. Without them, NVD is used."));
  draw();
  modal("API keys", [body], [["Save", async () => {
    if (!s.keychain) { Object.assign(appKeys, vals); return; }
    try { await post("/api/settings", {values:vals, forget:[...forget]}); } catch (e) { return e.message; }
  }]]);
}

/* ---------- modal ---------- */
function ask(message, ok = "OK", danger = false) {  // resolves true or false; sits above any open dialog
  return new Promise(done => {
    const box = h("div", {id:"ask", role:"alertdialog", "aria-modal":"true", "aria-label":message});
    const end = v => { box.remove(); document.removeEventListener("keydown", key, true); done(v); };
    const key = e => { if (e.key === "Escape") { e.stopPropagation(); end(false); } };
    const yes = h("button", {class:"btn" + (danger ? " danger" : ""), onclick:() => end(true)}, ok);
    box.append(h("div", {class:"menu"}, h("p", {style:"margin:0 0 14px"}, message),
      h("div", {class:"row", style:"justify-content:flex-end;margin:0"}, h("button", {class:"btn ghost", onclick:() => end(false)}, "Cancel"), yes)));
    box.addEventListener("click", e => e.target === box && end(false));
    document.addEventListener("keydown", key, true);
    document.body.append(box); yes.focus();
  });
}
function modal(title, body, actions, onClose) {
  const m = $("#modal"), err = h("p", {class:"errors", style:"display:none;margin:8px 0"});
  const close = () => { m.classList.remove("open"); m.replaceChildren(); onClose?.(); };
  m.replaceChildren(h("div", {class:"menu"}, h("div", {class:"title"}, title.toUpperCase()), body, err,
    h("div", {class:"row", style:"justify-content:flex-end"},
      h("button", {class:"btn ghost", onclick:close}, "Close"),
      actions.map(([t, fn]) => h("button", {class:"btn", onclick:async () => {
        const r = await fn();
        if (typeof r === "string") { err.textContent = r; err.style.display = "block"; }
        else if (r !== false) { m.classList.remove("open"); m.replaceChildren(); }
      }}, t)))));
  m.classList.add("open"); m._close = close;
  m.querySelector("input,textarea,select")?.focus();
}

/* ---------- command rail ---------- */
const IC = {
  Build:'<rect x="3.5" y="3.5" width="17" height="17" rx="3"/><path d="M12 8v8M8 12h8"/>',
  Connect:'<path d="M9.5 14.5l5-5"/><path d="M11 6.5l1.2-1.2a4 4 0 0 1 5.6 5.6L16.5 12M13 17.5l-1.2 1.2a4 4 0 0 1-5.6-5.6L7.5 12"/>',
  Discover:'<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6-6"/>',
  Push:'<path d="M12 15.5V4M7.5 8.5L12 4l4.5 4.5M4.5 19.5h15"/>',
  Audit:'<path d="M12 3l7.5 3v6c0 4.6-3.2 7.7-7.5 9-4.3-1.3-7.5-4.4-7.5-9V6z"/><path d="M8.7 12.2l2.3 2.3 4.3-4.6"/>',
  Advisor:'<path d="M12 3.5l1.8 5 5 1.8-5 1.8-1.8 5-1.8-5-5-1.8 5-1.8z"/><path d="M18.5 16.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z"/>',
  File:'<path d="M3.5 7.5a2 2 0 0 1 2-2h3.8l2 2h7.2a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>'};
const svgIcon = k => { const t = document.createElement("template");
  t.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${IC[k]}</svg>`;
  return t.content.firstChild; };
const MENU = [
  {label:"Build", sub:[["By brand and model…", openAddDevice], ["Router", () => addDevice("router")], ["L3 Switch", () => addDevice("l3switch")], ["Switch", () => addDevice("switch")], ["Firewall", () => addDevice("firewall")]]},
  {label:"Connect", act:startLink},
  {label:"Discover", act:openDiscover},
  {label:"Push", act:openPush},
  {label:"Audit", act:openAudit},
  {label:"Advisor", act:openAdvisor},
  {label:"File", sub:[["Save network", saveFile], ["Open network", openFile], ["History", openHistory], ["Export configs", exportAll], ["API keys", openKeys], ["Users", openUsers], ["Audit log", openTrail], ["Load example", loadExample], ["Load firewall example", () => loadExample("edge")], ["New network", newNet]]},
];
let mi = 0, si = -1;
function renderMenu() {
  const rail = MENU.map((m, k) => h("button", {class:"rb", "aria-current":k === mi, "aria-haspopup":m.sub ? "menu" : null, "aria-expanded":m.sub ? si >= 0 && k === mi : null,
    onmouseenter:() => { if (si < 0 && mi !== k) { mi = k; renderMenu(); } }, onclick:() => { mi = k; activate(); }}, svgIcon(m.label), h("span", {}, m.label)));
  $("#cmd").replaceChildren(...rail);
  if (si >= 0) {
    const fly = h("div", {class:"fly glass", role:"menu"}, h("div", {class:"k"}, MENU[mi].label), MENU[mi].sub.map(([t, fn], k) =>
      h("button", {role:"menuitem", "aria-current":k === si, onmouseenter:() => { if (si !== k) { si = k; renderMenu(); } }, onclick:() => { si = -1; renderMenu(); fn(); }}, t)));
    fly.style.top = rail[mi].offsetTop + "px";
    $("#cmd").append(fly);
  }
}
function activate() {
  const m = MENU[mi];
  if (m.sub) { si = si < 0 ? 0 : -1; renderMenu(); } else { si = -1; renderMenu(); m.act(); }
}
document.addEventListener("pointerdown", e => { if (si >= 0 && !e.target.closest("#cmd")) { si = -1; renderMenu(); } });
document.addEventListener("keydown", e => {
  if ($("#modal").classList.contains("open")) { if (e.key === "Escape") $("#modal")._close(); return; }
  if (e.target.closest("input,textarea,select")) return;
  const list = si >= 0 ? MENU[mi].sub : MENU;
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    const d = e.key === "ArrowDown" ? 1 : -1;
    si >= 0 ? si = (si + d + list.length) % list.length : mi = (mi + d + list.length) % list.length;
    renderMenu(); e.preventDefault();
  } else if ((e.key === "Enter" && !e.target.closest(".node,button")) || e.key === "ArrowRight") {
    si >= 0 ? (MENU[mi].sub[si][1](), si = -1, renderMenu()) : activate(); e.preventDefault();
  } else if (e.key === "Escape" || e.key === "ArrowLeft") {
    if (mode) endLink(); else if (si >= 0) { si = -1; renderMenu(); } else if (document.body.classList.contains("editing")) setEditing(false);
    else if (e.key === "Escape") openPanel(false);  // closes the drawer when the panel is one
  } else if ((e.key === "Delete" || e.key === "Backspace") && sel) deleteDevice(dev(sel));
});

/* ---------- activity (this session only) ---------- */
const EVENTS = [];
function logEvent(text, bad) {
  EVENTS.unshift({at:new Date().toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"}), text, bad:!!bad});
  EVENTS.length = Math.min(EVENTS.length, 50);
  renderDash();
}

/* ---------- dashboard ---------- */
// Every number on a widget comes from the model or the last build; nothing is sampled live or made up.
const SEV = ["critical", "high", "medium", "low"];
const avg = a => a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : null;
function stats() {
  const ds = net.devices, rs = ds.filter(d => built[d.hostname]).map(d => [d, built[d.hostname]]);
  const fs = rs.flatMap(([d, r]) => r.findings.filter(f => f.severity !== "info").map(f => ({...f, host:d.hostname})));
  const sum = f => rs.reduce((n, x) => n + (f(x) || 0), 0);
  const cved = rs.filter(([, r]) => r.cve);
  return {ds, rs, fs, stig:avg(rs.map(([, r]) => r.stig.summary.compliance)),
    sev:Object.fromEntries(SEV.map(s => [s, fs.filter(f => f.severity === s).length])),
    cat:{I:sum(([, r]) => r.stig.summary.open["CAT I"]), II:sum(([, r]) => r.stig.summary.open["CAT II"]), III:sum(([, r]) => r.stig.summary.open["CAT III"])},
    cve:{checked:cved.length, crit:cved.reduce((n, [, r]) => n + (r.cve.counts.Critical || 0), 0), high:cved.reduce((n, [, r]) => n + (r.cve.counts.High || 0), 0)}};
}
const ringSvg = (v, px, key) => { const t = document.createElement("template"), c = BANDC[band(v)], L = 2 * Math.PI * 26;
  t.innerHTML = `<svg viewBox="0 0 64 64" width="${px}" height="${px}" role="img" aria-label="Average STIG compliance ${v ?? "unknown"} percent"><title>Average STIG compliance: ${v ?? "—"}%</title><circle cx="32" cy="32" r="26" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="6"/>
    <circle class="arc" cx="32" cy="32" r="26" fill="none" stroke="${c}" stroke-width="6" stroke-linecap="round" stroke-dasharray="${L * (v || 0) / 100} ${L}" transform="rotate(-90 32 32)" style="filter:drop-shadow(0 0 4px ${c})"/>
    <circle cx="32" cy="32" r="19" fill="none" stroke="var(--line-2)" stroke-dasharray="1 3"/><circle class="spin" cx="32" cy="32" r="30.5" fill="none" stroke="var(--line-2)" stroke-dasharray="14 8"/>
    <text x="32" y="38" text-anchor="middle" style="font:600 17px var(--disp);font-variant-numeric:tabular-nums;fill:var(--tx)">${v ?? "—"}</text></svg>`;
  const el = t.content.firstChild, arc = el.querySelector(".arc");
  if (key) ticker(el.querySelector("text"), key, v, x => arc.setAttribute("stroke-dasharray", `${L * x / 100} ${L}`));
  return el; };
const meter = (v, cls) => h("span", {class:"meter"}, h("i", {class:cls || "", style:`width:${Math.max(0, Math.min(100, v))}%`}));
const empty = t => h("p", {class:"empty"}, t);
const sevCount = (label, n, sev) => h("button", {class:"sevk bare" + (n ? " on" : ""), style:`--c:var(--sev${sev})`, title:`Show ${label} findings`,
  onclick:() => showRisk(label)}, `${label} ${n}`);
const routingTags = d => [["ospf", "OSPF"], ["eigrp", "EIGRP"], ["bgp", "BGP"]].filter(([k]) => d[k]).map(([, t]) => t)
  .concat((d.static_routes || []).length ? ["Static"] : []);
const plural = (n, w, many) => `${n} ${n === 1 ? w : many || w + "s"}`;
function openDevice(name, t) { nodeClick(name); if (t) { tab = t; renderPanel(); } }
/* ---------- engineering widgets: checks worked out from the model, plus push needs and backups from the server ---------- */
let SIDE = {per:{}, saved:[], keychain:false, backups:{}};  // refreshed after each build
async function refreshSide() {
  try { const j = await post("/api/push/needs", {network:net, hostnames:net.devices.map(d => d.hostname)}); SIDE = {...SIDE, per:j.per_device || {}, saved:j.saved, keychain:j.keychain}; } catch {}
  try { SIDE.backups = await (await fetch("/api/backups")).json(); } catch {}
  renderDash();
}
const ip4 = s => { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(s || ""); return m ? {n:m.slice(1, 5).reduce((a, o) => a * 256 + +o, 0), p:+m[5]} : null; };
const netOf = a => Math.floor(a.n / 2 ** (32 - a.p));
function vlanSet(spec) {  // "10,20,30-40" -> Set; "" (all VLANs) -> null
  if (!spec) return null;
  const s = new Set();
  for (const part of spec.split(",")) { const [a, b] = part.split("-").map(Number); for (let v = a; v <= (b || a) && v - a < 4095; v++) s.add(v); }
  return s;
}
const carries = (i, v) => { const s = vlanSet(i.trunk_vlans); return !s || s.has(v); };
const iface = (d, n) => (d?.interfaces || []).find(i => i.name === n);

function linkIssues() {
  const out = [];
  for (const l of net.links) {
    const A = dev(l.a), B = dev(l.b);
    if (!A || !B) continue;
    const ia = iface(A, l.a_if), ib = iface(B, l.b_if), where = `${l.a} ${short(l.a_if)} ↔ ${l.b} ${short(l.b_if)}`;
    const add = (msg, host) => out.push({where, msg, host});
    if (!ia || !ib) { add(`${!ia ? l.a + " " + l.a_if : l.b + " " + l.b_if} isn't an interface on that device`, !ia ? l.a : l.b); continue; }
    if (ia.shutdown || ib.shutdown) add(`${ia.shutdown ? l.a : l.b} end is shut down`, ia.shutdown ? l.a : l.b);
    const ma = ia.mode || "routed", mb = ib.mode || "routed";
    if (ma !== mb && [ma, mb].includes("trunk") && [ma, mb].includes("access")) add(`Trunk on one end, access port on the other`, l.a);
    if (ma === "routed" && mb === "routed") {
      const a = ip4(ia.ip), b = ip4(ib.ip);
      if (!a || !b) add(`No IP address on ${!a ? l.a : l.b}`, !a ? l.a : l.b);
      else if (a.n === b.n) add(`Both ends use ${ia.ip.split("/")[0]}`, l.a);
      else if (a.p !== b.p || netOf(a) !== netOf(b)) add(`Different subnets: ${ia.ip} and ${ib.ip}`, l.a);
    }
    if (ma === "trunk" && mb === "trunk" && (ia.trunk_vlans || "") !== (ib.trunk_vlans || "")) add(`Allowed VLANs differ: ${ia.trunk_vlans || "all"} and ${ib.trunk_vlans || "all"}`, l.a);
    if (ma === "access" && mb === "access" && (ia.access_vlan || 1) !== (ib.access_vlan || 1)) add(`Access VLANs differ: ${ia.access_vlan || 1} and ${ib.access_vlan || 1}`, l.a);
  }
  return out;
}
function pushReady(d) {  // [ready, why not, note]
  const why = [], need = SIDE.per[d.hostname] || [], unsaved = need.filter(n => !SIDE.saved.includes(n));
  if (!d.mgmt_ip) why.push("No management IP");
  if (!built[d.hostname]) why.push("Not built: fix the problems shown in the panel");
  if (d.platform === "asa") why.push("ASA: OneConfig plans, you apply by hand");
  return [!why.length, why.join(" · "), need.length && SIDE.keychain ? (unsaved.length ? `${plural(unsaved.length, "value")} to type at push` : "Secrets saved") : need.length ? `${plural(need.length, "value")} to type at push` : ""];
}
function vlanRows() {
  const used = new Map(), add = (v, d, what) => { const u = used.get(v) || {devs:new Set(), svi:[], ports:0}; u.devs.add(d.hostname); if (what === "svi") u.svi.push(d.hostname); else u.ports++; used.set(v, u); };
  for (const d of net.devices) for (const i of d.interfaces || []) {
    if (i.mode === "access") { add(i.access_vlan || 1, d, "port"); if (i.voice_vlan) add(i.voice_vlan, d, "port"); }
    const m = /^(?:vlan|irb\.)(\d+)$/i.exec(i.name); if (m) add(+m[1], d, "svi");
  }
  const ids = [...new Set([...net.vlans.map(v => v.id), ...used.keys()])].sort((a, b) => a - b);
  return ids.map(id => {
    const v = net.vlans.find(x => x.id === id), u = used.get(id), issues = [];
    if (!v) issues.push("not defined in the network");
    if (!u) issues.push("defined but not used");
    for (const h of u?.devs || []) {  // used on a switch whose trunks all leave it out
      const trunks = (dev(h).interfaces || []).filter(i => i.mode === "trunk" && !i.channel_group);
      if (trunks.length && !trunks.some(i => carries(i, id))) issues.push(`no trunk on ${h} carries it`);
    }
    return {id, name:v?.name || "", u, issues};
  });
}
function routeRows() {
  const issues = [], seen = {};
  for (const d of net.devices) for (const p of ["ospf", "eigrp", "bgp"]) {
    const rid = d[p]?.router_id; if (!d[p]) continue;
    if (rid) { const k = p + rid; seen[k] ? issues.push(`${p.toUpperCase()} router ID ${rid} on both ${seen[k]} and ${d.hostname}`) : seen[k] = d.hostname; }
    else issues.push(`${d.hostname}: ${p.toUpperCase()} has no router ID`);
    if (p === "ospf" && !(d.interfaces || []).some(i => i.ospf_area != null)) issues.push(`${d.hostname}: OSPF is on but no interface is in an area`);
  }
  const rows = net.devices.filter(d => d.ospf || d.eigrp || d.bgp || (d.static_routes || []).length).map(d => {
    const areas = [...new Set((d.interfaces || []).filter(i => i.ospf_area != null).map(i => i.ospf_area))];
    const bits = [d.ospf ? `OSPF ${d.ospf.router_id || "?"}${areas.length ? " · area " + areas.join(", ") : ""}` : null,
      d.eigrp ? `EIGRP AS ${d.eigrp.asn ?? 100}` : null,
      d.bgp ? `BGP AS ${d.bgp.asn ?? 65000}${(d.bgp.neighbors || []).length ? " → " + d.bgp.neighbors.map(n => n.remote_as ?? "?").join(", ") : ""}` : null,
      (d.static_routes || []).length ? plural(d.static_routes.length, "static route") : null].filter(Boolean);
    return {d, text:bits.join(" · ")};
  });
  return {rows, issues};
}
const dotted = n => [24, 16, 8, 0].map(b => Math.floor(n / 2 ** b) % 256).join(".");
function ipPlan() {  // every address in the network: duplicates, overlapping subnets, management IPs outside the management subnet
  const addrs = [], issues = [];
  for (const d of net.devices) {
    for (const i of d.interfaces || []) { const a = ip4(i.ip); if (a) addrs.push({...a, host:d.hostname, ifn:short(i.name), ip:i.ip.split("/")[0]}); }
    if (d.mgmt_ip) addrs.push({n:ip4(d.mgmt_ip + "/32").n, p:32, host:d.hostname, ifn:"management", ip:d.mgmt_ip, mgmt:true});
  }
  const byIp = {};
  for (const a of addrs) (byIp[a.ip] ??= []).push(a);
  for (const [ip, list] of Object.entries(byIp)) if (list.length > 1 && !(list.length === 2 && list.some(x => x.mgmt) && list[0].host === list[1].host))
    issues.push(`${ip} is used twice: ${list.map(x => `${x.host} ${x.ifn}`).join(" and ")}`);
  const nets = {};
  for (const a of addrs.filter(x => !x.mgmt)) { const base = netOf(a) * 2 ** (32 - a.p), key = `${dotted(base)}/${a.p}`; (nets[key] ??= {base, p:a.p, size:2 ** (32 - a.p), on:[]}).on.push(`${a.host} ${a.ifn}`); }
  const list = Object.entries(nets).sort((a, b) => a[1].base - b[1].base || a[1].p - b[1].p);
  for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length && list[j][1].base < list[i][1].base + list[i][1].size; j++)
    issues.push(`${list[i][0]} and ${list[j][0]} overlap`);
  const mg = ip4(net.security?.mgmt_subnet || "");
  if (mg) for (const a of addrs.filter(x => x.mgmt)) if (Math.floor(a.n / 2 ** (32 - mg.p)) !== netOf(mg)) issues.push(`${a.host} management IP ${a.ip} is outside ${net.security.mgmt_subnet}`);
  const p2p = list.filter(([, v]) => v.p >= 30), pool = p2p.length ? Math.floor(p2p[0][1].base / 256) * 256 : null;  // the /24 the point-to-point links come from
  const free = len => { if (pool == null) return null; for (let b = pool; b < pool + 256; b += 2 ** (32 - len)) if (!list.some(([, v]) => b < v.base + v.size && v.base < b + 2 ** (32 - len))) return `${dotted(b)}/${len}`; return null; };
  return {list, issues, next30:free(30), next31:free(31), count:addrs.length};
}
const verKey = v => (v || "").split(/[^0-9]+/).filter(Boolean).map(n => n.padStart(6, "0")).join(".");
function fwRows() {
  const covers = (a, b) => (a || ["any"]).includes("any") || (b || ["any"]).every(x => (a || []).includes(x));
  return net.devices.filter(FW).map(d => {
    const rules = d.rules || [];
    const broad = rules.filter(r => (r.action || "allow") === "allow" && covers(r.source, ["any"]) && covers(r.destination, ["any"]));
    const shadowed = rules.filter((r, j) => rules.slice(0, j).some(q => q.from_zone === r.from_zone && q.to_zone === r.to_zone &&
      covers(q.source, r.source) && covers(q.destination, r.destination) && covers(q.service, r.service)));
    return {d, rules, broad, shadowed};
  });
}
const stamp = s => s ? new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(9, 11)}:${s.slice(11, 13)}`).toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"}) : "";
const wrow = (name, text, right, onclick, tone) => h("button", {class:"item", onclick, title:name ? `${name}: ${text}` : text},
  name ? h("span", {class:"wname"}, name) : null, h("span", {class:"grow" + (tone ? " pushst tone-" + tone : "")}, text), right != null ? h("span", {class:"rt"}, right) : null);
const WID = {
  health:{t:"Network health", sz:["t","l"], draw:(S, z) => S.stig == null ? [empty("Build a device to score it.")] : [
    h("div", {style:"display:flex;align-items:center;gap:12px;flex:1"}, ringSvg(S.stig, z === "l" ? 120 : 96, "health"),
      z === "l" ? h("div", {class:"sub", style:"line-height:1.8"}, `${S.rs.length} of ${S.ds.length} devices built`, h("br"),
        h("span", {class:S.cat.I ? "t-bad" : ""}, `${S.cat.I} CAT I open`)) : null),
    h("div", {class:"row", style:"margin:auto 0 0"}, h("button", {class:"btn ghost", onclick:showHealth}, "Details"))]},
  devices:{t:"Devices", sz:["s","w"], draw:S => [h("div", {class:"big"}, S.ds.length),
    h("div", {class:"sub"}, [["router","router"],["l3switch","L3 switch"],["switch","switch"],["firewall","firewall"]].map(([k, n]) => [S.ds.filter(d => d.role === k).length, n])
      .filter(x => x[0]).map(([c, n]) => c + " " + n + (c > 1 ? (n.endsWith("h") ? "es" : "s") : "")).join(" · ") || "none yet")]},
  findings:{t:"Open findings", sz:["s","w"], draw:(S, z) => [h("div", {class:"big" + (S.sev.critical + S.sev.high ? " t-bad" : "")}, S.fs.length),
    z === "w" ? h("div", {class:"list"}, SEV.map(s => h("div", {class:"row2"}, h("span", {style:"width:60px"}, s), meter(S.fs.length ? S.sev[s] / S.fs.length * 100 : 0, s === "medium" ? "mid" : s === "low" ? "" : "bad"), h("span", {}, S.sev[s]))))
      : h("div", {class:"sub"}, `${S.sev.critical + S.sev.high} critical or high`)]},
  stig:{t:"High risk", sz:["s","w"], draw:(S, z) => [h("button", {class:"big bare", style:S.cat.I ? "color:var(--sev1)" : null,
      "aria-label":`${plural(S.cat.I, "high-risk finding")}: show them`, onclick:() => showRisk("CAT I")}, S.cat.I),
    h("div", {class:"sub", style:"white-space:normal"}, sevCount("CAT II", S.cat.II, 2), " · ", sevCount("CAT III", S.cat.III, 3), z === "w" ? ` · across ${plural(S.rs.length, "device")}` : null)]},
  cves:{t:"Critical CVEs", sz:["s"], draw:S => S.cve.checked ? [h("div", {class:"big" + (S.cve.crit ? " t-bad" : " t-ok")}, S.cve.crit),
    h("div", {class:"sub"}, `${S.cve.high} high · ${S.cve.checked} of ${S.rs.length} checked`)] : [h("div", {class:"big", style:"color:var(--dim)"}, "—"), h("div", {class:"sub"}, "Not checked yet · Config tab")]},
  selected:{t:"Selected device", sz:["t","l"], draw:(S, z) => { const d = sel && dev(sel), r = d && built[d.hostname];
    if (!d) return [empty("Pick a device on the map.")];
    const rt = routingTags(d);
    return [h("div", {class:"num tilename", title:d.hostname}, d.hostname),
      h("div", {class:"sub", style:"white-space:nowrap;overflow:hidden;text-overflow:ellipsis", title:d.model || null}, d.model ? `${roleOs(d)} · ${d.model}` : roleOs(d)),
      z === "l" && r ? h("div", {style:`display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px`},
        [["CAT I", r.stig.summary.open["CAT I"], r.stig.summary.open["CAT I"] ? "t-bad" : ""], ["CVEs", r.cve ? r.cve.items.length : "—"]]
          .map(([k, v, c]) => h("div", {}, h("div", {class:"k"}, k), ticker(h("div", {class:"num " + (c || ""), style:"font-size:18px"}, v), `tile:${k}:${d.hostname}`, v)))) : null,
      h("div", {class:"tilegrid"},  // each label above its value, which gets the tile's full width; the full value is on hover
        h("div", {class:"k"}, "IP"), d.mgmt_ip ? h("span", {class:"sub", style:"color:var(--tx-2)", title:"Management IP"}, d.mgmt_ip)
          : h("span", {class:"sub pushst tone-warn", title:"No management IP. Push needs it: set it on the General tab, or run Discover."}, "Not set"),
        h("div", {class:"k"}, "Routing"), rt.length ? h("div", {class:"rtags"}, rt.map(t => h("span", {class:"rtag"}, t)))
          : h("span", {class:"sub"}, "None")),
      h("div", {class:"row", style:"margin:auto 0 0"}, h("button", {class:"btn", onclick:() => openDevice(d.hostname, "config")}, "Config"),
        z === "l" ? h("button", {class:"btn ghost", onclick:openPush}, "Push") : null)]; }},
  worst:{t:"Needs attention", sz:["w","l"], draw:S => S.rs.length ? [h("div", {class:"list"}, [...S.rs].sort((a, b) => a[1].stig.summary.compliance - b[1].stig.summary.compliance).map(([d, r]) => {
    const v = r.stig.summary.compliance; return h("button", {class:"item", onclick:() => openDevice(d.hostname, "config")}, h("span", {style:"width:92px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis", title:d.hostname}, d.hostname), meter(v, band(v) === "good" ? "" : band(v)), h("span", {class:"score"}, v)); }))]
    : [empty("Nothing built yet.")]},
  top:{t:"Top findings", sz:["w","l"], draw:S => S.fs.length ? [h("div", {class:"list"}, [...S.fs].sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity)).slice(0, 12).map(f =>
    h("button", {class:"item sev-" + f.severity, onclick:() => openDevice(f.host, "config")}, h("span", {class:"chip"}, f.severity), h("span", {class:"grow"}, f.title), h("span", {style:"color:var(--mu)"}, f.host))))]
    : [empty("No open findings. Every config passes.")]},
  routing:{t:"Dynamic routing", sz:["s","w"], draw:(S, z) => { const c = k => S.ds.filter(d => k === "static" ? (d.static_routes || []).length : d[k]).length;
    return [h("div", {class:"big"}, S.ds.filter(d => d.ospf || d.eigrp || d.bgp).length), h("div", {class:"sub"}, z === "w" ? `OSPF ${c("ospf")} · EIGRP ${c("eigrp")} · BGP ${c("bgp")} · static ${c("static")} devices` : `run OSPF, EIGRP or BGP`)]; }},
  links:{t:"Links", sz:["s"], draw:S => [h("div", {class:"big"}, net.links.length), h("div", {class:"sub"}, plural(net.links.filter(l => /^(port-channel|ae|agg)/i.test(l.a_if)).length, "port-channel"))]},
  activity:{t:"Activity this session", sz:["w","l"], draw:() => EVENTS.length ? [h("div", {class:"list"}, EVENTS.map(e =>
    h("div", {class:"row2", style:`justify-content:flex-start;border-left:2px solid ${e.bad ? "var(--t)" : "var(--a)"};padding-left:7px`}, h("span", {style:"color:var(--mu)"}, e.at), h("span", {class:e.bad ? "t-bad" : ""}, e.text))))]
    : [empty("Pushes, audits, discoveries and CVE checks show up here.")]},
  linkchecks:{t:"Link checks", sz:["w"], fit:true, draw:() => { const L = linkIssues(); return !net.links.length ? [empty("No links yet. Use Connect to join two devices.")]
    : [h("div", {class:"sub " + (L.length ? "pushst tone-warn" : "pushst tone-ok")}, L.length ? `${plural(L.length, "problem")} on ${plural(new Set(L.map(x => x.where)).size, "link")}` : `All ${plural(net.links.length, "link")} check out`),
      L.length ? h("div", {class:"list"}, L.map(x => wrow(null, `${x.where}: ${x.msg}`, null, () => openDevice(x.host, "interfaces"), "warn"))) : null]; }},
  pushready:{t:"Push readiness", sz:["w"], fit:true, draw:() => { if (!net.devices.length) return [empty("No devices yet.")];
    const R = net.devices.map(d => [d, ...pushReady(d)]), ok = R.filter(r => r[1]).length;
    return [h("div", {class:"sub"}, `${ok} of ${plural(net.devices.length, "device")} ready to push`),
      h("div", {class:"list"}, R.sort((a, b) => a[1] - b[1]).map(([d, ready, why, note]) => wrow(d.hostname, ready ? "Ready" + (note ? " · " + note : "") : why, null,
        () => openDevice(d.hostname, "general"), ready ? "ok" : "warn")))]; }},
  vlans:{t:"VLANs", sz:["w"], fit:true, draw:() => { const V = vlanRows(); if (!V.length) return [empty("No VLANs. Add them on the Network tab.")];
    const bad = V.filter(v => v.issues.length).length;
    return [h("div", {class:"sub" + (bad ? " pushst tone-warn" : "")}, `${plural(V.length, "VLAN")}` + (bad ? ` · ${bad} need a look` : " · all in use and carried")),
      h("div", {class:"list"}, V.map(v => wrow(`VLAN ${v.id}`, v.issues.length ? v.issues.join(" · ") : `${v.name ? v.name + " · " : ""}${plural(v.u.devs.size, "device")}${v.u.svi.length ? " · SVI " + v.u.svi.join(", ") : ""}`,
        null, () => { sel = null; tab = "network"; renderPanel(); drawCanvas(); renderHeader(); openPanel(); }, v.issues.length ? "warn" : "")))]; }},
  routes:{t:"Routing details", sz:["w"], fit:true, draw:() => { const {rows, issues} = routeRows(); if (!rows.length) return [empty("No routing configured yet.")];
    return [h("div", {class:"sub" + (issues.length ? " pushst tone-warn" : "")}, issues.length ? plural(issues.length, "problem") : `${plural(rows.length, "device")} routing · no duplicate router IDs`),
      h("div", {class:"list"}, issues.map(t => wrow(null, t, null, () => openDevice(t.split(/[: ]/).find(w => dev(w)) || rows[0].d.hostname, "routing"), "warn")),
        rows.map(r => wrow(r.d.hostname, r.text, null, () => openDevice(r.d.hostname, "routing"))))]; }},
  versions:{t:"Software versions", sz:["w"], fit:true, draw:() => { if (!net.devices.length) return [empty("No devices yet.")];
    const D = [...net.devices].sort((a, b) => !a.os_version - !b.os_version || (a.platform || "").localeCompare(b.platform || "") || verKey(a.os_version).localeCompare(verKey(b.os_version)));
    const none = D.filter(d => !d.os_version).length;
    return [h("div", {class:"sub" + (none ? " pushst tone-warn" : "")}, none ? `${plural(none, "device")} with no version: run Discover or set it on the General tab` : "Oldest release first, per OS"),
      h("div", {class:"list"}, D.map(d => { const c = built[d.hostname]?.cve;
        return wrow(d.hostname, `${OSN[d.platform || "ios-xe"]} ${d.os_version || "unknown"}`, c ? plural(c.items.length, "CVE") : d.os_version ? "not checked" : "",
          () => openDevice(d.hostname, d.os_version ? "config" : "general"), d.os_version ? "" : "warn"); }))]; }},
  fwrules:{t:"Firewall rules", sz:["w"], fit:true, draw:() => { const F = fwRows(); if (!F.length) return [empty("No firewalls in this network.")];
    return [h("div", {class:"sub"}, `${plural(F.length, "firewall")} · ${plural(F.reduce((n, f) => n + f.rules.length, 0), "rule")}`),
      h("div", {class:"list"}, F.map(f => { const bad = [f.broad.length ? `${f.broad.length} allow any to any` : null, f.shadowed.length ? `${f.shadowed.length} never match (${f.shadowed.map(r => r.name).join(", ")})` : null].filter(Boolean);
        return wrow(f.d.hostname, bad.length ? bad.join(" · ") : "No broad or shadowed rules", plural(f.rules.length, "rule"), () => openDevice(f.d.hostname, "rules"), bad.length ? "warn" : "ok"); }))]; }},
  backups:{t:"Backups", sz:["w"], fit:true, draw:() => { if (!net.devices.length) return [empty("No devices yet.")];
    const never = net.devices.filter(d => !SIDE.backups[d.hostname]).length;
    return [h("div", {class:"sub" + (never ? " pushst tone-warn" : "")}, (never ? `${plural(never, "device")} never backed up` : "Every device has a backup") + " · saved before each push"),
      h("div", {class:"list"}, [...net.devices].sort((a, b) => (SIDE.backups[a.hostname]?.latest || "").localeCompare(SIDE.backups[b.hostname]?.latest || "")).map(d => {
        const b = SIDE.backups[d.hostname];
        return wrow(d.hostname, b ? `Last ${stamp(b.latest)}` : "Never", b ? plural(b.count, "backup") : null, () => openDevice(d.hostname, "config"), b ? "" : "warn"); }))]; }},
  ipplan:{t:"IP plan", sz:["w"], fit:true, draw:() => { const P = ipPlan(); if (!P.count) return [empty("No addresses yet. Give interfaces an IP / prefix.")];
    return [h("div", {class:"sub" + (P.issues.length ? " pushst tone-warn" : "")}, `${plural(P.list.length, "subnet")} · ${plural(P.count, "address", "addresses")}` +
        (P.issues.length ? ` · ${plural(P.issues.length, "problem")}` : " · no duplicates or overlaps") + (P.next30 ? ` · next free ${P.next30}, ${P.next31}` : "")),
      h("div", {class:"list"}, P.issues.map(t => wrow(null, t, null, () => openDevice(t.split(" ").find(w => dev(w)) || net.devices[0].hostname, "interfaces"), "warn")),
        P.list.map(([k, v]) => wrow(k, v.on.join(", "), null, () => openDevice(v.on[0].split(" ")[0], "interfaces"))))]; }},
  config:{t:"Config preview", sz:["w","l"], draw:(S, z) => { const r = sel && built[sel];
    return r ? [h("pre", {}, r.config.split("\n").filter(l => l.trim() && !/^[!#]+$/.test(l.trim())).slice(0, z === "l" ? 18 : 4).join("\n"))] : [empty(sel ? "Building…" : "Pick a device on the map.")]; }},
};
const PRESETS = {
  "Overview":[["health","t"],["devices","s"],["findings","s"],["stig","s"],["cves","s"],["selected","t"],["routing","s"],["links","s"],["worst","w"],["activity","w"],["top","w"]],
  "Engineering":[["linkchecks","w"],["ipplan","w"],["pushready","w"],["vlans","w"],["routes","w"],["versions","w"],["fwrules","w"],["backups","w"],["selected","t"]],
  "Security":[["health","t"],["stig","s"],["cves","s"],["findings","s"],["selected","t"],["top","l"],["worst","l"]],
  "Change window":[["selected","t"],["devices","s"],["links","s"],["routing","s"],["health","t"],["config","l"],["activity","l"]],
  "Minimal":[["health","t"],["selected","t"]],
};
let PREF = {theme:"diorama", preset:"Overview", layouts:{}, local_only:true}, editing = false, dragW = null, prefTimer = null;
const WIDE = matchMedia("(min-width: 901px)");  // above this the dashboard fits the window (fitScreen); below, tiles stack and scroll
const MAXW = 12;  // widgets per layout: about one screen. More goes in another layout (the server refuses more too)
const ENG = ["linkchecks", "pushready", "vlans", "routes", "versions", "fwrules", "backups", "ipplan"];
function capLayouts() {  // a saved layout over the limit: engineering widgets move to Engineering, anything still over to "<name> more"
  for (const [name, L] of Object.entries({...PREF.layouts})) {
    if (L.length <= MAXW) continue;
    const eng = name === "Engineering" ? [] : L.filter(([k]) => ENG.includes(k)), keep = L.filter(x => !eng.includes(x));
    if (eng.length) PREF.layouts.Engineering ??= eng.map(([k]) => [k, "w"]);
    PREF.layouts[name] = keep.slice(0, MAXW);
    if (keep.length > MAXW) PREF.layouts[`${name.slice(0, 27)} more`] = keep.slice(MAXW, MAXW * 2);
  }
}
const layout = () => PREF.layouts[PREF.preset] ??= (PRESETS[PREF.preset] || PRESETS.Overview).map(x => [...x]);
function savePrefs() { clearTimeout(prefTimer); prefTimer = setTimeout(() => post("/api/prefs", PREF).catch(() => {}), 300); }
function setEditing(on) { editing = on; document.body.classList.toggle("editing", on); $("#customize").setAttribute("aria-pressed", on);
  $("#customize").textContent = on ? "Done" : "Customize"; renderDash(); }
function moveW(i, j) { const L = layout(); if (j < 0 || j >= L.length) return; const [x] = L.splice(i, 1); L.splice(j, 0, x); savePrefs(); renderDash(); }
function renderDash() {
  if (!net) return;
  const S = stats(), L = layout();
  const tiles = L.filter(([id]) => WID[id]).map(([id, z], i) => {
    const w = WID[id], el = h("div", {class:`w glass ${z === "w" ? "w2" : z}`, draggable:editing ? "true" : null, "data-w":id},
      h("div", {class:"wh"}, h("span", {class:"k"}, w.t), h("span", {class:"ctl"},
        w.sz.length > 1 ? h("button", {"aria-label":`Resize ${w.t}`, title:"Resize", onclick:() => { L[i][1] = w.sz[(w.sz.indexOf(z) + 1) % w.sz.length]; savePrefs(); renderDash(); }}, "⤢") : null,
        h("button", {"aria-label":`Move ${w.t} earlier`, onclick:() => moveW(i, i - 1)}, "‹"), h("button", {"aria-label":`Move ${w.t} later`, onclick:() => moveW(i, i + 1)}, "›"),
        h("button", {"aria-label":`Remove ${w.t}`, onclick:() => { L.splice(i, 1); savePrefs(); renderDash(); }}, "×"))),
      ...w.draw(S, z));
    el.addEventListener("dragstart", e => { dragW = i; el.classList.add("drag"); e.dataTransfer.effectAllowed = "move"; });
    el.addEventListener("dragend", () => el.classList.remove("drag"));
    el.addEventListener("dragover", e => { if (editing && dragW !== null) { e.preventDefault(); el.classList.add("over"); } });
    el.addEventListener("dragleave", () => el.classList.remove("over"));
    el.addEventListener("drop", e => { e.preventDefault(); const from = dragW; dragW = null; if (from !== null && from !== i) moveW(from, i); });
    return el;
  });
  const hidden = Object.keys(WID).filter(k => !L.some(x => x[0] === k)), nameIn = h("input", {class:"hsel", placeholder:"Name a new layout", maxlength:32, "aria-label":"Name for a new layout"});
  const saveNew = () => { const n = nameIn.value.trim();
    if (!/^[A-Za-z0-9 _-]{1,32}$/.test(n)) return nameIn.focus(); PREF.layouts[n] = layout().map(x => [...x]); PREF.preset = n; savePrefs(); renderDash(); };
  nameIn.addEventListener("keydown", e => e.key === "Enter" && saveNew());
  const head = h("div", {class:"libhead", title:"Drag to move"}, h("span", {class:"grip", "aria-hidden":"true"}, "⋮⋮"),
    h("span", {class:"k", style:"color:var(--t)"}, "Customize dashboard"), h("button", {class:"chipbtn", onclick:() => setEditing(false)}, "Done"));
  const lib = h("div", {class:"lib", role:"dialog", "aria-label":"Customize dashboard"}, head,
    h("div", {class:"row2", style:"flex-wrap:wrap;justify-content:flex-start"}, h("span", {class:"k", style:"color:var(--t)"}, "Layout"),  // which layout
      ...Object.keys({...PRESETS, ...PREF.layouts}).map(n => h("button", {class:"chipbtn" + (n === PREF.preset ? " on" : ""), onclick:() => { PREF.preset = n; savePrefs(); renderDash(); }}, n))),
    h("div", {class:"libactions"},  // what to do with it: keep a copy under a new name, or put it back
      h("div", {class:"saveas"}, nameIn, h("button", {class:"chipbtn", onclick:saveNew}, "Save as new")),
      PRESETS[PREF.preset] ? h("button", {class:"chipbtn", title:`Put ${PREF.preset} back to its original widgets`, onclick:() => { delete PREF.layouts[PREF.preset]; savePrefs(); renderDash(); }}, `Reset ${PREF.preset}`)
        : h("button", {class:"chipbtn danger", onclick:() => { delete PREF.layouts[PREF.preset]; PREF.preset = "Overview"; savePrefs(); renderDash(); }}, `Delete ${PREF.preset}`)),
    h("div", {class:"k hint"}, `Widgets you can add  ·  ${L.length} of ${MAXW} used  ·  drag tiles to reorder, ⤢ resizes, × removes`),
    h("div", {class:"items"}, L.length >= MAXW ? h("span", {class:"sub"}, `This layout holds ${MAXW} widgets, the most it can. Remove one to add another, or save a new layout.`)
      : hidden.length ? hidden.map(k => h("button", {class:"chipbtn", onclick:() => { if (L.length < MAXW) { L.push([k, WID[k].sz[0]]); savePrefs(); renderDash(); } }}, "+ " + WID[k].t))
      : h("span", {class:"sub"}, "Every widget is on this layout.")));
  placeLib(lib, head);
  const dash = $("#dash"), top = dash.scrollTop;  // a rebuild empties the grid for a moment, which scrolls it to the top
  dash.replaceChildren($("#stage"), ...tiles, lib);
  fitScreen();
  dash.scrollTop = top;
}
// Widgets marked fit take as many grid rows as their content needs (up to 4 tile units, then the list scrolls), so short lists leave no empty space
function fitTiles() {
  const g = getComputedStyle($("#dash")), row = parseFloat(g.gridAutoRows) || 90, gap = parseFloat(g.rowGap) || 8;
  for (const el of document.querySelectorAll("#dash .w[data-w]")) {
    if (!WID[el.dataset.w]?.fit) continue;
    const cs = getComputedStyle(el), list = el.querySelector(".list");
    const kids = [...el.children], fixed = kids.filter(k => k !== list).reduce((n, k) => n + k.offsetHeight, 0);
    const need = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom) + fixed + (list ? list.scrollHeight : 0) + (kids.length - 1) * (parseFloat(cs.rowGap) || 0);
    // 1 to 4 tile units, in quarter steps; when the dashboard fits the screen, never past the tile's own size (its list scrolls)
    const most = WIDE.matches ? (el.matches(".t, .l") ? 8 : 4) : 16;
    el.style.gridRow = `span ${Math.max(4, Math.min(most, Math.ceil((need + gap) / (row + gap))))}`;
  }
}
// The Customize box stays where it was last dragged (this browser only), kept on screen
function placeLib(lib, head) {
  const keep = (x, y) => { lib.style.left = Math.max(0, Math.min(x, innerWidth - 160)) + "px"; lib.style.top = Math.max(52, Math.min(y, innerHeight - 48)) + "px"; lib.style.right = "auto"; };
  const at = store.get("oneconfig.libpos");
  if (at) keep(at.x, at.y);
  head.addEventListener("pointerdown", e => {
    if (e.button !== 0 || e.target.closest("button")) return;
    const r = lib.getBoundingClientRect(), dx = e.clientX - r.left, dy = e.clientY - r.top;
    try { head.setPointerCapture(e.pointerId); } catch {}  // keeps the drag when the pointer leaves the title bar
    const move = ev => keep(ev.clientX - dx, ev.clientY - dy);
    head.addEventListener("pointermove", move);
    head.addEventListener("pointerup", () => { head.removeEventListener("pointermove", move); store.set("oneconfig.libpos", {x:parseFloat(lib.style.left), y:parseFloat(lib.style.top)}); }, {once:true});
  });
}
// Size the rows so the map and every widget fit the window without scrolling: as many tile units as the layout needs
// (8 at least), down to the 64px a tile still reads at. Narrow windows stack the tiles under the map and scroll as before;
// the Customize panel sits below the tiles and scrolls into view.
function fitScreen() {
  const dash = $("#dash"), stage = $("#stage"), was = [stage.clientWidth, stage.clientHeight];
  dash.style.setProperty("--units", 8);
  fitTiles();
  if (WIDE.matches) for (let k = 0; k < 4; k++) {  // fit tiles take more rows when rows shrink, so settle in a few passes
    const g = getComputedStyle(dash), row = parseFloat(g.gridAutoRows), gap = parseFloat(g.rowGap), top = dash.getBoundingClientRect().top + parseFloat(g.paddingTop);
    const bottom = dash.scrollTop + Math.max(...[...dash.querySelectorAll("#stage, .w[data-w]")].map(el => el.getBoundingClientRect().bottom));  // as if unscrolled
    const need = Math.max(8, Math.ceil(Math.round((bottom - top + gap) / (row + gap)) / 4)), now = +g.getPropertyValue("--units");
    if (need <= now || 4 * row + 3 * gap <= 64.5) break;  // fits, or as small as a tile can go: the rest scrolls
    dash.style.setProperty("--units", need);
    fitTiles();
  }
  if (stage.clientWidth !== was[0] || stage.clientHeight !== was[1]) drawCanvas();  // the map's own size changed
}
$("#customize").addEventListener("click", () => setEditing(!editing));
$("#panelbtn").addEventListener("click", () => openPanel(!document.body.classList.contains("panel-open")));
$("#theme").addEventListener("change", e => { PREF.theme = e.target.value; document.documentElement.dataset.theme = PREF.theme; savePrefs(); drawCanvas(); });

/* ---------- accounts, audit log, history ---------- */
let ME = {accounts:false, user:"local", role:"admin"};
function renderWho() {
  $("#who").replaceChildren(...(ME.accounts && ME.user ? [h("span", {}, ME.user), h("span", {class:"role"}, ME.role),
    h("button", {class:"btn ghost", onclick:async () => { await post("/api/logout", {}).catch(() => {}); try { sessionStorage.removeItem("oneconfig.s"); } catch {} location.reload(); }}, "Sign out")] : []));
}
let signing = null;
function signIn() {  // one sign-in box at a time; resolves once signed in
  if (signing) return signing;
  return signing = new Promise(done => {
    const user = h("input", {"aria-label":"User name", autocomplete:"username", spellcheck:"false"});
    const pass = h("input", {type:"password", "aria-label":"Password", autocomplete:"current-password"});
    const err = h("p", {class:"errors", style:"display:none;margin:8px 0"});
    const go = async () => {
      const r = await _fetch("/api/login", {method:"POST", headers:{"Content-Type":"application/json", "X-OneConfig-Token":TOKEN}, body:JSON.stringify({user:user.value.trim(), password:pass.value})});
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { err.textContent = (j.errors || [j.error || "Sign-in failed"]).join(" "); err.style.display = "block"; pass.select(); return; }
      try { sessionStorage.setItem("oneconfig.s", j.session); } catch {}
      ME = {accounts:true, user:j.user, role:j.role}; box.remove(); signing = null; renderWho(); done(j);
    };
    pass.addEventListener("keydown", e => e.key === "Enter" && go());
    const row = (label, el) => h("label", {class:"fld"}, h("span", {}, label), el);
    const box = h("div", {id:"signin", role:"dialog", "aria-modal":"true", "aria-label":"Sign in"},
      h("div", {class:"menu"}, h("div", {class:"title", style:"font:600 14px var(--disp);letter-spacing:.2em;color:var(--a);margin-bottom:10px"}, "SIGN IN"),
        row("User", user), row("Password", pass), err, h("div", {class:"row", style:"justify-content:flex-end"}, h("button", {class:"btn", onclick:go}, "Sign in"))));
    document.body.append(box); user.focus();
  });
}
async function openUsers() {
  const body = h("div"), f = {name:"", password:"", role:"operator", current:"", mine:""}, err = h("p", {class:"errors", style:"display:none;margin:8px 0"});
  const draw = async () => {
    let list = [];
    if (ME.accounts && ME.role === "admin") try { list = await (await fetch("/api/users")).json(); } catch {}
    const act = async (payload, msg) => {
      try { const j = await post("/api/users", payload); if (j.session) { try { sessionStorage.setItem("oneconfig.s", j.session); } catch {} ME = {accounts:true, user:j.user, role:j.role}; renderWho(); }
        err.style.display = "none"; logEvent(msg); draw(); } catch (e) { err.textContent = e.message; err.style.display = "block"; } };  // in-page: some browsers block alert()
    const roles = [["viewer","Viewer: look, build, audit"],["operator","Operator: also discover, push, CVE, Advisor"],["admin","Admin: also accounts and API keys"]];
    body.replaceChildren(err,
      !ME.accounts ? h("p", {class:"muted"}, "No accounts yet: whoever opens OneConfig from its launch link has full control. Create the first admin to make everyone sign in, with a role that limits what they can do.") : null,
      ...(ME.accounts && ME.role === "admin" ? [h("h3", {}, "Accounts"), ...list.map(u => h("div", {class:"row", style:"align-items:center"},
          h("b", {style:"min-width:120px"}, u.name),
          (() => { const sel = h("select", {class:"hsel", "aria-label":`Role for ${u.name}`}, roles.map(([v, t]) => h("option", {value:v}, v))); sel.value = u.role;
            sel.addEventListener("change", () => act({action:"role", name:u.name, role:sel.value}, `${u.name} is now ${sel.value}`)); return sel; })(),
          (() => { const np = h("input", {type:"password", class:"hsel", placeholder:"new password", "aria-label":`New password for ${u.name}`, style:"width:140px"});
            return h("span", {class:"row", style:"margin:0;gap:6px"}, np, h("button", {class:"btn ghost", onclick:() => np.value && act({action:"password", name:u.name, password:np.value}, `Reset ${u.name}'s password`)}, "Reset password")); })(),
          u.name !== ME.user ? h("button", {class:"btn danger", onclick:async () => { if (await ask(`Remove ${u.name}?`, "Remove", true)) act({action:"remove", name:u.name}, `Removed ${u.name}`); }}, "Remove") : null))] : []),
      ...(ME.role === "admin" ? [h("h3", {}, ME.accounts ? "Add an account" : "Create the first admin"),
        field("User name", f, "name", {onchange:() => {}}), field("Password", f, "password", {onchange:() => {}, type:"password", placeholder:"at least 10 characters"}),
        ME.accounts ? field("Role", f, "role", {onchange:() => {}, type:"select", options:roles}) : h("p", {class:"muted"}, "The first account is an admin."),
        h("div", {class:"row"}, h("button", {class:"btn", onclick:() => act({action:"add", name:f.name, password:f.password, role:ME.accounts ? f.role : "admin"}, `Added ${f.name}`)}, ME.accounts ? "Add account" : "Create admin and require sign-in"))] : []),
      ...(ME.accounts ? [h("h3", {}, "Change my password"), field("Current password", f, "current", {onchange:() => {}, type:"password"}),
        field("New password", f, "mine", {onchange:() => {}, type:"password", placeholder:"at least 10 characters"}),
        h("div", {class:"row"}, h("button", {class:"btn ghost", onclick:() => act({action:"password", name:ME.user, current:f.current, password:f.mine}, "Changed my password")}, "Change password"))] : []));
  };
  modal("Users", [body], []);
  draw();
}
const trailText = d => typeof d === "string" ? d : Object.entries(d || {}).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? Object.entries(v).map(([a, b]) => `${a} ${b}`).join(", ") : v}`).join(" · ");
async function openTrail() {
  let t;
  try { t = await (await fetch("/api/audit-trail")).json(); if (t.errors) throw new Error(t.errors[0]); } catch (e) { return modal("Audit log", [h("p", {class:"errors"}, e.message || "Couldn't read the audit log.")], []); }
  modal("Audit log", [
    h("p", {class:t.ok ? "muted" : "errors"}, t.ok ? `${plural(t.entries, "entry")}, chain intact${t.checked === false ? `. Signatures can't be checked here: ${t.why}` : t.signed ? ", signed with a key from your OS keychain" : t.entries ? " (not signed: no OS keychain)" : ""}. Kept in ~/.oneconfig/audit-trail.jsonl, on this computer only.`
      : `The log was changed: entry ${t.broken_at + 1} of ${t.entries} doesn't match the ones before it. Entries from there on can't be trusted.`),
    !t.items.length ? h("p", {class:"muted"}, "Nothing recorded yet. Sign-ins, discoveries, plans, pushes, rollbacks, CVE checks, Advisor questions, account and API key changes, and restores are recorded here.")
      : h("table", {class:"trail"}, h("tbody", {}, t.items.map(e => h("tr", {}, h("td", {}, new Date(e.at).toLocaleString()), h("td", {}, e.actor), h("td", {}, e.action), h("td", {}, trailText(e.detail))))))], []);
}
async function openHistory() {
  let list = [];
  try { list = await post("/api/history/list", {id:net.id}); } catch (e) { return modal("History", [h("p", {class:"errors"}, e.message)], []); }
  const ago = v => new Date(`${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6, 8)}T${v.slice(9, 11)}:${v.slice(11, 13)}:${v.slice(13, 15)}Z`).toLocaleString();
  modal("History", [
    h("p", {class:"muted"}, `Saved versions of ${net.name || "this network"}, newest first: kept on this computer, after edits and before anything that replaces or removes devices. The last 100 are kept.`),
    list.length ? h("div", {}, list.map(v => h("div", {class:"devrow", style:"cursor:default;align-items:flex-start"},
      h("div", {style:"flex:1;min-width:0"}, h("b", {}, ago(v.version)), h("div", {class:"muted"}, `${v.reason || "edited"} · ${plural(v.devices, "device")} · ${plural(v.links, "link")}`),
        h("div", {class:"muted", style:"overflow-wrap:anywhere"}, v.names.join(", ") + (v.devices > v.names.length ? "…" : ""))),
      h("button", {class:"btn ghost", onclick:async () => {
        if (!await ask(`Restore the version from ${ago(v.version)} (${plural(v.devices, "device")})? What's on the map now is saved first, so you can come back to it.`, "Restore")) return;
        const n = await post("/api/history/get", {id:net.id, version:v.version});
        setNet(n, "before restoring an older version"); $("#modal")._close();
        post("/api/history/restored", {version:v.version, devices:n.devices.length}).catch(() => {});
        logEvent(`Restored the version from ${ago(v.version)}`);
      }}, "Restore"))))
      : h("p", {class:"muted"}, "No saved versions yet. One is kept 20 seconds after you change something.")], []);
}

/* ---------- boot ---------- */
(async () => {
  if (!TOKEN) document.body.prepend(h("p", {class:"errors", style:"margin:8px"},
    "This tab has no access key. Open OneConfig from the link that `oneconfig serve` printed."));
  try { ME = await (await fetch("/api/me")).json(); } catch {}
  if (ME.accounts && !ME.user) await signIn();
  renderWho();
  try { PREF = {...PREF, ...(await (await fetch("/api/prefs")).json())}; } catch {}
  PREF.layouts ??= {};
  const over = Object.values(PREF.layouts).some(L => L.length > MAXW);
  capLayouts();
  if (over) savePrefs();
  if (![...$("#theme").options].some(o => o.value === PREF.theme)) PREF.theme = "diorama";
  if (!PRESETS[PREF.preset] && !PREF.layouts[PREF.preset]) PREF.preset = "Overview";
  document.documentElement.dataset.theme = $("#theme").value = PREF.theme;
  net = store.get("oneconfig.net");
  if (!net) try { net = await (await fetch("/api/example")).json(); } catch { net = null; }
  setNet(net || {});
  renderMenu();
})();

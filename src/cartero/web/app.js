"use strict";

/* Cartero — interfaz. Sin dependencias.
 * Regla de oro: todo el texto que viene de la red (dominios, nombres de
 * programas…) se pinta con textContent, nunca con innerHTML. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(`${res.status} ${path}`);
  return res.json();
}

/* ---------- glosario: bocadillos sobre palabras clave ---------- */
let glossary = {};
let glossaryRe = null;

function withGlossary(el) {
  if (!glossaryRe) return el;
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes) {
    if (node.parentElement.closest(".term, code, .tech")) continue;
    const text = node.nodeValue;
    glossaryRe.lastIndex = 0;
    if (!glossaryRe.test(text)) continue;
    glossaryRe.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let last = 0;
    for (const m of text.matchAll(glossaryRe)) {
      frag.append(text.slice(last, m.index));
      const key = m[0].toLowerCase();
      const tip = glossary[key] || glossary[key.replace(/es$|s$/, "")];
      frag.append(tip ? h("span", { class: "term", tabindex: "0", "data-tip": tip }, m[0]) : m[0]);
      last = m.index + m[0].length;
    }
    frag.append(text.slice(last));
    node.replaceWith(frag);
  }
  return el;
}

async function loadGlossary() {
  try {
    glossary = await api("/api/glossary");
    const words = Object.keys(glossary).sort((a, b) => b.length - a.length).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    glossaryRe = new RegExp(`(?<![\\p{L}])(?:${words.join("|")})(?:es|s)?(?![\\p{L}])`, "giu");
  } catch { /* sin glosario también funciona */ }
}

/* ---------- navegación ---------- */
const views = ["home", "scan", "live", "wifi"];
let current = null;
let liveTimer = null;
let scanTimer = null;

function go(view) {
  if (!views.includes(view)) view = "home";
  current = view;
  for (const v of views) $(`#view-${v}`).hidden = v !== view;
  for (const b of $$(".tabs button")) b.setAttribute("aria-current", b.dataset.go === view ? "page" : "false");
  clearInterval(liveTimer);
  clearInterval(scanTimer);
  if (location.hash.slice(1) !== view) history.replaceState(null, "", `#${view}`);
  if (view === "live") { refreshLive(); liveTimer = setInterval(refreshLive, 2500); }
  if (view === "scan") startScan();
  if (view === "wifi") loadWifi(false);
  window.scrollTo({ top: 0 });
}

document.addEventListener("click", (e) => {
  const target = e.target.closest("[data-go]");
  if (target) { e.preventDefault(); go(target.dataset.go); }
});

/* ---------- tarjetas ---------- */
const KIND_CHIP = { tracker: "tracker", unknown: "unknown" };

function chip(dest) {
  const label = dest.country ? `${dest.name} (${dest.country})` : dest.name;
  const cls = ["chip", dest.trusted && dest.kind !== "tracker" ? "verified" : "", KIND_CHIP[dest.kind] || ""].join(" ");
  return h("span", { class: cls, title: dest.trusted && dest.kind !== "tracker" ? "Empresa conocida y verificada" : null },
    dest.kind === "tracker" ? "👁️ " : null,
    label,
    dest.trusted && dest.kind !== "tracker" ? h("span", { class: "tick", "aria-label": "Empresa conocida y verificada" }, "✔") : null);
}

function renderCard(card) {
  const talks = card.talks_to.slice(0, 5);
  const more = card.talks_to.length - talks.length;
  const el = h("article", { class: `card level-${card.level}${card.noise ? " noise" : ""}`, "data-id": card.id },
    h("div", { class: "card-head" },
      h("span", { class: "dot", "aria-hidden": "true" }),
      h("div", {},
        h("h3", {}, card.program),
        h("p", { class: "status" }, card.level_label,
          card.known_program && card.file && card.file !== card.program ? h("span", { class: "file" }, ` · ${card.file}`) : null))),
    h("dl", { class: "qa" },
      h("div", {}, h("dt", {}, "¿Con quién habla?"),
        h("dd", { class: "chips" }, talks.map(chip), more > 0 ? h("span", { class: "chip" }, `y ${more} más`) : null)),
      h("div", {}, h("dt", {}, "¿Qué está haciendo?"), h("dd", {}, card.doing)),
      h("div", {}, h("dt", {}, "Dato curioso"), h("dd", {}, card.fact))),
    card.alerts.length ? h("div", { class: "alerts" },
      card.alerts.map((a) => h("button", { class: `alert ${a.level}`, onclick: () => openAlert(card, a) },
        h("span", { "aria-hidden": "true" }, a.icon), h("span", {}, a.title)))) : null,
    h("div", { class: "card-foot" },
      h("button", { class: "link-btn", onclick: () => openLookup(card) }, "¿Qué es esto?"),
      techDetails(card)));
  return withGlossary(el);
}

function techDetails(card) {
  return h("details", { class: "tech", "data-tech": card.id },
    h("summary", {}, "Detalles técnicos"),
    h("table", {}, h("tbody", {}, card.technical.map((t) => h("tr", {},
      h("td", {}, h("code", {}, `${t.proto} ${t.remote}`)),
      h("td", {}, t.domain || "—"),
      h("td", {}, [t.up && `↑${t.up}`, t.down && `↓${t.down}`].filter(Boolean).join(" ") || t.since))))));
}

function renderCards(container, cards) {
  const open = new Set($$("details.tech[open]", container).map((d) => d.dataset.tech));
  container.replaceChildren(...cards.map(renderCard));
  for (const id of open) { const d = $(`details[data-tech="${CSS.escape(id)}"]`, container); if (d) d.open = true; }
}

/* ---------- modal: semáforo de riesgo ---------- */
const LEVEL_TEXT = { info: "Para tu información", warn: "Para revisar", danger: "Atención" };

function openModal(...content) {
  const body = $("#modal-body");
  body.replaceChildren(...content);
  withGlossary(body);
  $("#modal").showModal();
}

function openAlert(card, a) {
  openModal(
    h("p", { class: `modal-level ${a.level}` }, `${a.icon} ${LEVEL_TEXT[a.level] || ""} · ${card.program}`),
    h("h2", { id: "modal-title" }, a.title),
    h("ol", { class: "three-q" },
      h("li", {}, h("h3", {}, "¿Qué está pasando?"), h("p", {}, a.what)),
      h("li", {}, h("h3", {}, "¿Por qué importa?"), h("p", {}, a.why)),
      h("li", {}, h("h3", {}, "¿Qué debo hacer?"), h("p", {}, a.todo))),
    h("div", { class: "actions" }, h("button", { class: "btn ghost", onclick: () => openLookup(card) }, "¿Qué es este programa?")));
}

function openLookup(card) {
  const info = card.lookup || {};
  openModal(
    h("p", { class: "modal-level info" }, "🔎 ¿Qué es esto?"),
    h("h2", { id: "modal-title" }, card.program),
    (info.explanation || []).map((line) => h("p", {}, line)),
    h("div", { class: "links" },
      (info.links || []).map((l) => h("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, `${l.label} ↗`))),
    info.exe ? h("p", { class: "exe" }, "Archivo: ", h("code", {}, info.exe)) : null);
}

/* ---------- vista en vivo ---------- */
async function refreshLive() {
  let data;
  try {
    data = await api(`/api/live?all=${$("#hide-noise").checked ? 0 : 1}`);
  } catch { return; }
  if (current !== "live") return;
  setBadge(data);
  $("#limited").hidden = !data.limited;
  const counter = $("#noise-counter");
  const hiding = $("#hide-noise").checked;
  counter.hidden = data.hidden_connections === 0;
  counter.textContent = hiding
    ? `🔕 Ocultando ${data.hidden_connections} ${data.hidden_connections === 1 ? "conexión normal" : "conexiones normales"} del sistema (haz clic para verlas)`
    : `🔔 Mostrando también ${data.hidden_connections} conexiones normales del sistema (haz clic para ocultarlas)`;
  renderCards($("#live-cards"), data.cards);
  $("#live-empty").hidden = data.cards.length > 0;
}

$("#hide-noise").addEventListener("change", refreshLive);
$("#noise-counter").addEventListener("click", () => {
  const box = $("#hide-noise");
  box.checked = !box.checked;
  refreshLive();
});

/* ---------- escaneo ---------- */
const TIPS = [
  "Puedes seguir usando el ordenador con normalidad.",
  "Estamos apuntando a quién escribe cada programa…",
  "Comprobamos si las cartas van en sobre cerrado o como postal abierta…",
  "Buscamos rastreadores de publicidad y destinos sin nombre…",
];

async function startScan(force = false) {
  clearInterval(scanTimer);
  $("#scan-running").hidden = false;
  $("#scan-result").hidden = true;
  try {
    // Si ya hay un escaneo en marcha o uno recién terminado (p. ej. al recargar), lo retomamos.
    const s = force ? { state: "idle" } : await api("/api/scan");
    if (s.state === "running") updateRing(s.progress, s.remaining);
    else if (s.state === "done" && s.finished_ago < 60) return showScan(s);
    else updateRing(0, (await api("/api/scan", { method: "POST" })).remaining ?? 30);
  } catch { return; }
  scanTimer = setInterval(pollScan, 500);
}

function updateRing(progress, remaining) {
  const bar = $(".ring-bar");
  bar.style.strokeDashoffset = String(326.7 * (1 - progress));
  bar.toggleAttribute("data-zero", progress <= 0);
  $("#scan-seconds").textContent = String(Math.max(0, Math.ceil(remaining)));
  $(".ring").setAttribute("aria-valuenow", String(Math.round(progress * 100)));
  $("#scan-tip").textContent = TIPS[Math.min(TIPS.length - 1, Math.floor(progress * TIPS.length))];
}

const VERDICT_ICON = { ok: "🟢", warn: "🟡", danger: "🔴" };

async function pollScan() {
  let s;
  try { s = await api("/api/scan"); } catch { return; }
  if (current !== "scan") return;
  if (s.state === "running") return updateRing(s.progress, s.remaining);
  if (s.state === "done") showScan(s);
}

function showScan(s) {
  clearInterval(scanTimer);
  const v = s.verdict;
  $("#verdict").className = `verdict ${v.level}`;
  $("#verdict").replaceChildren(
    h("div", { class: "verdict-icon", "aria-hidden": "true" }, VERDICT_ICON[v.level]),
    h("h2", {}, v.title),
    h("p", {}, v.message),
    h("div", { class: "stats" },
      h("span", {}, h("b", {}, v.programs), " programas revisados"),
      h("span", {}, h("b", {}, v.connections), " envíos"),
      h("span", {}, h("b", {}, v.trackers), v.trackers === 1 ? " programa con rastreadores" : " programas con rastreadores")));
  renderCards($("#scan-cards"), s.cards);
  $("#scan-running").hidden = true;
  $("#scan-result").hidden = false;
}

/* ---------- Wi-Fi ---------- */
async function loadWifi(deep) {
  const btn = $("#wifi-deep");
  btn.disabled = true;
  btn.textContent = deep ? "Buscando…" : "Buscar más a fondo";
  try {
    const data = await api(`/api/wifi?deep=${deep ? 1 : 0}`);
    $("#wifi-list").replaceChildren(...data.devices.map(renderDevice));
    $("#wifi-empty").hidden = data.devices.length > 0;
  } catch {
    $("#wifi-empty").hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Buscar más a fondo";
  }
}

function renderDevice(d) {
  const vendor = d.vendor && !d.is_me ? `Fabricante: ${d.vendor}` : null;
  return withGlossary(h("div", { class: `device${d.kind === "unknown" ? " unknown" : ""}` },
    h("span", { class: "device-icon", "aria-hidden": "true" }, d.icon),
    h("div", {},
      h("h3", {}, d.name, d.private_mac && d.kind !== "me" ? h("span", { class: "tag" }, "dirección privada") : null),
      vendor ? h("p", {}, vendor) : null,
      d.note ? h("p", {}, d.note) : null,
      h("p", {}, h("code", {}, d.ip)))));
}

$("#wifi-deep").addEventListener("click", () => loadWifi(true));
$("#scan-again").addEventListener("click", () => startScan(true));

/* ---------- arranque ---------- */
function setBadge(data) {
  const badge = $("#mode-badge");
  badge.hidden = false;
  if (data.mode === "demo") { badge.className = "badge demo"; badge.textContent = "Modo demostración"; }
  else if (data.capture) { badge.className = "badge capture"; badge.textContent = "Análisis completo"; }
  else { badge.className = "badge"; badge.textContent = "Modo básico"; badge.title = "Abre Cartero con --captura para medir datos"; }
}

$("#modal").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });

(async () => {
  await loadGlossary();
  try { setBadge(await api("/api/status")); } catch { /* el servidor aún arranca */ }
  go(location.hash.slice(1) || "home");
})();

"use strict";

// All content is built with textContent through h(); request data in the
// activity log comes from proxy clients and must never be parsed as HTML.

const TABS = ["activity", "secrets", "rules", "providers", "setup"];
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const MAX_ROWS = 500;
const MAX_EVENTS = 2000;

const state = {
  signedOut: false,
  status: null,
  config: { providers: {}, secrets: {}, rules: [] },
  secrets: [],
  events: [],
  paused: false,
  missed: 0,
  live: false,
};

const $ = (selector, root = document) => root.querySelector(selector);

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key === "value") el.value = value;
    else if (key === "checked") el.checked = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

// ---------------------------------------------------------------- session

// The session token is kept in localStorage, which is scoped to this origin
// including the port, and sent as a bearer header. Cookies are avoided
// because browsers send them to every port on 127.0.0.1, including ports a
// VM forwards to this machine.
const SESSION_KEY = "fullmakt.session";

function loadSession() {
  try {
    const s = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    if (s && s.session && new Date(s.expiresAt) > new Date()) return s.session;
  } catch {}
  return null;
}

function storeSession(s) {
  try {
    localStorage.setItem(SESSION_KEY, JSON.stringify(s));
  } catch {}
}

function clearSession() {
  try {
    localStorage.removeItem(SESSION_KEY);
  } catch {}
}

// Exchanges a single-use login token from the URL fragment for a session.
async function loginFromFragment() {
  const match = location.hash.match(/^#login=([0-9a-f]+)$/);
  if (!match) return;
  // Remove the token from the address bar and history right away.
  history.replaceState(null, "", location.pathname + "#activity");
  const res = await fetch("/api/session", {
    method: "POST",
    headers: { "X-Fullmakt-Request": "1", "Content-Type": "application/json" },
    body: JSON.stringify({ token: match[1] }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    toast(data?.errors?.[0] || "Login failed", true);
    return;
  }
  storeSession(await res.json());
}

function authHeaders() {
  const session = loadSession();
  return session ? { Authorization: `Bearer ${session}` } : {};
}

// ---------------------------------------------------------------- API

class ApiError extends Error {
  constructor(status, errors) {
    super(errors.join("; "));
    this.status = status;
    this.errors = errors;
  }
}

async function api(method, path, body) {
  const options = { method, headers: { "X-Fullmakt-Request": "1", ...authHeaders() } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const res = await fetch(path, options);
  if (res.status === 401) {
    clearSession();
    setSignedOut();
    throw new ApiError(401, ["Not signed in"]);
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data?.errors || [res.statusText]);
  return data;
}

function normalizeConfig(c) {
  return {
    providers: c.providers || {},
    secrets: c.secrets || {},
    rules: (c.rules || []).map((r) => ({
      name: r.name || "",
      disabled: !!r.disabled,
      host: r.host,
      clients: r.clients || [],
      methods: r.methods || [],
      paths: r.paths || [],
      inject: r.inject || [],
    })),
  };
}

async function loadAll() {
  const [status, config, secrets, events, clients] = await Promise.all([
    api("GET", "/api/status"),
    api("GET", "/api/config"),
    api("GET", "/api/secrets"),
    api("GET", "/api/events"),
    api("GET", "/api/clients"),
  ]);
  state.status = status;
  state.clients = clients || [];
  state.config = normalizeConfig(config);
  state.secrets = secrets || [];
  state.events = (events || []).reverse();
  renderAll();
}

async function refreshStatus() {
  const [status, secrets] = await Promise.all([api("GET", "/api/status"), api("GET", "/api/secrets")]);
  state.status = status;
  state.secrets = secrets || [];
}

// Applies a change to a copy of the configuration and saves it. The server
// validates the whole configuration and rejects the change on any error.
async function saveConfig(mutate) {
  const next = structuredClone(state.config);
  mutate(next);
  state.config = normalizeConfig(await api("PUT", "/api/config", next));
  await refreshStatus();
  renderAll();
}

// ---------------------------------------------------------------- shell

function setSignedOut() {
  state.signedOut = true;
  $("#signed-out").hidden = false;
  $("#logout").hidden = true;
  showTab();
  renderStatus();
}

function showTab() {
  const requested = location.hash.slice(1);
  const tab = TABS.includes(requested) ? requested : "activity";
  for (const t of TABS) $("#view-" + t).hidden = state.signedOut || t !== tab;
  for (const a of document.querySelectorAll("#tabs a")) {
    a.classList.toggle("active", a.dataset.tab === tab);
    a.toggleAttribute("aria-current", a.dataset.tab === tab);
  }
}

function renderStatus() {
  const el = $("#status");
  if (state.signedOut) {
    el.replaceChildren(h("span", { class: "dot off" }), "Signed out");
    return;
  }
  if (!state.status) return;
  el.replaceChildren(
    h("span", { class: state.live ? "dot" : "dot off", title: state.live ? "Live" : "Activity stream disconnected" }),
    `Proxy ${state.status.proxyListen}`,
  );
}

function renderAll() {
  renderStatus();
  renderAttention();
  renderClientFilter();
  renderActivity();
  renderSecrets();
  renderRules();
  renderProviders();
  renderSetup();
}

// Collects problems from status, secrets, rules and clients so they are
// visible without visiting every tab.
function renderAttention() {
  const items = [];
  const link = (text, tab) => h("a", { href: "#" + tab, text });
  if (state.status && (state.clients || []).length === 0) {
    items.push(["bad", ["No proxy clients, so every request is refused. ", link("Add a client", "setup")]]);
  }
  for (const s of state.secrets.filter((x) => x.error)) {
    items.push(["bad", [`Secret ${s.name} cannot be resolved. `, link("Details", "secrets")]]);
  }
  for (const w of state.status?.warnings || []) items.push(["warn", [w]]);
  for (const r of state.config.rules.filter((x) => x.disabled)) {
    items.push(["info", [`Rule ${r.name || r.host} is paused. `, link("Rules", "rules")]]);
  }
  $("#attention-list").replaceChildren(...items.map(([level, content]) => h("li", { class: level }, content)));
  $("#attention").hidden = items.length === 0;
}

function renderClientFilter() {
  const select = $("#activity-client");
  const current = select.value;
  const names = (state.clients || []).map((c) => c.name);
  select.replaceChildren(h("option", { value: "", text: "All clients" }), ...names.map((n) => h("option", { value: n, text: n })));
  select.value = names.includes(current) ? current : "";
}

let toastTimer;
function toast(message, bad = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("bad", bad);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), bad ? 6000 : 3000);
}

async function run(action, success) {
  try {
    await action();
    if (success) toast(success);
  } catch (err) {
    if (err.status !== 401) toast(err.message, true);
  }
}

// ---------------------------------------------------------------- dialog

let dialogSubmit = null;

function openDialog({ title, body, submitLabel = "Save", onSubmit = null }) {
  $("#dialog-title").textContent = title;
  $("#dialog-body").replaceChildren(body);
  setDialogErrors([]);
  const submit = $("#dialog-submit");
  submit.textContent = submitLabel;
  submit.hidden = !onSubmit;
  submit.disabled = false;
  $("#dialog-cancel").textContent = onSubmit ? "Cancel" : "Close";
  dialogSubmit = onSubmit;
  $("#dialog").showModal();
  $("input, select, textarea", body)?.focus();
}

function closeDialog() {
  $("#dialog").close();
  $("#dialog-body").replaceChildren();
  dialogSubmit = null;
}

function setDialogErrors(errors) {
  const list = $("#dialog-errors");
  list.replaceChildren(...errors.map((e) => h("li", { text: e })));
  list.hidden = errors.length === 0;
}

function field(label, input, hint) {
  return h("label", { class: "field" }, h("span", { text: label }), input, hint ? h("span", { class: "hint", text: hint }) : null);
}

function textInput(value, props = {}) {
  return h("input", { type: "text", value: value ?? "", autocomplete: "off", spellcheck: "false", ...props });
}

function secretInput() {
  return h("input", { type: "password", autocomplete: "new-password", spellcheck: "false" });
}

function select(options, value) {
  return h("select", {}, options.map(([v, label]) => h("option", { value: v, text: label, selected: v === value })));
}

function fail(message) {
  throw new ApiError(400, [message]);
}

// ---------------------------------------------------------------- activity

function statusClass(code) {
  if (code >= 500) return "bad";
  if (code >= 400) return "warn";
  if (code >= 200 && code < 300) return "ok";
  return "";
}

function modeBadge(mode) {
  const labels = { intercept: ["accent", "intercept"], tunnel: ["", "tunnel"], plain: ["warn", "plain http"] };
  const [cls, text] = labels[mode] || ["", mode || ""];
  return h("span", { class: "badge " + cls, text });
}

function chips(items) {
  return h("div", { class: "chips" }, (items || []).map((s) => h("span", { class: "badge accent", text: s })));
}

function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function eventMatches(e) {
  // An intercepted CONNECT is followed by its requests; show it only when
  // asked, or when it failed and no request follows.
  if (e.kind === "connect" && e.mode === "intercept" && !e.rejected && !e.error && !$("#activity-connections").checked) return false;
  if ($("#activity-secrets-only").checked && !(e.secrets && e.secrets.length)) return false;
  const client = $("#activity-client").value;
  if (client && e.client !== client) return false;
  const q = $("#activity-filter").value.trim().toLowerCase();
  if (!q) return true;
  return [e.host, e.path, e.rule, e.method, e.mode, e.client, ...(e.secrets || [])].some((v) => v && v.toLowerCase().includes(q));
}

// errorNote shows a one-line summary of a long error, with the full text on
// demand. The summary skips wrapper prefixes ("rule x: header y: ... error
// calling secret:") so the provider's own message comes first.
function errorNote(text, prefix = "") {
  const cause = text.split("error calling secret: ").pop().replace(/^secret "[^"]+": /, "");
  if (text.length <= 140 && cause === text) return h("span", { class: "note bad", text: prefix + text });
  const summary = prefix + (cause.length > 120 ? cause.slice(0, 117) + "…" : cause);
  return h("details", { class: "note bad" }, h("summary", { text: summary }), h("div", { class: "detail", text }));
}

function eventRow(e) {
  const request = h("div", { class: "request" }, h("span", { class: "method", text: e.kind === "connect" ? "CONNECT" : e.method }), e.host);
  if (e.path) request.append(h("span", { class: "path", text: e.path }));
  return h(
    "tr",
    {},
    h("td", { class: "time c-time", text: fmtTime(e.time), title: e.time }),
    h("td", { class: "mono nowrap c-client", text: e.client || "—" }),
    h("td", { class: "optional" }, modeBadge(e.mode)),
    h(
      "td",
      { class: "c-request" },
      request,
      // A rejection already explains the error; keep the detail as a tooltip.
      e.rejected ? h("span", { class: "note bad", text: "Rejected: " + e.rejected, title: e.error }) : null,
      e.error && !e.rejected ? errorNote(e.error) : null,
    ),
    h("td", { class: "optional nowrap", text: e.rule || "" }),
    h("td", { class: "c-secrets" }, chips(e.secrets)),
    h("td", { class: "num c-status" }, e.status ? h("span", { class: "badge " + statusClass(e.status), text: String(e.status) }) : ""),
    h("td", { class: "num time optional", text: e.kind === "request" ? String(e.durationMs ?? 0) : "" }),
  );
}

function renderActivity() {
  const rows = state.events.filter(eventMatches).slice(0, MAX_ROWS).map(eventRow);
  $("#activity-table tbody").replaceChildren(...rows);
  $("#activity-empty").hidden = rows.length > 0;
  $("#activity-table").hidden = rows.length === 0;
  $("#activity-pause").textContent = state.paused ? `Resume${state.missed ? ` (${state.missed} new)` : ""}` : "Pause";
}

function addEvent(e) {
  state.events.unshift(e);
  if (state.events.length > MAX_EVENTS) state.events.length = MAX_EVENTS;
  if (state.paused) {
    state.missed++;
    $("#activity-pause").textContent = `Resume (${state.missed} new)`;
    return;
  }
  if (!eventMatches(e)) return;
  const body = $("#activity-table tbody");
  body.prepend(eventRow(e));
  while (body.rows.length > MAX_ROWS) body.lastElementChild.remove();
  $("#activity-empty").hidden = true;
  $("#activity-table").hidden = false;
}

// Reads the server-sent event stream with fetch, which, unlike EventSource,
// can send the Authorization header. Reconnects after errors.
async function connectStream() {
  while (!state.signedOut) {
    try {
      const res = await fetch("/api/events/stream", { headers: authHeaders() });
      if (res.status === 401) {
        clearSession();
        setSignedOut();
        return;
      }
      if (!res.ok || !res.body) throw new Error(`stream status ${res.status}`);
      state.live = true;
      renderStatus();
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value;
        let end;
        while ((end = buffer.indexOf("\n\n")) >= 0) {
          const message = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          const data = message
            .split("\n")
            .filter((line) => line.startsWith("data: "))
            .map((line) => line.slice(6))
            .join("\n");
          if (data) addEvent(JSON.parse(data));
        }
      }
    } catch {}
    state.live = false;
    renderStatus();
    await new Promise((r) => setTimeout(r, 3000));
  }
}

// ---------------------------------------------------------------- secrets

function providerType(name) {
  return state.config.providers[name]?.type;
}

function secretPattern(name) {
  return new RegExp(`secret\\s+"${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`);
}

function rulesUsing(secretName) {
  const pattern = secretPattern(secretName);
  return state.config.rules.filter((r) => r.inject.some((i) => pattern.test(i.value))).map((r) => r.name || r.host);
}

function shortDuration(d) {
  return (d || "").replace(/([hm])0s$/, "$1").replace(/h0m$/, "h");
}

function secretStatusCell(st) {
  if (!st) return h("span", { class: "badge", text: "Unknown" });
  if (st.error) return [h("span", { class: "badge bad", text: "Error" }), errorNote(st.error)];
  if (st.cached) return [h("span", { class: "badge ok", text: "Cached" }), h("span", { class: "note", text: "until " + fmtTime(st.expiresAt) })];
  if (st.fetchedAt) return [h("span", { class: "badge", text: "Expired" }), h("span", { class: "note", text: "fetched " + fmtTime(st.fetchedAt) })];
  return h("span", { class: "badge", text: "Not fetched" });
}

function renderSecrets() {
  const statuses = Object.fromEntries(state.secrets.map((s) => [s.name, s]));
  const names = Object.keys(state.config.secrets).sort();
  const rows = names.map((name) => {
    const s = state.config.secrets[name];
    const used = rulesUsing(name);
    const isLocal = providerType(s.provider) === "local";
    const check = h("button", { type: "button", class: "btn small", text: "Check" });
    check.addEventListener("click", () => checkSecret(name, check));
    return h(
      "tr",
      {},
      h("td", { class: "nowrap" }, h("span", { class: "mono", text: name }), h("span", { class: "note", text: used.length ? "Used by " + used.join(", ") : "Not used by any rule" })),
      h(
        "td",
        { class: "nowrap" },
        h("span", { class: "badge", text: s.provider }),
        " ",
        h("span", { class: "mono", text: s.name }),
        s.version ? h("span", { class: "note", text: "version " + s.version }) : null,
      ),
      h("td", { text: shortDuration(s.ttl) }),
      h("td", {}, secretStatusCell(statuses[name])),
      h(
        "td",
        { class: "row-actions" },
        check,
        " ",
        isLocal ? h("button", { type: "button", class: "btn small", text: "Values", onclick: () => keysDialog(s.provider) }) : null,
        isLocal ? " " : null,
        h("button", { type: "button", class: "btn small", text: "Edit", onclick: () => secretDialog(name) }),
        " ",
        h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => deleteSecret(name) }),
      ),
    );
  });
  $("#secrets-table tbody").replaceChildren(...rows);
  renderAttention();
  $("#secrets-empty").hidden = rows.length > 0;
  $("#secrets-table").hidden = rows.length === 0;
}

async function checkSecret(name, button) {
  button.disabled = true;
  await run(async () => {
    const result = await api("POST", `/api/secrets/${encodeURIComponent(name)}/check`);
    state.secrets = (await api("GET", "/api/secrets")) || [];
    renderSecrets();
    if (result.ok) toast(`Secret ${name} resolved`);
    else toast(result.error, true);
  });
  button.disabled = false;
}

function secretDialog(original) {
  const providers = Object.keys(state.config.providers).sort();
  if (providers.length === 0) {
    toast("Add a provider first", true);
    location.hash = "#providers";
    return;
  }
  const s = original ? state.config.secrets[original] : { provider: providers[0], name: "", version: "", ttl: "15m0s" };
  const name = textInput(original, { placeholder: "github", pattern: "[A-Za-z0-9_-]+" });
  const provider = select(providers.map((p) => [p, `${p} (${state.config.providers[p].type})`]), s.provider);
  const remote = textInput(s.name);
  const version = textInput(s.version, { placeholder: "latest" });
  const ttl = textInput(shortDuration(s.ttl), { placeholder: "15m" });
  const value = secretInput();

  const remoteField = field("", remote);
  const versionField = field("Version", version, "Empty means the latest version.");
  const valueField = field("Value", value, "Optional. Encrypted in the provider's file; it can never be viewed or changed, only deleted.");
  const sync = () => {
    const local = providerType(provider.value) === "local";
    remoteField.firstChild.textContent = local ? "Key in file" : "Key Vault secret name";
    versionField.hidden = local;
    // Existing values are never edited; only new secrets can bring a value.
    valueField.hidden = !local || Boolean(original);
  };
  provider.addEventListener("change", sync);
  sync();

  openDialog({
    title: original ? `Edit secret ${original}` : "Add secret",
    body: h(
      "div",
      { class: "stack" },
      field("Name", name, "Used in rule templates as {{ secret \"name\" }}. Letters, digits, _ and -."),
      field("Provider", provider),
      remoteField,
      versionField,
      field("Cache TTL", ttl, "How long the value is kept in memory, e.g. 5m or 1h."),
      valueField,
    ),
    onSubmit: async () => {
      const key = name.value.trim();
      if (!key) fail("Name is required");
      if (key !== original && state.config.secrets[key]) fail(`Secret ${key} already exists`);
      const local = providerType(provider.value) === "local";
      const entry = { provider: provider.value, name: remote.value.trim(), ttl: ttl.value.trim() || "15m" };
      if (!local && version.value.trim()) entry.version = version.value.trim();
      // Store the value first: if it already exists, nothing else changes.
      if (local && !original && value.value) await addLocalValue(entry.provider, entry.name, value.value);
      await saveConfig((cfg) => {
        if (original && original !== key) {
          delete cfg.secrets[original];
          renameSecretInRules(cfg, original, key);
        }
        cfg.secrets[key] = entry;
      });
      toast(original ? "Secret updated" : "Secret added");
    },
  });
}

function renameSecretInRules(cfg, from, to) {
  const pattern = new RegExp(secretPattern(from).source, "g");
  for (const rule of cfg.rules) {
    for (const inj of rule.inject) inj.value = inj.value.replace(pattern, `secret "${to}"`);
  }
}

function deleteSecret(name) {
  const used = rulesUsing(name);
  if (used.length) {
    toast(`Secret ${name} is used by ${used.join(", ")}. Change those rules first.`, true);
    return;
  }
  if (!confirm(`Delete secret ${name}? Values stored in providers are not deleted.`)) return;
  run(() => saveConfig((cfg) => delete cfg.secrets[name]), "Secret deleted");
}

async function addLocalValue(provider, name, value) {
  await api("POST", `/api/providers/${encodeURIComponent(provider)}/keys`, { name, value });
  state.secrets = (await api("GET", "/api/secrets")) || [];
  renderSecrets();
}

// ---------------------------------------------------------------- rules

const FORMATS = [
  ["bearer", "Bearer token"],
  ["basic", "Basic auth (user + secret)"],
  ["raw", "Secret value only"],
  ["custom", "Custom template"],
];

function quote(s) {
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

function parseTemplate(value) {
  let m;
  if ((m = value.match(/^Bearer \{\{\s*secret "([A-Za-z0-9_-]+)"\s*\}\}$/))) return { format: "bearer", secret: m[1] };
  if ((m = value.match(/^\{\{\s*basic "((?:[^"\\]|\\.)*)" \(secret "([A-Za-z0-9_-]+)"\)\s*\}\}$/)))
    return { format: "basic", user: m[1].replace(/\\(.)/g, "$1"), secret: m[2] };
  if ((m = value.match(/^\{\{\s*secret "([A-Za-z0-9_-]+)"\s*\}\}$/))) return { format: "raw", secret: m[1] };
  return { format: "custom", template: value };
}

function buildTemplate({ format, secret, user, template }) {
  switch (format) {
    case "bearer":
      return `Bearer {{ secret "${secret}" }}`;
    case "basic":
      return `{{ basic ${quote(user)} (secret "${secret}") }}`;
    case "raw":
      return `{{ secret "${secret}" }}`;
    default:
      return template;
  }
}

// describeInject renders a header template in readable form, with secrets
// as chips: "Bearer ‹github›", "Basic x-access-token : ‹github›".
function describeInject(inj) {
  const p = parseTemplate(inj.value);
  const secret = (name) => h("span", { class: "badge accent", text: name });
  let value;
  switch (p.format) {
    case "bearer":
      value = ["Bearer ", secret(p.secret)];
      break;
    case "basic":
      value = ["Basic ", h("span", { class: "mono", text: p.user }), " : ", secret(p.secret)];
      break;
    case "raw":
      value = [secret(p.secret)];
      break;
    default:
      value = [h("span", { class: "mono", text: inj.value })];
  }
  return h("div", { class: "inject" }, h("span", { class: "header", text: inj.header }), h("span", { class: "value" }, value));
}

function renderRules() {
  const rules = state.config.rules;
  const known = new Set((state.clients || []).map((c) => c.name));
  const items = rules.map((r, i) => {
    const clientChips = r.clients.length
      ? h(
          "div",
          { class: "chips" },
          r.clients.map((c) => h("span", { class: known.has(c) ? "badge accent" : "badge warn", text: c, title: known.has(c) ? null : "No such client; the rule does not apply to it" })),
        )
      : h("span", { class: "note", text: "All clients" });
    return h(
      "li",
      { class: r.disabled ? "card paused" : "card" },
      h(
        "div",
        { class: "card-head" },
        h("span", { class: "order", text: `${i + 1}` }),
        h("div", { class: "title" }, h("h2", { text: r.name || r.host }), r.name ? h("span", { class: "mono host", text: r.host }) : null),
        r.disabled ? h("span", { class: "badge warn", text: "Paused" }) : null,
        h(
          "div",
          { class: "btn-group" },
          h("button", {
            type: "button",
            class: "btn small",
            text: r.disabled ? "Resume" : "Pause",
            title: r.disabled ? "Start injecting secrets for this rule again" : "Stop injecting secrets for this rule",
            onclick: () => toggleRule(i),
          }),
          h("button", { type: "button", class: "btn small icon", text: "↑", title: "Move up", "aria-label": "Move up", disabled: i === 0, onclick: () => moveRule(i, -1) }),
          h("button", { type: "button", class: "btn small icon", text: "↓", title: "Move down", "aria-label": "Move down", disabled: i === rules.length - 1, onclick: () => moveRule(i, 1) }),
          h("button", { type: "button", class: "btn small", text: "Edit", onclick: () => ruleDialog(i) }),
          h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => deleteRule(i) }),
        ),
      ),
      h(
        "dl",
        { class: "kv" },
        h("dt", { text: "Clients" }),
        h("dd", {}, clientChips),
        h("dt", { text: "Requests" }),
        h(
          "dd",
          {},
          h("span", { class: "mono", text: r.methods.length ? r.methods.join(", ") : "Any method" }),
          h("span", { class: "sep", text: " · " }),
          h("span", { class: "mono", text: r.paths.length ? r.paths.join("  ") : "any path" }),
        ),
        h("dt", { text: "Headers" }),
        h("dd", {}, r.inject.map(describeInject)),
      ),
    );
  });
  $("#rules-list").replaceChildren(...items);
  $("#rules-empty").hidden = items.length > 0;
}

function moveRule(i, delta) {
  run(() =>
    saveConfig((cfg) => {
      const [rule] = cfg.rules.splice(i, 1);
      cfg.rules.splice(i + delta, 0, rule);
    }),
  );
}

function toggleRule(i) {
  const r = state.config.rules[i];
  const label = r.name || r.host;
  run(
    () => saveConfig((cfg) => (cfg.rules[i].disabled = !r.disabled)),
    r.disabled ? `Rule ${label} resumed` : `Rule ${label} paused`,
  );
}

function deleteRule(i) {
  const r = state.config.rules[i];
  if (!confirm(`Delete rule ${r.name || r.host}?`)) return;
  run(() => saveConfig((cfg) => cfg.rules.splice(i, 1)), "Rule deleted");
}

function injectRow(inj, secretNames, container) {
  const parsed = parseTemplate(inj.value || `Bearer {{ secret "${secretNames[0] || ""}" }}`);
  const header = textInput(inj.header || "Authorization", { placeholder: "Authorization", "aria-label": "Header name" });
  const format = select(FORMATS, parsed.format);
  format.setAttribute("aria-label", "Value format");
  const secret = select(secretNames.map((n) => [n, n]), parsed.secret || secretNames[0]);
  secret.setAttribute("aria-label", "Secret");
  const user = textInput(parsed.user ?? "x-access-token", { placeholder: "user", "aria-label": "Basic auth user" });
  const template = h("textarea", { rows: "2", "aria-label": "Template", spellcheck: "false" });
  template.value = parsed.template ?? inj.value ?? "";
  const preview = h("div", { class: "preview" });
  const remove = h("button", { type: "button", class: "btn small danger", text: "Remove" });

  const row = h(
    "div",
    { class: "inject-row" },
    h("div", { class: "line" }, header, format, remove),
    h("div", { class: "line" }, secret, user, h("span")),
    template,
    preview,
  );
  const value = () => buildTemplate({ format: format.value, secret: secret.value, user: user.value, template: template.value });
  const sync = () => {
    const custom = format.value === "custom";
    secret.hidden = custom;
    user.hidden = format.value !== "basic";
    template.hidden = !custom;
    preview.textContent = custom ? "" : `${header.value}: ${value()}`;
  };
  // Switching to a custom template starts from the current value.
  let lastFormat = format.value;
  format.addEventListener("change", () => {
    if (format.value === "custom" && !template.value) {
      template.value = buildTemplate({ format: lastFormat, secret: secret.value, user: user.value });
    }
    lastFormat = format.value;
    sync();
  });
  for (const el of [header, secret, user]) el.addEventListener("input", sync);
  remove.addEventListener("click", () => row.remove());
  sync();
  row.read = () => ({ header: header.value.trim(), value: value() });
  container.append(row);
}

function ruleDialog(index) {
  const secretNames = Object.keys(state.config.secrets).sort();
  if (secretNames.length === 0) {
    toast("Add a secret first", true);
    location.hash = "#secrets";
    return;
  }
  const r = index === undefined ? { name: "", disabled: false, host: "", clients: [], methods: [], paths: [], inject: [{ header: "Authorization", value: "" }] } : state.config.rules[index];
  const name = textInput(r.name, { placeholder: "github-api" });
  const host = textInput(r.host, { placeholder: "api.github.com" });
  const clientNames = (state.clients || []).map((c) => c.name);
  // Keep clients the rule names even if they no longer exist, so the server
  // can report them instead of the dialog silently dropping them.
  const clientOptions = [...new Set([...clientNames, ...r.clients])].sort();
  const clientBoxes = clientOptions.map((c) => h("label", { class: "check" }, h("input", { type: "checkbox", value: c, checked: r.clients.includes(c) }), c));
  const methodBoxes = METHODS.map((m) => h("label", { class: "check" }, h("input", { type: "checkbox", value: m, checked: r.methods.includes(m) }), m));
  const paths = h("textarea", { rows: "3", placeholder: "/repos/my-org/*", spellcheck: "false" });
  paths.value = r.paths.join("\n");
  const injects = h("div", { class: "inject-list" });
  for (const inj of r.inject) injectRow(inj, secretNames, injects);
  const addHeader = h("button", { type: "button", class: "btn small", text: "Add header", onclick: () => injectRow({ header: "", value: "" }, secretNames, injects) });

  openDialog({
    title: index === undefined ? "Add rule" : `Edit rule ${r.name || r.host}`,
    body: h(
      "div",
      { class: "stack" },
      h("div", { class: "field-row" }, field("Name", name), field("Host", host, "api.github.com, *.example.com or host:8443. Port defaults to 443.")),
      h(
        "div",
        { class: "field" },
        h("span", { text: "Clients" }),
        clientBoxes.length ? h("div", { class: "methods" }, clientBoxes) : null,
        h("span", { class: "hint", text: clientBoxes.length ? "Only these clients receive the secret. None selected means all clients." : "No clients yet; the rule applies to all clients. Add clients under Setup." }),
      ),
      h("div", { class: "field" }, h("span", { text: "Methods" }), h("div", { class: "methods" }, methodBoxes), h("span", { class: "hint", text: "None selected means any method." })),
      field("Paths", paths, "One per line. * matches any characters, including /. Empty means any path."),
      h("div", { class: "field" }, h("span", { text: "Headers" }), injects, h("div", {}, addHeader)),
    ),
    onSubmit: async () => {
      const rule = {
        name: name.value.trim(),
        disabled: r.disabled || false,
        host: host.value.trim(),
        clients: clientBoxes.map((l) => $("input", l)).filter((c) => c.checked).map((c) => c.value),
        methods: methodBoxes.map((l) => $("input", l)).filter((c) => c.checked).map((c) => c.value),
        paths: paths.value.split("\n").map((p) => p.trim()).filter(Boolean),
        inject: [...injects.children].map((row) => row.read()),
      };
      if (!rule.host) fail("Host is required");
      if (rule.inject.length === 0) fail("Add at least one header");
      await saveConfig((cfg) => {
        if (index === undefined) cfg.rules.push(rule);
        else cfg.rules[index] = rule;
      });
      toast(index === undefined ? "Rule added" : "Rule updated");
    },
  });
}

// ---------------------------------------------------------------- providers

const PROVIDER_TYPES = [
  ["local", "Local file"],
  ["azure-keyvault", "Azure Key Vault"],
];

function renderProviders() {
  const names = Object.keys(state.config.providers).sort();
  const rows = names.map((name) => {
    const p = state.config.providers[name];
    const label = PROVIDER_TYPES.find(([t]) => t === p.type)?.[1] || p.type;
    return h(
      "tr",
      {},
      h("td", { class: "mono", text: name }),
      h("td", { text: label }),
      h("td", { class: "mono", text: p.file || p.vaultUri || "" }),
      h(
        "td",
        { class: "row-actions" },
        p.type === "local" ? h("button", { type: "button", class: "btn small", text: "Values", onclick: () => keysDialog(name) }) : null,
        p.type === "local" ? " " : null,
        h("button", { type: "button", class: "btn small", text: "Edit", onclick: () => providerDialog(name) }),
        " ",
        h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => deleteProvider(name) }),
      ),
    );
  });
  $("#providers-table tbody").replaceChildren(...rows);
  $("#providers-empty").hidden = rows.length > 0;
  $("#providers-table").hidden = rows.length === 0;
}

function providerDialog(original) {
  const p = original ? state.config.providers[original] : { type: "local", file: "~/.config/fullmakt/secrets.enc", vaultUri: "" };
  const name = textInput(original, { placeholder: "kv" });
  const type = select(PROVIDER_TYPES, p.type);
  const file = textInput(p.file, { placeholder: "~/.config/fullmakt/secrets.enc" });
  const vault = textInput(p.vaultUri, { placeholder: "https://my-vault.vault.azure.net" });
  const fileField = field("File", file, "Encrypted with the master key. Created with mode 600 when you add the first value.");
  const vaultField = field("Vault URI", vault, "Signs in with DefaultAzureCredential, for example `az login`. Needs the Key Vault Secrets User role.");
  const sync = () => {
    fileField.hidden = type.value !== "local";
    vaultField.hidden = type.value !== "azure-keyvault";
  };
  type.addEventListener("change", sync);
  sync();

  openDialog({
    title: original ? `Edit provider ${original}` : "Add provider",
    body: h("div", { class: "stack" }, field("Name", name), field("Type", type), fileField, vaultField),
    onSubmit: async () => {
      const key = name.value.trim();
      if (!key) fail("Name is required");
      if (key !== original && state.config.providers[key]) fail(`Provider ${key} already exists`);
      const entry = { type: type.value };
      if (type.value === "local") entry.file = file.value.trim();
      else entry.vaultUri = vault.value.trim();
      await saveConfig((cfg) => {
        if (original && original !== key) {
          delete cfg.providers[original];
          for (const s of Object.values(cfg.secrets)) if (s.provider === original) s.provider = key;
        }
        cfg.providers[key] = entry;
      });
      toast(original ? "Provider updated" : "Provider added");
    },
  });
}

function deleteProvider(name) {
  const used = Object.entries(state.config.secrets).filter(([, s]) => s.provider === name).map(([n]) => n);
  if (used.length) {
    toast(`Provider ${name} is used by secrets ${used.join(", ")}`, true);
    return;
  }
  if (!confirm(`Delete provider ${name}? Stored values are not deleted.`)) return;
  run(() => saveConfig((cfg) => delete cfg.providers[name]), "Provider deleted");
}

function fmtDateTime(iso) {
  return new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

async function keysDialog(provider) {
  let entries;
  try {
    entries = await api("GET", `/api/providers/${encodeURIComponent(provider)}/keys`);
  } catch (err) {
    if (err.status !== 401) toast(err.message, true);
    return;
  }
  const list = h("div", { class: "table-wrap" });
  const renderEntries = () => {
    const rows = [...entries]
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((e) =>
        h(
          "tr",
          {},
          h("td", { class: "mono", text: e.name }),
          h("td", { class: "time", text: fmtDateTime(e.addedAt), title: e.addedAt }),
          h(
            "td",
            { class: "row-actions" },
            h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => removeEntry(e.name) }),
          ),
        ),
      );
    list.replaceChildren(
      rows.length
        ? h("table", { class: "table" }, h("thead", {}, h("tr", {}, h("th", { text: "Name" }), h("th", { text: "Added" }), h("th"))), h("tbody", {}, rows))
        : h("p", { class: "empty", text: "No values stored yet." }),
    );
  };
  const removeEntry = (name) => {
    const used = Object.entries(state.config.secrets).filter(([, s]) => s.provider === provider && s.name === name).map(([n]) => n);
    const warning = used.length ? ` Secret ${used.join(", ")} will stop resolving.` : "";
    if (!confirm(`Delete ${name} from ${provider}? This cannot be undone.${warning}`)) return;
    run(async () => {
      await api("DELETE", `/api/providers/${encodeURIComponent(provider)}/keys/${encodeURIComponent(name)}`);
      entries = entries.filter((e) => e.name !== name);
      renderEntries();
      state.secrets = (await api("GET", "/api/secrets")) || [];
      renderSecrets();
    }, "Value deleted");
  };
  const name = textInput("", { placeholder: "name", "aria-label": "Name" });
  const value = secretInput();
  value.placeholder = "value";
  value.setAttribute("aria-label", "Value");
  const add = h("button", { type: "button", class: "btn small primary", text: "Add" });
  const store = () =>
    run(async () => {
      const n = name.value.trim();
      if (!n || !value.value) fail("Name and value are required");
      await addLocalValue(provider, n, value.value);
      entries = [...entries, { name: n, addedAt: new Date().toISOString() }];
      name.value = value.value = "";
      renderEntries();
    }, "Value added");
  add.addEventListener("click", store);
  for (const input of [name, value]) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        store();
      }
    });
  }
  renderEntries();
  openDialog({
    title: `Values in ${provider}`,
    body: h(
      "div",
      { class: "stack" },
      h("p", { class: "sub", text: "Values are encrypted and write-only: they can be added and deleted, never viewed or changed. To replace one, delete it and add it again." }),
      list,
      h("div", { class: "field" }, h("span", { text: "Add a value" }), h("div", { class: "field-row" }, name, value), h("div", {}, add)),
    ),
  });
}

// ---------------------------------------------------------------- setup

function copyable(pre, text) {
  pre.textContent = text;
  const button = h("button", { type: "button", class: "btn small", text: "Copy" });
  button.addEventListener("click", () =>
    navigator.clipboard.writeText(text).then(
      () => toast("Copied"),
      () => toast("Copy failed", true),
    ),
  );
  pre.nextElementSibling?.classList.contains("copy") && pre.nextElementSibling.remove();
  pre.after(h("p", { class: "copy" }, button));
}

function renderSetup() {
  const s = state.status;
  if (!s) return;
  const port = s.proxyListen.split(":").pop();
  copyable(
    $("#setup-ca"),
    [
      "# Inside the sandbox (Ubuntu / Debian)",
      "sudo cp fullmakt-ca.pem /usr/local/share/ca-certificates/fullmakt.crt",
      "sudo update-ca-certificates",
    ].join("\n"),
  );
  renderClients();
  copyable(
    $("#setup-env"),
    [
      "# From a Lima VM, with the client's name and token",
      `export HTTPS_PROXY=http://<client>:<token>@host.lima.internal:${port}`,
      `export HTTP_PROXY=http://<client>:<token>@host.lima.internal:${port}`,
      "export NO_PROXY=localhost,127.0.0.1",
      "",
      "# Runtimes with their own trust stores",
      "export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/fullmakt.crt",
      "export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt",
      "export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
      "",
      "# Placeholder credentials; rules replace the header",
      "export GH_TOKEN=proxy-managed",
      "export OPENAI_API_KEY=proxy-managed",
    ].join("\n"),
  );
  const facts = [
    ["Proxy", s.proxyListen],
    ["UI", s.uiListen],
    ["Config", s.configPath],
    ["CA", s.caPath],
    ["Version", s.version],
  ];
  $("#setup-facts").replaceChildren(...facts.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", { text: v })]));
}

function renderClients() {
  const rows = (state.clients || []).map((c) =>
    h(
      "tr",
      {},
      h("td", { class: "mono", text: c.name }),
      h("td", { class: "time", text: c.addedAt ? fmtDateTime(c.addedAt) : "" }),
      h(
        "td",
        { class: "row-actions" },
        h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => deleteClient(c.name) }),
      ),
    ),
  );
  $("#clients-table tbody").replaceChildren(...rows);
  $("#clients-empty").hidden = rows.length > 0;
  $("#clients-table").hidden = rows.length === 0;
}

async function refreshClients() {
  state.clients = (await api("GET", "/api/clients")) || [];
  renderClients();
  renderClientFilter();
  renderAttention();
  renderRules();
}

function clientDialog() {
  const name = textInput("", { placeholder: "agentbox", pattern: "[A-Za-z0-9_-]+" });
  openDialog({
    title: "Add client",
    submitLabel: "Create",
    body: h("div", { class: "stack" }, field("Name", name, "One per sandbox, for example the VM or container name.")),
    onSubmit: async () => {
      const result = await api("POST", "/api/clients", { name: name.value.trim() });
      await refreshClients();
      // Show the token once, in a fresh dialog; it cannot be retrieved later.
      setTimeout(() => showClientToken(result), 0);
    },
  });
}

function showClientToken({ name, token }) {
  const port = state.status.proxyListen.split(":").pop();
  const pre = h("pre", { class: "code" });
  const body = h(
    "div",
    { class: "stack" },
    h("p", { class: "sub", text: "Copy this now. Only a hash is stored, so the token cannot be shown again. Anyone with it can use your secrets through the proxy." }),
    pre,
  );
  openDialog({ title: `Token for ${name}`, body });
  copyable(pre, [`export HTTPS_PROXY=http://${name}:${token}@host.lima.internal:${port}`, `export HTTP_PROXY=http://${name}:${token}@host.lima.internal:${port}`].join("\n"));
}

function deleteClient(name) {
  const used = state.config.rules.filter((r) => r.clients.includes(name)).map((r) => r.name || r.host);
  if (used.length) {
    toast(`Client ${name} is used by rules ${used.join(", ")}. Remove it from those rules first.`, true);
    return;
  }
  if (!confirm(`Delete client ${name}? Its token stops working immediately.`)) return;
  run(async () => {
    await api("DELETE", `/api/clients/${encodeURIComponent(name)}`);
    await refreshClients();
  }, "Client deleted");
}

async function downloadCA() {
  const res = await fetch("/api/ca.pem", { headers: authHeaders() });
  if (!res.ok) {
    toast("Download failed", true);
    return;
  }
  const url = URL.createObjectURL(await res.blob());
  const a = h("a", { href: url, download: "fullmakt-ca.pem" });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------- wiring

function init() {
  $("#dialog-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!dialogSubmit) {
      closeDialog();
      return;
    }
    const submit = $("#dialog-submit");
    submit.disabled = true;
    try {
      await dialogSubmit();
      closeDialog();
    } catch (err) {
      setDialogErrors(err.errors || [err.message]);
    } finally {
      submit.disabled = false;
    }
  });
  $("#dialog-cancel").addEventListener("click", closeDialog);
  $("#dialog").addEventListener("close", () => (dialogSubmit = null));

  $("#activity-filter").addEventListener("input", renderActivity);
  $("#activity-secrets-only").addEventListener("change", renderActivity);
  $("#activity-connections").addEventListener("change", renderActivity);
  $("#activity-client").addEventListener("change", renderActivity);
  $("#activity-pause").addEventListener("click", () => {
    state.paused = !state.paused;
    state.missed = 0;
    renderActivity();
  });
  $("#activity-clear").addEventListener("click", () => {
    state.events = [];
    state.missed = 0;
    renderActivity();
  });
  $("#add-secret").addEventListener("click", () => secretDialog());
  $("#add-rule").addEventListener("click", () => ruleDialog());
  $("#add-provider").addEventListener("click", () => providerDialog());
  $("#add-client").addEventListener("click", () => clientDialog());
  $("#download-ca").addEventListener("click", downloadCA);
  $("#logout").addEventListener("click", () =>
    run(async () => {
      await api("DELETE", "/api/session").catch(() => {});
      clearSession();
      setSignedOut();
    }),
  );
  $("#reload-config").addEventListener("click", () =>
    run(async () => {
      state.config = normalizeConfig(await api("POST", "/api/reload"));
      await refreshStatus();
      renderAll();
    }, "Configuration reloaded"),
  );

  window.addEventListener("hashchange", showTab);
  showTab();

  loginFromFragment()
    .then(loadAll)
    .then(
    () => {
      $("#logout").hidden = false;
      connectStream();
      setInterval(() => {
        if (state.signedOut || document.hidden) return;
        api("GET", "/api/secrets")
          .then((s) => {
            state.secrets = s || [];
            renderSecrets();
          })
          .catch(() => {});
      }, 15000);
    },
    (err) => {
      if (err.status !== 401) toast(err.message, true);
    },
  );
}

init();

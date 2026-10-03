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

// ---------------------------------------------------------------- API

class ApiError extends Error {
  constructor(status, errors) {
    super(errors.join("; "));
    this.status = status;
    this.errors = errors;
  }
}

async function api(method, path, body) {
  const options = { method, headers: { "X-Fullmakt-Request": "1" } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const res = await fetch(path, options);
  if (res.status === 401) {
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
      methods: r.methods || [],
      paths: r.paths || [],
      inject: r.inject || [],
    })),
  };
}

async function loadAll() {
  const [status, config, secrets, events] = await Promise.all([
    api("GET", "/api/status"),
    api("GET", "/api/config"),
    api("GET", "/api/secrets"),
    api("GET", "/api/events"),
  ]);
  state.status = status;
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
  showTab();
  renderStatus();
}

function showTab() {
  const requested = location.hash.slice(1);
  const tab = TABS.includes(requested) ? requested : "activity";
  for (const t of TABS) $("#" + t).hidden = state.signedOut || t !== tab;
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
  renderActivity();
  renderSecrets();
  renderRules();
  renderProviders();
  renderSetup();
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
  if ($("#activity-secrets-only").checked && !(e.secrets && e.secrets.length)) return false;
  const q = $("#activity-filter").value.trim().toLowerCase();
  if (!q) return true;
  return [e.host, e.path, e.rule, e.method, e.mode, ...(e.secrets || [])].some((v) => v && v.toLowerCase().includes(q));
}

function eventRow(e) {
  const request = h("div", { class: "request" }, h("span", { class: "method", text: e.kind === "connect" ? "CONNECT" : e.method }), e.host);
  if (e.path) request.append(h("span", { class: "path", text: e.path }));
  return h(
    "tr",
    {},
    h("td", { class: "time", text: fmtTime(e.time), title: e.time }),
    h("td", {}, modeBadge(e.mode)),
    h(
      "td",
      {},
      request,
      // A rejection already explains the error; keep the detail as a tooltip.
      e.rejected ? h("span", { class: "note bad", text: "Rejected: " + e.rejected, title: e.error }) : null,
      e.error && !e.rejected ? h("span", { class: "note bad", text: e.error }) : null,
    ),
    h("td", { text: e.rule || "" }),
    h("td", {}, chips(e.secrets)),
    h("td", { class: "num" }, e.status ? h("span", { class: "badge " + statusClass(e.status), text: String(e.status) }) : ""),
    h("td", { class: "num time", text: e.kind === "request" ? String(e.durationMs ?? 0) : "" }),
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

function connectStream() {
  const source = new EventSource("/api/events/stream");
  source.onopen = () => {
    state.live = true;
    renderStatus();
  };
  source.onmessage = (m) => addEvent(JSON.parse(m.data));
  source.onerror = () => {
    state.live = false;
    renderStatus();
  };
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
  if (st.error) return [h("span", { class: "badge bad", text: "Error" }), h("span", { class: "note bad", text: st.error })];
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
      h("td", {}, h("span", { class: "mono", text: name }), h("span", { class: "note", text: used.length ? "Used by " + used.join(", ") : "Not used by any rule" })),
      h("td", {}, h("span", { class: "mono", text: `${s.provider} › ${s.name}` }), s.version ? h("span", { class: "note", text: "version " + s.version }) : null),
      h("td", { text: shortDuration(s.ttl) }),
      h("td", {}, secretStatusCell(statuses[name])),
      h(
        "td",
        { class: "row-actions" },
        check,
        " ",
        isLocal ? h("button", { type: "button", class: "btn small", text: "Set value", onclick: () => setValueDialog(s.provider, s.name) }) : null,
        isLocal ? " " : null,
        h("button", { type: "button", class: "btn small", text: "Edit", onclick: () => secretDialog(name) }),
        " ",
        h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => deleteSecret(name) }),
      ),
    );
  });
  $("#secrets-table tbody").replaceChildren(...rows);
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
  const valueField = field("Value", value, original ? "Leave empty to keep the current value." : "Stored in the provider's file. It cannot be read back.");
  const sync = () => {
    const local = providerType(provider.value) === "local";
    remoteField.firstChild.textContent = local ? "Key in file" : "Key Vault secret name";
    versionField.hidden = local;
    valueField.hidden = !local;
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
      await saveConfig((cfg) => {
        if (original && original !== key) {
          delete cfg.secrets[original];
          renameSecretInRules(cfg, original, key);
        }
        cfg.secrets[key] = entry;
      });
      if (local && value.value) await putLocalValue(entry.provider, entry.name, value.value);
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

async function putLocalValue(provider, key, value) {
  await api("PUT", `/api/providers/${encodeURIComponent(provider)}/keys/${encodeURIComponent(key)}`, { value });
  state.secrets = (await api("GET", "/api/secrets")) || [];
  renderSecrets();
}

function setValueDialog(provider, key) {
  const value = secretInput();
  openDialog({
    title: `Set value for ${key}`,
    body: h("div", { class: "stack" }, field("Value", value, `Written to provider ${provider}. Values are write-only and cannot be read back here.`)),
    onSubmit: async () => {
      if (!value.value) fail("Value is required");
      await putLocalValue(provider, key, value.value);
      toast("Value saved");
    },
  });
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

function renderRules() {
  const rules = state.config.rules;
  const items = rules.map((r, i) =>
    h(
      "li",
      { class: r.disabled ? "card paused" : "card" },
      h(
        "div",
        { class: "card-head" },
        h("span", { class: "order", text: `${i + 1}.` }),
        h("h2", { text: r.name || r.host }),
        r.disabled ? h("span", { class: "badge warn", text: "Paused" }) : null,
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
      h(
        "dl",
        { class: "kv" },
        h("dt", { text: "Host" }),
        h("dd", { class: "mono", text: r.host }),
        h("dt", { text: "Methods" }),
        h("dd", {}, r.methods.length ? chips(r.methods) : h("span", { class: "note", text: "Any method" })),
        h("dt", { text: "Paths" }),
        h("dd", {}, r.paths.length ? r.paths.map((p) => h("div", { class: "mono", text: p })) : h("span", { class: "note", text: "Any path" })),
        h("dt", { text: "Headers" }),
        h("dd", {}, r.inject.map((inj) => h("div", { class: "inject" }, h("span", { class: "header", text: inj.header + ": " }), inj.value))),
      ),
    ),
  );
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
  const r = index === undefined ? { name: "", disabled: false, host: "", methods: [], paths: [], inject: [{ header: "Authorization", value: "" }] } : state.config.rules[index];
  const name = textInput(r.name, { placeholder: "github-api" });
  const host = textInput(r.host, { placeholder: "api.github.com" });
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
      h("div", { class: "field" }, h("span", { text: "Methods" }), h("div", { class: "methods" }, methodBoxes), h("span", { class: "hint", text: "None selected means any method." })),
      field("Paths", paths, "One per line. * matches any characters, including /. Empty means any path."),
      h("div", { class: "field" }, h("span", { text: "Headers" }), injects, h("div", {}, addHeader)),
    ),
    onSubmit: async () => {
      const rule = {
        name: name.value.trim(),
        disabled: r.disabled || false,
        host: host.value.trim(),
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
  const p = original ? state.config.providers[original] : { type: "local", file: "~/.config/fullmakt/secrets.yaml", vaultUri: "" };
  const name = textInput(original, { placeholder: "kv" });
  const type = select(PROVIDER_TYPES, p.type);
  const file = textInput(p.file, { placeholder: "~/.config/fullmakt/secrets.yaml" });
  const vault = textInput(p.vaultUri, { placeholder: "https://my-vault.vault.azure.net" });
  const fileField = field("File", file, "YAML file of key: value pairs. Created with mode 600 when you set the first value.");
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

async function keysDialog(provider) {
  let keys;
  try {
    keys = await api("GET", `/api/providers/${encodeURIComponent(provider)}/keys`);
  } catch (err) {
    if (err.status !== 401) toast(err.message, true);
    return;
  }
  const list = h("div", { class: "table-wrap" });
  const renderKeys = () => {
    list.replaceChildren(
      keys.length
        ? h(
            "table",
            { class: "table" },
            h(
              "tbody",
              {},
              keys.map((k) =>
                h(
                  "tr",
                  {},
                  h("td", { class: "mono", text: k }),
                  h(
                    "td",
                    { class: "row-actions" },
                    h("button", { type: "button", class: "btn small danger", text: "Delete", onclick: () => removeKey(k) }),
                  ),
                ),
              ),
            ),
          )
        : h("p", { class: "empty", text: "No values stored yet." }),
    );
  };
  const removeKey = (k) => {
    if (!confirm(`Delete value ${k} from ${provider}?`)) return;
    run(async () => {
      await api("DELETE", `/api/providers/${encodeURIComponent(provider)}/keys/${encodeURIComponent(k)}`);
      keys = keys.filter((x) => x !== k);
      renderKeys();
    }, "Value deleted");
  };
  const key = textInput("", { placeholder: "key" });
  const value = secretInput();
  value.placeholder = "value";
  const add = h("button", { type: "button", class: "btn small primary", text: "Store" });
  const store = () =>
    run(async () => {
      const k = key.value.trim();
      if (!k || !value.value) fail("Key and value are required");
      await putLocalValue(provider, k, value.value);
      if (!keys.includes(k)) keys = [...keys, k].sort();
      key.value = value.value = "";
      renderKeys();
    }, "Value stored");
  add.addEventListener("click", store);
  for (const input of [key, value]) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        store();
      }
    });
  }
  renderKeys();
  openDialog({
    title: `Values in ${provider}`,
    body: h(
      "div",
      { class: "stack" },
      h("p", { class: "sub", text: "Key names only. Values are write-only: you can replace or delete them, never read them." }),
      list,
      h("div", { class: "field" }, h("span", { text: "Store a value" }), h("div", { class: "field-row" }, key, value), h("div", {}, add)),
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
      "# Ubuntu / Debian",
      "sudo cp fullmakt-ca.pem /usr/local/share/ca-certificates/fullmakt.crt",
      "sudo update-ca-certificates",
      "",
      "# macOS",
      "sudo security add-trusted-cert -d -r trustRoot \\",
      "  -k /Library/Keychains/System.keychain fullmakt-ca.pem",
    ].join("\n"),
  );
  copyable(
    $("#setup-env"),
    [
      "# From a Lima VM. On this machine, use 127.0.0.1.",
      `export HTTPS_PROXY=http://host.lima.internal:${port}`,
      `export HTTP_PROXY=http://host.lima.internal:${port}`,
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
  $("#reload-config").addEventListener("click", () =>
    run(async () => {
      state.config = normalizeConfig(await api("POST", "/api/reload"));
      await refreshStatus();
      renderAll();
    }, "Configuration reloaded"),
  );

  window.addEventListener("hashchange", showTab);
  showTab();

  loadAll().then(
    () => {
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

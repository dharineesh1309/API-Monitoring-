const API_BASE = "/api";
const PROXY_API = "/centralwatch/proxy/keys";
const PROXY_ROLES_API = "/centralwatch/proxy/roles";
const PROXY_HISTORY_API = "/centralwatch/proxy/history";
const PROXY_METRICS_API = "/centralwatch/proxy/metrics";
const TOKEN_KEY = "cw-token";
const ACTIVITY_KEY = "cw-activity";
const CHAT_TOKEN_KEY = "cw-gemini-proxy-token";
const THEME_KEY = "centralwatch-theme-preference";

const SYSTEMS = [
  { key: "demo", name: "Demo application", purpose: "FastAPI business APIs", endpoint: ":8000", health: "/system/demo", port: "8000", path: "/docs" },
  { key: "proxy", name: "API proxy", purpose: "Credential injection and IP policy", endpoint: "/api/centralwatch/proxy", health: PROXY_API, view: "proxy" },
  { key: "grafana", name: "Grafana", purpose: "Dashboards and exploration", endpoint: ":3000", health: "/system/grafana", port: "3000" },
  { key: "prometheus", name: "Prometheus", purpose: "Metrics storage", endpoint: ":9090", health: "/system/prometheus", port: "9090" },
  { key: "loki", name: "Loki", purpose: "Log aggregation", endpoint: ":3100", health: "/system/loki", port: "3100", path: "/ready" },
  { key: "tempo", name: "Tempo", purpose: "Distributed traces", endpoint: ":3200", health: "/system/tempo", port: "3200", path: "/ready" },
  { key: "localstack", name: "LocalStack", purpose: "Local AWS services", endpoint: ":4566", health: "/system/localstack", port: "4566", path: "/_localstack/health" },
  { key: "collector", name: "OTel Collector", purpose: "Telemetry processing", endpoint: ":8889", health: "/system/collector", port: "8889", path: "/metrics" },
];

const PAGE_META = {
  overview: ["Overview", "Service health and recent activity"],
  proxy: ["API proxy", "Managed upstream services"],
  security: ["Security scan", "Authenticated OWASP ASTF scanning"],
  "aws-security": ["AWS security agent", "Read-only assessment and approved baseline fixes"],
  observability: ["Observability", "Grafana metrics, logs, and traces"],
  chat: ["Gemini chatbot", "Gemini through the CentralWatch credential firewall"],
  orders: ["Orders", "DynamoDB order workflows"],
  files: ["Files", "S3 uploads and metadata"],
  aws: ["AWS workflows", "SNS, SQS, S3, and Lambda"],
  simulations: ["Simulations", "Generate observable test scenarios"],
};

const state = {
  token: safeStorageGet(TOKEN_KEY),
  user: null,
  services: [],
  proxyRoles: [],
  proxyHistory: [],
  proxyMetrics: null,
  lastProxyAccessToken: null,
  geminiProxyToken: safeSessionGet(CHAT_TOKEN_KEY),
  chatMessages: [],
  orders: [],
  files: [],
  activity: readActivity(),
  activeView: "overview",
  grafanaInitialized: false,
  securityScan: null,
  securityReportUrl: null,
  securityReportHtml: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

function safeStorageGet(key) {
  try { return localStorage.getItem(key); } catch (_) { return null; }
}

function safeStorageSet(key, value) {
  try { localStorage.setItem(key, value); } catch (_) { /* storage can be disabled */ }
}

function safeStorageRemove(key) {
  try { localStorage.removeItem(key); } catch (_) { /* storage can be disabled */ }
}

function safeSessionGet(key) {
  try { return sessionStorage.getItem(key); } catch (_) { return null; }
}

function safeSessionSet(key, value) {
  try { sessionStorage.setItem(key, value); } catch (_) { /* storage can be disabled */ }
}

function safeSessionRemove(key) {
  try { sessionStorage.removeItem(key); } catch (_) { /* storage can be disabled */ }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  })[character]);
}

function errorDetail(payload, fallback) {
  if (!payload) return fallback;
  if (typeof payload.detail === "string") return payload.detail;
  if (Array.isArray(payload.detail)) return payload.detail.map((item) => item.msg || "Invalid value").join(" · ");
  return payload.message || payload.error || fallback;
}

async function apiRequest(path, options = {}) {
  const { auth = true, body, headers = {}, ...requestOptions } = options;
  const requestHeaders = { Accept: "application/json", ...headers };
  if (auth) {
    if (!state.token) throw new ApiError("Authentication required", 401, null);
    requestHeaders.Authorization = `Bearer ${state.token}`;
  }
  let requestBody = body;
  if (body && !(body instanceof FormData) && typeof body !== "string") {
    requestHeaders["Content-Type"] = "application/json";
    requestBody = JSON.stringify(body);
  }
  const response = await fetch(`${API_BASE}${path}`, { ...requestOptions, headers: requestHeaders, body: requestBody, cache: "no-store" });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json().catch(() => null) : await response.text().catch(() => "");
  if (!response.ok) {
    if (auth && response.status === 401) clearSession();
    throw new ApiError(errorDetail(payload, `Request failed (${response.status})`), response.status, payload);
  }
  return payload;
}

function browserHost() {
  return window.location.hostname === "localhost" ? "127.0.0.1" : window.location.hostname;
}

function externalUrl(port, path = "/") {
  return `http://${browserHost()}:${port}${path}`;
}

function configureExternalLinks() {
  $$(".external-link[data-port]").forEach((link) => {
    link.href = externalUrl(link.dataset.port, link.dataset.path || "/");
    link.target = "_blank";
    link.rel = "noopener";
  });
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let amount = bytes / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index += 1; }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${units[index]}`;
}

function formatMoney(value) {
  return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(Number(value || 0));
}

function setBusy(button, busy, busyLabel = "Working…") {
  if (!button) return;
  if (busy) {
    button.dataset.idleLabel = button.textContent;
    button.textContent = busyLabel;
    button.disabled = true;
    button.classList.add("loading");
  } else {
    button.textContent = button.dataset.idleLabel || button.textContent;
    button.disabled = false;
    button.classList.remove("loading");
  }
}

function setMessage(element, message = "", isError = false) {
  if (!element) return;
  element.textContent = message;
  element.classList.toggle("error", isError);
}

function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => toast.classList.remove("visible"), 3600);
}

function readActivity() {
  try {
    const parsed = JSON.parse(safeStorageGet(ACTIVITY_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.slice(0, 30) : [];
  } catch (_) { return []; }
}

function recordActivity(action, detail, status = "success") {
  state.activity.unshift({ id: crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`, action, detail, status, timestamp: new Date().toISOString() });
  state.activity = state.activity.slice(0, 30);
  safeStorageSet(ACTIVITY_KEY, JSON.stringify(state.activity));
  renderActivity();
}

function renderActivity() {
  const container = $("#activity-list");
  if (!state.activity.length) {
    container.innerHTML = '<div class="empty-state"><strong>No recent activity</strong><span>Completed actions will appear here.</span></div>';
    return;
  }
  container.innerHTML = state.activity.slice(0, 12).map((entry) => `
    <div class="activity-item ${entry.status === "error" ? "error" : ""}">
      <strong>${escapeHtml(entry.action)}</strong><span>${escapeHtml(entry.detail)}</span><time datetime="${escapeHtml(entry.timestamp)}">${escapeHtml(formatDate(entry.timestamp))}</time>
    </div>`).join("");
}

function currentTheme() {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function currentThemePreference() {
  const preference = document.documentElement.dataset.themePreference;
  return ["light", "dark"].includes(preference) ? preference : currentTheme();
}

function applyTheme(preference, persist = true) {
  const normalizedPreference = preference === "dark" ? "dark" : "light";
  const previousTheme = currentTheme();
  const theme = normalizedPreference;
  document.documentElement.dataset.themePreference = normalizedPreference;
  document.documentElement.dataset.theme = theme;
  $$('[data-theme-choice]').forEach((button) => {
    const selected = button.dataset.themeChoice === normalizedPreference;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-checked", String(selected));
  });
  $("#theme-color").setAttribute("content", theme === "dark" ? "#070b14" : "#eef4ff");
  if (persist) {
    safeStorageSet(THEME_KEY, normalizedPreference);
    safeStorageRemove("centralwatch-theme");
  }
  if (state.grafanaInitialized && previousTheme !== theme) reloadGrafana();
  if (state.securityReportHtml && previousTheme !== theme) renderSecurityReportFrame(false);
}

function showView(viewName) {
  const name = PAGE_META[viewName] ? viewName : "overview";
  state.activeView = name;
  $$("[data-view]").forEach((view) => { view.hidden = view.dataset.view !== name; view.classList.toggle("active", view.dataset.view === name); });
  $$("[data-view-link]").forEach((link) => link.classList.toggle("active", link.dataset.viewLink === name));
  $("#current-page-title").textContent = PAGE_META[name][0];
  $("#current-page-subtitle").textContent = PAGE_META[name][1];
  closeSidebar();
  loadViewData(name);
  window.scrollTo({ top: 0, behavior: "instant" });
}

function routeFromHash() {
  showView(window.location.hash.replace(/^#/, "") || "overview");
}

function openSidebar() {
  $("#sidebar").classList.add("open");
  $("#sidebar-scrim").hidden = false;
}

function closeSidebar() {
  $("#sidebar").classList.remove("open");
  $("#sidebar-scrim").hidden = true;
}

function openDialog(id) {
  const dialog = $(`#${id}`);
  if (dialog && !dialog.open) dialog.showModal();
}

function closeDialog(id) {
  const dialog = $(`#${id}`);
  if (dialog?.open) dialog.close();
}

function setProtectedVisibility() {
  $$('[data-auth-notice]').forEach((element) => { element.hidden = Boolean(state.user); });
  $$('[data-protected-content]').forEach((element) => { element.hidden = !state.user; });
  $("#security-auth-required").hidden = Boolean(state.user);
  $("#security-content").hidden = !state.user;
}

function userInitials(user) {
  const value = user?.name || user?.email || "?";
  return value.split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
}

function updateAuthUI() {
  const authenticated = Boolean(state.user && state.token);
  $("#account-name").textContent = authenticated ? state.user.name : "Sign in";
  $("#account-detail").textContent = authenticated ? state.user.email : "Required for demo APIs";
  $("#account-avatar").textContent = authenticated ? userInitials(state.user) : "?";
  $("#auth-forms").hidden = authenticated;
  $("#account-profile").hidden = !authenticated;
  if (authenticated) {
    $("#profile-avatar").textContent = userInitials(state.user);
    $("#profile-name").textContent = state.user.name;
    $("#profile-email").textContent = state.user.email;
    $("#profile-user-id").textContent = state.user.user_id;
    $("#profile-status").textContent = state.user.status;
    $("#profile-cidrs").textContent = state.user.allowed_cidrs.join(", ");
    $("#order-user-id").value = state.user.user_id;
  }
  setProtectedVisibility();
}

function clearSession() {
  closeSecurityReport();
  state.token = null;
  state.user = null;
  safeStorageRemove(TOKEN_KEY);
  updateAuthUI();
}

async function restoreSession() {
  if (!state.token) { updateAuthUI(); return; }
  try {
    state.user = await apiRequest("/auth/profile");
  } catch (_) {
    clearSession();
  }
  updateAuthUI();
  loadViewData(state.activeView);
}

function openAuthDialog() {
  updateAuthUI();
  if (!state.user) showAuthMode("login");
  openDialog("auth-dialog");
}

function showAuthMode(mode) {
  const register = mode === "register";
  $("#login-form").hidden = register;
  $("#register-form").hidden = !register;
  $("#show-login").classList.toggle("active", !register);
  $("#show-register").classList.toggle("active", register);
  $("#auth-dialog-title").textContent = register ? "Create account" : "Sign in";
  $("#auth-dialog-subtitle").textContent = register ? "Register a local DynamoDB-backed operator." : "Use a CentralWatch account to access protected APIs.";
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const button = $("#login-submit");
  const message = $("#login-message");
  const data = new FormData(form);
  setBusy(button, true, "Signing in…");
  setMessage(message, "");
  try {
    const response = await apiRequest("/auth/login", { method: "POST", auth: false, body: { email: data.get("email").trim(), password: data.get("password") } });
    state.token = response.token;
    state.user = response.user;
    safeStorageSet(TOKEN_KEY, response.token);
    form.reset();
    updateAuthUI();
    closeDialog("auth-dialog");
    recordActivity("Signed in", response.user.email);
    showToast(`Signed in as ${response.user.name}`);
    loadViewData(state.activeView);
  } catch (error) {
    setMessage(message, error.message, true);
  } finally { setBusy(button, false); }
}

async function handleRegister(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const button = $("#register-submit");
  const message = $("#register-message");
  const data = new FormData(form);
  const payload = {
    name: data.get("name").trim(), email: data.get("email").trim(), password: data.get("password"),
    allowed_cidrs: data.get("allowed_cidrs").split(",").map((value) => value.trim()).filter(Boolean),
  };
  setBusy(button, true, "Creating…");
  setMessage(message, "");
  try {
    await apiRequest("/auth/register", { method: "POST", auth: false, body: payload });
    const login = await apiRequest("/auth/login", { method: "POST", auth: false, body: { email: payload.email, password: payload.password } });
    state.token = login.token;
    state.user = login.user;
    safeStorageSet(TOKEN_KEY, login.token);
    form.reset();
    updateAuthUI();
    closeDialog("auth-dialog");
    recordActivity("Account created", login.user.email);
    showToast(`Account created for ${login.user.name}`);
    loadViewData(state.activeView);
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

function signOut() {
  const email = state.user?.email || "operator";
  clearSession();
  closeDialog("auth-dialog");
  recordActivity("Signed out", email);
  showToast("Signed out");
}

async function checkSystem(system) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 5000);
  try {
    const response = await fetch(system.health, { cache: "no-store", signal: controller.signal });
    return { ...system, online: response.ok };
  } catch (_) { return { ...system, online: false }; }
  finally { window.clearTimeout(timeout); }
}

function systemHref(system) {
  if (system.view) return `#${system.view}`;
  return externalUrl(system.port, system.path || "/");
}

function renderSystems(results) {
  $("#system-table-body").innerHTML = results.map((system) => `
    <tr><td><strong>${escapeHtml(system.name)}</strong></td><td>${escapeHtml(system.purpose)}</td><td><code>${escapeHtml(system.endpoint)}</code></td><td><span class="status-badge ${system.online ? "success" : "error"}"><i></i>${system.online ? "Online" : "Offline"}</span></td><td><div class="row-actions"><a class="table-button" href="${escapeHtml(systemHref(system))}" ${system.view ? "" : 'target="_blank" rel="noopener"'}>Open</a></div></td></tr>`).join("");
}

async function loadHealth() {
  const button = $("#refresh-health");
  setBusy(button, true, "Checking…");
  const results = await Promise.all(SYSTEMS.map(checkSystem));
  renderSystems(results);
  const online = results.filter((item) => item.online).length;
  const telemetryKeys = new Set(["grafana", "prometheus", "loki", "tempo", "collector"]);
  const telemetryOk = results.filter((item) => telemetryKeys.has(item.key)).every((item) => item.online);
  $("#online-count").textContent = `${online}/${results.length}`;
  $("#online-summary").textContent = online === results.length ? "All services operational" : `${results.length - online} service${results.length - online === 1 ? "" : "s"} unavailable`;
  $("#telemetry-state").textContent = telemetryOk ? "Healthy" : "Degraded";
  $("#last-check").textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const global = $("#global-status");
  global.className = `global-status ${online === results.length ? "online" : "degraded"}`;
  $("span", global).textContent = online === results.length ? "All systems operational" : `${online}/${results.length} systems online`;
  setBusy(button, false);
}

async function loadServices() {
  const refresh = $("#refresh-services");
  setBusy(refresh, true, "Loading…");
  try {
    state.services = await apiRequest(PROXY_API, { auth: false });
    $("#service-count").textContent = String(state.services.length);
    renderServices();
  } catch (error) {
    $("#service-count").textContent = "Error";
    $("#service-table-body").innerHTML = `<tr><td colspan="7"><div class="empty-state error-state"><strong>Registry unavailable</strong><span>${escapeHtml(error.message)}</span></div></td></tr>`;
  } finally { setBusy(refresh, false); }
}

function renderServices() {
  const query = $("#proxy-search").value.trim().toLowerCase();
  const services = state.services.filter((service) => [service.service_name, service.base_url, ...service.allowed_ips].join(" ").toLowerCase().includes(query));
  if (!services.length) {
    $("#service-table-body").innerHTML = `<tr><td colspan="7"><div class="empty-state"><strong>${state.services.length ? "No matching services" : "No services configured"}</strong><span>${state.services.length ? "Try a different search." : "Add the first upstream service using the form."}</span></div></td></tr>`;
    return;
  }
  $("#service-table-body").innerHTML = services.map((service) => `
    <tr><td><strong>${escapeHtml(service.service_name)}</strong></td><td><code>${escapeHtml(service.base_url)}</code></td><td>${escapeHtml(service.allowed_ips.join(", "))}</td><td><span class="status-badge neutral">${escapeHtml(service.role_name)}</span></td><td><code>${escapeHtml(service.token_hint)}</code></td><td><code>${escapeHtml(service.api_key)}</code><small class="table-detail">${escapeHtml(service.auth_type || "bearer")}</small></td><td><div class="row-actions"><button class="table-button" type="button" data-copy-proxy="${escapeHtml(service.service_name)}">Copy endpoint</button><button class="table-button" type="button" data-rotate-proxy-token="${escapeHtml(service.service_name)}">Rotate token</button></div></td></tr>`).join("");
}

async function handleProxySubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const data = new FormData(form);
  const payload = {
    service_name: data.get("service_name").trim(), base_url: data.get("base_url").trim(), api_key: data.get("api_key"),
    allowed_ips: data.get("allowed_ips").split(",").map((value) => value.trim()).filter(Boolean),
    role_name: data.get("role_name"),
    auth_type: data.get("auth_type"),
    timeout_seconds: Number(data.get("timeout_seconds")),
  };
  const button = $("#submit-proxy");
  const message = $("#proxy-form-message");
  setBusy(button, true, "Saving…");
  setMessage(message, "");
  try {
    const result = await apiRequest(PROXY_API, { method: "POST", auth: false, body: payload });
    showProxyAccessToken(result.access_token);
    if (payload.service_name === "gemini_api") setGeminiProxyToken(result.access_token);
    $("#input-key").value = "";
    $("#endpoint-example").textContent = externalUrl("8000", `/centralwatch/proxy/${payload.service_name}/{path}`);
    setMessage(message, `${payload.service_name} is ready.`);
    recordActivity("Proxy saved", payload.service_name);
    showToast(`Saved proxy service ${payload.service_name}`);
    await loadServices();
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

async function loadProxyRoles() {
  try {
    state.proxyRoles = await apiRequest(PROXY_ROLES_API, { auth: false });
    renderProxyRoles();
  } catch (error) {
    $("#proxy-roles-body").innerHTML = `<tr><td colspan="4"><div class="empty-state error-state"><strong>Roles unavailable</strong><span>${escapeHtml(error.message)}</span></div></td></tr>`;
  }
}

function renderProxyRoles() {
  const body = $("#proxy-roles-body");
  body.innerHTML = state.proxyRoles.length ? state.proxyRoles.map((role) => `<tr><td><strong>${escapeHtml(role.role_name)}</strong></td><td>${escapeHtml(role.allowed_services.join(", "))}</td><td>${escapeHtml(role.allowed_methods.join(", "))}</td><td>${escapeHtml(role.assigned_services)}</td></tr>`).join("") : `<tr><td colspan="4"><div class="empty-state compact"><strong>No roles configured</strong><span>Create the first proxy role above.</span></div></td></tr>`;
  const select = $("#proxy-service-role");
  const selected = select.value;
  select.innerHTML = `<option value="">Select a role</option>${state.proxyRoles.map((role) => `<option value="${escapeHtml(role.role_name)}">${escapeHtml(role.role_name)}</option>`).join("")}`;
  if (state.proxyRoles.some((role) => role.role_name === selected)) select.value = selected;
  else if (state.proxyRoles.some((role) => role.role_name === "proxy_reader")) select.value = "proxy_reader";
}

async function handleProxyRoleSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const data = new FormData(form);
  const payload = {
    role_name: data.get("role_name").trim(),
    allowed_services: data.get("allowed_services").split(",").map((value) => value.trim()).filter(Boolean),
    allowed_methods: data.get("allowed_methods").split(",").map((value) => value.trim().toUpperCase()).filter(Boolean),
  };
  const button = $("#save-proxy-role");
  const message = $("#proxy-role-message");
  setBusy(button, true, "Saving…");
  setMessage(message, "");
  try {
    await apiRequest(PROXY_ROLES_API, { method: "POST", auth: false, body: payload });
    setMessage(message, `${payload.role_name} is ready to assign to a proxy API.`);
    recordActivity("Proxy role saved", payload.role_name);
    showToast(`Saved proxy role ${payload.role_name}`);
    await loadProxyRoles();
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

function showProxyAccessToken(token) {
  state.lastProxyAccessToken = token;
  $("#proxy-access-token").textContent = token;
  $("#proxy-access-token-result").hidden = false;
}

async function rotateProxyAccessToken(serviceName, button) {
  setBusy(button, true, "Rotating…");
  try {
    const result = await apiRequest(`${PROXY_API}/${encodeURIComponent(serviceName)}/rotate-token`, { method: "POST", auth: false });
    showProxyAccessToken(result.access_token);
    if (serviceName === "gemini_api") setGeminiProxyToken(result.access_token);
    recordActivity("Proxy token rotated", serviceName);
    showToast(`New proxy token generated for ${serviceName}`);
    await loadServices();
  } catch (error) { showToast(error.message, true); }
  finally { setBusy(button, false); }
}

function renderProxyMetrics(metrics) {
  state.proxyMetrics = metrics;
  $("#proxy-total-requests").textContent = metrics.total_requests;
  $("#proxy-success-rate").textContent = `${Number(metrics.success_rate).toFixed(1)}%`;
  $("#proxy-success-count").textContent = `${metrics.successful_requests} successful`;
  $("#proxy-blocked-count").textContent = metrics.blocked_requests;
  $("#proxy-error-count").textContent = metrics.error_requests;
  $("#proxy-average-latency").textContent = `${Number(metrics.average_latency_ms).toFixed(1)} ms`;
  $("#proxy-p95-latency").textContent = `${Number(metrics.p95_latency_ms).toFixed(1)} ms`;
  $("#proxy-metrics-since").textContent = `${Number(metrics.requests_per_minute).toFixed(1)}/min · Since ${formatDate(metrics.since)}`;
  $("#proxy-method-metrics").textContent = Object.entries(metrics.by_method).map(([method, count]) => `${method}: ${count}`).join(" · ") || "None";
  $("#proxy-status-metrics").textContent = Object.entries(metrics.by_status).map(([status, count]) => `${status}: ${count}`).join(" · ") || "None";
  $("#proxy-bytes-in").textContent = formatBytes(metrics.bytes_in);
  $("#proxy-bytes-out").textContent = formatBytes(metrics.bytes_out);
  $("#proxy-unique-ips").textContent = metrics.unique_client_ips;
  $("#proxy-token-count").textContent = metrics.authenticated_proxy_tokens;
  $("#proxy-service-metrics-body").innerHTML = metrics.by_service.length ? metrics.by_service.map((service) => `<tr><td><strong>${escapeHtml(service.service_name)}</strong></td><td>${service.requests}</td><td>${service.successful}</td><td>${service.blocked}</td><td>${service.errors}</td><td>${Number(service.average_latency_ms).toFixed(1)} ms</td></tr>`).join("") : `<tr><td colspan="6"><div class="empty-state compact"><strong>No proxy traffic</strong><span>Metrics appear after the first request.</span></div></td></tr>`;
}

function proxyOutcomeType(item) {
  if (item.outcome.startsWith("blocked")) return "blocked";
  if (item.status_code >= 400) return "error";
  return "success";
}

function renderProxyHistory() {
  const query = $("#proxy-history-search").value.trim().toLowerCase();
  const outcome = $("#proxy-history-outcome").value;
  const records = state.proxyHistory.filter((item) => {
    const matchesText = [item.service_name, item.token_hint, item.role_name, item.client_ip, item.method, item.path, item.outcome].join(" ").toLowerCase().includes(query);
    return matchesText && (!outcome || proxyOutcomeType(item) === outcome);
  });
  $("#proxy-history-body").innerHTML = records.length ? records.map((item) => {
    const type = proxyOutcomeType(item);
    const identity = item.role_name ? `${item.role_name} / ${item.token_hint || "token unavailable"}` : "No matching service";
    return `<tr><td>${escapeHtml(formatDate(item.timestamp))}</td><td><strong>${escapeHtml(item.service_name)}</strong></td><td><code>${escapeHtml(item.method)} ${escapeHtml(item.path)}</code></td><td><code>${escapeHtml(item.client_ip)}</code></td><td>${escapeHtml(identity)}</td><td><span class="status-badge ${type === "success" ? "success" : type === "blocked" ? "warning" : "error"}">${escapeHtml(item.outcome.replaceAll("_", " "))}</span></td><td>${item.status_code}</td><td>${Number(item.duration_ms).toFixed(1)} ms</td><td>${escapeHtml(formatBytes(item.bytes_in))} / ${escapeHtml(formatBytes(item.bytes_out))}</td></tr>`;
  }).join("") : `<tr><td colspan="9"><div class="empty-state"><strong>${state.proxyHistory.length ? "No matching usage" : "No usage recorded"}</strong><span>${state.proxyHistory.length ? "Change the history filters." : "Proxy requests will appear here."}</span></div></td></tr>`;
}

async function loadProxyObservability() {
  try {
    const [metrics, history] = await Promise.all([
      apiRequest(PROXY_METRICS_API, { auth: false }),
      apiRequest(`${PROXY_HISTORY_API}?limit=250`, { auth: false }),
    ]);
    renderProxyMetrics(metrics);
    state.proxyHistory = history;
    renderProxyHistory();
  } catch (error) {
    $("#proxy-history-body").innerHTML = `<tr><td colspan="9"><div class="empty-state error-state"><strong>Usage data unavailable</strong><span>${escapeHtml(error.message)}</span></div></td></tr>`;
  }
}

async function loadProxyWorkspace() {
  await Promise.all([loadServices(), loadProxyRoles(), loadProxyObservability()]);
}

function setGeminiProxyToken(token) {
  state.geminiProxyToken = token || null;
  if (state.geminiProxyToken) safeSessionSet(CHAT_TOKEN_KEY, state.geminiProxyToken);
  else safeSessionRemove(CHAT_TOKEN_KEY);
  updateGeminiStatus();
}

function geminiService() {
  return state.services.find((service) => service.service_name === "gemini_api");
}

function updateGeminiStatus() {
  const service = geminiService();
  const configured = Boolean(service?.secret_configured);
  const hasToken = Boolean(state.geminiProxyToken);
  $("#gemini-key-status").textContent = configured ? "Configured in CentralWatch" : "Placeholder - add a real key";
  $("#gemini-token-status").textContent = hasToken ? "Loaded for this browser tab" : "Not loaded";
  const badge = $("#chat-ready-state");
  badge.className = `status-badge ${configured && hasToken ? "success" : "warning"}`;
  $("span", badge).textContent = configured && hasToken ? "Ready" : configured ? "Token required" : "Setup required";
}

async function loadGeminiStatus() {
  try {
    state.services = await apiRequest(PROXY_API, { auth: false });
    updateGeminiStatus();
  } catch (error) {
    $("#gemini-key-status").textContent = "Registry unavailable";
    setMessage($("#gemini-config-message"), error.message, true);
  }
}

async function configureGemini(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const button = $("#configure-gemini");
  const message = $("#gemini-config-message");
  const apiKey = $("#gemini-api-key").value;
  setBusy(button, true, "Saving…");
  setMessage(message, "");
  try {
    const result = await apiRequest(PROXY_API, {
      method: "POST",
      auth: false,
      body: {
        service_name: "gemini_api",
        base_url: "https://generativelanguage.googleapis.com/v1beta",
        api_key: apiKey,
        allowed_ips: ["127.0.0.1", "::1"],
        role_name: "gemini_chat",
        auth_type: "x-goog-api-key",
        timeout_seconds: 60,
      },
    });
    $("#gemini-api-key").value = "";
    setGeminiProxyToken(result.access_token);
    setMessage(message, "Gemini is configured. The proxy token is held only for this browser tab.");
    recordActivity("Gemini configured", "gemini_api · gemini_chat");
    showToast("Gemini connection configured");
    await loadGeminiStatus();
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

function useGeminiProxyToken(event) {
  event.preventDefault();
  const token = $("#gemini-proxy-token").value.trim();
  const message = $("#gemini-token-message");
  if (!token.startsWith("cw_proxy_")) {
    setMessage(message, "Enter a CentralWatch token beginning with cw_proxy_.", true);
    return;
  }
  setGeminiProxyToken(token);
  $("#gemini-proxy-token").value = "";
  setMessage(message, "Proxy token loaded for this browser tab.");
  showToast("Gemini proxy token loaded");
}

function renderChatMessages() {
  const container = $("#chat-messages");
  if (!state.chatMessages.length) {
    container.innerHTML = '<div class="empty-state"><strong>No messages yet</strong><span>Configure Gemini, then send a prompt.</span></div>';
    return;
  }
  container.innerHTML = state.chatMessages.map((message) => `<article class="chat-message ${escapeHtml(message.role)}"><header><strong>${message.role === "user" ? "You" : "Gemini"}</strong>${message.model ? `<span>${escapeHtml(message.model)}</span>` : ""}</header><p>${escapeHtml(message.text)}</p></article>`).join("");
  container.scrollTop = container.scrollHeight;
}

async function handleChatSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const message = $("#chat-message");
  if (!state.geminiProxyToken) {
    setMessage(message, "Configure Gemini or load its CentralWatch proxy token first.", true);
    return;
  }
  const prompt = $("#chat-prompt").value.trim();
  const model = $("#chat-model").value.trim();
  const button = $("#send-chat");
  state.chatMessages.push({ role: "user", text: prompt });
  renderChatMessages();
  $("#chat-prompt").value = "";
  setBusy(button, true, "Waiting…");
  setMessage(message, "CentralWatch is forwarding the prompt to Gemini.");
  try {
    const result = await apiRequest("/chat", {
      method: "POST",
      auth: false,
      headers: { "X-CentralWatch-Proxy-Token": state.geminiProxyToken },
      body: { prompt, model },
    });
    state.chatMessages.push({ role: "assistant", text: result.reply, model: result.model });
    renderChatMessages();
    setMessage(message, "Response received through CentralWatch.");
    recordActivity("Gemini prompt completed", result.model);
  } catch (error) {
    state.chatMessages.push({ role: "assistant", text: `Request failed: ${error.message}` });
    renderChatMessages();
    setMessage(message, error.message, true);
    recordActivity("Gemini prompt failed", error.message, "error");
  } finally { setBusy(button, false); }
}

function clearChat() {
  state.chatMessages = [];
  renderChatMessages();
  setMessage($("#chat-message"), "");
}

async function copyText(value, successMessage) {
  try { await navigator.clipboard.writeText(value); showToast(successMessage); }
  catch (_) { showToast("Copy is unavailable in this browser.", true); }
}

function grafanaUrl(path) {
  return `${externalUrl("3000", path)}?orgId=1&theme=${currentTheme()}&refresh=30s&kiosk`;
}

let reloadGrafana = () => {};
function initializeGrafana() {
  if (state.grafanaInitialized) return;
  state.grafanaInitialized = true;
  const frame = $("#grafana-frame");
  const loader = $("#grafana-loader");
  const tabs = $$(".grafana-card .tab");
  const select = (tab, force = false) => {
    tabs.forEach((item) => { const active = item === tab; item.classList.toggle("active", active); item.setAttribute("aria-selected", String(active)); });
    $("#embed-dashboard-title").textContent = tab.dataset.title;
    const url = grafanaUrl(tab.dataset.path);
    $("#open-current-grafana").href = url;
    frame.title = `${tab.dataset.title} Grafana dashboard`;
    loader.classList.remove("loaded");
    frame.src = force ? `${url}&_=${Date.now()}` : url;
  };
  tabs.forEach((tab) => tab.addEventListener("click", () => select(tab)));
  frame.addEventListener("load", () => loader.classList.add("loaded"));
  $("#reload-grafana").addEventListener("click", () => select(tabs.find((tab) => tab.classList.contains("active")) || tabs[0], true));
  reloadGrafana = () => select(tabs.find((tab) => tab.classList.contains("active")) || tabs[0], true);
  select(tabs[0]);
}

function setScanState(label, type = "neutral") {
  const badge = $("#scan-state");
  badge.className = `status-badge ${type}`;
  $("span", badge).textContent = label;
}

function setAwsAgentState(label, type = "neutral") {
  const badge = $("#aws-agent-state");
  badge.className = `status-badge ${type}`;
  $("span", badge).textContent = label;
}

function renderAwsSecurityScan(scan) {
  state.securityScan = scan;
  $("#aws-agent-results").hidden = false;
  $("#agent-total").textContent = scan.summary.total;
  $("#agent-passed").textContent = scan.summary.passed;
  const failed = scan.findings.filter((finding) => finding.status === "fail");
  $("#agent-high").textContent = failed.filter((finding) => finding.severity === "high").length;
  $("#agent-medium").textContent = failed.filter((finding) => finding.severity === "medium").length;
  $("#agent-low").textContent = failed.filter((finding) => finding.severity === "low").length;
  $("#agent-scan-meta").textContent = `${scan.scope}. ${new Date(scan.generated_at).toLocaleString()}`;
  const policy = $("#remediation-policy");
  policy.className = `status-badge ${scan.remediation_enabled ? "success" : "warning"}`;
  $("span", policy).textContent = scan.remediation_enabled ? "Remediation enabled" : "Remediation disabled by policy";

  const body = $("#aws-findings-body");
  const severityOrder = { high: 0, medium: 1, low: 2 };
  const statusOrder = { fail: 0, error: 1, unavailable: 2, pass: 3 };
  const orderedFindings = [...scan.findings].sort((left, right) =>
    statusOrder[left.status] - statusOrder[right.status]
      || severityOrder[left.severity] - severityOrder[right.severity]
      || left.service.localeCompare(right.service),
  );
  body.innerHTML = orderedFindings.map((finding) => {
    const actionable = finding.status === "fail" && finding.remediable && scan.remediation_enabled;
    const badgeType = finding.status === "pass" ? "success" : finding.status === "fail" ? "warning" : finding.status === "error" ? "error" : "neutral";
    return `<tr>
      <td class="select-column">${actionable ? `<input class="finding-checkbox" type="checkbox" value="${escapeHtml(finding.finding_id)}" aria-label="Select ${escapeHtml(finding.title)} for remediation">` : ""}</td>
      <td><strong>${escapeHtml(finding.title)}</strong><small class="table-detail">${escapeHtml(finding.description)}</small></td>
      <td><strong>${escapeHtml(finding.service)}</strong><code>${escapeHtml(finding.resource)}</code></td>
      <td><span class="severity-label ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
      <td><span class="status-badge ${badgeType}"><i></i>${escapeHtml(finding.status)}</span><small class="table-detail">Current: ${escapeHtml(finding.current_value)}</small></td>
      <td><span class="risk-copy">${escapeHtml(finding.risk)}</span></td>
      <td><span class="remediation-copy">${escapeHtml(finding.remediation)}</span><small class="table-detail">Target: ${escapeHtml(finding.desired_value)}</small></td>
    </tr>`;
  }).join("");

  setAwsAgentState(
    scan.summary.errors ? "Scan issues" : scan.summary.failed ? "Review findings" : "Baseline met",
    scan.summary.errors ? "error" : scan.summary.failed ? "warning" : "success",
  );
  setMessage(
    $("#aws-agent-message"),
    scan.remediation_enabled
      ? `${scan.summary.failed} risk${scan.summary.failed === 1 ? "" : "s"} found; ${scan.summary.remediable} can be selected for approval.${scan.summary.errors || scan.summary.unavailable ? ` ${scan.summary.errors + scan.summary.unavailable} check${scan.summary.errors + scan.summary.unavailable === 1 ? " could" : "s could"} not be completed.` : ""}`
      : "Scanning is available, but remediation is disabled by server policy.",
    false,
  );
  updateAwsAgentSelection();
}

function selectedAwsFindingIds() {
  return $$(".finding-checkbox:checked", $("#aws-findings-body")).map((input) => input.value);
}

function updateAwsAgentSelection() {
  const selected = selectedAwsFindingIds();
  const apply = $("#apply-agent-findings");
  const select = $("#select-agent-findings");
  const actionable = $$(".finding-checkbox", $("#aws-findings-body"));
  apply.disabled = !state.securityScan?.remediation_enabled || selected.length === 0;
  apply.textContent = selected.length ? `Apply selected (${selected.length})` : "Apply selected";
  select.disabled = actionable.length === 0;
  select.textContent = actionable.length && selected.length === actionable.length ? "Clear selection" : "Select actionable";
}

async function runAwsSecurityScan() {
  if (!protectedOrAuth()) return;
  const button = $("#run-aws-security-scan");
  setBusy(button, true, "Scanning...");
  setAwsAgentState("Scanning", "warning");
  setMessage($("#aws-agent-message"), "Reading AWS configuration. No changes are being made.");
  try {
    const scan = await apiRequest("/security-agent/scan", { method: "POST" });
    renderAwsSecurityScan(scan);
    recordActivity("AWS security scan", `${scan.summary.passed}/${scan.summary.total} controls passed`, scan.summary.failed ? "warning" : "success");
    showToast("AWS security scan completed");
  } catch (error) {
    setAwsAgentState("Scan failed", "error");
    setMessage($("#aws-agent-message"), error.message, true);
    recordActivity("AWS security scan failed", error.message, "error");
    showToast(error.message, true);
  } finally { setBusy(button, false); }
}

async function loadLatestAwsSecurityScan() {
  if (!state.token || state.securityScan) return;
  try {
    renderAwsSecurityScan(await apiRequest("/security-agent/latest"));
  } catch (error) {
    if (error.status !== 404) setMessage($("#aws-agent-message"), error.message, true);
  }
}

function toggleAwsFindingSelection() {
  const checkboxes = $$(".finding-checkbox", $("#aws-findings-body"));
  const shouldSelect = checkboxes.some((input) => !input.checked);
  checkboxes.forEach((input) => { input.checked = shouldSelect; });
  updateAwsAgentSelection();
}

async function applyAwsSecurityFindings() {
  if (!protectedOrAuth() || !state.securityScan) return;
  const findingIds = selectedAwsFindingIds();
  if (!findingIds.length) return;
  const selected = state.securityScan.findings.filter((finding) => findingIds.includes(finding.finding_id));
  const summary = selected.map((finding) => `${finding.service}: ${finding.resource} - ${finding.remediation}`).join("\n");
  const approved = window.confirm(`Apply these AWS security changes?\n\n${summary}\n\nThis action changes the selected AWS resource configurations.`);
  if (!approved) {
    setMessage($("#aws-agent-message"), "No changes were made.");
    return;
  }

  const button = $("#apply-agent-findings");
  setBusy(button, true, "Applying...");
  setAwsAgentState("Applying", "warning");
  try {
    const result = await apiRequest("/security-agent/remediate", {
      method: "POST",
      body: {
        scan_id: state.securityScan.scan_id,
        finding_ids: findingIds,
        confirm: true,
        acknowledgement: "APPLY_SELECTED_REMEDIATIONS",
      },
    });
    renderAwsSecurityScan(result.scan);
    const applied = result.actions.filter((action) => action.status === "applied").length;
    const failed = result.actions.length - applied;
    setMessage($("#aws-agent-message"), `${applied} remediation${applied === 1 ? "" : "s"} applied.${failed ? ` ${failed} failed.` : ""}`, failed > 0);
    recordActivity("AWS security remediation", `${applied} applied, ${failed} failed`, failed ? "warning" : "success");
    showToast(failed ? "Some AWS remediations failed" : "Selected AWS security controls applied", failed > 0);
  } catch (error) {
    setAwsAgentState("Apply failed", "error");
    setMessage($("#aws-agent-message"), error.message, true);
    recordActivity("AWS remediation failed", error.message, "error");
    showToast(error.message, true);
  } finally { setBusy(button, false); updateAwsAgentSelection(); }
}

async function handleSecurityScan(event) {
  event.preventDefault();
  if (!state.token) { openAuthDialog(); return; }
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const target = $("#scan-target").value.trim();
  const button = $("#trigger-security-scan");
  closeSecurityReport();
  $("#scan-progress").hidden = false;
  $("#scan-result").hidden = true;
  setBusy(button, true, "Scanning…");
  setScanState("Scanning", "warning");
  setMessage($("#scan-message"), "Authenticated request accepted. Waiting for ASTF to finish.");
  try {
    const result = await apiRequest(`/centralwatch/security-scan?target_url=${encodeURIComponent(target)}`, { method: "POST" });
    $("#scan-result-target").textContent = result.target;
    $("#scan-result-size").textContent = formatBytes(result.report_bytes);
    $("#scan-result-findings").textContent = result.findings_detected ? "Detected. Review report" : "No findings reported";
    $("#scan-result-title").textContent = result.findings_detected ? "Report generated. Findings detected" : "Report generated";
    $("#scan-result").hidden = false;
    setScanState(result.findings_detected ? "Findings" : "Complete", result.findings_detected ? "warning" : "success");
    setMessage($("#scan-message"), "Report generated successfully. Loading it below.");
    const displayed = await openSecurityReport({ scroll: true });
    setMessage(
      $("#scan-message"),
      displayed ? "Report generated and displayed below." : "Report generated, but the embedded view could not be loaded.",
      !displayed,
    );
    recordActivity("Security scan", `${target} · ${result.report_bytes} bytes`, result.findings_detected ? "warning" : "success");
    showToast("OWASP security report generated");
  } catch (error) {
    setScanState("Failed", "error");
    setMessage($("#scan-message"), error.message, true);
    recordActivity("Security scan failed", error.message, "error");
    showToast(error.message, true);
  } finally { $("#scan-progress").hidden = true; setBusy(button, false); }
}

function securityReportThemeCss(theme) {
  const dark = theme === "dark";
  const colors = dark
    ? {
        bg: "#070b14", surface: "#0d1624", elevated: "#121e2f", border: "#1c3044",
        text: "#e8f6ff", muted: "#93a6ba", accent: "#24d7ee", accentSoft: "#0d3040",
        critical: "#ff6478", criticalSoft: "#3b1821", high: "#fb8b6f", highSoft: "#382117",
        medium: "#f9c74f", mediumSoft: "#392d12", low: "#3ee6a0", lowSoft: "#0d3529",
        info: "#67b7ff", infoSoft: "#102b49",
      }
    : {
        bg: "#eef4ff", surface: "#ffffff", elevated: "#f8fbff", border: "#d5def0",
        text: "#111b31", muted: "#61708d", accent: "#0868f5", accentSoft: "#e4efff",
        critical: "#d9364f", criticalSoft: "#ffe8ec", high: "#c84f2f", highSoft: "#fff0ea",
        medium: "#a35d00", mediumSoft: "#fff2d6", low: "#087f5b", lowSoft: "#e5f7ef",
        info: "#0868f5", infoSoft: "#e4efff",
      };
  return `
    :root { color-scheme: ${dark ? "dark" : "light"}; --cw-bg: ${colors.bg}; --cw-surface: ${colors.surface}; --cw-elevated: ${colors.elevated}; --cw-border: ${colors.border}; --cw-text: ${colors.text}; --cw-muted: ${colors.muted}; --cw-accent: ${colors.accent}; --cw-accent-soft: ${colors.accentSoft}; }
    * { box-sizing: border-box; }
    html { background: var(--cw-bg); }
    body { margin: 0; color: var(--cw-text); background: var(--cw-bg); font-family: "Segoe UI Variable", "Segoe UI", ui-sans-serif, sans-serif; font-size: 13px; line-height: 1.55; }
    .header { padding: 19px 22px; border-bottom: 1px solid var(--cw-border); border-left: 3px solid var(--cw-accent); color: var(--cw-text); background: var(--cw-surface); }
    .header h1 { margin: 0; color: var(--cw-text); font-size: 20px; font-weight: 720; letter-spacing: -.025em; }
    .header p { margin: 3px 0 0; color: var(--cw-muted); opacity: 1; }
    .container { width: min(1180px, 100%); margin: 0 auto; padding: 18px; }
    h2, .summary h2 { margin: 0 0 12px; color: var(--cw-text); font-size: 16px; letter-spacing: -.015em; }
    .summary, .finding { border: 1px solid var(--cw-border); border-radius: 8px; color: var(--cw-text); background: var(--cw-surface); box-shadow: none; }
    .summary { padding: 16px 18px; margin-bottom: 12px; }
    .summary p { margin: 5px 0; color: var(--cw-muted); }
    .summary strong, .finding strong { color: var(--cw-text); }
    .severity-grid { display: grid; grid-template-columns: repeat(5, minmax(100px, 1fr)); gap: 8px; margin-bottom: 18px; }
    .severity-card { min-width: 0; padding: 13px; border: 1px solid transparent; border-radius: 8px; text-align: left; }
    .severity-card .count { font-family: Consolas, monospace; font-size: 25px; font-weight: 750; line-height: 1; }
    .severity-card .label { margin-top: 7px; font-size: 9px; font-weight: 750; letter-spacing: .08em; }
    .severity-critical { border-color: ${colors.critical}; color: ${colors.critical}; background: ${colors.criticalSoft}; }
    .severity-high { border-color: ${colors.high}; color: ${colors.high}; background: ${colors.highSoft}; }
    .severity-medium { border-color: ${colors.medium}; color: ${colors.medium}; background: ${colors.mediumSoft}; }
    .severity-low { border-color: ${colors.low}; color: ${colors.low}; background: ${colors.lowSoft}; }
    .severity-info { border-color: ${colors.info}; color: ${colors.info}; background: ${colors.infoSoft}; }
    .finding { padding: 16px 18px; margin-bottom: 10px; border-left: 3px solid var(--cw-border); }
    .finding:has(.badge-critical) { border-left-color: ${colors.critical}; }
    .finding:has(.badge-high) { border-left-color: ${colors.high}; }
    .finding:has(.badge-medium) { border-left-color: ${colors.medium}; }
    .finding:has(.badge-low) { border-left-color: ${colors.low}; }
    .finding:has(.badge-info) { border-left-color: ${colors.info}; }
    .finding-header { gap: 8px; margin-bottom: 9px; }
    .finding p { margin: 8px 0; color: var(--cw-muted); }
    .badge { padding: 4px 7px; border: 1px solid transparent; border-radius: 5px; font-size: 9px; }
    .badge-critical { border-color: ${colors.critical}; color: ${colors.critical}; background: ${colors.criticalSoft}; }
    .badge-high { border-color: ${colors.high}; color: ${colors.high}; background: ${colors.highSoft}; }
    .badge-medium { border-color: ${colors.medium}; color: ${colors.medium}; background: ${colors.mediumSoft}; }
    .badge-low { border-color: ${colors.low}; color: ${colors.low}; background: ${colors.lowSoft}; }
    .badge-info { border-color: ${colors.info}; color: ${colors.info}; background: ${colors.infoSoft}; }
    .test-id, code { border: 1px solid var(--cw-border); border-radius: 4px; color: var(--cw-muted); background: var(--cw-elevated); font-family: Consolas, monospace; }
    .test-id { padding: 3px 6px; }
    code { padding: 2px 5px; }
    .remediation { margin-top: 11px; padding: 10px 12px; border: 1px solid var(--cw-border); border-left: 3px solid var(--cw-accent); border-radius: 5px; color: var(--cw-muted); background: var(--cw-accent-soft); }
    .no-findings { border: 1px solid ${colors.low}; border-radius: 8px; color: ${colors.low}; background: ${colors.lowSoft}; }
    .footer { padding: 18px; border-top: 1px solid var(--cw-border); color: var(--cw-muted); background: var(--cw-surface); }
    a { color: var(--cw-accent); }
    @media (max-width: 760px) { .container { padding: 12px; } .severity-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .header { padding: 16px; } .finding { padding: 14px; } }
  `;
}

function themedSecurityReportHtml(reportHtml, theme) {
  const themeStyle = `<style id="centralwatch-report-theme">${securityReportThemeCss(theme)}</style>`;
  return /<\/head>/i.test(reportHtml)
    ? reportHtml.replace(/<\/head>/i, `${themeStyle}</head>`)
    : `${themeStyle}${reportHtml}`;
}

function renderSecurityReportFrame(scroll = true) {
  if (!state.securityReportHtml) return false;
  const panel = $("#security-report-panel");
  const frame = $("#security-report-frame");
  const loading = $("#security-report-loading");
  panel.hidden = false;
  frame.hidden = true;
  $("#security-report-error").hidden = true;
  loading.classList.remove("loaded");
  $("#open-security-report").setAttribute("aria-expanded", "true");
  if (state.securityReportUrl) URL.revokeObjectURL(state.securityReportUrl);
  const documentHtml = themedSecurityReportHtml(state.securityReportHtml, currentTheme());
  state.securityReportUrl = URL.createObjectURL(new Blob([documentHtml], { type: "text/html;charset=utf-8" }));
  frame.onload = () => {
    frame.hidden = false;
    loading.classList.add("loaded");
  };
  frame.src = state.securityReportUrl;
  if (scroll) panel.scrollIntoView({ behavior: "smooth", block: "start" });
  return true;
}

async function openSecurityReport(options = {}) {
  if (!state.token) { openAuthDialog(); return; }
  const shouldScroll = options?.scroll !== false;
  const button = $("#open-security-report");
  const panel = $("#security-report-panel");
  const frame = $("#security-report-frame");
  const loading = $("#security-report-loading");
  const errorState = $("#security-report-error");
  panel.hidden = false;
  frame.hidden = true;
  errorState.hidden = true;
  loading.classList.remove("loaded");
  button.setAttribute("aria-expanded", "true");
  if (shouldScroll) panel.scrollIntoView({ behavior: "smooth", block: "start" });
  setBusy(button, true, "Loading report…");
  try {
    const response = await fetch(`${API_BASE}/centralwatch/security-scan/report`, { headers: { Authorization: `Bearer ${state.token}` }, cache: "no-store" });
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new ApiError(errorDetail(payload, `Report request failed (${response.status})`), response.status, payload);
    }
    state.securityReportHtml = await response.text();
    renderSecurityReportFrame(shouldScroll);
    return true;
  } catch (error) {
    loading.classList.add("loaded");
    frame.hidden = true;
    $("#security-report-error-message").textContent = error.message;
    errorState.hidden = false;
    showToast(error.message, true);
    return false;
  } finally { setBusy(button, false); }
}

function closeSecurityReport() {
  const frame = $("#security-report-frame");
  if (frame) {
    frame.onload = null;
    frame.removeAttribute("src");
    frame.hidden = true;
  }
  if (state.securityReportUrl) {
    URL.revokeObjectURL(state.securityReportUrl);
    state.securityReportUrl = null;
  }
  state.securityReportHtml = null;
  const panel = $("#security-report-panel");
  if (panel) panel.hidden = true;
  const button = $("#open-security-report");
  if (button) button.setAttribute("aria-expanded", "false");
}

function protectedOrAuth() {
  if (state.user && state.token) return true;
  openAuthDialog();
  return false;
}

async function loadOrders() {
  if (!state.token) return;
  const button = $("#refresh-orders");
  setBusy(button, true, "Loading…");
  try {
    const response = await apiRequest("/orders");
    state.orders = response.orders || [];
    renderOrders();
  } catch (error) {
    $("#orders-table-body").innerHTML = `<tr><td colspan="7"><div class="empty-state error-state"><strong>Orders unavailable</strong><span>${escapeHtml(error.message)}</span></div></td></tr>`;
  } finally { setBusy(button, false); }
}

function renderOrders() {
  const query = $("#orders-search").value.trim().toLowerCase();
  const status = $("#orders-status").value;
  const sort = $("#orders-sort").value;
  const orders = state.orders.filter((order) => (!status || order.status === status) && [order.order_id, order.user_id, order.status, ...order.items.map((item) => `${item.product_id} ${item.name}`)].join(" ").toLowerCase().includes(query));
  orders.sort((a, b) => {
    if (sort === "oldest") return new Date(a.created_at) - new Date(b.created_at);
    if (sort === "total-desc") return b.total - a.total;
    if (sort === "total-asc") return a.total - b.total;
    return new Date(b.created_at) - new Date(a.created_at);
  });
  if (!orders.length) {
    $("#orders-table-body").innerHTML = `<tr><td colspan="7"><div class="empty-state"><strong>${state.orders.length ? "No matching orders" : "No orders yet"}</strong><span>${state.orders.length ? "Adjust the filters." : "Create the first order to generate DynamoDB activity."}</span></div></td></tr>`;
    return;
  }
  $("#orders-table-body").innerHTML = orders.map((order) => `<tr><td><code>${escapeHtml(order.order_id)}</code></td><td><code>${escapeHtml(order.user_id)}</code></td><td>${order.items.length}</td><td><strong>${escapeHtml(formatMoney(order.total))}</strong></td><td><span class="status-badge success">${escapeHtml(order.status)}</span></td><td>${escapeHtml(formatDate(order.created_at))}</td><td><div class="row-actions"><button class="table-button" type="button" data-order-view="${escapeHtml(order.order_id)}">View</button></div></td></tr>`).join("");
}

function addOrderItem(item = {}) {
  const container = $("#order-items");
  const row = document.createElement("div");
  row.className = "order-item";
  row.innerHTML = `<label>Product ID<input class="item-product" required value="${escapeHtml(item.product_id || "")}" placeholder="product_1"></label><label>Name<input class="item-name" required value="${escapeHtml(item.name || "")}" placeholder="Product name"></label><label>Quantity<input class="item-quantity" type="number" min="1" step="1" required value="${escapeHtml(item.quantity || 1)}"></label><label>Unit price<input class="item-price" type="number" min="0" step="0.01" required value="${escapeHtml(item.unit_price || 0)}"></label><button class="table-button danger remove-order-item" type="button">Remove</button>`;
  container.append(row);
}

function openOrderDialog() {
  if (!protectedOrAuth()) return;
  $("#order-form").reset();
  $("#order-user-id").value = state.user.user_id;
  $("#order-items").replaceChildren();
  addOrderItem();
  setMessage($("#order-message"), "");
  openDialog("order-dialog");
}

async function handleOrderSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const items = $$(".order-item", form).map((row) => ({ product_id: $(".item-product", row).value.trim(), name: $(".item-name", row).value.trim(), quantity: Number($(".item-quantity", row).value), unit_price: Number($(".item-price", row).value) }));
  if (!items.length) { setMessage($("#order-message"), "Add at least one item.", true); return; }
  const button = $("#create-order");
  setBusy(button, true, "Creating…");
  try {
    const order = await apiRequest("/orders", { method: "POST", body: { user_id: $("#order-user-id").value.trim(), items } });
    closeDialog("order-dialog");
    recordActivity("Order created", `${order.order_id} · ${formatMoney(order.total)}`);
    showToast(`Created order ${order.order_id}`);
    await loadOrders();
  } catch (error) { setMessage($("#order-message"), error.message, true); }
  finally { setBusy(button, false); }
}

async function showOrderDetail(orderId) {
  try {
    const order = await apiRequest(`/orders/${encodeURIComponent(orderId)}`);
    $("#detail-title").textContent = "Order details";
    $("#detail-subtitle").textContent = order.order_id;
    $("#detail-content").innerHTML = `<dl class="detail-table"><div><dt>User</dt><dd><code>${escapeHtml(order.user_id)}</code></dd></div><div><dt>Status</dt><dd>${escapeHtml(order.status)}</dd></div><div><dt>Total</dt><dd><strong>${escapeHtml(formatMoney(order.total))}</strong></dd></div><div><dt>Created</dt><dd>${escapeHtml(formatDate(order.created_at))}</dd></div></dl><div class="table-wrap detail-items"><table><thead><tr><th>Product</th><th>Name</th><th>Quantity</th><th>Unit price</th></tr></thead><tbody>${order.items.map((item) => `<tr><td><code>${escapeHtml(item.product_id)}</code></td><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.quantity)}</td><td>${escapeHtml(formatMoney(item.unit_price))}</td></tr>`).join("")}</tbody></table></div>`;
    openDialog("detail-dialog");
  } catch (error) { showToast(error.message, true); }
}

async function loadFiles() {
  if (!state.token) return;
  const button = $("#refresh-files");
  setBusy(button, true, "Loading…");
  try {
    const response = await apiRequest("/files");
    state.files = response.files || [];
    renderFiles();
  } catch (error) {
    $("#files-table-body").innerHTML = `<tr><td colspan="5"><div class="empty-state error-state"><strong>Files unavailable</strong><span>${escapeHtml(error.message)}</span></div></td></tr>`;
  } finally { setBusy(button, false); }
}

function renderFiles() {
  const query = $("#files-search").value.trim().toLowerCase();
  const sort = $("#files-sort").value;
  const files = state.files.filter((file) => [file.name, file.content_type, file.file_id].join(" ").toLowerCase().includes(query));
  files.sort((a, b) => {
    if (sort === "oldest") return new Date(a.created_at) - new Date(b.created_at);
    if (sort === "size-desc") return b.size - a.size;
    if (sort === "size-asc") return a.size - b.size;
    return new Date(b.created_at) - new Date(a.created_at);
  });
  if (!files.length) {
    $("#files-table-body").innerHTML = `<tr><td colspan="5"><div class="empty-state"><strong>${state.files.length ? "No matching files" : "No files uploaded"}</strong><span>${state.files.length ? "Try another search." : "Upload a file to create an S3 object."}</span></div></td></tr>`;
    return;
  }
  $("#files-table-body").innerHTML = files.map((file) => `<tr><td><strong>${escapeHtml(file.name)}</strong><br><code>${escapeHtml(file.file_id)}</code></td><td>${escapeHtml(file.content_type)}</td><td>${escapeHtml(formatBytes(file.size))}</td><td>${escapeHtml(formatDate(file.created_at))}</td><td><div class="row-actions"><button class="table-button" type="button" data-file-view="${escapeHtml(file.file_id)}">View</button><button class="table-button danger" type="button" data-file-delete="${escapeHtml(file.file_id)}">Delete</button></div></td></tr>`).join("");
}

async function handleFileUpload(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const file = $("#file-upload-input").files[0];
  const body = new FormData();
  body.append("file", file);
  const button = $("#upload-file");
  const message = $("#file-upload-message");
  setBusy(button, true, "Uploading…"); setMessage(message, "");
  try {
    const result = await apiRequest("/files/upload", { method: "POST", body });
    form.reset(); setMessage(message, `${result.name} uploaded.`);
    recordActivity("File uploaded", `${result.name} · ${formatBytes(result.size)}`);
    showToast(`Uploaded ${result.name}`); await loadFiles();
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

async function showFileDetail(fileId) {
  try {
    const file = await apiRequest(`/files/${encodeURIComponent(fileId)}`);
    $("#detail-title").textContent = "File details";
    $("#detail-subtitle").textContent = file.name;
    $("#detail-content").innerHTML = `<dl class="detail-table"><div><dt>File ID</dt><dd><code>${escapeHtml(file.file_id)}</code></dd></div><div><dt>Type</dt><dd>${escapeHtml(file.content_type)}</dd></div><div><dt>Size</dt><dd>${escapeHtml(formatBytes(file.size))}</dd></div><div><dt>Bucket</dt><dd><code>${escapeHtml(file.bucket)}</code></dd></div><div><dt>Object key</dt><dd><code>${escapeHtml(file.key)}</code></dd></div><div><dt>Created</dt><dd>${escapeHtml(formatDate(file.created_at))}</dd></div></dl>${file.download_url ? `<a class="button primary" href="${escapeHtml(file.download_url)}" target="_blank" rel="noopener">Download file</a>` : ""}`;
    openDialog("detail-dialog");
  } catch (error) { showToast(error.message, true); }
}

async function deleteFile(fileId) {
  const file = state.files.find((entry) => entry.file_id === fileId);
  if (!window.confirm(`Delete ${file?.name || fileId}? This removes the S3 object and metadata.`)) return;
  try {
    await apiRequest(`/files/${encodeURIComponent(fileId)}`, { method: "DELETE" });
    recordActivity("File deleted", file?.name || fileId);
    showToast("File deleted"); await loadFiles();
  } catch (error) { showToast(error.message, true); }
}

async function handleNotification(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (!form.reportValidity()) return;
  const data = new FormData(form);
  const channel = data.get("channel");
  const button = $("#send-notification");
  const message = $("#notification-message");
  setBusy(button, true, "Sending…"); setMessage(message, "");
  try {
    const result = await apiRequest(`/notifications/${channel}`, { method: "POST", body: { recipient: data.get("recipient").trim(), subject: channel === "email" ? data.get("subject").trim() : "", message: data.get("message").trim() } });
    setMessage(message, `Published ${result.channel} notification (${result.message_id}).`);
    recordActivity("Notification sent", `${channel} · ${data.get("recipient")}`); showToast("Notification published to SNS");
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

async function handleQueueSend(event) {
  event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return;
  const button = $("#send-queue-message"); const message = $("#queue-send-message"); const data = new FormData(form);
  setBusy(button, true, "Sending…"); setMessage(message, "");
  try {
    const result = await apiRequest("/queue/send", { method: "POST", body: { body: data.get("body").trim() } });
    form.reset(); setMessage(message, `Queued message ${result.message_id}.`); recordActivity("Queue message sent", result.message_id); showToast("Message sent to SQS");
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

async function receiveQueueMessages() {
  const button = $("#receive-queue"); setBusy(button, true, "Receiving…");
  try {
    const result = await apiRequest("/queue/messages");
    $("#queue-message-list").innerHTML = result.messages.length ? result.messages.map((message) => `<div class="message-item"><code>${escapeHtml(message.message_id)}</code><p>${escapeHtml(message.body)}</p></div>`).join("") : '<div class="empty-state compact"><strong>Queue is empty</strong><span>No messages were available.</span></div>';
    recordActivity("Queue received", `${result.received} message${result.received === 1 ? "" : "s"}`); showToast(`Received ${result.received} queue message${result.received === 1 ? "" : "s"}`);
  } catch (error) { showToast(error.message, true); }
  finally { setBusy(button, false); }
}

async function handleImageProcess(event) {
  event.preventDefault(); const form = event.currentTarget; if (!form.reportValidity()) return;
  const body = new FormData(); const file = $("#image-input").files[0]; body.append("file", file);
  const button = $("#process-image"); const message = $("#image-message");
  setBusy(button, true, "Processing…"); setMessage(message, ""); $("#image-result").hidden = true;
  try {
    const result = await apiRequest("/images/process", { method: "POST", body });
    $("#image-result").textContent = JSON.stringify(result, null, 2); $("#image-result").hidden = false;
    form.reset(); setMessage(message, "Image workflow completed."); recordActivity("Image processed", `${result.processing_id} · ${formatBytes(result.size_bytes)}`); showToast("Image processing workflow completed");
  } catch (error) { setMessage(message, error.message, true); }
  finally { setBusy(button, false); }
}

async function runSimulation(name, button) {
  const resultBox = $(`[data-simulation-result="${name}"]`);
  setBusy(button, true, name === "timeout" ? "Waiting…" : "Running…"); resultBox.hidden = true; resultBox.classList.remove("error");
  try {
    const result = await apiRequest(`/simulate/${name}`);
    resultBox.textContent = JSON.stringify(result, null, 2); resultBox.hidden = false; recordActivity("Simulation complete", name); showToast(`${name} simulation completed`);
  } catch (error) {
    resultBox.textContent = JSON.stringify(error.payload || { status: error.status, detail: error.message }, null, 2); resultBox.hidden = false; resultBox.classList.add("error");
    const expected = name === "error" || name === "s3-error";
    recordActivity(expected ? "Simulation produced expected error" : "Simulation failed", `${name} · HTTP ${error.status || "error"}`, expected ? "success" : "error");
    showToast(expected ? `${name} generated the expected HTTP ${error.status}` : error.message, !expected);
  } finally { setBusy(button, false); }
}

function loadViewData(name) {
  if (name === "overview") { loadHealth(); loadServices(); }
  if (name === "proxy") loadProxyWorkspace();
  if (name === "aws-security" && state.token) loadLatestAwsSecurityScan();
  if (name === "observability") initializeGrafana();
  if (name === "chat") loadGeminiStatus();
  if (name === "orders" && state.token) loadOrders();
  if (name === "files" && state.token) loadFiles();
}

function bindEvents() {
  window.addEventListener("hashchange", routeFromHash);
  $("#mobile-menu").addEventListener("click", openSidebar);
  $("#sidebar-scrim").addEventListener("click", closeSidebar);
  $$('[data-theme-choice]').forEach((button) => button.addEventListener("click", () => applyTheme(button.dataset.themeChoice)));
  $("#account-button").addEventListener("click", openAuthDialog);
  $$('[data-open-auth]').forEach((button) => button.addEventListener("click", openAuthDialog));
  $$('[data-dialog-close]').forEach((button) => button.addEventListener("click", () => closeDialog(button.dataset.dialogClose)));
  $("#show-login").addEventListener("click", () => showAuthMode("login"));
  $("#show-register").addEventListener("click", () => showAuthMode("register"));
  $("#login-form").addEventListener("submit", handleLogin);
  $("#register-form").addEventListener("submit", handleRegister);
  $("#sign-out").addEventListener("click", signOut);
  $("#refresh-health").addEventListener("click", loadHealth);
  $("#refresh-services").addEventListener("click", loadProxyWorkspace);
  $("#proxy-search").addEventListener("input", renderServices);
  $("#proxy-form").addEventListener("submit", handleProxySubmit);
  $("#proxy-role-form").addEventListener("submit", handleProxyRoleSubmit);
  $("#copy-proxy-access-token").addEventListener("click", () => {
    if (state.lastProxyAccessToken) copyText(state.lastProxyAccessToken, "Proxy token copied");
  });
  $("#proxy-history-search").addEventListener("input", renderProxyHistory);
  $("#proxy-history-outcome").addEventListener("change", renderProxyHistory);
  $("#service-table-body").addEventListener("click", (event) => {
    const copyButton = event.target.closest("[data-copy-proxy]");
    if (copyButton) {
      const path = externalUrl("8000", `/centralwatch/proxy/${copyButton.dataset.copyProxy}/{path}`);
      $("#endpoint-example").textContent = path;
      copyText(path, `Copied ${copyButton.dataset.copyProxy} endpoint`);
      return;
    }
    const rotateButton = event.target.closest("[data-rotate-proxy-token]");
    if (rotateButton) rotateProxyAccessToken(rotateButton.dataset.rotateProxyToken, rotateButton);
  });
  $("#copy-endpoint").addEventListener("click", () => copyText($("#endpoint-example").textContent, "Endpoint copied"));
  $("#clear-activity").addEventListener("click", () => { state.activity = []; safeStorageRemove(ACTIVITY_KEY); renderActivity(); });
  $("#gemini-config-form").addEventListener("submit", configureGemini);
  $("#gemini-token-form").addEventListener("submit", useGeminiProxyToken);
  $("#chat-form").addEventListener("submit", handleChatSubmit);
  $("#clear-chat").addEventListener("click", clearChat);
  $("#security-scan-form").addEventListener("submit", handleSecurityScan);
  $("#open-security-report").addEventListener("click", openSecurityReport);
  $("#run-aws-security-scan").addEventListener("click", runAwsSecurityScan);
  $("#select-agent-findings").addEventListener("click", toggleAwsFindingSelection);
  $("#apply-agent-findings").addEventListener("click", applyAwsSecurityFindings);
  $("#aws-findings-body").addEventListener("change", (event) => { if (event.target.matches(".finding-checkbox")) updateAwsAgentSelection(); });
  $("#refresh-orders").addEventListener("click", () => protectedOrAuth() && loadOrders());
  $("#new-order").addEventListener("click", openOrderDialog);
  $("#orders-search").addEventListener("input", renderOrders);
  $("#orders-status").addEventListener("change", renderOrders);
  $("#orders-sort").addEventListener("change", renderOrders);
  $("#orders-table-body").addEventListener("click", (event) => { const button = event.target.closest("[data-order-view]"); if (button) showOrderDetail(button.dataset.orderView); });
  $("#add-order-item").addEventListener("click", () => addOrderItem());
  $("#order-items").addEventListener("click", (event) => { const button = event.target.closest(".remove-order-item"); if (button) button.closest(".order-item").remove(); });
  $("#order-form").addEventListener("submit", handleOrderSubmit);
  $("#refresh-files").addEventListener("click", () => protectedOrAuth() && loadFiles());
  $("#files-search").addEventListener("input", renderFiles);
  $("#files-sort").addEventListener("change", renderFiles);
  $("#file-upload-form").addEventListener("submit", handleFileUpload);
  $("#files-table-body").addEventListener("click", (event) => {
    const view = event.target.closest("[data-file-view]"); const remove = event.target.closest("[data-file-delete]");
    if (view) showFileDetail(view.dataset.fileView);
    if (remove) deleteFile(remove.dataset.fileDelete);
  });
  $("#notification-channel").addEventListener("change", (event) => { $(".notification-subject").hidden = event.target.value === "sms"; });
  $("#notification-form").addEventListener("submit", handleNotification);
  $("#queue-form").addEventListener("submit", handleQueueSend);
  $("#receive-queue").addEventListener("click", receiveQueueMessages);
  $("#image-form").addEventListener("submit", handleImageProcess);
  $$("[data-simulation]").forEach((button) => button.addEventListener("click", () => runSimulation(button.dataset.simulation, button)));
}

applyTheme(currentThemePreference(), false);
configureExternalLinks();
bindEvents();
renderActivity();
updateAuthUI();
routeFromHash();
restoreSession();
window.setInterval(() => { if (state.activeView === "overview") loadHealth(); }, 30000);
window.setInterval(() => { if (state.activeView === "proxy") loadProxyObservability(); }, 15000);

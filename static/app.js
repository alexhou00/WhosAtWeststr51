const appConfig = window.APP_CONFIG || {};

const personCards = Array.from(document.querySelectorAll("[data-person-card]"));
const debugOutput = document.getElementById("debug-output");
const refreshButton = document.getElementById("refresh-button");
const loadDebugButton = document.getElementById("load-debug-button");
const refreshNote = document.getElementById("refresh-note");
const globalLastChecked = document.getElementById("global-last-checked");
let lastSuccessfulCheckedText = "-";

const pollSeconds = Number(appConfig.pollingIntervalSeconds || 20);
const idleRefreshNote = `Auto-refresh every ${pollSeconds} seconds.`;
refreshNote.textContent = idleRefreshNote;

function setBadgeState(element, kind, text) {
  element.textContent = text;
  element.className = "badge";

  if (kind === "present") {
    element.classList.add("badge-success");
    return;
  }

  if (kind === "absent") {
    element.classList.add("badge-danger");
    return;
  }

  element.classList.add("badge-neutral");
}

function formatTimestamp(value) {
  if (!value) {
    return "-";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString([], {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function labelForMatchedBy(value) {
  if (!value) {
    return "-";
  }

  if (value === "mac_address") {
    return "MAC address";
  }

  if (value === "ip_address") {
    return "IP address";
  }

  if (value === "hostname") {
    return "Hostname";
  }

  return value;
}

function setField(card, fieldName, value) {
  const field = card.querySelector(`[data-field="${fieldName}"]`);
  if (field) {
    field.textContent = value || "-";
  }
}

function renderPerson(person) {
  const card = document.querySelector(`[data-person-card="${person.name}"]`);
  if (!card) {
    return;
  }

  const badge = card.querySelector(".person-badge");
  const statusText = card.querySelector(".person-status");
  const badgeKind = person.present ? "present" : "absent";

  setBadgeState(badge, badgeKind, person.status_text || "Unknown");
  card.classList.toggle("person-card-present", Boolean(person.present));
  card.classList.toggle("person-card-absent", !person.present);

  statusText.textContent = person.present
    ? `${person.name}'s device was detected on the network.`
    : `${person.name} is probably not at home right now.`;

  setField(card, "method", person.method || "-");
  setField(card, "matched_by", labelForMatchedBy(person.matched_by));
  setField(card, "target_identifier", person.target_identifier || "-");
  setField(card, "last_positive_detection", formatTimestamp(person.last_positive_detection));
}

function renderStatus(data) {
  lastSuccessfulCheckedText = formatTimestamp(data.last_checked);
  globalLastChecked.textContent = lastSuccessfulCheckedText;
  const people = Array.isArray(data.people) ? data.people : [];
  for (const person of people) {
    renderPerson(person);
  }
}

function renderDebugData(data) {
  debugOutput.textContent = JSON.stringify(data, null, 2);
}

function renderFetchError(message) {
  globalLastChecked.textContent = lastSuccessfulCheckedText;
  for (const card of personCards) {
    const badge = card.querySelector(".person-badge");
    const statusText = card.querySelector(".person-status");
    setBadgeState(badge, "neutral", "Check failed");
    statusText.textContent = message;
  }

  renderDebugData({
    error: "status_refresh_failed",
    message,
    last_successful_checked: lastSuccessfulCheckedText,
    occurred_at: new Date().toISOString(),
  });
}

async function fetchJson(url) {
  const requestUrl = new URL(url, window.location.href);
  requestUrl.searchParams.set("_ts", Date.now().toString());

  const response = await fetch(requestUrl.toString(), { cache: "no-store" });
  let payload = {};

  try {
    payload = await response.json();
  } catch (error) {
    payload = {};
  }

  if (!response.ok) {
    const message = payload.message || payload.error || `Request failed with HTTP ${response.status}`;
    throw new Error(message);
  }

  return payload;
}

async function refreshStatus() {
  refreshButton.disabled = true;
  refreshButton.textContent = "Refreshing...";
  refreshNote.textContent = "Refreshing from backend...";

  try {
    const results = await Promise.allSettled([
      fetchJson(appConfig.statusEndpoint || "/api/status"),
      fetchJson(appConfig.debugEndpoint || "/api/devices/debug"),
    ]);

    const statusResult = results[0];
    const debugResult = results[1];

    if (statusResult.status === "fulfilled") {
      renderStatus(statusResult.value);
    } else {
      renderFetchError(statusResult.reason.message);
    }

    if (debugResult.status === "fulfilled") {
      renderDebugData(debugResult.value);
    } else {
      renderDebugData({
        error: "debug_refresh_failed",
        message: debugResult.reason.message,
        last_successful_checked: lastSuccessfulCheckedText,
        occurred_at: new Date().toISOString(),
      });
    }
  } finally {
    refreshButton.disabled = false;
    refreshButton.textContent = "Refresh now";
    refreshNote.textContent = idleRefreshNote;
  }
}

async function loadFullDebug() {
  loadDebugButton.disabled = true;

  try {
    const data = await fetchJson(appConfig.debugEndpoint || "/api/devices/debug");
    renderDebugData(data);
  } catch (error) {
    renderDebugData({
      error: "debug_refresh_failed",
      message: error.message,
      last_successful_checked: lastSuccessfulCheckedText,
      occurred_at: new Date().toISOString(),
    });
  } finally {
    loadDebugButton.disabled = false;
  }
}

refreshButton.addEventListener("click", refreshStatus);
loadDebugButton.addEventListener("click", loadFullDebug);

refreshStatus();
window.setInterval(refreshStatus, pollSeconds * 1000);

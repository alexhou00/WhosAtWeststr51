const appConfig = window.APP_CONFIG || {};

const statusBadge = document.getElementById("status-badge");
const statusText = document.getElementById("status-text");
const lastChecked = document.getElementById("last-checked");
const method = document.getElementById("method");
const matchedBy = document.getElementById("matched-by");
const targetIdentifier = document.getElementById("target-identifier");
const confidence = document.getElementById("confidence");
const lastPositive = document.getElementById("last-positive");
const debugOutput = document.getElementById("debug-output");
const refreshButton = document.getElementById("refresh-button");
const loadDebugButton = document.getElementById("load-debug-button");
const refreshNote = document.getElementById("refresh-note");

const pollSeconds = Number(appConfig.pollingIntervalSeconds || 20);
refreshNote.textContent = `Auto-refresh every ${pollSeconds} seconds.`;

function setBadgeState(kind, text) {
  statusBadge.textContent = text;
  statusBadge.className = "badge";

  if (kind === "present") {
    statusBadge.classList.add("badge-success");
    return;
  }

  if (kind === "absent") {
    statusBadge.classList.add("badge-danger");
    return;
  }

  statusBadge.classList.add("badge-neutral");
}

function formatTimestamp(value) {
  if (!value) {
    return "-";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
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

function renderStatus(data) {
  const badgeKind = data.present
    ? "present"
    : data.status_text === "Probably not at Home"
      ? "absent"
      : "neutral";
  setBadgeState(badgeKind, data.status_text || "Unknown");

  if (data.present) {
    statusText.textContent = "The target device matched one of the configured identifiers.";
  } else if (data.status_text && data.status_text !== "Probably not at Home") {
    statusText.textContent = data.status_text;
  } else {
    statusText.textContent = "No configured target identifier matched during the latest check.";
  }

  lastChecked.textContent = formatTimestamp(data.last_checked);
  method.textContent = data.method || "-";
  matchedBy.textContent = labelForMatchedBy(data.matched_by);
  targetIdentifier.textContent = data.target_identifier || "-";
  confidence.textContent = data.confidence || "-";
  lastPositive.textContent = formatTimestamp(data.last_positive_detection);

  debugOutput.textContent = JSON.stringify(
    {
      present: data.present,
      status_text: data.status_text,
      last_checked: data.last_checked,
      method: data.method,
      matched_by: data.matched_by,
      target_identifier: data.target_identifier,
      confidence: data.confidence,
      last_positive_detection: data.last_positive_detection,
      sources_attempted: data.sources_attempted,
      errors: data.errors,
      details: data.details,
    },
    null,
    2
  );
}

function renderFetchError(message) {
  setBadgeState("neutral", "Check failed");
  statusText.textContent = message;
}

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
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

  try {
    const data = await fetchJson(appConfig.statusEndpoint || "/api/status");
    renderStatus(data);
  } catch (error) {
    renderFetchError(error.message);
  } finally {
    refreshButton.disabled = false;
  }
}

async function loadFullDebug() {
  loadDebugButton.disabled = true;

  try {
    const data = await fetchJson(appConfig.debugEndpoint || "/api/devices/debug");
    debugOutput.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    debugOutput.textContent = `Failed to load debug data: ${error.message}`;
  } finally {
    loadDebugButton.disabled = false;
  }
}

refreshButton.addEventListener("click", refreshStatus);
loadDebugButton.addEventListener("click", loadFullDebug);

refreshStatus();
window.setInterval(refreshStatus, pollSeconds * 1000);

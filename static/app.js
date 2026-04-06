const appConfig = window.APP_CONFIG || {};

const personCards = Array.from(document.querySelectorAll("[data-person-card]"));
const debugOutput = document.getElementById("debug-output");
const refreshButton = document.getElementById("refresh-button");
const loadDebugButton = document.getElementById("load-debug-button");
const refreshNote = document.getElementById("refresh-note");

const pollSeconds = Number(appConfig.pollingIntervalSeconds || 20);
refreshNote.textContent = `Auto-refresh every ${pollSeconds} seconds.`;

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
    ? `${person.name} matched one of the configured device identifiers.`
    : `${person.name} did not match any configured device during the latest check.`;

  setField(card, "last_checked", formatTimestamp(person.last_checked));
  setField(card, "method", person.method || "-");
  setField(card, "matched_by", labelForMatchedBy(person.matched_by));
  setField(card, "target_identifier", person.target_identifier || "-");
  setField(card, "confidence", person.confidence || "-");
  setField(card, "last_positive_detection", formatTimestamp(person.last_positive_detection));
}

function renderStatus(data) {
  const people = Array.isArray(data.people) ? data.people : [];
  for (const person of people) {
    renderPerson(person);
  }

  debugOutput.textContent = JSON.stringify(
    {
      last_checked: data.last_checked,
      sources_attempted: data.sources_attempted,
      errors: data.errors,
      people: data.people,
      details: data.details,
    },
    null,
    2
  );
}

function renderFetchError(message) {
  for (const card of personCards) {
    const badge = card.querySelector(".person-badge");
    const statusText = card.querySelector(".person-status");
    setBadgeState(badge, "neutral", "Check failed");
    statusText.textContent = message;
  }
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

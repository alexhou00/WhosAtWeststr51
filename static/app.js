const appConfig = window.APP_CONFIG || {};

const personCards = Array.from(document.querySelectorAll("[data-person-card]"));
const personCardMap = new Map(
  personCards
    .map((card) => [card.dataset.personCard || "", card])
    .filter(([name]) => name)
);
const debugOutput = document.getElementById("debug-output");
const refreshButton = document.getElementById("refresh-button");
const loadDebugButton = document.getElementById("load-debug-button");
const refreshNote = document.getElementById("refresh-note");
const globalLastChecked = document.getElementById("global-last-checked");
let lastSuccessfulCheckedText = "-";
let latestStatusPayload = null;
let latestDeviceDebugPayload = null;
let latestFrontendIssue = null;
let activeRefreshPromise = null;

const pollSeconds = Number(appConfig.pollingIntervalSeconds || 600);
const idleRefreshNote = `Auto-refresh every ${pollSeconds} seconds.`;
if (refreshNote) {
  refreshNote.textContent = idleRefreshNote;
}

function setBadgeState(element, kind, text) {
  if (!element) {
    return;
  }

  element.textContent = text;
  element.classList.remove("badge-success", "badge-danger", "badge-neutral");
  element.classList.add("person-badge", "badge");

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

function errorMessageFrom(error) {
  if (error instanceof Error && error.message) {
    return error.message;
  }

  return String(error || "Unknown error");
}

function renderDebugSnapshot() {
  if (!debugOutput) {
    return;
  }

  const payload = {
    last_successful_checked: lastSuccessfulCheckedText,
    status_response: latestStatusPayload,
    device_debug_response: latestDeviceDebugPayload,
    frontend_issue: latestFrontendIssue,
  };

  debugOutput.textContent = JSON.stringify(payload, null, 2);
}

function renderPerson(person) {
  const personName = String(person?.name || "").trim();
  const card = personCardMap.get(personName);
  if (!card) {
    throw new Error(`No person card exists for "${personName || "unknown"}".`);
  }

  const badge = card.querySelector(".person-badge");
  const statusText = card.querySelector(".person-status");
  if (!badge || !statusText) {
    throw new Error(`Person card markup is incomplete for "${personName || "unknown"}".`);
  }

  const badgeKind = person.present ? "present" : "absent";

  setBadgeState(badge, badgeKind, person.status_text || "Unknown");
  card.classList.toggle("person-card-present", Boolean(person.present));
  card.classList.toggle("person-card-absent", !person.present);

  statusText.textContent = person.present
    ? `${personName}'s device was detected on the network. She is very likely at home. However, she may have just left or may have left home without the phone.`
    : `${personName} is probably not at home right now, or the device is not connected to home Wi-Fi or is inactive.`;

  setField(card, "method", person.method || "-");
  setField(card, "matched_by", labelForMatchedBy(person.matched_by));
  setField(card, "target_identifier", person.target_identifier || "-");
  setField(card, "last_positive_detection", formatTimestamp(person.last_positive_detection));
}

function renderStatus(data) {
  latestStatusPayload = data;
  latestFrontendIssue = null;
  lastSuccessfulCheckedText = formatTimestamp(data.last_checked);
  if (globalLastChecked) {
    globalLastChecked.textContent = lastSuccessfulCheckedText;
  }

  renderDebugSnapshot();

  const people = Array.isArray(data.people) ? data.people : [];
  for (const person of people) {
    try {
      renderPerson(person);
    } catch (error) {
      latestFrontendIssue = {
        error: "person_render_failed",
        message: errorMessageFrom(error),
        person,
        occurred_at: new Date().toISOString(),
      };
      renderDebugSnapshot();
    }
  }
}

function renderDebugData(data) {
  latestDeviceDebugPayload = data;
  renderDebugSnapshot();
}

function renderFetchError(message, extra = {}) {
  if (globalLastChecked) {
    globalLastChecked.textContent = lastSuccessfulCheckedText;
  }

  for (const card of personCards) {
    const badge = card.querySelector(".person-badge");
    const statusText = card.querySelector(".person-status");
    setBadgeState(badge, "neutral", "Check failed");
    if (statusText) {
      statusText.textContent = message;
    }
  }

  latestFrontendIssue = {
    error: "status_refresh_failed",
    message,
    ...extra,
    last_successful_checked: lastSuccessfulCheckedText,
    occurred_at: new Date().toISOString(),
  };
  renderDebugSnapshot();
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
  if (activeRefreshPromise) {
    return activeRefreshPromise;
  }

  activeRefreshPromise = (async () => {
    if (refreshButton) {
      refreshButton.disabled = true;
      refreshButton.textContent = "Refreshing...";
    }
    if (refreshNote) {
      refreshNote.textContent = "Refreshing from backend...";
    }

    const statusPromise = fetchJson(appConfig.statusEndpoint || "/api/status");
    const debugPromise = fetchJson(appConfig.debugEndpoint || "/api/devices/debug");

    try {
      const statusData = await statusPromise;
      renderStatus(statusData);
    } catch (error) {
      renderFetchError(errorMessageFrom(error));
    }

    try {
      const debugData = await debugPromise;
      renderDebugData(debugData);
    } catch (error) {
      renderDebugData({
        error: "debug_refresh_failed",
        message: errorMessageFrom(error),
        last_successful_checked: lastSuccessfulCheckedText,
        occurred_at: new Date().toISOString(),
      });
    } finally {
      if (refreshButton) {
        refreshButton.disabled = false;
        refreshButton.textContent = "Refresh now";
      }
      if (refreshNote) {
        refreshNote.textContent = idleRefreshNote;
      }
    }
  })();

  try {
    await activeRefreshPromise;
  } finally {
    activeRefreshPromise = null;
  }
}

async function loadFullDebug() {
  if (loadDebugButton) {
    loadDebugButton.disabled = true;
  }

  try {
    const data = await fetchJson(appConfig.debugEndpoint || "/api/devices/debug");
    renderDebugData(data);
  } catch (error) {
    renderDebugData({
      error: "debug_refresh_failed",
      message: errorMessageFrom(error),
      last_successful_checked: lastSuccessfulCheckedText,
      occurred_at: new Date().toISOString(),
    });
  } finally {
    if (loadDebugButton) {
      loadDebugButton.disabled = false;
    }
  }
}

if (refreshButton) {
  refreshButton.addEventListener("click", refreshStatus);
}
if (loadDebugButton) {
  loadDebugButton.addEventListener("click", loadFullDebug);
}

refreshStatus();
window.setInterval(refreshStatus, pollSeconds * 1000);

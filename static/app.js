const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

const state = {
  incidents: [],
  selectedId: null,
  search: "",
  chats: {},

  filters: {
      priority: "all",
      status: "all",
      source: "all"
  }
};
let severityChart = null;
let sourceChart = null;
const alertTemplates = {

  credential: {
      source: "Sysmon",
      external_id: "SYS-1001",
      severity: "critical",
      title: "Credential dumping attempt",
      description:
          "LSASS memory was accessed by mimikatz.exe. Potential credential theft detected."
  },

  ransomware: {
      source: "CrowdStrike Falcon",
      external_id: "CS-2001",
      severity: "critical",
      title: "Ransomware behavior detected",
      description:
          "Multiple files encrypted within seconds. Suspicious ransomware activity observed."
  },

  powershell: {
      source: "Sysmon",
      external_id: "SYS-3001",
      severity: "high",
      title: "Suspicious PowerShell execution",
      description:
          "Encoded PowerShell command executed with hidden window and bypass policy."
  },

  phishing: {
      source: "Microsoft Defender",
      external_id: "MD-4001",
      severity: "medium",
      title: "Phishing email detected",
      description:
          "Email containing malicious attachment blocked before delivery."
  },

  bruteforce: {
      source: "Microsoft Sentinel",
      external_id: "MS-5001",
      severity: "medium",
      title: "Multiple failed login attempts",
      description:
          "Repeated authentication failures detected from a single IP address."
  },

  travel: {
      source: "Microsoft Sentinel",
      external_id: "MS-6001",
      severity: "high",
      title: "Impossible travel detected",
      description:
          "User authenticated from India and Germany within 20 minutes."
  }

};

const escapeText = (value) => String(value ?? "");
const escapeHtml = (str) => {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `Request failed (${response.status})`);
  }
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json") ? response.json() : response;
}

function setFeedback(selector, message, isError = false) {
  const element = $(selector);
  element.textContent = message;
  element.className = `feedback ${message ? (isError ? "error" : "success") : ""}`;
}
function showToast(message, type = "info") {

  const container = $("#toast-container");

  const toast = document.createElement("div");

  toast.className = `toast ${type}`;

  toast.textContent = message;

  container.appendChild(toast);

  setTimeout(() => {

      toast.style.opacity = "0";
      toast.style.transform = "translateX(40px)";

      setTimeout(() => {
          toast.remove();
      }, 300);

  }, 3000);

}
function priorityClass(priority) { return `priority-${priority}`; }
function statusLabel(value) { return value.replace(/\b\w/g, (char) => char.toUpperCase()); }

function updateStats() {
  const incidents = state.incidents;
  const averageRisk = incidents.length
    ? Math.round(
        incidents.reduce(
            (sum, incident) => sum + incident.assessment.risk_score,
            0
        ) / incidents.length
    )
    : 0;
  $("#stat-total").textContent = incidents.length;
  $("#stat-critical").textContent = incidents.filter((item) => item.assessment.priority === "critical").length;
  $("#stat-high").textContent = incidents.filter((item) => item.assessment.priority === "high").length;
  $("#stat-active").textContent = incidents.filter((item) => ["triaged", "investigating", "contained"].includes(item.status)).length;
  $("#stat-average-risk").textContent = `${averageRisk}/100`;
}

function renderQueue() {
  const root = $("#incidents-list");
  root.textContent = "";
  const filtered = state.incidents.filter((incident) => {

    const q = state.search.toLowerCase().trim();

    const matchesSearch =
      !q ||
      incident.alert.title.toLowerCase().includes(q) ||
      incident.alert.source.toLowerCase().includes(q) ||
      (incident.alert.external_id && incident.alert.external_id.toLowerCase().includes(q)) ||
      (incident.alert.description && incident.alert.description.toLowerCase().includes(q)) ||
      incident.assessment.priority.toLowerCase().includes(q) ||
      (incident.assessment.summary && incident.assessment.summary.toLowerCase().includes(q)) ||
      (incident.assessment.mitre_techniques && incident.assessment.mitre_techniques.some(t => 
        (t.technique_id && t.technique_id.toLowerCase().includes(q)) ||
        (t.name && t.name.toLowerCase().includes(q)) ||
        (t.tactic && t.tactic.toLowerCase().includes(q))
      )) ||
      (incident.assessment.extracted_indicators && incident.assessment.extracted_indicators.some(ind =>
        ind.value && ind.value.toLowerCase().includes(q)
      ));

    const matchesPriority =
      state.filters.priority === "all" ||
      incident.assessment.priority === state.filters.priority;

    const matchesStatus =
      state.filters.status === "all" ||
      incident.status === state.filters.status;

    const matchesSource =
      state.filters.source === "all" ||
      incident.alert.source === state.filters.source;

    return matchesSearch && matchesPriority && matchesStatus && matchesSource;
  });
  
  const qCount = $("#queue-count"); if (qCount) qCount.textContent = `${filtered.length}`;
  $("#empty-state").classList.toggle("hidden", filtered.length > 0);
  
  filtered.forEach((incident) => {
    const button = document.createElement("button");
    button.className = `  
incident-row
priority-${incident.assessment.priority}
${state.selectedId === incident.id ? "selected" : ""}
`;
    button.type = "button";
    button.innerHTML = `
<div class="incident-row-top" style="display:flex; justify-content:space-between; align-items:center;">
    <div style="display:flex; gap:6px; align-items:center;">
        <span class="priority-pill ${priorityClass(incident.assessment.priority)}">
            ${escapeText(incident.assessment.priority)}
        </span>
        <span class="status-pill">
            ${escapeText(incident.status)}
        </span>
    </div>
    <button class="delete-single-btn button secondary danger" type="button" style="padding:2px 7px; font-size:11px; margin:0;" title="Delete this single alert">
        🗑
    </button>
</div>

<h3 class="incident-title"></h3>

<div class="incident-meta">

    <div class="meta-row">
        <span class="meta-label">📍 Source</span>
        <span class="meta-value source"></span>
    </div>

    <div class="meta-row">
    <span class="meta-label">🎯 Risk</span>
</div>

<div class="risk-bar">
    <div class="risk-fill"></div>
</div>

<div class="risk-score"></div>

    <div class="meta-row">
        <span class="meta-label">🛡 MITRE</span>
        <span class="meta-value mitre"></span>
    </div>

</div>
`;
button.querySelector(".incident-title").textContent =
incident.alert.title;

button.querySelector(".source").textContent =
incident.alert.source;

const score = incident.assessment.risk_score;

button.querySelector(".risk-score").textContent =
    `${score}/100`;

const fill = button.querySelector(".risk-fill");
fill.style.width = `${score}%`;

if (score >= 80) {
    fill.classList.add("critical");
}
else if (score >= 60) {
    fill.classList.add("high");
}
else {
    fill.classList.add("medium");
}

const firstTechnique = incident.assessment.mitre_techniques?.[0];

button.querySelector(".mitre").textContent =
    firstTechnique
        ? firstTechnique.technique_id
        : "Unknown";

    const singleDelBtn = button.querySelector(".delete-single-btn");
    if (singleDelBtn) {
      singleDelBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (confirm(`Delete incident '${incident.alert.title}' (${incident.alert.external_id})?`)) {
          try {
            await api(`/api/incidents/${incident.id}`, { method: "DELETE" });
            showToast(`Incident ${incident.alert.external_id} deleted`, "info");
            if (state.selectedId === incident.id) {
              state.selectedId = null;
            }
            await refreshIncidents();
          } catch (err) {
            showToast(err.message, "error");
          }
        }
      });
    }

    button.addEventListener("click", () => selectIncident(incident.id));
    root.append(button);
  });
  updateStats();
}

const deleteCurrentBtn = $("#delete-current-incident");
if (deleteCurrentBtn) {
  deleteCurrentBtn.addEventListener("click", async () => {
    if (!state.selectedId) return;
    const inc = state.incidents.find((i) => i.id === state.selectedId);
    const title = inc ? inc.alert.title : "this incident";
    if (confirm(`Are you sure you want to delete '${title}' from the database?`)) {
      try {
        await api(`/api/incidents/${state.selectedId}`, { method: "DELETE" });
        showToast("Incident deleted from database", "info");
        state.selectedId = null;
        await refreshIncidents();
      } catch (err) {
        showToast(err.message, "error");
      }
    }
  });
}

function chip(technique) {
  const node = document.createElement("div");
  node.className = "chip";
  const strong = document.createElement("b"); strong.textContent = technique.technique_id;
  node.append(strong, ` · ${technique.name}`);
  node.title = technique.reason;
  return node;
}

function indicatorCard(item) {
  const node = document.createElement("div");
  node.className = "indicator";
  node.innerHTML = `
    <div class="indicator-header" style="display:flex; justify-content:space-between; align-items:center;">
      <div style="display:flex; gap:8px; align-items:center;">
        <span class="indicator-type">${escapeText(item.indicator_type)}</span>
        <span style="font-size:11px; color:var(--muted);">${escapeText(item.provider || '')}</span>
      </div>
      <button class="button secondary copy-ioc-btn" data-ioc="${escapeText(item.value)}" style="padding:2px 8px; font-size:10px; height:24px; min-height:0; border-radius:4px;" title="Copy IOC">
        📋 Copy
      </button>
    </div>
    <code style="display:block; margin-top:4px; font-family:var(--font-mono); font-weight:500;">${escapeText(item.value)}</code>
    <p style="margin:4px 0 0 0; color:var(--muted); font-size:11px;"><strong>${escapeText(item.classification)}:</strong> ${escapeText(item.summary)}</p>
  `;

  const copyBtn = node.querySelector(".copy-ioc-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const val = copyBtn.dataset.ioc;
      if (val) {
        await navigator.clipboard.writeText(val);
        showToast(`Copied ${val} to clipboard`, "info");
        copyBtn.textContent = "✅ Copied!";
        setTimeout(() => { copyBtn.textContent = "📋 Copy"; }, 1500);
      }
    });
  }

  return node;
}

function renderDetail(incident) {
  const emptyElem = $("#detail-empty");
  if (emptyElem) emptyElem.classList.toggle("hidden", Boolean(incident));

  const detailElem = $("#incident-detail");
  if (detailElem) detailElem.classList.toggle("hidden", !incident);

  if (!incident) return;
  const assessment = incident.assessment;
  $("#detail-source").textContent = `${incident.alert.source} · ${incident.alert.external_id}`;
  $("#detail-status").textContent = statusLabel(incident.status);
  $("#detail-title").textContent = incident.alert.title;
  $("#detail-description").textContent = incident.alert.description;
  $("#detail-score").textContent = `${assessment.risk_score}/100`;
  $("#detail-confidence").textContent = `${assessment.confidence}%`;
  $("#detail-summary").textContent = assessment.summary;
  $("#status-select").value = incident.status;
  const pdfBtn = $("#download-pdf"); if (pdfBtn) pdfBtn.href = `/api/incidents/${incident.id}/report?format=pdf`;
  const mdBtn = $("#download-markdown"); if (mdBtn) mdBtn.href = `/api/incidents/${incident.id}/report?format=markdown`;
  const stixBtn = $("#download-stix"); if (stixBtn) stixBtn.href = `/api/incidents/${incident.id}/stix`;

  const soarContainer = $("#soar-container");
  if (soarContainer) soarContainer.classList.add("hidden");
  state.soarPlaybook = null;
  const mitre = $("#mitre-list"); mitre.textContent = "";
  if (assessment.mitre_techniques.length) assessment.mitre_techniques.forEach((item) => mitre.append(chip(item)));
  else mitre.textContent = "No automated mapping; inspect the alert context.";
  const iocs = $("#indicator-list"); iocs.textContent = "";
  if (assessment.enrichment.length) assessment.enrichment.forEach((item) => iocs.append(indicatorCard(item)));
  else iocs.textContent = "No indicators extracted.";
  const actions = $("#action-list"); actions.textContent = "";
  assessment.recommended_actions.forEach((item) => { const li = document.createElement("li"); li.textContent = item; actions.append(li); });
  const chat = $("#copilot-chat");

chat.innerHTML = "";

$("#copilot-question").value = "";

const history = state.chats[incident.id] || [];

history.forEach(message => {

    const block = document.createElement("div");

    block.className = "chat-message";

    if (message.role === "user") {

        block.innerHTML = `
        <div class="chat-label">👤 You</div>
        <div class="user-message">
            ${message.text}
        </div>
        `;

    } else {
        block.innerHTML = `
        <div class="chat-label" style="display:flex; justify-content:space-between; align-items:center;">
            <span>🤖 IR Copilot</span>
            <button class="copy-msg-btn button secondary" style="padding:3px 10px; font-size:11px; margin:0;" title="Copy this analyst note">
              📋 Copy Analyst Note
            </button>
        </div>
        <div class="ai-message completed">
            ${marked.parse(message.text)}
        </div>
        `;

        const msgCopyBtn = block.querySelector(".copy-msg-btn");
        const aiMessage = block.querySelector(".ai-message");
        if (msgCopyBtn && aiMessage) {
          msgCopyBtn.addEventListener("click", async () => {
            const text = aiMessage.innerText || aiMessage.textContent;
            await navigator.clipboard.writeText(text);
            showToast("Analyst note copied to clipboard", "info");
            msgCopyBtn.textContent = "✅ Copied!";
            setTimeout(() => {
              msgCopyBtn.textContent = "📋 Copy Analyst Note";
            }, 1800);
          });
        }
    }

    chat.appendChild(block);
});
  const timeline = $("#incident-timeline");
  timeline.innerHTML = "";

  if (incident.audit_logs && incident.audit_logs.length) {
    incident.audit_logs.forEach(event => {
      const item = document.createElement("div");
      item.className = "timeline-item";
      const dt = new Date(event.timestamp);
      const timeStr = dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      item.innerHTML = `
        <div class="timeline-dot"></div>
        <div class="timeline-content">
          <strong><span class="timeline-badge ${event.event_type}">${event.event_type.replace('_', ' ')}</span> ${escapeText(event.summary)} <span class="timeline-time">${timeStr}</span></strong>
          <p>${escapeText(event.details)}</p>
        </div>
      `;
      timeline.appendChild(item);
    });
  } else {
    timeline.innerHTML = `
      <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-content">
          <strong>Alert Received</strong>
          <p>${escapeText(incident.alert.source)} detected "${escapeText(incident.alert.title)}"</p>
        </div>
      </div>
    `;
  }

  const notesInput = $("#analyst-notes-input");
  if (notesInput) {
    notesInput.value = incident.analyst_notes || "";
  }
  const statusSpan = $("#notes-save-status");
  if (statusSpan) {
    statusSpan.textContent = "";
  }

  const currentActions = incident.actions || [];
  document.querySelectorAll(".incident-actions input").forEach(box => {
    box.checked = currentActions.includes(box.value);
  });

  $("#copy-note").classList.add("hidden");
  const containmentContainer = $("#containment-tasks-list");
  if (containmentContainer) {
    containmentContainer.innerHTML = `<p style="color:#7a8c9e; font-size:13px; margin:4px 0;">Click below to generate AI containment tasks for this case.</p>`;
  }
}


async function refreshIncidents(selectNewest = false) {
  state.incidents = await api("/api/incidents");
  const sourceFilter = $("#filter-source");

sourceFilter.innerHTML =
`
<option value="all">All Sources</option>
`;

const sources = [
    ...new Set(
        state.incidents.map(
            incident => incident.alert.source
        )
    )
];

sources.sort();

sources.forEach(source => {

    const option = document.createElement("option");

    option.value = source;
    option.textContent = source;

    sourceFilter.appendChild(option);

});
  if (selectNewest && state.incidents.length) state.selectedId = state.incidents[0].id;
  if (state.selectedId && !state.incidents.some((item) => item.id === state.selectedId)) state.selectedId = null;
  renderQueue();
  updateFilterLabel();
renderCharts();

if (state.selectedId) {

  const selected = state.incidents.find(
      item => item.id === state.selectedId
  );

  renderDetail(selected || null);

} else {

  renderDetail(null);

}
}

async function selectIncident(id) {
  state.selectedId = id;
  renderQueue();
  updateFilterLabel();
  renderDetail(state.incidents.find((item) => item.id === id));
}

async function loadDemo() {
  const button = $("#load-demo-btn") || $("#load-demo");
  if (button) { button.disabled = true; button.textContent = "Loading…"; }
  try { await api("/api/demo/load", { method: "POST" }); await refreshIncidents(true); }
  catch (error) { showToast(error.message, "error"); }
  finally { if (button) { button.disabled = false; button.textContent = "⚡ Load 5 Sample SIEM Alerts"; } }
}

function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter(line => line.trim().length > 0);
  if (lines.length < 2) return null;

  const parseCSVLine = (line) => {
    const result = [];
    let cur = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"' || c === "'") {
        inQuotes = !inQuotes;
      } else if (c === ',' && !inQuotes) {
        result.push(cur.trim().replace(/^["']|["']$/g, ''));
        cur = "";
      } else {
        cur += c;
      }
    }
    result.push(cur.trim().replace(/^["']|["']$/g, ''));
    return result;
  };

  const headers = parseCSVLine(lines[0]).map(h => h.toLowerCase());
  const findCol = (possibleNames) => headers.findIndex(h => possibleNames.some(p => h.includes(p)));
  
  const titleIdx = findCol(["title", "alert", "name", "signature", "event", "rule"]);
  const descIdx = findCol(["description", "desc", "message", "msg", "details", "raw", "summary"]);
  const srcIdx = findCol(["source", "provider", "vendor", "logsource", "tool"]);
  const sevIdx = findCol(["severity", "level", "priority", "risk"]);
  const idIdx = findCol(["id", "external_id", "alert_id", "event_id"]);

  const items = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCSVLine(lines[i]);
    if (cols.length < headers.length * 0.4) continue;

    const title = titleIdx !== -1 && cols[titleIdx] ? cols[titleIdx] : `CSV Alert Row #${i}`;
    const desc = descIdx !== -1 && cols[descIdx] ? cols[descIdx] : cols.join(" | ");
    const src = srcIdx !== -1 && cols[srcIdx] ? cols[srcIdx] : "CSV Log Export";
    let sev = sevIdx !== -1 && cols[sevIdx] ? cols[sevIdx].toLowerCase() : "medium";
    if (!["low", "medium", "high", "critical"].includes(sev)) {
      if (sev.includes("crit") || sev.includes("fatal") || sev.includes("4") || sev.includes("5")) sev = "critical";
      else if (sev.includes("high") || sev.includes("3") || sev.includes("warn")) sev = "high";
      else if (sev.includes("low") || sev.includes("1") || sev.includes("info")) sev = "low";
      else sev = "medium";
    }
    const extId = idIdx !== -1 && cols[idIdx] ? cols[idIdx] : `csv-${i}-${Date.now()}`;

    items.push({ title, description: desc, source: src, severity: sev, external_id: extId });
  }
  return items.length ? items : null;
}

function parseRawLogs(text) {
  const lines = text.split(/\r?\n/).filter(line => line.trim().length > 0);
  if (!lines.length) return null;

  const items = [];
  lines.forEach((line, idx) => {
    let title = "Security Log Event";
    let sev = "medium";
    let src = "Raw Log Feed";

    const lower = line.toLowerCase();
    if (lower.includes("failed") || lower.includes("unauthorized") || lower.includes("denied") || lower.includes("attack")) {
      sev = "high";
      title = "Unauthorized Security Event";
    }
    if (lower.includes("critical") || lower.includes("malware") || lower.includes("exploit") || lower.includes("ransomware")) {
      sev = "critical";
      title = "Critical Security Alert";
    }
    if (lower.includes("ssh") || lower.includes("login") || lower.includes("auth")) {
      title = "Authentication / Sign-in Event";
    } else if (lower.includes("firewall") || lower.includes("blocked") || lower.includes("drop")) {
      title = "Firewall / Perimeter Block";
    } else if (lower.includes("powershell") || lower.includes("cmd") || lower.includes("exec")) {
      title = "Process Execution Event";
    }

    items.push({
      title: `${title} #${idx + 1}`,
      description: line,
      source: src,
      severity: sev,
      external_id: `log-${idx + 1}-${Date.now()}`
    });
  });

  return items.length ? items : null;
}

function parseUniversalAlertPayload(rawText, fileName = "") {
  let text = rawText.trim();
  if (!text) throw new Error("File content is empty.");

  const ext = fileName ? fileName.split(".").pop().toLowerCase() : "";

  // 1. Try JSON / JSONL first if format looks like JSON or extension is .json / .jsonl
  if (ext === "json" || ext === "jsonl" || text.startsWith("{") || text.startsWith("[")) {
    try {
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch (e) {
        const jsonlLines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        const items = [];
        for (const l of jsonlLines) {
          try { items.push(JSON.parse(l)); } catch (err) {}
        }
        if (items.length) parsed = items;
      }
      if (parsed) {
        if (!Array.isArray(parsed) && typeof parsed === "object") {
          const listKey = ["alerts", "records", "data", "events", "items", "results"].find(k => Array.isArray(parsed[k]));
          parsed = listKey ? parsed[listKey] : [parsed];
        }
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (e) {}
  }

  // 2. Try CSV if extension is .csv or content contains headers/commas
  if (ext === "csv" || text.includes(",")) {
    const csvParsed = parseCSV(text);
    if (csvParsed && csvParsed.length) return csvParsed;
  }

  // 3. Fallback to Raw Log / TXT parsing
  const logParsed = parseRawLogs(text);
  if (logParsed && logParsed.length) return logParsed;

  throw new Error("Could not parse file into security alerts. Supported formats: JSON, JSONL, CSV, TXT, LOG.");
}

async function importAlerts() {
  const text = $("#json-input").value.trim();
  if (!text) {
    return setFeedback(
        "#import-message",
        "Please select a valid JSON alert file or paste JSON data before analyzing.",
        true
    );
  }
  try {
    const payload = parseAlertPayload(text);
    setFeedback("#import-message", `Analyzing ${payload.length} alert(s)...`);
    await api("/api/alerts/bulk", { method: "POST", body: JSON.stringify(payload) });
    setFeedback("#import-message", `Successfully analyzed and ingested ${payload.length} alert(s).`);
    await refreshIncidents(true);
    showToast(`${payload.length} Security alert(s) ingested successfully!`, "success");
  } catch (error) {
    setFeedback("#import-message", `Ingestion Error: ${error.message}`, true);
    showToast(`Ingestion Error: ${error.message}`, "error");
  }
}

async function submitManual(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  try {
    const incident = await api("/api/alerts", { method: "POST", body: JSON.stringify(payload) });
    setFeedback("#form-message", "Alert analyzed and added to the queue.");
    state.selectedId = incident.id;
    await refreshIncidents();
    showToast("Test alert created successfully", "success");
  } catch (error) { setFeedback("#form-message", error.message, true); }
}
function loadTemplate(name) {

  const template = alertTemplates[name];

  if (!template) return;

  document.querySelector('[name="source"]').value =
      template.source;

  document.querySelector('[name="external_id"]').value =
      template.external_id;

  document.querySelector('[name="severity"]').value =
      template.severity;

  document.querySelector('[name="title"]').value =
      template.title;

  document.querySelector('[name="description"]').value =
      template.description;

      showToast(`${template.title} loaded`, "success");
      setFeedback("#form-message", "");

}

async function updateStatus() {
  if (!state.selectedId) return;
  try {
    const incident = await api(`/api/incidents/${state.selectedId}`, { method: "PATCH", body: JSON.stringify({ status: $("#status-select").value }) });
    const index = state.incidents.findIndex((item) => item.id === incident.id);
    state.incidents[index] = incident;
    renderQueue(); updateFilterLabel(); renderDetail(incident); showToast("Incident status updated", "success");
  } catch (error) { showToast(error.message, "error"); }
}
async function clearIncidents() {

  const confirmed = confirm(
      "Delete ALL uploaded incidents?\n\nThis cannot be undone."
  );

  if (!confirmed) return;

  try {

      await api("/api/incidents", {
          method: "DELETE"
      });

      state.incidents = [];
      state.selectedId = null;
      state.chats = {};

      renderQueue();
      renderDetail(null);
      renderCharts();

  }
  catch (error) {
  }
}

async function typeWriter(element, text, speed = 10) {
  const words = text.split(" ");
  let current = "";
  element.innerHTML = "";

  for (let i = 0; i < words.length; i++) {
    current += words[i] + " ";
    const parsed = marked.parse(current)
      .replace(/<h2>Assessment<\/h2>/g, "<h2>📋 Assessment</h2>")
      .replace(/<h2>Evidence<\/h2>/g, "<h2>🔍 Evidence</h2>")
      .replace(/<h2>Investigation Steps<\/h2>/g, "<h2>🧭 Investigation Steps</h2>")
      .replace(/<h2>Escalation Note<\/h2>/g, "<h2>⚠️ Escalation Note</h2>");

    element.innerHTML = parsed + '<span id="active-ai-cursor" class="ai-cursor"></span>';

    if (i % 2 === 0) {
      const cursor = document.getElementById("active-ai-cursor");
      if (cursor) {
        cursor.scrollIntoView({ behavior: "smooth", block: "nearest" });
      } else {
        element.scrollIntoView({ behavior: "smooth", block: "end" });
      }
    }

    await new Promise(resolve => setTimeout(resolve, speed));
  }

  const finalParsed = marked.parse(current)
    .replace(/<h2>Assessment<\/h2>/g, "<h2>📋 Assessment</h2>")
    .replace(/<h2>Evidence<\/h2>/g, "<h2>🔍 Evidence</h2>")
    .replace(/<h2>Investigation Steps<\/h2>/g, "<h2>🧭 Investigation Steps</h2>")
    .replace(/<h2>Escalation Note<\/h2>/g, "<h2>⚠️ Escalation Note</h2>");
    
  element.innerHTML = finalParsed;
  element.scrollIntoView({ behavior: "smooth", block: "end" });
}

async function askCopilot() {
  if (!state.selectedId) return;
  const button = $("#ask-copilot");
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span> Generating Analyst Note...`;

  const questionText = $("#copilot-question").value || "Generate initial assessment report";

  try {
    const chat = $("#copilot-chat");

    const userBlock = document.createElement("div");
    userBlock.className = "chat-message action-pop-in";
    userBlock.innerHTML = `
      <div class="chat-label">👤 You</div>
      <div class="user-message">${escapeHtml(questionText)}</div>
    `;
    chat.appendChild(userBlock);

    const aiBlock = document.createElement("div");
    aiBlock.className = "chat-message action-pop-in";
    aiBlock.innerHTML = `
      <div class="chat-label" style="display:flex; justify-content:space-between; align-items:center;">
        <span>🤖 IR Copilot</span>
        <button class="copy-msg-btn button secondary" style="padding:3px 10px; font-size:11px; margin:0;" title="Copy this analyst note">
          📋 Copy Analyst Note
        </button>
      </div>
      <div class="ai-message generating">
        <div class="ai-thinking-radar">
          <div class="radar-pulse-box">
            <div class="radar-dot"></div>
            <div class="radar-wave"></div>
          </div>
          <span class="thinking-label">⚡ Gemini Copilot analyzing threat telemetry &amp; generating response...</span>
        </div>
      </div>
    `;
    chat.appendChild(aiBlock);

    const aiMessage = aiBlock.querySelector(".ai-message");
    const msgCopyBtn = aiBlock.querySelector(".copy-msg-btn");
    if (msgCopyBtn) {
      msgCopyBtn.addEventListener("click", async () => {
        const text = aiMessage.innerText || aiMessage.textContent;
        await navigator.clipboard.writeText(text);
        showToast("Analyst note copied to clipboard", "info");
        msgCopyBtn.textContent = "✅ Copied!";
        setTimeout(() => {
          msgCopyBtn.textContent = "📋 Copy Analyst Note";
        }, 1800);
      });
    }

    aiBlock.scrollIntoView({ behavior: "smooth", block: "nearest" });

    const answer = await api(`/api/incidents/${state.selectedId}/copilot`, {
      method: "POST",
      body: JSON.stringify({ question: questionText })
    });

    $("#copilot-provider").textContent = answer.provider;

    await new Promise(resolve => setTimeout(resolve, 400));

    await typeWriter(aiMessage, answer.answer, 10);

    aiMessage.classList.remove("generating");
    aiMessage.classList.add("completed");

    $("#copilot-question").value = "";
    showToast("Analyst note generated", "success");

    if (!state.chats[state.selectedId]) {
      state.chats[state.selectedId] = [];
    }
    state.chats[state.selectedId].push({ role: "user", text: questionText });
    state.chats[state.selectedId].push({ role: "assistant", text: answer.answer });

  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
    button.innerHTML = "✨ Ask Copilot";
  }
}

const copilotQInput = $("#copilot-question");
if (copilotQInput) {
  copilotQInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      askCopilot();
    }
  });
}

async function saveActions() {

  if (!state.selectedId) return;

  const actions = [];

  document
      .querySelectorAll(".incident-actions input:checked")
      .forEach(box => actions.push(box.value));

  try {

      const incident = await api(
          `/api/incidents/${state.selectedId}/actions`,
          {
              method: "PATCH",

              body: JSON.stringify({
                  actions
              })
          }
      );

      const index =
          state.incidents.findIndex(
              i => i.id === incident.id
          );

      state.incidents[index] = incident;

      showToast(
          "Incident actions saved",
          "success"
      );

  }
  catch(error){

      showToast(error.message, "error");

  }

}

const submitJsonBtn = $("#submit-json");
if (submitJsonBtn) {
  submitJsonBtn.addEventListener("click", importAlerts);
}

const refreshBtn = $("#refresh");
if (refreshBtn) {
  refreshBtn.addEventListener("click", async () => {
    refreshBtn.disabled = true;
    refreshBtn.textContent = "⟳";
    state.selectedId = null;
    await refreshIncidents();
    showToast("Dashboard refreshed", "success");
    refreshBtn.disabled = false;
    refreshBtn.textContent = "↻";
  });
}

const alertForm = $("#alert-form");
if (alertForm) {
  alertForm.addEventListener("submit", submitManual);
}

const statusSelect = $("#status-select");
if (statusSelect) {
  statusSelect.addEventListener("change", updateStatus);
}

const askCopilotBtn = $("#ask-copilot");
if (askCopilotBtn) {
  askCopilotBtn.addEventListener("click", askCopilot);
}
async function processFileImport(file) {
  if (!file) return;
  const fileNameEl = $("#selected-file-name");
  if (fileNameEl) fileNameEl.textContent = file.name;
  const selectedFileEl = $("#selected-file");
  if (selectedFileEl) selectedFileEl.classList.remove("hidden");

  setFeedback("#import-message", `Reading ${file.name}...`);
  try {
    const text = await file.text();
    const payload = parseUniversalAlertPayload(text, file.name);
    payload.forEach((item) => {
      if (typeof item === "object" && item !== null) {
        item.source_file = file.name;
      }
    });
    setFeedback("#import-message", `Analyzing & ingesting ${payload.length} alert(s)...`);
    await api("/api/alerts/bulk", { method: "POST", body: JSON.stringify(payload) });
    setFeedback("#import-message", `Successfully ingested ${payload.length} alert(s) from ${file.name}.`);
    await refreshIncidents(true);
    showToast(`${payload.length} Security alert(s) ingested from ${file.name}!`, "success");
  } catch (error) {
    setFeedback("#import-message", `Ingestion Error: ${error.message}`, true);
    showToast(`Ingestion Error: ${error.message}`, "error");
  }
}

const browseBtn = $("#browse-file-btn");
const fileInput = $("#json-file");

if (browseBtn && fileInput) {
  browseBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.click();
  });
}

if (fileInput) {
  fileInput.addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (file) await processFileImport(file);
  });
}

const uploadBox = $("#upload-box");
if (uploadBox) {
  uploadBox.addEventListener("dragover", (event) => {
      event.preventDefault();
      uploadBox.classList.add("dragover");
  });

  uploadBox.addEventListener("dragleave", () => {
      uploadBox.classList.remove("dragover");
  });

  uploadBox.addEventListener("drop", async (event) => {
      event.preventDefault();
      uploadBox.classList.remove("dragover");

      const file = event.dataTransfer.files[0];
      if (file) await processFileImport(file);
  });
}
const searchInput = $("#search-incidents");
if (searchInput) {
  searchInput.addEventListener("input", (event) => {
    state.search = event.target.value;
    renderQueue();
    updateFilterLabel();
  });
}
const filterPriority = $("#filter-priority");
if (filterPriority) {
  filterPriority.addEventListener("change", (e) => {
    state.filters.priority = e.target.value;
    updateSevPillsUI(e.target.value);
    renderQueue();
    updateFilterLabel();
  });
}
const filterStatus = $("#filter-status");
if (filterStatus) {
  filterStatus.addEventListener("change", (e) => {
    state.filters.status = e.target.value;
    renderQueue();
    updateFilterLabel();
  });
}
const filterSource = $("#filter-source");
if (filterSource) {
  filterSource.addEventListener("change", (e) => {
    state.filters.source = e.target.value;
    renderQueue();
    updateFilterLabel();
  });
}
function updateFilterLabel() {

  const root = $("#active-filters");

  const labels = [];

  if (state.filters.priority !== "all")
      labels.push(`Priority: ${state.filters.priority}`);

  if (state.filters.status !== "all")
      labels.push(`Status: ${state.filters.status}`);

  if (state.filters.source !== "all")
      labels.push(`Source: ${state.filters.source}`);

  root.textContent =
      labels.length
          ? "Active Filters • " + labels.join(" | ")
          : "";

}
function renderCharts() {

  const incidents = state.incidents;

  // ------------------------
  // Severity Pie Chart
  // ------------------------

  const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
  };

  incidents.forEach(i => {
      severityCounts[i.assessment.priority]++;
  });

  if (severityChart) {
      severityChart.destroy();
  }

  severityChart = new Chart(
      document.getElementById("severity-chart"),
      {
          type: "doughnut",

          data: {
              labels: ["Critical", "High", "Medium", "Low"],

              datasets: [{
                  data: [
                      severityCounts.critical,
                      severityCounts.high,
                      severityCounts.medium,
                      severityCounts.low
                  ],

                  backgroundColor: [
                      "#ff5252",
                      "#ffb300",
                      "#29b6f6",
                      "#66bb6a"
                  ],
                  borderColor: "#0b1d28",
                  borderWidth: 3,
                  hoverOffset: 8
              }]
          },

          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
        
            onClick(event, elements) {
                if (!elements.length) return;
                const index = elements[0].index;
                const severities = ["critical", "high", "medium", "low"];
                const clicked = severities[index];
        
                if (state.filters.priority === clicked)
                  state.filters.priority = "all";
                else
                  state.filters.priority = clicked;

                $("#filter-priority").value = state.filters.priority;
                renderQueue();
                updateFilterLabel();
            },
        
            plugins: {
                legend: {
                    position: "right",
                    labels: {
                        color: "#e2eaf0",
                        font: { size: 12, weight: "600" },
                        padding: 16,
                        usePointStyle: true,
                        pointStyle: "circle"
                    }
                }
            }
        }
      }
  );

  // ------------------------
  // Source Bar Chart
  // ------------------------

  const sources = {};
  incidents.forEach(i => {
      const source = i.alert.source;
      sources[source] = (sources[source] || 0) + 1;
  });

  if (sourceChart) {
      sourceChart.destroy();
  }

  sourceChart = new Chart(
      document.getElementById("source-chart"),
      {
          type: "bar",

          data: {
              labels: Object.keys(sources),

              datasets: [{
                  label: "Alerts Ingested",
                  data: Object.values(sources),
                  backgroundColor: [
                      "#39d4c2",
                      "#4ea8de",
                      "#ffb703",
                      "#9d4edd",
                      "#ff7272",
                      "#48cae4"
                  ],
                  hoverBackgroundColor: [
                      "#5ce1e6",
                      "#68bbf0",
                      "#ffc93c",
                      "#b366ff",
                      "#ff8888",
                      "#64dfdf"
                  ],
                  borderRadius: { topRight: 8, bottomRight: 8, topLeft: 0, bottomLeft: 0 },
                  borderSkipped: false,
                  barPercentage: 0.65
              }]
          },

          options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
        
            onClick(event, elements) {
                if (!elements.length) return;
                const source = Object.keys(sources)[elements[0].index];
        
                if (state.filters.source === source)
                    state.filters.source = "all";
                else
                    state.filters.source = source;
                
                $("#filter-source").value = state.filters.source;
                renderQueue();
                updateFilterLabel();
            },
        
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: {
                        color: "#8fdcff",
                        font: { size: 11, weight: "600" },
                        stepSize: 1,
                        precision: 0
                    }
                },
                y: {
                    grid: { display: false },
                    ticks: {
                        color: "#e2eaf0",
                        font: { size: 12, weight: "700" }
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#091924",
                    titleColor: "#ffffff",
                    bodyColor: "#39d4c2",
                    borderColor: "#315066",
                    borderWidth: 1,
                    padding: 12,
                    displayColors: false,
                    callbacks: {
                        label: function(context) {
                            return ` Alerts: ${context.parsed.x}`;
                        }
                    }
                }
            }
        }
      }
  );

}
function clearManualForm() {

  document.querySelector('[name="source"]').value =
      "Demo SIEM";

  document.querySelector('[name="external_id"]').value =
      "manual-001";

  document.querySelector('[name="severity"]').value =
      "medium";

  document.querySelector('[name="title"]').value = "";

  document.querySelector('[name="description"]').value = "";

  setFeedback("#form-message", "");

  showToast("Manual form cleared", "info");

}
document.querySelectorAll(".quick-action").forEach(button => {

  button.addEventListener("click", () => {

      $("#copilot-question").value = button.dataset.prompt;

      askCopilot();

  });

});
document.querySelectorAll(".template-btn").forEach(button => {

  button.addEventListener("click", () => {

      loadTemplate(
          button.dataset.template
      );

  });

});
refreshIncidents().catch((error) => showToast(
  `Could not load incidents: ${error.message}`,
  "error"
));
const copyNoteBtn = $("#copy-note");
if (copyNoteBtn) {
  copyNoteBtn.addEventListener("click", async () => {
    const el = $("#copilot-answer") || $(".ai-message");
    if (!el) return;
    const text = el.innerText || el.textContent;
    await navigator.clipboard.writeText(text);
    showToast("Analyst note copied", "info");
    copyNoteBtn.textContent = "✅ Copied!";
    setTimeout(() => {
      copyNoteBtn.textContent = "📋 Copy Analyst Note";
    }, 1500);
  });
}

const toggleFilterBtn = $("#toggle-filter-drawer");
const filterDrawer = $("#filter-drawer");

if (toggleFilterBtn && filterDrawer) {
  toggleFilterBtn.addEventListener("click", () => {
    filterDrawer.classList.toggle("hidden");
    toggleFilterBtn.classList.toggle("active");
  });
}

function updateFilterLabel() {
  const isFiltered = Boolean(state.search) || state.filters.priority !== "all" || state.filters.status !== "all" || state.filters.source !== "all";
  const clearBtn = $("#clear-filters");
  if (clearBtn) {
    clearBtn.classList.toggle("hidden", !isFiltered);
  }
  if (toggleFilterBtn) {
    if (isFiltered) {
      toggleFilterBtn.style.borderColor = "#39d4c2";
      toggleFilterBtn.style.color = "#39d4c2";
      toggleFilterBtn.textContent = "🎛️ Filters (Active)";
    } else {
      toggleFilterBtn.style.borderColor = "";
      toggleFilterBtn.style.color = "";
      toggleFilterBtn.textContent = "🎛️ Filters";
    }
  }
}

const clearIncidentsBtn = $("#clear-incidents");
if (clearIncidentsBtn) {
  clearIncidentsBtn.addEventListener("click", clearIncidents);
}

const clearFiltersBtn = $("#clear-filters");
if (clearFiltersBtn) {
  clearFiltersBtn.addEventListener("click", () => {
    state.search = "";
    state.filters.priority = "all";
    state.filters.status = "all";
    state.filters.source = "all";
    const sInput = $("#search-incidents"); if (sInput) sInput.value = "";
    const fPriority = $("#filter-priority"); if (fPriority) fPriority.value = "all";
    const fStatus = $("#filter-status"); if (fStatus) fStatus.value = "all";
    const fSource = $("#filter-source"); if (fSource) fSource.value = "all";
    renderQueue();
    updateFilterLabel();
  });
}

const clearManualBtn = $("#clear-manual");
if (clearManualBtn) {
  clearManualBtn.addEventListener("click", clearManualForm);
}
async function saveNotes() {
  if (!state.selectedId) return;
  const notes = $("#analyst-notes-input").value;
  const statusSpan = $("#notes-save-status");
  statusSpan.textContent = "Saving...";
  try {
    const incident = await api(`/api/incidents/${state.selectedId}/notes`, {
      method: "PUT",
      body: JSON.stringify({ notes }),
    });
    const index = state.incidents.findIndex((i) => i.id === incident.id);
    if (index !== -1) {
      state.incidents[index] = incident;
    }
    renderDetail(incident);
    showToast("Analyst notes saved", "success");
    statusSpan.textContent = "Saved";
    setTimeout(() => { statusSpan.textContent = ""; }, 2000);
  } catch (error) {
    statusSpan.textContent = "Error";
    showToast(error.message, "error");
  }
}

$("#save-actions").addEventListener(
  "click",
  async () => {
    await saveActions();
    const updated = state.incidents.find(i => i.id === state.selectedId);
    if (updated) renderDetail(updated);
  }
);
const saveNotesBtn = $("#save-notes-btn");
if (saveNotesBtn) {
  saveNotesBtn.addEventListener("click", saveNotes);
}

// ---------- Phase 4: AI Containment & Playbook ----------
async function loadContainmentPlan() {
  if (!state.selectedId) return;
  const btn = $("#generate-containment-btn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Generating AI Containment Tasks...";
  }

  try {
    const plan = await api(`/api/incidents/${state.selectedId}/containment-plan`);
    renderContainmentTasks(plan.tasks);
    showToast("AI Containment Playbook generated!", "success");
    const updated = await api(`/api/incidents/${state.selectedId}`);
    const idx = state.incidents.findIndex(i => i.id === updated.id);
    if (idx !== -1) state.incidents[idx] = updated;
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "⚡ Refresh AI Containment Tasks";
    }
  }
}

function renderContainmentTasks(tasks) {
  const container = $("#containment-tasks-list");
  if (!container) return;
  if (!tasks || !tasks.length) {
    container.innerHTML = `<p style="color:#7a8c9e; font-size:13px; margin:4px 0;">No containment tasks generated yet.</p>`;
    return;
  }

  container.innerHTML = tasks.map(task => `
    <div class="containment-task-card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <span class="badge priority-medium">${escapeHtml(task.category.toUpperCase())}</span>
        <span style="font-size:12px; color:#39d4c2;">Target: <strong>${escapeHtml(task.target)}</strong></span>
      </div>
      <div style="font-weight:700; font-size:13px; color:#ffffff; margin-bottom:4px;">${escapeHtml(task.action)}</div>
      <div style="font-size:12px; color:#9eb2bf; line-height:1.4;">${escapeHtml(task.reason)}</div>
    </div>
  `).join("");
}

const genContainmentBtn = $("#generate-containment-btn");
if (genContainmentBtn) {
  genContainmentBtn.addEventListener("click", loadContainmentPlan);
}

// ---------- Phase 3 & 5: View Navigation & MITRE Matrix ----------
const tabTriage = $("#tab-triage");
const tabThreatIntel = $("#tab-threat-intel");
const tabMitre = $("#tab-mitre");

const triageHero = $("#triage-hero");
const importArea = $("#import-area");
const statsSection = $(".stats");
const chartsSection = $(".charts");
const workspaceSection = $(".workspace");
const manualCard = $(".manual-card");

const threatIntelView = $("#threat-intel-view");
const mitreMatrixView = $("#mitre-matrix-view");

function switchView(view) {
  // Reset active tab buttons
  if (tabTriage) tabTriage.classList.remove("active");
  if (tabThreatIntel) tabThreatIntel.classList.remove("active");
  if (tabMitre) tabMitre.classList.remove("active");

  // Hide all main containers
  if (triageHero) triageHero.classList.add("hidden");
  if (importArea) importArea.classList.add("hidden");
  if (statsSection) statsSection.classList.add("hidden");
  if (chartsSection) chartsSection.classList.add("hidden");
  if (workspaceSection) workspaceSection.classList.add("hidden");
  if (manualCard) manualCard.classList.add("hidden");

  if (threatIntelView) threatIntelView.classList.add("hidden");
  if (mitreMatrixView) mitreMatrixView.classList.add("hidden");

  if (view === "threat-intel") {
    if (tabThreatIntel) tabThreatIntel.classList.add("active");
    if (threatIntelView) threatIntelView.classList.remove("hidden");
    loadThreatIntelSummary();
  } else if (view === "mitre-matrix") {
    if (tabMitre) tabMitre.classList.add("active");
    if (mitreMatrixView) mitreMatrixView.classList.remove("hidden");
    loadMitreMatrix();
  } else {
    if (tabTriage) tabTriage.classList.add("active");
    if (triageHero) triageHero.classList.remove("hidden");
    if (importArea) importArea.classList.remove("hidden");
    if (statsSection) statsSection.classList.remove("hidden");
    if (chartsSection) chartsSection.classList.remove("hidden");
    if (workspaceSection) workspaceSection.classList.remove("hidden");
    if (manualCard) manualCard.classList.remove("hidden");
  }
}

if (tabTriage) tabTriage.addEventListener("click", () => switchView("triage"));
if (tabThreatIntel) tabThreatIntel.addEventListener("click", () => switchView("threat-intel"));
if (tabMitre) tabMitre.addEventListener("click", () => switchView("mitre-matrix"));

async function loadMitreMatrix() {
  try {
    const data = await api("/api/analytics/mitre-matrix");
    const mappedEl = $("#mitre-total-mapped");
    const hitsEl = $("#mitre-total-hits");
    const activeEl = $("#mitre-active-tactics");

    if (mappedEl) mappedEl.textContent = data.total_techniques_mapped;
    if (hitsEl) hitsEl.textContent = data.total_technique_hits;
    const activeTactics = data.tactics.filter(t => t.total_hits > 0).length;
    if (activeEl) activeEl.textContent = activeTactics;

    const grid = $("#mitre-matrix-grid");
    if (!grid) return;

    if (!data.tactics || !data.tactics.length) {
      grid.innerHTML = `<p style="color:#7a8c9e;">No MITRE ATT&CK techniques mapped yet. Ingest an alert to view coverage.</p>`;
      return;
    }

    grid.innerHTML = data.tactics.map(tactic => {
      const techsHtml = tactic.techniques.length
        ? tactic.techniques.map(tech => `
            <div class="mitre-tech-card ${tech.hit_count > 0 ? 'has-hits' : ''}" onclick="filterByMitreTechnique('${escapeHtml(tech.technique_id)}')">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="mitre-tech-id">${escapeHtml(tech.technique_id)}</span>
                ${tech.hit_count > 0 ? `<span class="count-badge">${tech.hit_count} hits</span>` : ''}
              </div>
              <div class="mitre-tech-name">${escapeHtml(tech.name)}</div>
            </div>
          `).join("")
        : `<div style="font-size:12px; color:#5c7385; text-align:center; padding:12px 0;">No active hits</div>`;

      return `
        <div class="mitre-tactic-col">
          <div class="mitre-tactic-header">
            <h3>${escapeHtml(tactic.tactic_name)}</h3>
            <span class="badge priority-medium" style="font-size:10px;">${tactic.total_hits} hits</span>
          </div>
          <div class="mitre-tactic-body">
            ${techsHtml}
          </div>
        </div>
      `;
    }).join("");

  } catch (error) {
    showToast(`MITRE Matrix error: ${error.message}`, "error");
  }
}

function filterByMitreTechnique(techId) {
  switchView("triage");
  state.search = techId;
  const sInput = $("#search-incidents");
  if (sInput) sInput.value = techId;
  renderQueue();
  updateFilterLabel();
  showToast(`Filtered incidents by MITRE technique: ${techId}`, "info");
}

async function loadThreatIntelSummary() {
  try {
    const summary = await api("/api/threat-intel/summary");
    $("#ti-total-iocs").textContent = summary.total_iocs;
    $("#ti-malicious-iocs").textContent = summary.malicious_iocs;
    $("#ti-suspicious-iocs").textContent = summary.suspicious_iocs;
    $("#ti-clean-iocs").textContent = summary.clean_iocs;

    // Render top lists
    const renderList = (elId, items) => {
      const container = $(elId);
      if (!items || !items.length) {
        container.innerHTML = `<li class="ti-list-item"><span>No data observed</span></li>`;
        return;
      }
      container.innerHTML = items
        .map(
          (item) => `
        <li class="ti-list-item" style="cursor:pointer;" onclick="triggerTISearch('${escapeHtml(item.value)}')">
          <span title="${escapeHtml(item.value)}">${escapeHtml(item.value.length > 25 ? item.value.substring(0, 22) + "..." : item.value)}</span>
          <span class="count-badge">${item.count} alerts</span>
        </li>
      `
        )
        .join("");
    };

    renderList("#ti-top-ips", summary.top_ips);
    renderList("#ti-top-domains", summary.top_domains);
    renderList("#ti-top-hashes", summary.top_hashes);

    // Render feed table
    const feedBody = $("#ti-feed-body");
    if (!summary.recent_enrichments || !summary.recent_enrichments.length) {
      feedBody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#7a8c9e;">No indicators enriched yet. Upload an alert to begin.</td></tr>`;
      return;
    }

    feedBody.innerHTML = summary.recent_enrichments
      .map((enr) => {
        const classPill =
          enr.classification === "malicious"
            ? `<span class="badge priority-critical">MALICIOUS</span>`
            : enr.classification === "suspicious"
            ? `<span class="badge priority-high">SUSPICIOUS</span>`
            : `<span class="badge priority-low">${enr.classification.toUpperCase()}</span>`;

        return `
        <tr>
          <td><strong style="font-family:monospace; color:#8fdcff;">${escapeHtml(enr.value)}</strong></td>
          <td><span class="badge priority-medium">${escapeHtml(enr.indicator_type.toUpperCase())}</span></td>
          <td>${classPill}</td>
          <td>${escapeHtml(enr.provider)}</td>
          <td>${enr.reputation_score !== null && enr.reputation_score !== undefined ? `${enr.reputation_score}%` : 'N/A'}</td>
          <td>${escapeHtml(enr.country || 'N/A')} ${enr.asn ? `/ ${escapeHtml(enr.asn)}` : ''}</td>
          <td><small style="color:#b8c7d6;">${escapeHtml(enr.threat_category || enr.summary)}</small></td>
        </tr>
      `;
      })
      .join("");
  } catch (error) {
    showToast(`Threat Intel error: ${error.message}`, "error");
  }
}

async function executeTISearch() {
  const query = $("#ti-search-input").value.trim();
  if (!query) return;
  const resultsContainer = $("#ti-search-results");
  resultsContainer.innerHTML = `<p style="color:#8fdcff;">Searching threat intelligence and cases for "${escapeHtml(query)}"...</p>`;
  resultsContainer.classList.remove("hidden");

  try {
    const res = await api(`/api/threat-intel/search?query=${encodeURIComponent(query)}`);
    let html = `<div style="margin-bottom:14px;"><strong>Indicator Type:</strong> <span class="badge priority-medium">${res.indicator_type.toUpperCase()}</span> | <strong>Matching Incidents:</strong> ${res.total_matches}</div>`;

    if (res.enrichment) {
      const enr = res.enrichment;
      html += `
        <div style="background:#0c2434; border:1px solid #234c69; border-radius:10px; padding:16px; margin-bottom:16px;">
          <h4 style="margin:0 0 8px 0; color:#39d4c2;">🌐 Live Reputation Result (${escapeHtml(enr.provider)})</h4>
          <p style="margin:4px 0;"><strong>Classification:</strong> ${escapeHtml(enr.classification.toUpperCase())} | <strong>Reputation Score:</strong> ${enr.reputation_score}%</p>
          <p style="margin:4px 0; color:#cbe1f0;">${escapeHtml(enr.summary)}</p>
          ${enr.country ? `<p style="margin:4px 0; font-size:12px; color:#8fdcff;">Location/ASN: ${escapeHtml(enr.country)} - ${escapeHtml(enr.asn || '')}</p>` : ''}
        </div>
      `;
    }

    if (!res.matches || !res.matches.length) {
      html += `<p style="color:#7a8c9e;">No existing cases matched this indicator.</p>`;
    } else {
      html += res.matches
        .map(
          (m) => `
        <div class="ti-search-match-card" onclick="selectIncidentFromTI('${m.incident_id}')">
          <div>
            <strong style="color:#ffffff;">${escapeHtml(m.incident_title)}</strong>
            <p style="margin:4px 0 0 0; font-size:12px; color:#8fdcff;">Source: ${escapeHtml(m.source)} | Matched in: ${escapeHtml(m.match_field)}</p>
          </div>
          <div>
            <span class="badge priority-${m.severity.toLowerCase()}">${m.severity.toUpperCase()}</span>
          </div>
        </div>
      `
        )
        .join("");
    }
    resultsContainer.innerHTML = html;
  } catch (error) {
    resultsContainer.innerHTML = `<p style="color:#ff6464;">Search failed: ${escapeHtml(error.message)}</p>`;
  }
}

function triggerTISearch(val) {
  const input = $("#ti-search-input");
  if (input) {
    input.value = val;
    executeTISearch();
  }
}

function selectIncidentFromTI(incidentId) {
  switchView("triage");
  state.selectedId = incidentId;
  const incident = state.incidents.find((i) => i.id === incidentId);
  if (incident) {
    renderDetail(incident);
    renderQueue();
  }
}

const tiSearchBtn = $("#ti-search-btn");
if (tiSearchBtn) {
  tiSearchBtn.addEventListener("click", executeTISearch);
}
const tiSearchInput = $("#ti-search-input");
if (tiSearchInput) {
  tiSearchInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") executeTISearch();
  });
}

async function renderFilesModal() {
  const listEl = $("#files-list");
  if (!listEl) return;
  listEl.innerHTML = `<p style="color:#7190a0; font-size:13px;"><span class="spinner"></span> Loading ingested alert files...</p>`;

  try {
    const files = await api("/api/incidents/sources/list");
    if (!files || files.length === 0) {
      listEl.innerHTML = `<p style="color:#7190a0; font-size:13px; padding:16px; text-align:center; background:#0e202d; border-radius:8px;">No alert files currently in database.</p>`;
      return;
    }

    listEl.innerHTML = "";
    files.forEach((file) => {
      const card = document.createElement("div");
      card.style.cssText = "background:#0e202d; border:1px solid #1f4155; border-radius:12px; padding:16px;";

      const samplesHtml = file.sample_titles.length
        ? file.sample_titles.map((t) => `<li style="margin-bottom:2px;">• ${escapeHtml(t)}</li>`).join("")
        : "";

      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
          <div>
            <h3 style="margin:0 0 6px 0; font-size:15px; color:#ffffff; font-weight:700;">📄 ${escapeHtml(file.source_file)}</h3>
            <div style="display:flex; gap:10px; align-items:center; font-size:12px; color:#7899ab;">
              <span>📍 ${escapeHtml(file.source)}</span>
              <span>•</span>
              <span style="font-weight:700; color:#39d4c2;">${file.incident_count} Alert(s)</span>
            </div>
          </div>
          <div style="display:flex; gap:8px;">
            <button class="filter-file-btn button secondary" style="padding:4px 10px; font-size:12px;" title="Filter Case Queue by this file">
              👁 View Alerts
            </button>
            <button class="delete-file-btn button secondary danger" style="padding:4px 10px; font-size:12px;" title="Delete all alerts from this file">
              🗑 Delete Batch
            </button>
          </div>
        </div>

        <div style="display:flex; gap:8px; margin-top:10px; font-size:11px;">
          ${file.priorities.critical ? `<span style="background:rgba(255,90,95,0.2); color:#ff5a5f; padding:2px 8px; border-radius:4px; font-weight:600;">🚨 ${file.priorities.critical} Critical</span>` : ""}
          ${file.priorities.high ? `<span style="background:rgba(255,160,0,0.2); color:#ffa000; padding:2px 8px; border-radius:4px; font-weight:600;">⚠️ ${file.priorities.high} High</span>` : ""}
          ${file.priorities.medium ? `<span style="background:rgba(57,212,194,0.2); color:#39d4c2; padding:2px 8px; border-radius:4px; font-weight:600;">🔹 ${file.priorities.medium} Medium</span>` : ""}
          ${file.priorities.low ? `<span style="background:rgba(122,140,158,0.2); color:#7a8c9e; padding:2px 8px; border-radius:4px; font-weight:600;">🟢 ${file.priorities.low} Low</span>` : ""}
        </div>

        ${file.sample_titles.length ? `<div style="margin-top:12px; font-size:12px; color:#9db7c7;"><span style="font-weight:600; color:#c7dedf;">Sample Alerts in Batch:</span><ul style="margin:4px 0 0 0; padding-left:10px; list-style:none;">${samplesHtml}</ul></div>` : ""}
      `;

      card.querySelector(".filter-file-btn").addEventListener("click", () => {
        state.search = file.source_file;
        const searchInput = $("#search-input");
        if (searchInput) searchInput.value = file.source_file;
        $("#files-modal").classList.add("hidden");
        switchView("triage");
        renderQueue();
        showToast(`Filtered queue for file '${file.source_file}'`, "info");
      });

      card.querySelector(".delete-file-btn").addEventListener("click", async () => {
        const confirmMsg = `Are you sure you want to delete ALL ${file.incident_count} alert(s) belonging to file:\n\n'${file.source_file}'?\n\nSample alerts to be deleted:\n${file.sample_titles.map(t => '• ' + t).join('\n')}`;
        if (confirm(confirmMsg)) {
          try {
            const res = await api(`/api/incidents/sources/delete?filename=${encodeURIComponent(file.source_file)}`, { method: "DELETE" });
            showToast(`Deleted all ${res.deleted_count} alert(s) from '${file.source_file}'`, "info");
            await renderFilesModal();
            await refreshIncidents();
          } catch (err) {
            showToast(err.message, "error");
          }
        }
      });

      listEl.appendChild(card);
    });
  } catch (error) {
    listEl.innerHTML = `<p style="color:#ff6464; font-size:13px;">Error loading files: ${escapeHtml(error.message)}</p>`;
  }
}

const manageFilesBtn = $("#manage-files-btn");
if (manageFilesBtn) {
  manageFilesBtn.addEventListener("click", () => {
    $("#files-modal").classList.remove("hidden");
    renderFilesModal();
  });
}

const closeFilesModalBtn = $("#close-files-modal");
if (closeFilesModalBtn) {
  closeFilesModalBtn.addEventListener("click", () => {
    $("#files-modal").classList.add("hidden");
  });
}

async function generateSOARPlaybook() {
  if (!state.selectedId) return;
  const btn = $("#generate-soar-btn");
  if (!btn) return;

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Generating Executable SOAR Playbook...`;

  try {
    const res = await api(`/api/incidents/${state.selectedId}/soar-playbook`);
    state.soarPlaybook = res.scripts;

    const soarContainer = $("#soar-container");
    if (soarContainer) soarContainer.classList.remove("hidden");

    renderActiveSOARScript("powershell");
    showToast("SOAR Executable Playbook generated successfully!", "success");
  } catch (err) {
    showToast(`SOAR Error: ${err.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.innerHTML = "⚡ Generate Executable SOAR Playbook";
  }
}

function renderActiveSOARScript(lang) {
  if (!state.soarPlaybook) return;
  const scriptObj = state.soarPlaybook.find((s) => s.language === lang) || state.soarPlaybook[0];
  const codeBlock = $("#soar-code-block");
  if (codeBlock && scriptObj) {
    codeBlock.textContent = scriptObj.code;
  }

  document.querySelectorAll(".soar-tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.lang === lang);
  });
}

const generateSoarBtn = $("#generate-soar-btn");
if (generateSoarBtn) {
  generateSoarBtn.addEventListener("click", generateSOARPlaybook);
}

document.querySelectorAll(".soar-tab").forEach((tab) => {
  tab.addEventListener("click", (e) => {
    const lang = e.currentTarget.dataset.lang;
    renderActiveSOARScript(lang);
  });
});

const copySoarBtn = $("#copy-soar-script-btn");
if (copySoarBtn) {
  copySoarBtn.addEventListener("click", async () => {
    const codeBlock = $("#soar-code-block");
    if (codeBlock && codeBlock.textContent) {
      await navigator.clipboard.writeText(codeBlock.textContent);
      showToast("SOAR script copied to clipboard!", "info");
      copySoarBtn.textContent = "✅ Copied!";
      setTimeout(() => {
        copySoarBtn.textContent = "📋 Copy Script";
      }, 1800);
    }
  });
}

async function initTIKeys() {
  let serverConfig = { abuseipdb_configured: false, virustotal_configured: false };
  try {
    serverConfig = await api("/api/threat-intel/config");
  } catch (e) {}

  const abuseKey = localStorage.getItem("ABUSEIPDB_API_KEY") || "";
  const vtKey = localStorage.getItem("VIRUSTOTAL_API_KEY") || "";

  const abuseInput = $("#abuseipdb-key-input");
  if (abuseInput) abuseInput.value = abuseKey;

  const vtInput = $("#virustotal-key-input");
  if (vtInput) vtInput.value = vtKey;

  updateTIBadges(
    Boolean(abuseKey || serverConfig.abuseipdb_configured),
    Boolean(vtKey || serverConfig.virustotal_configured),
    Boolean(serverConfig.abuseipdb_configured),
    Boolean(serverConfig.virustotal_configured)
  );
}

function updateTIBadges(hasAbuse, hasVT, fromEnvAbuse = false, fromEnvVT = false) {
  const abuseBadge = $("#abuseipdb-badge");
  if (abuseBadge) {
    if (hasAbuse) {
      abuseBadge.textContent = fromEnvAbuse ? "🟢 Live API Connected (.env)" : "🟢 Live API Connected";
      abuseBadge.style.background = "rgba(57, 212, 194, 0.2)";
      abuseBadge.style.color = "#39d4c2";
    } else {
      abuseBadge.textContent = "⚪ Local Mode";
      abuseBadge.style.background = "#153043";
      abuseBadge.style.color = "#7899ab";
    }
  }

  const vtBadge = $("#virustotal-badge");
  if (vtBadge) {
    if (hasVT) {
      vtBadge.textContent = fromEnvVT ? "🟢 Live API Connected (.env)" : "🟢 Live API Connected";
      vtBadge.style.background = "rgba(57, 212, 194, 0.2)";
      vtBadge.style.color = "#39d4c2";
    } else {
      vtBadge.textContent = "⚪ Local Mode";
      vtBadge.style.background = "#153043";
      vtBadge.style.color = "#7899ab";
    }
  }

  const statusPill = $("#ti-api-status");
  if (statusPill) {
    if (hasAbuse || hasVT) {
      statusPill.textContent = "⚡ Live Threat Intel Active";
      statusPill.style.background = "rgba(57, 212, 194, 0.25)";
      statusPill.style.color = "#39d4c2";
    } else {
      statusPill.textContent = "Local Engine Active";
      statusPill.style.background = "rgba(57, 212, 194, 0.15)";
      statusPill.style.color = "#39d4c2";
    }
  }
}

const saveKeysBtn = $("#save-api-keys-btn");
if (saveKeysBtn) {
  saveKeysBtn.addEventListener("click", () => {
    const abuseKey = ($("#abuseipdb-key-input")?.value || "").trim();
    const vtKey = ($("#virustotal-key-input")?.value || "").trim();

    localStorage.setItem("ABUSEIPDB_API_KEY", abuseKey);
    localStorage.setItem("VIRUSTOTAL_API_KEY", vtKey);

    updateTIBadges(abuseKey, vtKey);
    showToast("Threat Intel API configuration saved!", "success");
  });
}

initTIKeys();

function updateSevPillsUI(sev) {
  document.querySelectorAll(".sev-pill").forEach((p) => {
    p.classList.toggle("active", p.dataset.sev === sev);
  });
}

document.querySelectorAll(".sev-pill").forEach((pill) => {
  pill.addEventListener("click", (e) => {
    const sev = e.currentTarget.dataset.sev;
    state.filters.priority = sev;
    updateSevPillsUI(sev);
    const prioritySelect = $("#filter-priority");
    if (prioritySelect) {
      prioritySelect.value = sev;
    }
    renderQueue();
    if (typeof updateFilterLabel === "function") updateFilterLabel();
  });
});


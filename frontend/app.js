/**
 * AI SOC — Frontend Application Logic
 * Handles SSE streaming, alert rendering.
 */

'use strict';

const API = '';   // Same origin — backend serves the frontend

// ── State ────────────────────────────────────────────────────────────────────
let localStream = null;
let logCount = 0;
let paused = false;
let allAlerts = [];
let liveAlertUpdates = false; // manual refresh only
let pendingAlerts = 0;

// ── Startup ───────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  setConnectionStatus('connecting');
  loadAlerts();
  refreshAgentStatus();
  loadThreatIntelNews();
  setInterval(refreshAgentStatus, 8000);
  setInterval(loadThreatIntelNews, 300000); // 5 mins
});

// ── Connection Status ─────────────────────────────────────────────────────────
function setConnectionStatus(state, label) {
  const dot = document.getElementById('conn-status-dot');
  const lbl = document.getElementById('conn-status-label');
  dot.className = 'status-dot';
  const labels = { connected: 'Connected', connecting: 'Connecting...', error: 'Disconnected' };
  if (state === 'connected') dot.classList.add('connected');
  if (state === 'error')     dot.classList.add('error');
  lbl.textContent = label || labels[state] || state;
}

// ── Mode Switching ────────────────────────────────────────────────────────────
function switchMode(mode) {
  // Remote mode removed: keep API shape, but always remain local.
  const _mode = 'local';
  document.getElementById('tab-local').classList.toggle('active', true);
  document.getElementById('local-controls').style.display = 'block';
  const modeLabel = document.getElementById('stream-mode-label');
  modeLabel.textContent = 'Local machine';

  clearLogStream();

  if (_mode === 'local' && localStream) {
    document.getElementById('stream-pulse').classList.add('active');
  }
}

// ── Local Analysis ────────────────────────────────────────────────────────────
async function startLocalAnalysis() {
  try {
    const resp = await fetch(`${API}/api/analyze/local`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ timeframe_hours: 5 }),
    });
    const data = await resp.json();
    toast('Analysis pipeline started!', 'success');
    openLocalStream();

    document.getElementById('btn-start-local').style.display = 'none';
    document.getElementById('btn-stop-local').style.display = 'flex';
  } catch (e) {
    toast(`Error: ${e.message}`, 'error');
  }
}

async function stopLocalAnalysis() {
  try {
    await fetch(`${API}/api/analyze/stop`, { method: 'POST' });
  } catch (e) {}
  closeLocalStream();
  document.getElementById('btn-start-local').style.display = 'flex';
  document.getElementById('btn-stop-local').style.display = 'none';
  toast('Analysis stopped.', 'info');
}

async function openLocalStream() {
  closeLocalStream();
  const terminal = document.getElementById('log-terminal');
  terminal.innerHTML = '';   // clear placeholder
  logCount = 0;

  // Fetch recent logs first for immediate display
  try {
    const resp = await fetch(`${API}/api/logs/recent?limit=50`);
    if (resp.ok) {
        const data = await resp.json();
        if (data.logs && data.logs.length) {
            data.logs.forEach(evt => appendLogEntry(evt.data, 'local'));
        }
    }
  } catch(e) { console.error("Could not fetch recent logs", e); }

  localStream = new EventSource(`${API}/api/stream/local`);

  localStream.onopen = () => {
    setConnectionStatus('connected', 'Streaming local logs');
    document.getElementById('stream-pulse').classList.add('active');
  };

  localStream.onmessage = (ev) => {
    if (paused) return;
    try {
      const event = JSON.parse(ev.data);
      handleStreamEvent(event, 'local');
    } catch (e) {}
  };

  localStream.onerror = () => {
    setConnectionStatus('error');
    document.getElementById('stream-pulse').classList.remove('active');
  };
}

function closeLocalStream() {
  if (localStream) { localStream.close(); localStream = null; }
  setConnectionStatus('connecting');
  document.getElementById('stream-pulse').classList.remove('active');
}

// ── Stream Event Handler ───────────────────────────────────────────────────────
function handleStreamEvent(event, source) {
  if (event.type === 'log') {
    appendLogEntry(event.data, source);
    updateLastUpdate();
  } else if (event.type === 'alert') {
    if (liveAlertUpdates) {
      prependAlert(event.data);
      shakeMetrics();
    } else {
      pendingAlerts++;
      updatePendingAlertsUI();
      toast(`New alert received (${pendingAlerts} pending). Click refresh.`, 'info');
    }
    updateLastUpdate();
  } else if (event.type === 'status') {
    console.log('[SSE Status]', event.data?.message);
  }
}

// ── Log Terminal ──────────────────────────────────────────────────────────────
function appendLogEntry(row, source) {
  const terminal = document.getElementById('log-terminal');
  const maxEntries = 500;

  // Remove placeholder
  const placeholder = terminal.querySelector('.terminal-placeholder');
  if (placeholder) placeholder.remove();

  // Trim old entries
  while (terminal.children.length >= maxEntries) {
    terminal.removeChild(terminal.firstChild);
  }

  const ts = (row.timestamp || '').replace('T', ' ').substring(0, 19);
  const eid = row.event_id || '?';
  const logType = row.log_type || '';
  const desc = row.event_description || row.raw_message || '— no description —';

  const entry = document.createElement('div');
  entry.className = 'log-entry';
  // flex-shrink:0 prevents entries from collapsing in a flex column container
  entry.style.flexShrink = '0';
  entry.innerHTML = `
    <span class="log-ts">${ts}</span>
    <span class="log-eid">EID:${eid}</span>
    <span class="log-type ${logType}">${logType}</span>
    <span class="log-desc" title="${escapeHtml(desc)}">${escapeHtml(desc)}</span>
  `;
  terminal.appendChild(entry);
  // scrollTop works on both block and flex-overflow containers
  requestAnimationFrame(() => { terminal.scrollTop = terminal.scrollHeight; });

  logCount++;
  document.getElementById('log-count').textContent = `${logCount} events`;
}

function clearLogStream() {
  const terminal = document.getElementById('log-terminal');
  terminal.innerHTML = '';
  const ph = document.createElement('div');
  ph.className = 'terminal-placeholder';
  ph.innerHTML = `<span class="placeholder-icon">📡</span><p>Select a mode and start analysis to see live logs here.</p>`;
  terminal.appendChild(ph);
  logCount = 0;
  document.getElementById('log-count').textContent = '0 events';
  document.getElementById('stream-mode-label').textContent = '—';
}

function togglePause() {
  paused = !paused;
  const btn = document.getElementById('btn-pause-stream');
  btn.textContent = paused ? '▶' : '⏸';
  btn.title = paused ? 'Resume' : 'Pause';
  toast(paused ? 'Stream paused' : 'Stream resumed', 'info');
}

// ── Alerts ────────────────────────────────────────────────────────────────────
async function loadAlerts() {
  try {
    const filterEl = document.getElementById('alert-filter');
    const severity = filterEl ? filterEl.value : '';
    const url = severity ? `${API}/api/alerts?severity=${severity}` : `${API}/api/alerts`;
    const resp = await fetch(url);
    if (!resp.ok) return;
    const data = await resp.json();
    allAlerts = data.alerts || [];
    renderAlerts(allAlerts);
    updateMetrics(allAlerts);
    pendingAlerts = 0;
    updatePendingAlertsUI();
  } catch (e) {}
}

function filterAlerts() { loadAlerts(); }

function refreshAlerts() {
  loadAlerts();
  toast('Alerts refreshed.', 'info');
}

function updatePendingAlertsUI() {
  const btn = document.querySelector('#alerts-panel .panel-actions button[onclick="refreshAlerts()"]');
  if (!btn) return;
  if (pendingAlerts > 0) {
    btn.textContent = `🔄 ${pendingAlerts}`;
    btn.title = `Refresh alerts (${pendingAlerts} pending)`;
  } else {
    btn.textContent = '🔄';
    btn.title = 'Refresh alerts';
  }
}

function renderAlerts(alerts) {
  const container = document.getElementById('alerts-container');
  if (!alerts.length) {
    container.innerHTML = `<div class="empty-state"><span>🛡️</span><p>No alerts yet. System is clean or pipeline hasn't run.</p></div>`;
    return;
  }

  container.innerHTML = alerts.map((a, i) => {
    const sev = a.severity || 'LOW';
    const ts = (a.timestamp || '').replace('T', ' ').substring(0, 19);
    const cve = a.matched_zero_day?.cve || '—';
    const title = a.event_description || a.matched_zero_day?.title || 'Security Event';
    const conf = typeof a.confidence === 'number' ? (a.confidence * 100).toFixed(0) + '%' : '—';
    const reasoning = escapeHtml(a.explanation || a.llm_analysis?.reasoning || 'No reasoning available.');
    const logJson = escapeHtml(JSON.stringify(a.log_source || {}, null, 2));

    return `
      <div class="alert-card" data-sev="${sev}" id="alert-${i}">
        <div class="alert-header" onclick="toggleAlert(${i})">
          <span class="alert-badge badge-${sev}">${sev}</span>
          <span class="alert-title">${escapeHtml(title)}</span>
          ${cve !== '—' ? `<span style="color:var(--accent-cyan);font-size:0.72rem;font-family:var(--font-mono)">${cve}</span>` : ''}
          <span class="alert-confidence">${conf}</span>
          <span class="alert-ts">${ts}</span>
        </div>
        <div class="alert-body" id="alert-body-${i}">
          <div class="alert-reasoning">${reasoning}</div>
          <div class="alert-json">${logJson}</div>
        </div>
      </div>`;
  }).join('');
}

function prependAlert(alert) {
  allAlerts.unshift(alert);
  renderAlerts(allAlerts);
  updateMetrics(allAlerts);
}

function toggleAlert(i) {
  const body = document.getElementById(`alert-body-${i}`);
  if (body) body.classList.toggle('expanded');
}

function updateMetrics(alerts) {
  document.getElementById('total-alerts').textContent = alerts.length;
  const criticals = alerts.filter(a => a.severity === 'CRITICAL').length;
  document.getElementById('critical-alerts').textContent = criticals;
  if (criticals > 0) {
    document.getElementById('chip-critical').classList.add('critical');
  }
}

async function clearAlerts() {
  try {
    await fetch(`${API}/api/alerts`, { method: 'DELETE' });
    allAlerts = [];
    renderAlerts([]);
    updateMetrics([]);
    toast('Alerts cleared.', 'success');
  } catch (e) {
    toast('Failed to clear alerts.', 'error');
  }
}

// ── Agent Status ──────────────────────────────────────────────────────────────
async function refreshAgentStatus() {
  try {
    const resp = await fetch(`${API}/api/agents/status`);
    if (!resp.ok) { setConnectionStatus('error'); return; }
    const data = await resp.json();
    setConnectionStatus('connected', 'Backend connected');
    renderAgentCards(data);
  } catch (e) {
    setConnectionStatus('error', 'Backend unreachable');
  }
}

function renderAgentCards(data) {
  const container = document.getElementById('agent-cards');
  const agents = [
    { key: 'agent1', label: 'Agent 1 — Log Collector' },
    { key: 'agent2', label: 'Agent 2 — Threat Intel' },
    { key: 'agent3', label: 'Agent 3 — Synthetic Gen' },
    { key: 'agent4', label: 'Agent 4 — Pattern Detector' },
  ];
  container.innerHTML = agents.map(({ key, label }) => {
    const info = data[key] || {};
    const status = info.status || 'unknown';
    return `
      <div class="agent-card">
        <div class="agent-indicator ${status}"></div>
        <div>
          <div class="agent-name">${label}</div>
          <div class="agent-desc">${info.description || status}</div>
        </div>
      </div>`;
  }).join('');
}

// ── Threat Intel Pipeline ─────────────────────────────────────────────────────
async function runThreatIntel() {
  try {
    const resp = await fetch(`${API}/api/pipeline/threat-intel`, { method: 'POST' });
    const data = await resp.json();
    toast(data.message || 'Threat intel pipeline started.', 'success');
  } catch (e) {
    toast(`Error: ${e.message}`, 'error');
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function updateLastUpdate() {
  const now = new Date();
  document.getElementById('last-update').textContent =
    now.toTimeString().substring(0, 8);
}

function shakeMetrics() {
  const chip = document.getElementById('chip-alerts');
  chip.style.transform = 'scale(1.15)';
  setTimeout(() => { chip.style.transform = ''; }, 200);
}

function escapeHtml(str) {
  if (typeof str !== 'string') str = String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Threat Intel News ─────────────────────────────────────────────────────────

async function loadThreatIntelNews() {
  const container = document.getElementById('threat-news-list');
  if (!container) return;
  try {
    const resp = await fetch(`${API}/api/threat-intel/news`);
    const data = await resp.json();
    if (!data.news || data.news.length === 0) {
      container.innerHTML = `<div class="empty-state"><span>📰</span><p>No threat intel available.<br>Run Threat Intel Update.</p></div>`;
      return;
    }
    container.innerHTML = data.news.map(n => `
      <div class="news-card">
        <div class="news-card-header">
           <span class="news-source">${escapeHtml(n.source)}</span>
           <span style="font-size: 0.7rem; color: var(--text-dim);">${escapeHtml(n.published?.split('T')[0] || '')}</span>
        </div>
        <a href="${escapeHtml(n.url || '#')}" target="_blank" class="news-title news-link">${escapeHtml(n.title)}</a>
        <div class="news-summary">${escapeHtml(n.summary)}</div>
        <div class="news-footer">
           <span style="color: var(--sev-${n.severity?.toLowerCase() || 'medium'})">${escapeHtml(n.severity || 'INFO')}</span>
           <span>${escapeHtml(n.cve || '')}</span>
        </div>
      </div>
    `).join('');
  } catch (e) {
    container.innerHTML = `<div class="empty-state" style="color:var(--sev-critical)"><span>⚠️</span><p>Failed to load intel.</p></div>`;
  }
}

// (Alert → Qdrant compare UI removed)

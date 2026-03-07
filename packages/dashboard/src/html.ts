/**
 * PRISM Dashboard — embedded single-file HTML frontend.
 *
 * Generates a complete HTML page with nonce-based CSP.
 * All dynamic content rendered via textContent (never innerHTML) to prevent XSS.
 * Dark theme, system fonts, responsive layout, <25KB total.
 */
export function generateHtml(nonce: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRISM Dashboard</title>
<style nonce="${nonce}">
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--text-muted:#8b949e;--accent:#58a6ff;--accent-hover:#79c0ff;--danger:#f85149;--success:#3fb950;--warning:#d29922;--font:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace;--radius:6px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.5}
button{font-family:inherit;cursor:pointer;border:1px solid var(--border);background:var(--surface);color:var(--text);padding:6px 12px;border-radius:var(--radius);font-size:13px}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);color:#000;border-color:var(--accent)}
button.primary:hover{background:var(--accent-hover)}
button.danger{border-color:var(--danger);color:var(--danger)}
button.success{border-color:var(--success);color:var(--success);cursor:default}
input,select{font-family:inherit;background:var(--surface);color:var(--text);border:1px solid var(--border);padding:6px 10px;border-radius:var(--radius);font-size:13px}
input:focus,select:focus{outline:none;border-color:var(--accent)}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:100}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:24px;min-width:340px;max-width:480px}
.modal h2{margin-bottom:16px;font-size:18px}
.modal .field{margin-bottom:12px}
.modal .field label{display:block;margin-bottom:4px;color:var(--text-muted);font-size:12px}
.modal .field input{width:100%}
.modal .actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
header{display:flex;align-items:center;justify-content:space-between;padding:12px 20px;border-bottom:1px solid var(--border);background:var(--surface)}
header h1{font-size:16px;font-weight:600}
.token-display{font-family:var(--mono);font-size:12px;color:var(--text-muted);cursor:pointer}
.component-strip{display:flex;gap:8px;flex-wrap:wrap;padding:10px 20px;background:var(--surface);border-bottom:1px solid var(--border)}
.component-chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:1px solid var(--border);border-radius:999px;font-size:12px;background:#111824}
.component-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.component-dot.online{background:var(--success);box-shadow:0 0 0 2px rgba(63,185,80,.25)}
.component-dot.offline{background:var(--danger);box-shadow:0 0 0 2px rgba(248,81,73,.25)}
.component-state{font-family:var(--mono);font-size:11px;color:var(--text-muted)}
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);background:var(--surface);padding:0 20px}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;border-radius:0;padding:10px 16px;color:var(--text-muted);font-size:14px}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-content{display:none;padding:20px}
.tab-content.active{display:block}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;align-items:center}
.filters select,.filters input{min-width:120px}
.filters .search-input{flex:1;min-width:180px}
.auto-refresh{display:flex;align-items:center;gap:4px;font-size:12px;color:var(--text-muted);margin-left:auto}
.auto-refresh input[type=checkbox]{margin:0}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border)}
th{color:var(--text-muted);font-size:12px;font-weight:500;text-transform:uppercase;letter-spacing:.5px}
td{font-size:13px}
td.mono{font-family:var(--mono);font-size:12px}
tr:hover{background:rgba(88,166,255,.04)}
.event-badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:500;font-family:var(--mono)}
.event-badge.exec{background:#1f3a2e;color:var(--success)}
.event-badge.path{background:#3d2c10;color:var(--warning)}
.event-badge.pattern{background:#3c1e28;color:var(--danger)}
.event-badge.secret{background:#2d1a3e;color:#bc8cff}
.event-badge.other{background:#1c2333;color:var(--accent)}
.legacy-badge{font-size:10px;color:var(--warning);margin-left:4px}
.pagination{display:flex;gap:8px;justify-content:center;margin-top:16px}
.empty-state{text-align:center;padding:40px;color:var(--text-muted)}
.config-section{margin-bottom:24px}
.config-section h3{font-size:14px;margin-bottom:8px;color:var(--text-muted)}
.tag-list{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.tag{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-family:var(--mono);font-size:12px}
.tag .remove{cursor:pointer;color:var(--text-muted);font-size:14px;line-height:1}
.tag .remove:hover{color:var(--danger)}
.add-row{display:flex;gap:6px}
.add-row input{flex:1}
.scalar-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.scalar-row label{min-width:160px;color:var(--text-muted);font-size:13px}
.scalar-row input{width:200px}
.config-actions{display:flex;gap:8px;margin-top:20px;padding-top:16px;border-top:1px solid var(--border)}
.status-msg{padding:8px 12px;border-radius:var(--radius);margin-bottom:12px;font-size:13px;display:none}
.status-msg.error{display:block;background:#3c1e28;color:var(--danger);border:1px solid var(--danger)}
.status-msg.success{display:block;background:#1f3a2e;color:var(--success);border:1px solid var(--success)}
.status-msg.warn{display:block;background:#3d2c10;color:var(--warning);border:1px solid var(--warning)}
.detail-cell{max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media(max-width:768px){.filters{flex-direction:column}.detail-cell{max-width:180px}header{flex-direction:column;gap:8px}.component-strip{padding:10px 12px}}
.hidden{display:none!important}
.config-rev{margin-left:auto;font-size:12px;color:var(--text-muted)}
.mt-8{margin-top:8px}
.doctor-hint{padding:6px 20px;font-size:11px;color:var(--text-muted);border-bottom:1px solid var(--border);background:var(--bg)}
.doctor-hint code{font-family:var(--mono);font-size:11px;color:var(--accent);background:rgba(88,166,255,.08);padding:1px 5px;border-radius:3px}
</style>
</head>
<body>

<div id="auth-modal" class="modal-overlay">
<div class="modal">
<h2>PRISM Dashboard</h2>
<div class="field"><label>Dashboard Token</label><input id="token-input" type="password" placeholder="Enter PRISM_DASHBOARD_TOKEN"></div>
<div class="actions"><button class="primary" id="connect-btn">Connect</button></div>
</div>
</div>

<header>
<h1>PRISM Security Dashboard</h1>
<span class="token-display" id="token-display" title="Click to re-enter token"></span>
</header>
<div class="component-strip" id="component-strip"></div>
<div class="doctor-hint">OpenClaw config diagnostics: <code>openclaw doctor</code> · Auto-fix (use with caution): <code>openclaw doctor --fix</code></div>

<nav class="tabs">
<button class="tab-btn active" data-tab="blocks">Blocks</button>
<button class="tab-btn" data-tab="config">Config</button>
</nav>

<div id="tab-blocks" class="tab-content active">
<div class="filters">
<select id="event-filter"><option value="">All Events</option><option value="exec_whitelist_block">exec_whitelist_block</option><option value="path_block">path_block</option><option value="exec_pattern_block">exec_pattern_block</option><option value="outbound_secret_blocked">outbound_secret_blocked</option><option value="risk_escalation_block">risk_escalation_block</option><option value="blocked_domain">blocked_domain</option><option value="risky_domain_flagged">risky_domain_flagged</option></select>
<input id="since-input" type="datetime-local" title="Since (start time)">
<input id="session-input" placeholder="Session..." type="text" title="Filter by session ID">
<input id="search-input" class="search-input" placeholder="Search..." type="text">
<button id="refresh-btn">Refresh</button>
<label class="auto-refresh"><input type="checkbox" id="auto-refresh-cb">Auto (5s)</label>
</div>
<div id="blocks-status" class="status-msg"></div>
<table><thead><tr><th>Time</th><th>Event</th><th>Details</th><th>Session</th><th>Action</th></tr></thead><tbody id="blocks-body"></tbody></table>
<div id="blocks-empty" class="empty-state hidden">No block events found.</div>
<div class="pagination"><button id="page-older" class="hidden">← Older</button><button id="page-newer" class="hidden">Newer →</button></div>
</div>

<div id="tab-config" class="tab-content">
<div id="config-status" class="status-msg"></div>
<div id="config-sections"></div>
<div class="config-actions">
<button id="validate-btn">Validate</button>
<button id="save-btn" class="primary">Save Config</button>
<span id="config-revision" class="config-rev"></span>
</div>
</div>

<div id="allow-modal" class="modal-overlay hidden">
<div class="modal">
<h2>Allow Action</h2>
<div id="allow-body"></div>
<div id="allow-confirm-row" class="field hidden"><label>Type ALLOW to confirm</label><input id="allow-confirm-input" type="text" placeholder="ALLOW"></div>
<div id="allow-error" class="status-msg mt-8"></div>
<div class="actions"><button id="allow-cancel">Cancel</button><button id="allow-submit" class="primary">Confirm</button></div>
</div>
</div>

<script nonce="${nonce}">
(function(){
'use strict';
const $ = (s,p) => (p||document).querySelector(s);
const $$ = (s,p) => [...(p||document).querySelectorAll(s)];
const ce = t => document.createElement(t);

/* ── State ── */
let token = sessionStorage.getItem('prism_token') || '';
let cursorStack = [];
let currentCursor = undefined;
let configData = null;
let configDirty = {};
let autoTimer = null;
let componentTimer = null;

/* ── Auth ── */
function showAuth() { $('#auth-modal').classList.remove('hidden'); }
function hideAuth() { $('#auth-modal').classList.add('hidden'); }
function updateTokenDisplay() {
  const d = $('#token-display');
  if (token) { d.textContent = token.slice(0,4) + '····'; hideAuth(); }
  else { d.textContent = ''; showAuth(); }
}
$('#connect-btn').onclick = () => {
  token = $('#token-input').value.trim();
  if (!token) return;
  sessionStorage.setItem('prism_token', token);
  updateTokenDisplay();
  loadComponentStatuses();
  loadBlocks();
  loadConfig();
};
$('#token-input').onkeydown = e => { if (e.key === 'Enter') $('#connect-btn').click(); };
$('#token-display').onclick = showAuth;

/* ── API ── */
async function api(path, opts = {}) {
  const headers = { 'authorization': 'Bearer ' + token, ...opts.headers };
  if (opts.body && typeof opts.body === 'object') {
    headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) { token = ''; sessionStorage.removeItem('prism_token'); updateTokenDisplay(); throw new Error('Unauthorized'); }
  const data = await res.json();
  if (!res.ok && !data.valid && data.error) throw new Error(data.error);
  return data;
}

/* ── Tabs ── */
$$('.tab-btn').forEach(btn => {
  btn.onclick = () => {
    $$('.tab-btn').forEach(b => b.classList.remove('active'));
    $$('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    $('#tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'config' && !configData) loadConfig();
  };
});

/* ── Blocks ── */
function eventClass(ev) {
  if (ev.includes('exec_whitelist')) return 'exec';
  if (ev.includes('path')) return 'path';
  if (ev.includes('pattern')) return 'pattern';
  if (ev.includes('secret')) return 'secret';
  return 'other';
}

function blockDetail(b) {
  if (b.command) return b.command;
  if (b.canonicalPath) return b.canonicalPath;
  if (b.rawPath) return b.rawPath;
  if (b.path) return b.path;
  if (b.pattern) return b.pattern;
  if (b.url) return b.url;
  return JSON.stringify(b).slice(0, 80);
}

function renderBlocks(data) {
  const tbody = $('#blocks-body');
  const empty = $('#blocks-empty');
  tbody.innerHTML = '';
  if (!data.blocks || data.blocks.length === 0) { empty.classList.remove('hidden'); return; }
  empty.classList.add('hidden');
  for (const b of data.blocks) {
    const tr = ce('tr');
    const tdTime = ce('td'); tdTime.classList.add('mono');
    tdTime.textContent = b.ts ? new Date(b.ts).toLocaleTimeString() : '—';
    const tdEvent = ce('td');
    const badge = ce('span'); badge.className = 'event-badge ' + eventClass(b.event || '');
    badge.textContent = (b.event || '').replace(/_/g, '_');
    tdEvent.appendChild(badge);
    if (b.legacyRecord) { const lbl = ce('span'); lbl.className = 'legacy-badge'; lbl.textContent = '⚠ legacy'; tdEvent.appendChild(lbl); }
    const tdDetail = ce('td'); tdDetail.className = 'detail-cell mono';
    tdDetail.textContent = blockDetail(b);
    tdDetail.title = blockDetail(b);
    const tdSession = ce('td'); tdSession.classList.add('mono');
    tdSession.textContent = b.session ? b.session.slice(0, 12) : '—';
    const tdAction = ce('td');
    if (b.allowAction && b.allowAction.supported) {
      const btn = ce('button');
      if (b.allowAction.alreadyApplied) {
        btn.textContent = '✓ Allowed';
        btn.className = 'success';
        btn.disabled = true;
      } else {
        btn.textContent = 'Allow';
        btn.onclick = () => openAllowModal(b);
      }
      tdAction.appendChild(btn);
    }
    tr.append(tdTime, tdEvent, tdDetail, tdSession, tdAction);
    tbody.appendChild(tr);
  }
  $('#page-older').classList.toggle('hidden', !data.hasMore);
  $('#page-newer').classList.toggle('hidden', cursorStack.length === 0);
}

function renderComponentStatuses(data) {
  const strip = $('#component-strip');
  strip.innerHTML = '';
  const components = Array.isArray(data?.components) ? data.components : [];
  if (components.length === 0) {
    const empty = ce('span');
    empty.className = 'component-state';
    empty.textContent = 'components: unavailable';
    strip.appendChild(empty);
    return;
  }

  for (const component of components) {
    const chip = ce('div');
    chip.className = 'component-chip';
    const dot = ce('span');
    dot.className = 'component-dot ' + (component.ok ? 'online' : 'offline');
    const name = ce('span');
    name.textContent = component.name;
    const state = ce('span');
    state.className = 'component-state';
    state.textContent = component.ok ? 'online' : 'offline';
    chip.title = (component.url || component.name) + (component.detail ? ' · ' + component.detail : '');
    chip.append(dot, name, state);
    strip.appendChild(chip);
  }
}

async function loadComponentStatuses() {
  if (!token) return;
  try {
    const data = await api('/api/components/status');
    renderComponentStatuses(data);
  } catch {
    renderComponentStatuses({ components: [] });
  }
}

function startComponentPolling() {
  if (componentTimer) clearInterval(componentTimer);
  componentTimer = setInterval(() => {
    if (token) loadComponentStatuses();
  }, 5000);
}

async function loadBlocks() {
  if (!token) return;
  try {
    const params = new URLSearchParams();
    params.set('limit', '50');
    const ev = $('#event-filter').value;
    if (ev) params.set('event', ev);
    const since = $('#since-input').value;
    if (since) params.set('since', new Date(since).toISOString());
    const sess = $('#session-input').value.trim();
    if (sess) params.set('session', sess);
    const q = $('#search-input').value.trim();
    if (q) params.set('q', q);
    if (currentCursor) params.set('cursor', currentCursor);
    const data = await api('/api/blocks?' + params);
    renderBlocks(data);
    if (data.nextCursor) $('#page-older').dataset.cursor = data.nextCursor;
  } catch (e) {
    showStatus('blocks-status', e.message, 'error');
  }
}

$('#refresh-btn').onclick = () => { cursorStack = []; currentCursor = undefined; loadBlocks(); };
$('#event-filter').onchange = () => { cursorStack = []; currentCursor = undefined; loadBlocks(); };
$('#since-input').onchange = () => { cursorStack = []; currentCursor = undefined; loadBlocks(); };
$('#session-input').onkeydown = e => { if (e.key === 'Enter') { cursorStack = []; currentCursor = undefined; loadBlocks(); } };
$('#search-input').onkeydown = e => { if (e.key === 'Enter') { cursorStack = []; currentCursor = undefined; loadBlocks(); } };
$('#page-older').onclick = () => {
  const next = $('#page-older').dataset.cursor;
  if (next) { cursorStack.push(currentCursor); currentCursor = next; loadBlocks(); }
};
$('#page-newer').onclick = () => {
  currentCursor = cursorStack.pop();
  loadBlocks();
};
$('#auto-refresh-cb').onchange = () => {
  if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
  if ($('#auto-refresh-cb').checked) { autoTimer = setInterval(() => { if (!currentCursor) loadBlocks(); }, 5000); }
};

/* ── Allow Modal ── */
let pendingAllow = null;
let allowAbort = null;

function openAllowModal(block) {
  if (allowAbort) allowAbort.abort();
  allowAbort = new AbortController();
  const signal = allowAbort.signal;
  pendingAllow = block;
  const body = $('#allow-body');
  body.innerHTML = '';
  const p1 = ce('p'); p1.textContent = 'Loading preview...'; body.appendChild(p1);
  $('#allow-modal').classList.remove('hidden');
  $('#allow-error').className = 'status-msg mt-8';
  $('#allow-confirm-row').classList.add('hidden');
  $('#allow-confirm-input').value = '';

  api('/api/allow/preview', { method: 'POST', body: { sourceCursor: block.cursor }, signal }).then(preview => {
    if (signal.aborted) return;
    body.innerHTML = '';
    if (!preview.supported) {
      const warn = ce('p'); warn.textContent = 'Not supported: ' + (preview.reason || 'unknown'); warn.style.color = 'var(--warning)';
      body.appendChild(warn);
      $('#allow-submit').classList.add('hidden');
      return;
    }
    pendingAllow._preview = preview;
    $('#allow-submit').classList.remove('hidden');
    const desc = ce('p'); desc.style.marginBottom = '8px';
    desc.textContent = preview.action.description;
    body.appendChild(desc);
    if (preview.impact) {
      const impact = ce('p'); impact.style.fontSize = '13px'; impact.style.color = 'var(--text-muted)';
      impact.textContent = preview.impact.description;
      body.appendChild(impact);
      const risk = ce('p'); risk.style.marginTop = '8px';
      const rlabel = ce('span'); rlabel.textContent = 'Risk: ';
      const rval = ce('span');
      rval.textContent = preview.impact.riskLevel;
      rval.style.color = preview.impact.riskLevel === 'low' ? 'var(--success)' : preview.impact.riskLevel === 'medium' ? 'var(--warning)' : 'var(--danger)';
      rval.style.fontWeight = '600';
      risk.append(rlabel, rval);
      body.appendChild(risk);
      if (preview.impact.requiresConfirmation) {
        $('#allow-confirm-row').classList.remove('hidden');
      }
    }
  }).catch(e => {
    if (signal.aborted) return;
    body.innerHTML = '';
    const err = ce('p'); err.textContent = 'Error: ' + e.message; err.style.color = 'var(--danger)';
    body.appendChild(err);
    $('#allow-submit').classList.add('hidden');
  });
}

$('#allow-cancel').onclick = () => { if (allowAbort) allowAbort.abort(); $('#allow-modal').classList.add('hidden'); pendingAllow = null; };

$('#allow-submit').onclick = async () => {
  if (!pendingAllow?._preview) return;
  const preview = pendingAllow._preview;
  const confirmation = $('#allow-confirm-input').value.trim();
  if (preview.impact?.requiresConfirmation && confirmation !== 'ALLOW') {
    showStatus('allow-error', 'Type ALLOW to confirm', 'error'); return;
  }
  try {
    $('#allow-submit').disabled = true;
    await api('/api/allow/apply', {
      method: 'POST',
      body: {
        sourceCursor: pendingAllow.cursor,
        revision: preview.currentRevision,
        confirmation: confirmation || undefined,
        action: preview.action,
      },
    });
    $('#allow-modal').classList.add('hidden');
    pendingAllow = null;
    if (configData) void loadConfig();
    await loadBlocks();
  } catch (e) {
    showStatus('allow-error', e.message, 'error');
  } finally {
    $('#allow-submit').disabled = false;
  }
};

/* ── Config ── */
const ARRAY_FIELDS = [
  { key: 'execAllowedPrefixes', label: 'Exec Allowed Prefixes' },
  { key: 'protectedPathPatterns', label: 'Protected Path Patterns' },
  { key: 'protectedPathExceptions', label: 'Protected Path Exceptions' },
  { key: 'execBlockedPatterns', label: 'Exec Blocked Patterns', regex: true },
  { key: 'outboundSecretPatterns', label: 'Outbound Secret Patterns', regex: true },
  { key: 'scanTools', label: 'Scan Tools' },
  { key: 'blockedDomains', label: 'Blocked Domains (Tier A)' },
  { key: 'riskyDomains', label: 'Risky Domains (Tier B)' },
];
const SCALAR_FIELDS = [
  { key: 'riskTtlMs', label: 'Risk TTL (ms)', type: 'number' },
  { key: 'scannerUrl', label: 'Scanner URL', type: 'text' },
  { key: 'scannerTimeoutMs', label: 'Scanner Timeout (ms)', type: 'number' },
  { key: 'maxScanChars', label: 'Max Scan Chars', type: 'number' },
];
const BOOL_FIELDS = [
  { key: 'persistRiskState', label: 'Persist Risk State' },
  { key: 'blockOnScannerFailure', label: 'Block on Scanner Failure' },
];

function renderConfig(data) {
  configData = data;
  configDirty = JSON.parse(JSON.stringify(data.config));
  const container = $('#config-sections');
  container.innerHTML = '';
  $('#config-revision').textContent = 'rev: ' + data.revision;

  for (const field of ARRAY_FIELDS) {
    const section = ce('div'); section.className = 'config-section';
    const h3 = ce('h3'); h3.textContent = field.label; section.appendChild(h3);
    const tagList = ce('div'); tagList.className = 'tag-list'; tagList.id = 'tags-' + field.key;
    const values = configDirty[field.key] || [];
    for (const val of values) {
      tagList.appendChild(createTag(field.key, val));
    }
    section.appendChild(tagList);
    const addRow = ce('div'); addRow.className = 'add-row';
    const inp = ce('input'); inp.placeholder = field.regex ? 'Add regex pattern...' : 'Add value...'; inp.id = 'add-' + field.key;
    const addBtn = ce('button'); addBtn.textContent = '+';
    addBtn.onclick = () => addValue(field.key, inp, field.regex);
    inp.onkeydown = e => { if (e.key === 'Enter') addBtn.click(); };
    addRow.append(inp, addBtn);
    section.appendChild(addRow);
    container.appendChild(section);
  }

  const scalarSection = ce('div'); scalarSection.className = 'config-section';
  const sh3 = ce('h3'); sh3.textContent = 'Settings'; scalarSection.appendChild(sh3);
  for (const field of SCALAR_FIELDS) {
    const row = ce('div'); row.className = 'scalar-row';
    const label = ce('label'); label.textContent = field.label;
    const inp = ce('input'); inp.type = field.type; inp.value = configDirty[field.key] ?? '';
    inp.onchange = () => {
      const v = field.type === 'number' ? (inp.value ? Number(inp.value) : undefined) : (inp.value || undefined);
      if (v !== undefined) configDirty[field.key] = v; else delete configDirty[field.key];
    };
    row.append(label, inp);
    scalarSection.appendChild(row);
  }
  for (const field of BOOL_FIELDS) {
    const row = ce('div'); row.className = 'scalar-row';
    const label = ce('label'); label.textContent = field.label;
    const sel = ce('select');
    const optU = ce('option'); optU.value = ''; optU.textContent = '(default)';
    const optT = ce('option'); optT.value = 'true'; optT.textContent = 'true';
    const optF = ce('option'); optF.value = 'false'; optF.textContent = 'false';
    sel.append(optU, optT, optF);
    if (configDirty[field.key] === true) sel.value = 'true';
    else if (configDirty[field.key] === false) sel.value = 'false';
    else sel.value = '';
    sel.onchange = () => {
      if (sel.value === 'true') configDirty[field.key] = true;
      else if (sel.value === 'false') configDirty[field.key] = false;
      else delete configDirty[field.key];
    };
    row.append(label, sel);
    scalarSection.appendChild(row);
  }
  container.appendChild(scalarSection);
}

function createTag(fieldKey, value) {
  const tag = ce('span'); tag.className = 'tag';
  const text = ce('span'); text.textContent = value;
  const rm = ce('span'); rm.className = 'remove'; rm.textContent = '×';
  rm.onclick = () => {
    configDirty[fieldKey] = (configDirty[fieldKey] || []).filter(v => v !== value);
    tag.remove();
  };
  tag.append(text, rm);
  return tag;
}

function addValue(fieldKey, input, isRegex) {
  const val = input.value.trim();
  if (!val) return;
  if (isRegex) {
    try { new RegExp(val); } catch (e) { showStatus('config-status', 'Invalid regex: ' + e.message, 'error'); return; }
  }
  if (!configDirty[fieldKey]) configDirty[fieldKey] = [];
  if (configDirty[fieldKey].includes(val)) { input.value = ''; return; }
  configDirty[fieldKey].push(val);
  const tagList = $('#tags-' + fieldKey);
  tagList.appendChild(createTag(fieldKey, val));
  input.value = '';
}

async function loadConfig() {
  if (!token) return;
  try {
    const data = await api('/api/config');
    renderConfig(data);
  } catch (e) {
    showStatus('config-status', e.message, 'error');
  }
}

$('#validate-btn').onclick = async () => {
  try {
    const result = await api('/api/config/validate', { method: 'POST', body: { config: configDirty } });
    if (result.valid) {
      showStatus('config-status', 'Configuration is valid' + (result.warnings ? ' (' + result.warnings.length + ' warnings)' : ''), 'success');
    } else {
      showStatus('config-status', 'Validation failed: ' + result.errors.map(e => e.field + ': ' + e.message).join('; '), 'error');
    }
  } catch (e) { showStatus('config-status', e.message, 'error'); }
};

$('#save-btn').onclick = async () => {
  try {
    const result = await api('/api/config', {
      method: 'PUT',
      body: { config: configDirty, revision: configData.revision },
    });
    showStatus('config-status', 'Saved successfully (rev: ' + result.revision + ')', 'success');
    configData.revision = result.revision;
    $('#config-revision').textContent = 'rev: ' + result.revision;
  } catch (e) {
    if (e.message === 'revision mismatch') {
      showStatus('config-status', 'Config was modified externally. Reloading...', 'warn');
      loadConfig();
    } else {
      showStatus('config-status', e.message, 'error');
    }
  }
};

/* ── Utilities ── */
function showStatus(id, msg, type) {
  const el = $('#' + id);
  el.textContent = msg;
  el.className = 'status-msg ' + type;
  if (type === 'success') setTimeout(() => { el.className = 'status-msg'; }, 4000);
}

/* ── Init ── */
updateTokenDisplay();
startComponentPolling();
if (token) { loadComponentStatuses(); loadBlocks(); loadConfig(); }
})();
</script>
</body>
</html>`;
}

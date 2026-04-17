// ── helpers ──────────────────────────────────────────────────────────────────

const SKILL_CLASS = {
  rspamd_scan_email:           'skill-rspamd',
  email_header_auth_check:     'skill-header',
  urgency_check:               'skill-urgency',
  url_reputation_check:        'skill-url',
  error_pattern_memory_check:  'skill-memory',
};

const SKILL_DONE_DOT = {
  rspamd_scan_email:           'done-purple',
  email_header_auth_check:     'done-green',
  urgency_check:               'done-amber',
  url_reputation_check:        'done-red',
  error_pattern_memory_check:  'done-slate',
};

const VERDICT_DISPLAY = {
  benign:               { label: '✓ BENIGN',    cls: 'benign' },
  suspicious:           { label: '⚠ SUSPICIOUS', cls: 'suspicious' },
  phishing_or_spoofing: { label: '⚠ PHISHING',  cls: 'phishing_or_spoofing' },
  error:                { label: '✕ ERROR',      cls: 'error' },
};

function verdictBadgeHtml(verdict) {
  if (!verdict) return '<span class="badge badge-none">—</span>';
  const map = {
    benign:               'badge badge-benign',
    suspicious:           'badge badge-suspicious',
    phishing_or_spoofing: 'badge badge-phishing',
    error:                'badge badge-error',
  };
  const labels = { benign: 'BENIGN', suspicious: 'SUSPICIOUS', phishing_or_spoofing: 'PHISHING', error: 'ERROR' };
  const cls = map[verdict] || 'badge badge-none';
  const text = labels[verdict] || verdict.toUpperCase();
  return `<span class="${cls}">${text}</span>`;
}

// ── state ────────────────────────────────────────────────────────────────────

let activeUid = null;
let activeEventSource = null;
const skillNodes = {};   // uid → { skillName → {dotEl, cardEl} }

// ── inbox ────────────────────────────────────────────────────────────────────

async function loadEmails() {
  const resp = await fetch('/api/emails');
  const emails = await resp.json();

  const list = document.getElementById('inbox-list');
  const header = document.getElementById('inbox-header');
  header.textContent = `INBOX · ${emails.length} messages`;

  if (emails.length === 0) {
    list.innerHTML = '<div style="padding:16px;color:#334155;font-size:11px;">No emails found</div>';
    return;
  }

  list.innerHTML = emails.map(e => `
    <div class="email-row" data-uid="${e.uid}" onclick="selectEmail(${e.uid}, ${JSON.stringify(e).replace(/"/g, '&quot;')})">
      <div class="row-top">
        <span class="subject ${e.analyzed ? '' : 'unread'}">${escHtml(e.subject)}</span>
        ${verdictBadgeHtml(e.final_verdict)}
      </div>
      <div class="sender">${escHtml(e.from_address)}</div>
    </div>
  `).join('');

  updateStatus();
}

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function updateStatus() {
  const resp = await fetch('/api/status');
  const data = await resp.json();
  const dot = document.getElementById('status-dot');
  const label = document.getElementById('account-label');
  dot.className = data.monitor_running ? 'connected' : '';
  label.textContent = data.monitor_running ? 'monitor running' : 'monitor stopped';
  const addrs = data.mailbox_addresses || [];
  const addrEl = document.getElementById('mailbox-address');
  if (addrEl) addrEl.textContent = addrs.length ? addrs.join(', ') : '';
}

// ── email selection ──────────────────────────────────────────────────────────

function selectEmail(uid, emailData) {
  if (activeEventSource) {
    activeEventSource.close();
    activeEventSource = null;
  }
  activeUid = uid;

  // Highlight selected row
  document.querySelectorAll('.email-row').forEach(r => r.classList.remove('selected'));
  const row = document.querySelector(`.email-row[data-uid="${uid}"]`);
  if (row) row.classList.add('selected');

  // Show analysis panel
  document.getElementById('analysis-empty').style.display = 'none';
  const content = document.getElementById('analysis-content');
  content.classList.add('visible');

  // Set header
  document.getElementById('email-subject').textContent = emailData.subject || '(no subject)';
  document.getElementById('email-meta').textContent =
    `From: ${emailData.from_address || ''}`;

  // Reset panels
  resetAnalysisPanel();

  // Start streaming
  streamAnalysis(uid);
}

function resetAnalysisPanel() {
  // Clear timeline (keep label)
  const timeline = document.getElementById('timeline');
  timeline.innerHTML = '<div class="timeline-section-label">ANALYSIS</div>';
  skillNodes[activeUid] = {};

  // Hide/reset reasoning
  const rb = document.getElementById('reasoning-box');
  rb.textContent = '';
  rb.classList.remove('visible');

  // Hide verdict
  const vb = document.getElementById('verdict-bar');
  vb.className = '';
  vb.style.display = 'none';

  // Hide body
  const bs = document.getElementById('body-section');
  bs.classList.remove('visible');
  document.getElementById('body-content').textContent = '';
  document.getElementById('body-content').classList.remove('blurred');
  document.getElementById('body-overlay').classList.add('hidden');
}

// ── SSE streaming ────────────────────────────────────────────────────────────

function streamAnalysis(uid) {
  const es = new EventSource(`/api/stream/${uid}`);
  activeEventSource = es;

  es.onmessage = (event) => {
    const data = JSON.parse(event.data);
    handleEvent(uid, data);
    if (data.type === 'agent_complete' || data.type === 'done' || data.type === 'error') {
      es.close();
      activeEventSource = null;
      if (data.type === 'agent_complete') {
        loadEmailBody(uid, data.verdict);
        refreshInboxBadge(uid, data.verdict);
      }
    }
  };

  es.onerror = () => {
    es.close();
    activeEventSource = null;
  };
}

function handleEvent(uid, data) {
  if (uid !== activeUid) return;

  switch (data.type) {
    case 'skill_start':
      addSkillNode(uid, data.skill, 'running');
      break;
    case 'skill_complete':
      completeSkillNode(uid, data.skill, data.ok, data.summary || '');
      break;
    case 'reasoning_text':
      showReasoning(data.text);
      break;
    case 'agent_complete':
      if (data.cached) {
        showCachedResult(data);
      } else {
        showVerdict(data.verdict, data.elapsed_ms);
      }
      break;
    case 'error':
      showError(data.message);
      break;
  }
}

// ── timeline nodes ───────────────────────────────────────────────────────────

function addSkillNode(uid, skillName, state) {
  const nodes = skillNodes[uid] || (skillNodes[uid] = {});
  if (nodes[skillName]) return;  // already added

  const timeline = document.getElementById('timeline');
  const skillCls = SKILL_CLASS[skillName] || 'skill-memory';

  const wrapper = document.createElement('div');
  wrapper.style.display = 'flex';
  wrapper.style.flexDirection = 'column';

  const nodeEl = document.createElement('div');
  nodeEl.className = 'skill-node';

  const connEl = document.createElement('div');
  connEl.className = 'skill-node-connector';

  const dotEl = document.createElement('div');
  dotEl.className = `skill-dot ${state}`;

  const lineEl = document.createElement('div');
  lineEl.className = 'connector-line';

  connEl.appendChild(dotEl);
  connEl.appendChild(lineEl);

  const cardEl = document.createElement('div');
  cardEl.className = `skill-card ${skillCls} ${state}`;
  cardEl.innerHTML = `<div class="skill-name">${escHtml(skillName)}</div><div class="skill-result"></div>`;

  nodeEl.appendChild(connEl);
  nodeEl.appendChild(cardEl);
  wrapper.appendChild(nodeEl);
  timeline.appendChild(wrapper);

  nodes[skillName] = { dotEl, cardEl };
}

function completeSkillNode(uid, skillName, ok, summary) {
  const nodes = skillNodes[uid] || {};
  if (!nodes[skillName]) {
    addSkillNode(uid, skillName, 'running');
  }
  const { dotEl, cardEl } = nodes[skillName];
  const skillCls = SKILL_CLASS[skillName] || 'skill-memory';
  const dotCls = ok ? (SKILL_DONE_DOT[skillName] || 'done-slate') : 'done-error';

  dotEl.className = `skill-dot ${dotCls}`;
  dotEl.textContent = ok ? '✓' : '✕';

  cardEl.className = `skill-card ${skillCls} done`;
  cardEl.querySelector('.skill-result').textContent = summary;
}

// ── reasoning ────────────────────────────────────────────────────────────────

function showReasoning(text) {
  const rb = document.getElementById('reasoning-box');
  rb.classList.add('visible');
  rb.textContent = text;
}

// ── verdict ───────────────────────────────────────────────────────────────────

function showVerdict(verdict, elapsedMs) {
  const vb = document.getElementById('verdict-bar');
  const info = VERDICT_DISPLAY[verdict] || { label: verdict.toUpperCase(), cls: 'error' };
  vb.className = `visible ${info.cls}`;
  vb.style.display = 'flex';
  document.getElementById('verdict-label').textContent = info.label;
  document.getElementById('verdict-meta').textContent =
    elapsedMs ? `${(elapsedMs / 1000).toFixed(1)}s` : '';
}

function showCachedResult(data) {
  const rb = document.getElementById('reasoning-box');
  if (data.summary) {
    rb.textContent = data.summary;
    rb.classList.add('visible');
  }
  showVerdict(data.verdict, 0);
}

function showError(message) {
  const rb = document.getElementById('reasoning-box');
  rb.textContent = `Error: ${message}`;
  rb.classList.add('visible');
  rb.style.borderLeftColor = '#dc2626';
}

// ── email body ────────────────────────────────────────────────────────────────

async function loadEmailBody(uid, verdict) {
  const resp = await fetch(`/api/email/${uid}/raw`);
  if (!resp.ok) return;
  const data = await resp.json();

  const bodySection = document.getElementById('body-section');
  const bodyContent = document.getElementById('body-content');
  const overlay = document.getElementById('body-overlay');
  const overlayLabel = document.getElementById('body-overlay-label');

  bodyContent.textContent = data.body || '(empty body)';
  bodySection.classList.add('visible');

  const blur = verdict === 'suspicious' || verdict === 'phishing_or_spoofing';
  if (blur) {
    bodyContent.classList.add('blurred');
    overlay.classList.remove('hidden');
    overlayLabel.textContent =
      verdict === 'phishing_or_spoofing'
        ? '⚠ Blurred — classified as phishing'
        : '⚠ Blurred — classified as suspicious';
  }
}

document.getElementById('reveal-btn').addEventListener('click', () => {
  document.getElementById('body-content').classList.remove('blurred');
  document.getElementById('body-overlay').classList.add('hidden');
});

// ── inbox badge refresh ───────────────────────────────────────────────────────

function refreshInboxBadge(uid, verdict) {
  const row = document.querySelector(`.email-row[data-uid="${uid}"]`);
  if (!row) return;
  const badgeEl = row.querySelector('.badge');
  if (badgeEl) badgeEl.outerHTML = verdictBadgeHtml(verdict);
  row.querySelector('.subject')?.classList.remove('unread');
}

// ── init ─────────────────────────────────────────────────────────────────────

loadEmails();

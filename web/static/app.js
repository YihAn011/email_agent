// ── helpers ──────────────────────────────────────────────────────────────────

const SKILL_CLASS = {
  rspamd_scan_email: 'skill-rspamd',
  email_header_auth_check: 'skill-header',
  urgency_check: 'skill-urgency',
  url_reputation_check: 'skill-url',
  error_pattern_memory_check: 'skill-memory',
  puter_openai_browser: 'skill-memory',
};

const SKILL_DONE_DOT = {
  rspamd_scan_email: 'done-purple',
  email_header_auth_check: 'done-green',
  urgency_check: 'done-amber',
  url_reputation_check: 'done-red',
  error_pattern_memory_check: 'done-slate',
  puter_openai_browser: 'done-purple',
};

const VERDICT_DISPLAY = {
  benign: { label: '✓ BENIGN', cls: 'benign' },
  suspicious: { label: '⚠ SUSPICIOUS', cls: 'suspicious' },
  phishing_or_spoofing: { label: '⚠ PHISHING', cls: 'phishing_or_spoofing' },
  error: { label: '✕ ERROR', cls: 'error' },
};

const PUTER_PROVIDER = 'puter-openai';
const SERVER_PROVIDER = 'server-agent';
const PUTER_DEFAULT_MODEL = 'gpt-5.4';

function escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function verdictBadgeHtml(verdict) {
  if (!verdict) return '<span class="badge badge-none">—</span>';
  const map = {
    benign: 'badge badge-benign',
    suspicious: 'badge badge-suspicious',
    phishing_or_spoofing: 'badge badge-phishing',
    error: 'badge badge-error',
  };
  const labels = {
    benign: 'BENIGN',
    suspicious: 'SUSPICIOUS',
    phishing_or_spoofing: 'PHISHING',
    error: 'ERROR',
  };
  const cls = map[verdict] || 'badge badge-none';
  const text = labels[verdict] || verdict.toUpperCase();
  return `<span class="${cls}">${text}</span>`;
}

function currentAnalyzer() {
  return document.getElementById('model-provider').value || SERVER_PROVIDER;
}

function currentModel() {
  const explicit = document.getElementById('model-name').value.trim();
  if (explicit) return explicit;
  return currentAnalyzer() === PUTER_PROVIDER ? PUTER_DEFAULT_MODEL : '';
}

function storeModelPreferences() {
  localStorage.setItem('mail_analyzer_provider', currentAnalyzer());
  localStorage.setItem('mail_analyzer_model', currentModel());
}

function defaultModelFor(provider) {
  return provider === PUTER_PROVIDER ? PUTER_DEFAULT_MODEL : '';
}

function readQueryConfig() {
  const params = new URLSearchParams(window.location.search);
  return {
    provider: params.get('provider') || '',
    model: params.get('model') || '',
  };
}

function initModelControls() {
  const providerEl = document.getElementById('model-provider');
  const modelEl = document.getElementById('model-name');
  const hintEl = document.getElementById('provider-hint');
  const query = readQueryConfig();
  const savedProvider = localStorage.getItem('mail_analyzer_provider') || '';
  const savedModel = localStorage.getItem('mail_analyzer_model') || '';
  const provider = query.provider || savedProvider || SERVER_PROVIDER;
  const model = query.model || savedModel || defaultModelFor(provider);

  providerEl.value = provider;
  modelEl.value = model;
  syncProviderHint();

  providerEl.addEventListener('change', () => {
    if (!modelEl.value.trim()) {
      modelEl.value = defaultModelFor(providerEl.value);
    }
    syncProviderHint();
    storeModelPreferences();
  });

  modelEl.addEventListener('change', storeModelPreferences);
  modelEl.addEventListener('blur', storeModelPreferences);

  hintEl.title = 'Puter OpenAI requires internet access and runs in the browser session.';
}

function syncProviderHint() {
  const hintEl = document.getElementById('provider-hint');
  if (currentAnalyzer() === PUTER_PROVIDER) {
    hintEl.textContent = 'Puter OpenAI runs in-browser and may prompt for sign-in.';
    if (!document.getElementById('model-name').value.trim()) {
      document.getElementById('model-name').value = PUTER_DEFAULT_MODEL;
    }
    return;
  }
  hintEl.textContent = 'Server Agent uses the backend Gemini/Ollama runtime.';
}

function extractVerdict(text) {
  const match = text.match(/verdict\s*:\s*(benign|suspicious|phishing_or_spoofing)/i);
  if (match) return match[1].toLowerCase();
  const lower = text.toLowerCase();
  if (lower.includes('phishing') || lower.includes('spoof')) return 'phishing_or_spoofing';
  if (lower.includes('suspicious')) return 'suspicious';
  if (lower.includes('benign') || lower.includes('legitimate') || lower.includes('safe')) return 'benign';
  return 'suspicious';
}

function buildPuterPrompt(email) {
  return [
    'You are an email security analyst.',
    'Analyze the raw RFC822 email below for phishing, spoofing, fraud, urgency abuse, and malicious links.',
    'Reply in plain text using exactly this structure:',
    'Verdict: benign|suspicious|phishing_or_spoofing',
    'Confidence: low|medium|high',
    'Summary: one concise paragraph',
    'Signals:',
    '- bullet 1',
    '- bullet 2',
    '- bullet 3',
    '',
    `Subject: ${email.subject || '(no subject)'}`,
    `From: ${email.from_address || ''}`,
    '',
    'Raw email:',
    email.raw_email || '',
  ].join('\n');
}

// ── state ────────────────────────────────────────────────────────────────────

let activeUid = null;
let activeEventSource = null;
let activeAnalysisToken = 0;
const skillNodes = {};

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

  list.innerHTML = emails.map((e) => `
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

function stopActiveAnalysis() {
  activeAnalysisToken += 1;
  if (activeEventSource) {
    activeEventSource.close();
    activeEventSource = null;
  }
}

function selectEmail(uid, emailData) {
  stopActiveAnalysis();
  activeUid = uid;

  document.querySelectorAll('.email-row').forEach((r) => r.classList.remove('selected'));
  const row = document.querySelector(`.email-row[data-uid="${uid}"]`);
  if (row) row.classList.add('selected');

  document.getElementById('analysis-empty').style.display = 'none';
  const content = document.getElementById('analysis-content');
  content.classList.add('visible');

  document.getElementById('email-subject').textContent = emailData.subject || '(no subject)';
  document.getElementById('email-meta').textContent = `From: ${emailData.from_address || ''}`;

  resetAnalysisPanel();
  streamAnalysis(uid);
}

function resetAnalysisPanel() {
  const timeline = document.getElementById('timeline');
  timeline.innerHTML = '<div class="timeline-section-label">ANALYSIS</div>';
  skillNodes[activeUid] = {};

  const rb = document.getElementById('reasoning-box');
  rb.textContent = '';
  rb.classList.remove('visible');
  rb.style.borderLeftColor = '#334155';

  const vb = document.getElementById('verdict-bar');
  vb.className = '';
  vb.style.display = 'none';

  const bs = document.getElementById('body-section');
  bs.classList.remove('visible');
  document.getElementById('body-content').textContent = '';
  document.getElementById('body-content').classList.remove('blurred');
  document.getElementById('body-overlay').classList.add('hidden');
}

// ── analysis dispatch ────────────────────────────────────────────────────────

function streamAnalysis(uid) {
  if (currentAnalyzer() === PUTER_PROVIDER) {
    streamPuterAnalysis(uid, activeAnalysisToken);
    return;
  }
  streamServerAnalysis(uid);
}

function streamServerAnalysis(uid) {
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

async function streamPuterAnalysis(uid, token) {
  addSkillNode(uid, 'puter_openai_browser', 'running');
  showReasoning('Connecting to Puter OpenAI...');

  try {
    const emailResp = await fetch(`/api/email/${uid}/source`);
    if (!emailResp.ok) {
      throw new Error('Unable to load raw email source for browser analysis.');
    }
    const email = await emailResp.json();
    if (token !== activeAnalysisToken) return;

    if (!window.puter || !window.puter.ai || typeof window.puter.ai.chat !== 'function') {
      throw new Error('Puter SDK did not load. Check network access and reload the analyzer.');
    }

    const startedAt = Date.now();
    const prompt = buildPuterPrompt(email);
    let output = '';
    const response = await window.puter.ai.chat(prompt, {
      model: currentModel() || PUTER_DEFAULT_MODEL,
      stream: true,
      temperature: 0,
    });

    for await (const part of response) {
      if (token !== activeAnalysisToken) return;
      output += part?.text || '';
      showReasoning(output.trim() || 'Waiting for model output...');
    }

    if (token !== activeAnalysisToken) return;

    const verdict = extractVerdict(output);
    completeSkillNode(
      uid,
      'puter_openai_browser',
      true,
      `model ${currentModel() || PUTER_DEFAULT_MODEL} · browser analysis`
    );
    showVerdict(verdict, Date.now() - startedAt);
    refreshInboxBadge(uid, verdict);
    loadEmailBody(uid, verdict);
  } catch (error) {
    if (token !== activeAnalysisToken) return;
    completeSkillNode(uid, 'puter_openai_browser', false, String(error?.message || error));
    showError(error?.message || String(error));
  }
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
  if (nodes[skillName]) return;

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

// ── verdict ──────────────────────────────────────────────────────────────────

function showVerdict(verdict, elapsedMs) {
  const vb = document.getElementById('verdict-bar');
  const info = VERDICT_DISPLAY[verdict] || { label: verdict.toUpperCase(), cls: 'error' };
  vb.className = `visible ${info.cls}`;
  vb.style.display = 'flex';
  document.getElementById('verdict-label').textContent = info.label;
  document.getElementById('verdict-meta').textContent = elapsedMs ? `${(elapsedMs / 1000).toFixed(1)}s` : '';
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

// ── email body ───────────────────────────────────────────────────────────────

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

// ── inbox badge refresh ──────────────────────────────────────────────────────

function refreshInboxBadge(uid, verdict) {
  const row = document.querySelector(`.email-row[data-uid="${uid}"]`);
  if (!row) return;
  const badgeEl = row.querySelector('.badge');
  if (badgeEl) {
    badgeEl.outerHTML = verdictBadgeHtml(verdict);
  }
  row.querySelector('.subject')?.classList.remove('unread');
}

// ── init ─────────────────────────────────────────────────────────────────────

initModelControls();
loadEmails();

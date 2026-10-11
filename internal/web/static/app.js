'use strict';

// ---- tiny DOM helper (always text nodes, never innerHTML) --------------------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

async function api(method, path, body) {
  const r = await fetch(path, {
    method, credentials: 'same-origin',
    headers: Object.assign({ 'X-Certsmith': '1' }, body ? { 'Content-Type': 'application/json' } : {}),
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (!r.ok) {
    const msg = (data && data.error) || r.statusText;
    // an expired session or a fresh install sends the user to the right screen
    if (r.status === 401 && !path.startsWith('/api/login')) { showAuth('login'); throw new Error('Please sign in'); }
    if (r.status === 403 && /setup required/.test(msg) && !path.startsWith('/api/login')) { showAuth('setup'); throw new Error('Setup required'); }
    const err = new Error(msg);
    err.data = data; err.status = r.status;
    throw err;
  }
  return data;
}

let toastTimer;
// ms is how long it stays; 0 keeps it until the next message replaces it (for work in progress).
function toast(msg, bad, ms) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer);
  if (ms === 0) return;
  toastTimer = setTimeout(() => { t.className = ''; }, ms || (bad ? 6000 : 2800));
}

// ---- state --------------------------------------------------------------------
let S = null;        // database snapshot (secrets masked)
let me = '';         // signed-in user
let users = [];      // all users (names only)
let schema = null;   // plugin descriptors
let view = 'overview';
let appVersion = '', updateInfo = null; // what the server says about this build and newer releases
let modalOpen = false;

const zero = d => !d || String(d).startsWith('0001-');
const daysLeft = d => Math.floor((new Date(d) - Date.now()) / 864e5);
const fmt = d => zero(d) ? 'never' : new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const ago = d => {
  if (zero(d)) return 'never';
  const s = Math.max(0, (Date.now() - new Date(d)) / 1000);
  if (s < 90) return 'just now';
  if (s < 5400) return Math.round(s / 60) + ' min ago';
  if (s < 129600) return Math.round(s / 3600) + ' h ago';
  return Math.round(s / 86400) + ' d ago';
};
const spinner = () => h('span', { class: 'spin', 'aria-hidden': 'true' });
const openLogs = new Set(); // certificates whose log panel the user has opened
const byId = (list, id) => (list || []).find(x => x.id === id);

function expiryClass(days) {
  if (days <= 7) return 'bad';
  if (days <= S.settings.warn_days) return 'warn';
  return '';
}

// A background refresh must never rebuild a page the person is editing: that would
// wipe whatever they are typing or pasting. The Settings page is all forms, and any
// page with a box that has focus counts as being edited.
function userIsEditing() {
  if (view === 'settings') return true;
  const a = document.activeElement;
  return !!a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) && document.getElementById('view').contains(a);
}

// opts.background marks the automatic timer; refreshes caused by a click always redraw.
let lastSig = '';
async function refresh(opts) {
  try {
    const res = await api('GET', '/api/state');
    // The automatic refresh redraws only when something changed (or once a minute, so "3 h ago" stays true).
    // A redraw rebuilds the whole page, which is what made it jump while certificates were issuing.
    const sig = JSON.stringify([res.db, res.me, res.users, res.ui_cert]);
    const unchanged = sig === lastSig && Date.now() - lastRenderAt < 60000;
    if (opts && opts.background && unchanged) return;
    S = res.db;
    me = res.me || ''; users = res.users || [];
    uiCert = res.ui_cert || {};
    appVersion = res.version || '';
    updateInfo = res.update || null;
    for (const k of ['dns_providers', 'certificates', 'targets', 'events', 'pending_dns']) S[k] = S[k] || [];
    if (!schema) schema = await api('GET', '/api/schema');
    if (!modalOpen && !authing && !(opts && opts.background && userIsEditing())) { render(); lastSig = sig; }
  } catch (e) { if (!authing) toast(e.message, true); }
}

// ---- sign in / first-run setup ------------------------------------------------------
let authing = false;

function authCard(...kids) {
  return h('div', { class: 'authwrap' }, h('div', { class: 'authcard' },
    h('div', { class: 'row', style: 'justify-content:center;margin-bottom:4px' },
      h('img', { class: 'logo', src: 'favicon.svg', alt: '', width: 30, height: 30 }), h('h1', { style: 'margin:0' }, 'CertSmith')),
    ...kids));
}

function showAuth(mode) {
  authing = true; modalOpen = false; S = null;
  document.body.classList.add('authing');
  document.getElementById('modal-root').replaceChildren();
  const view = document.getElementById('view');
  if (mode === 'setup') renderWizard(view); else renderLogin(view);
}

function renderLogin(view) {
  const user = h('input', { type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', 'aria-label': 'Username' });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'Password' });
  const msg = h('div', { class: 'err', style: 'min-height:20px;margin:4px 0 8px' });
  const btn = h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, 'Sign in');
  view.replaceChildren(authCard(
    h('p', { class: 'sub', style: 'text-align:center' }, 'Sign in to continue.'),
    h('form', {
      onsubmit: async e => {
        e.preventDefault(); msg.textContent = ''; btn.disabled = true;
        try {
          await api('POST', '/api/login', { username: user.value, password: pw.value });
          pw.value = ''; enterApp();
        } catch (err) { msg.textContent = err.message; } finally { btn.disabled = false; }
      },
    },
      h('div', { class: 'field' }, h('label', {}, 'Username'), user),
      h('div', { class: 'field' }, h('label', {}, 'Password'), revealWrap(pw)), msg, btn)));
  user.focus();
}

// First-run wizard. Step 1 creates the first user; step 2 collects the one setting
// issuance cannot work without, the ACME account email.
function renderWizard(view) {
  const dots = n => h('div', { class: 'steps' }, [1, 2].map(i => h('span', { class: 'step' + (i === n ? ' on' : i < n ? ' done' : '') }, i)),
    h('span', { class: 'meta' }, n === 1 ? 'Create your account' : 'Certificate authority'));
  const step1 = () => {
    const user = h('input', { type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', placeholder: 'e.g. admin' });
    const pw = h('input', { type: 'password', autocomplete: 'new-password' });
    const pw2 = h('input', { type: 'password', autocomplete: 'new-password' });
    const msg = h('div', { class: 'err', style: 'min-height:20px;margin:4px 0 8px' });
    const btn = h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, 'Continue');
    const card = authCard(dots(1),
      h('p', { class: 'sub', style: 'text-align:center' }, 'Create the first administrator account. Further users can be added later under Settings.'),
      h('form', {
        onsubmit: async e => {
          e.preventDefault(); msg.textContent = '';
          if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$/.test(user.value.trim())) { msg.textContent = 'Username: 2-32 letters, digits, dot, dash or underscore.'; return; }
          if (pw.value.length < 12) { msg.textContent = 'Use at least 12 characters for the password.'; return; }
          if (pw.value !== pw2.value) { msg.textContent = 'The two passwords do not match.'; return; }
          btn.disabled = true;
          try {
            await api('POST', '/api/setup', { username: user.value.trim(), password: pw.value });
            pw.value = pw2.value = '';
            view.replaceChildren(step2());
            view.querySelector('input').focus();
          } catch (err) { msg.textContent = err.message; } finally { btn.disabled = false; }
        },
      },
        h('div', { class: 'field' }, h('label', {}, 'Username'), user),
        h('div', { class: 'field' }, h('label', {}, 'Password (12+ characters)'), revealWrap(pw)),
        h('div', { class: 'field' }, h('label', {}, 'Confirm password'), revealWrap(pw2)), msg, btn,
        h('p', { class: 'meta', style: 'margin-top:14px' }, 'This screen works once. Until you finish it, anyone who can reach this page could create the first user, so complete it now.')));
    return card;
  };
  const step2 = () => {
    const email = h('input', { type: 'email', autocomplete: 'email', placeholder: 'you@example.com', spellcheck: 'false' });
    const mode = h('select', {}, h('option', { value: 'production' }, 'Real certificates (production)'),
      h('option', { value: 'staging' }, 'Test certificates (staging, not trusted by browsers)'));
    const msg = h('div', { class: 'err', style: 'min-height:20px;margin:4px 0 8px' });
    const btn = h('button', { class: 'btn primary', type: 'submit', style: 'width:100%' }, 'Finish setup');
    return authCard(dots(2),
      h('p', { class: 'sub', style: 'text-align:center' }, 'Enter the contact email address for the Let\'s Encrypt account. Certificates are requested from Let\'s Encrypt.'),
      h('form', {
        onsubmit: async e => {
          e.preventDefault(); msg.textContent = '';
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.value.trim())) { msg.textContent = 'Enter a valid email address.'; return; }
          btn.disabled = true;
          try {
            const cur = (await api('GET', '/api/state')).db.settings;
            cur.acme_email = email.value.trim(); cur.acme_directory = mode.value;
            await api('PUT', '/api/settings', cur);
            enterApp();
          } catch (err) { msg.textContent = err.message; btn.disabled = false; }
        },
      },
        h('div', { class: 'field' }, h('label', {}, 'Email address'), email,
          h('div', { class: 'help' }, 'Let\'s Encrypt uses it for expiry warnings if renewals ever stop working.')),
        h('div', { class: 'field' }, h('label', {}, 'Start with'), mode,
          h('div', { class: 'help' }, 'Real certificates are trusted by browsers. Choose test certificates only to practise: they are not trusted, and you can switch to real ones later in Settings (existing certificates are reissued automatically).')),
        msg, btn,
        h('p', { class: 'meta', style: 'margin-top:14px;text-align:center' }, h('a', { href: '#', onclick: e => { e.preventDefault(); enterApp(); } }, 'Skip for now'), ' (you will be reminded until it is set)')));
  };
  view.replaceChildren(step1());
  view.querySelector('input').focus();
}

function enterApp() {
  authing = false;
  document.body.classList.remove('authing');
  document.getElementById('view').replaceChildren(h('p', { class: 'sub' }, 'Loading…'));
  refresh();
}

async function boot() {
  try {
    const s = await api('GET', '/api/session');
    if (s.state === 'ok') enterApp(); else showAuth(s.state);
  } catch (e) { toast(e.message, true); }
}

// ---- layout ---------------------------------------------------------------------
const TABS = [['overview', 'Certificates'], ['targets', 'Targets'], ['dns', 'Certificate providers'], ['settings', 'Settings'], ['events', 'Events']];

// "v0.12.2" and "0.12.2" are the same version; the builds of this program carry "+commit" after it.
const plainVersion = v => String(v || '').replace(/^v/, '').split('+')[0];
const safeLink = u => (typeof u === 'string' && /^https:\/\/[^\s"'<>]+$/.test(u)) ? u : '';

function renderFooter() {
  const f = document.getElementById('appfoot');
  if (!f) return;
  const kids = [h('span', {}, 'CertSmith' + (appVersion ? ' ' + plainVersion(appVersion) : ''))];
  if (updateInfo && updateInfo.available) {
    kids.push(' · ', h('a', { href: '#', onclick: e => { e.preventDefault(); view = 'settings'; render(); } },
      'Version ' + plainVersion(updateInfo.latest) + ' is available'));
  }
  kids.push(' · ', h('a', { href: 'THIRD_PARTY_NOTICES.txt', target: '_blank', rel: 'noopener' }, 'Third-party licences'));
  f.replaceChildren(...kids);
}

let lastView = null, lastRenderAt = 0;
function render() {
  // The same page redrawn (the automatic refresh): keep the reader's place. A different page starts at the top.
  const keepY = lastView === view ? window.scrollY : 0;
  document.getElementById('logout-btn').textContent = me ? 'Sign out (' + me + ')' : 'Sign out';
  const nav = document.getElementById('nav');
  nav.replaceChildren(...TABS.map(([id, label]) =>
    h('button', { class: view === id ? 'on' : '', onclick: () => { view = id; render(); } }, label)));
  const v = document.getElementById('view');
  const fn = { overview: renderOverview, targets: renderTargets, dns: renderDNS, settings: renderSettings, events: renderEvents }[view];
  v.replaceChildren(fn());
  renderFooter();
  lastView = view; lastRenderAt = Date.now();
  window.scrollTo(0, keepY);
}

// a certificate issued from a different ACME directory than the selected one is replaced by the scheduler
function reissueDirection(c) {
  if (!c.serial) return false;
  const from = c.issued_directory || ((c.issuer || '').includes('STAGING') ? 'staging' : '');
  return !!from && from !== effectiveDir(c);
}

function chipTitled(text, cls, title) { const c = chip(text, cls); c.title = title; return c; }

function chip(text, cls) { return h('span', { class: 'chip ' + (cls || '') }, text); }

// ---- overview ---------------------------------------------------------------------
function targetStatus(t, c) {
  if (!t.enabled) return chip('disabled');
  if (t.kind === 'watch') return chip('monitoring');
  if (t.last_error) return chip('deploy failed', 'bad');
  if (!c || !c.serial) return chip('waiting for certificate', 'warn');
  if (t.paused) return chipTitled(t.deployed_serial !== c.serial ? 'paused: new certificate waiting' : 'paused', 'warn',
    'Automatic deployment is paused. Renewals are still issued but are not pushed to this device until you resume.');
  if (t.deployed_serial !== c.serial) return t.auto_deploy ? chip('pending', 'warn') : chip('ready: press Deploy', 'info');
  return chip('deployed', 'ok');
}

// The device's IP or domain, as shown to people: host (and the port when it is not the usual one).
function targetAddress(t) {
  const c = t.config || {};
  const usual = { fortigate: '443', fortimanager: '443', fortianalyzer: '443', pve: '8006' }[t.kind];
  if (c.host) {
    let host = c.host.trim(), port = (c.port || '').trim();
    const m = /^([^:\[\]]+):(\d+)$/.exec(host); // "host:port" typed into the host box by an older version
    if (m) { host = m[1]; port = port || m[2]; }
    return host + (port && port !== usual ? ':' + port : '');
  }
  if (c.url) { try { return new URL(c.url).host; } catch (_) { return c.url; } }
  if (t.kind === 'files') return 'this server: ' + (c.dir || '');
  if (t.kind === 'selfui') return schema.hostname || 'this server';
  const watch = (c.verify || '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
  return watch.length ? watch[0] + (watch.length > 1 ? ' +' + (watch.length - 1) : '') : '';
}

// What a failed live check means, in words. The raw error stays visible underneath, because the
// address and the exact cause are what somebody troubleshooting needs.
function describeProbeError(err) {
  const e = String(err || '');
  if (/i\/o timeout|timed out|deadline exceeded/i.test(e)) return 'No answer: the connection timed out. The device may be switched off, or something is blocking the port.';
  if (/connection refused/i.test(e)) return 'The device refused the connection: nothing is listening on that port.';
  if (/no route to host|network is unreachable/i.test(e)) return 'No route to the device. Check its address and the network path.';
  if (/no such host|server misbehaving|lookup /i.test(e)) return 'The name could not be resolved in DNS.';
  if (/connection reset|EOF|broken pipe/i.test(e)) return 'The device closed the connection. It may be restarting.';
  if (/tls|handshake|certificate|x509/i.test(e)) return 'The device answered, but the secure connection could not be set up.';
  return 'The endpoint could not be checked.';
}

// The one-line summary a plugin returns after a deployment ("a; b; c") as a short list.
function deploymentNotes(message) {
  const items = String(message || '').split(/;\s+/).map(x => x.trim()).filter(Boolean)
    .map(x => x.charAt(0).toUpperCase() + x.slice(1));
  if (items.length <= 1) return h('div', { class: 'meta' }, items[0] || '');
  return h('ul', { class: 'notes' }, items.map(x => h('li', {}, x)));
}

function probeLine(p, managed) {
  let st;
  if (p.error) st = chip('unreachable', p.bad >= 2 ? 'bad' : 'warn');
  else if (!p.match && managed) st = chip('serving a different cert', p.bad >= 2 ? 'bad' : 'warn');
  else st = chip('serving', 'ok');
  const kids = [h('span', { class: 'mono' }, p.addr), st];
  if (!p.error) {
    const d = daysLeft(p.not_after);
    kids.push(chip(d < 0 ? 'expired' : d + ' d left', d <= 7 ? 'bad' : d <= S.settings.warn_days ? 'warn' : 'ok'));
    if (p.chain_len === 1 && !p.self_signed) {
      const w = chip('chain incomplete', 'warn');
      w.title = 'The server sent only the certificate, not the intermediate CA that signed it. Browsers that cannot fetch it themselves will show the certificate as untrusted.';
      kids.push(w);
    }
    kids.push(h('span', { class: 'meta' }, (p.subject || '?') + ' · ' + (p.issuer || '?')));
  } else {
    // the reason on its own line, in words, with the exact error beneath it
    kids.push(h('div', { class: 'perr' },
      h('div', { class: 'err' }, describeProbeError(p.error)),
      h('div', { class: 'meta mono small' }, p.error)));
  }
  return h('div', { class: 'probe', title: 'checked ' + ago(p.checked_at) }, kids);
}

// Before the first deployment the action is Deploy (always a deliberate click). Once a target has
// been deployed to, renewals go out by themselves and the action becomes Pause / Resume.
function targetAction(t, c) {
  if (t.kind === 'watch') return null;
  if (t.deploying) return h('button', { class: 'btn small', disabled: true }, spinner(), ' Deploying…');
  if (!t.auto_deploy) {
    const ready = c && c.serial && t.deployed_serial !== c.serial;
    return h('button', { class: 'btn small' + (ready ? ' primary' : ''), title: 'The first deployment is always started by you; renewals after it are automatic',
      onclick: () => act('POST', `/api/targets/${t.id}/deploy`, 'Deployment started') }, 'Deploy');
  }
  if (t.paused) return h('button', { class: 'btn small primary', title: 'Resume automatic deployment: anything renewed meanwhile is deployed',
    onclick: () => act('POST', `/api/targets/${t.id}/resume`, 'Resumed: renewals will be deployed automatically') }, 'Resume');
  return h('button', { class: 'btn small', title: 'Pause automatic deployment of renewals to this target',
    onclick: () => act('POST', `/api/targets/${t.id}/pause`, 'Paused: renewals will not be deployed to this target until you resume') }, 'Pause');
}

// Once a target is armed its main button is Pause/Resume, so running the deployment again by hand
// (after changing a setting on the device, or to retry) needs a button of its own.
function redeployButton(t) {
  if (t.kind === 'watch' || t.deploying || !t.auto_deploy) return null;
  return h('button', { class: 'btn small ghost', title: 'Deploy the current certificate to this device again, now',
    onclick: () => act('POST', `/api/targets/${t.id}/deploy`, 'Deployment started') }, 'Redeploy');
}

// Local date and time to the second, sortable and unambiguous: 2026-10-09 10:30:59
const stamp = d => {
  const t = new Date(d), p = n => String(n).padStart(2, '0');
  return `${t.getFullYear()}-${p(t.getMonth() + 1)}-${p(t.getDate())} ${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`;
};

// Did the device refuse this call? Its own account of the answer wins over the HTTP status, because
// FortiManager and FortiAnalyzer answer HTTP 200 and put the real result inside.
const callFailed = c => !!c.error || !c.status || (c.answer ? !!c.failed : c.status >= 400);

// Does this kind of target talk to a device over an API at all? (Files and monitor-only targets do not.)
const usesAPI = kind => ((schema.targets.find(d => d.kind === kind) || {}).calls || []).some(d => d.method !== '-');

const openCalls = new Set(); // targets whose verbose call panel the user has opened
// What each open panel last showed and where the reader was in it. The page is redrawn every couple of
// seconds while something runs; without this an open panel went back to "Loading…" (the page shrank and
// grew again, so the scroll position drifted) and its own scroll position jumped to the end.
const callState = new Map(); // target id -> { calls, top, follow }

// A collapsed "Verbose" panel with the API calls made to a target, like the ACME log under a certificate.
function callsPanel(t) {
  const st = callState.get(t.id) || { calls: null, top: 0, follow: true };
  callState.set(t.id, st);
  const box = h('pre', { class: 'acmelog' });
  const d = h('details', { class: 'verbose' }, h('summary', {}, 'Verbose · API calls'), box);
  // follow the newest line while the reader is at the bottom; otherwise stay where they were
  const place = () => { box.scrollTop = st.follow ? box.scrollHeight : st.top; };
  box.addEventListener('scroll', () => { st.top = box.scrollTop; st.follow = box.scrollTop + box.clientHeight >= box.scrollHeight - 4; });
  const paint = calls => {
    if (!calls.length) { box.textContent = 'Nothing has been sent to this device yet. Use Test connection or Deploy.'; return; }
    box.replaceChildren(...calls.map(c => {
      const line = `${stamp(c.time)}  ${c.op.padEnd(6)}  ${c.detail || c.method + ' ' + c.path}  ->  ${c.status || 'no reply'}`
        + (c.answer ? '  ' + c.answer : '') + (c.error ? '  ' + c.error : '') + `  (${c.ms} ms)`;
      return h('div', { class: callFailed(c) ? 'bad' : '' }, line);
    }));
  };
  const load = async () => {
    try {
      st.calls = (await api('GET', '/api/targets/' + t.id + '/calls')).calls.slice(-80);
      paint(st.calls); place();
    } catch (e) { box.textContent = e.message; }
  };
  if (st.calls) paint(st.calls); else box.textContent = 'Loading…';
  d.open = openCalls.has(t.id);
  d.addEventListener('toggle', () => { if (d.open) { openCalls.add(t.id); load(); } else openCalls.delete(t.id); });
  if (d.open) { requestAnimationFrame(place); load(); }
  return d;
}

function callsButton(t) {
  return h('button', { class: 'btn small ghost', title: 'Every request sent to this device, and what each plugin call is for', onclick: () => callsDialog(t) }, 'API calls');
}

function targetRow(t, c) {
  const kind = (schema.targets.find(d => d.kind === t.kind) || {}).label || t.kind;
  const status = [targetStatus(t, c)];
  if (t.deployed_at && !zero(t.deployed_at) && t.kind !== 'watch') status.push(h('div', { class: 'meta' }, 'deployed ' + ago(t.deployed_at)));
  return h('div', { class: 'trow' },
    h('div', {}, h('div', { class: 'nm' }, t.name), h('div', { class: 'meta mono' }, targetAddress(t) || kind), targetAddress(t) ? h('div', { class: 'meta' }, kind) : null),
    h('div', {}, status),
    h('div', {},
      t.last_error ? h('div', { class: 'err' }, t.last_error) : null,
      t.message && !t.last_error && t.kind !== 'watch' ? deploymentNotes(t.message) : null,
      (t.probes || []).map(p => probeLine(p, !!c)),
      !(t.probes || []).length && t.kind !== 'watch'
        ? h('div', { class: 'meta' }, ((schema.targets.find(d => d.kind === t.kind) || {}).auto_verify) ? 'waiting for the first live check' : 'no address to check') : null),
    h('div', { class: 'row' },
      targetAction(t, c),
      redeployButton(t),
      callsButton(t),
      h('button', { class: 'btn small ghost', onclick: () => targetForm(t) }, 'Edit')),
    usesAPI(t.kind) ? h('div', { class: 'fullrow' }, callsPanel(t)) : null);
}

// A collapsed "Verbose" panel with the raw ACME log. Meant for troubleshooting.
const logState = new Map(); // certificate id -> { text, top, follow }, see callState
function logPanel(c) {
  const st = logState.get(c.id) || { text: '', top: 0, follow: true };
  logState.set(c.id, st);
  const pre = h('pre', { class: 'acmelog' }, st.text || 'Loading…');
  const d = h('details', { class: 'verbose' }, h('summary', {}, 'Verbose · ACME log'), pre);
  const place = () => { pre.scrollTop = st.follow ? pre.scrollHeight : st.top; }; // follow the log while it is being written
  pre.addEventListener('scroll', () => { st.top = pre.scrollTop; st.follow = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 4; });
  const load = async () => {
    try {
      const r = await fetch('/api/certs/' + c.id + '/log', { credentials: 'same-origin' });
      st.text = (await r.text()).trim() || 'No issuance has run yet.';
      pre.textContent = st.text;
      place();
    } catch (e) { pre.textContent = e.message; }
  };
  d.open = openLogs.has(c.id);
  d.addEventListener('toggle', () => { if (d.open) { openLogs.add(c.id); load(); } else openLogs.delete(c.id); });
  if (d.open) { requestAnimationFrame(place); load(); }
  return h('div', { class: 'logrow' }, d);
}

function issuingTooltip(c) {
  const secs = Math.max(0, Math.round((Date.now() - new Date(c.last_attempt)) / 1000));
  const took = secs >= 60 ? Math.floor(secs / 60) + ' min ' + (secs % 60) + ' s' : secs + ' s';
  return 'Issuing for ' + took + (c.stage ? ': ' + c.stage : '') + '. Click to stop.';
}

// Which certificates are folded up on the main page. Remembered in this browser only; the page works
// the same when storage is unavailable (a private window, say), the folds just are not remembered.
const collapsedCerts = (() => {
  try { return new Set(JSON.parse(localStorage.getItem('certsmith.collapsed') || '[]')); } catch (_) { return new Set(); }
})();
// Which Settings sections are folded. Remembered in this browser only, like the certificate folds.
const settingsFolded = (() => {
  try { return new Set(JSON.parse(localStorage.getItem('certsmith.settings.folded') || '[]')); } catch (_) { return new Set(); }
})();
function setCollapsed(ids, collapsed) {
  ids.forEach(id => collapsed ? collapsedCerts.add(id) : collapsedCerts.delete(id));
  try { localStorage.setItem('certsmith.collapsed', JSON.stringify([...collapsedCerts])); } catch (_) { /* not remembered */ }
  render();
}

// Is this target in trouble? (a failed deployment, or an endpoint serving the wrong certificate or not answering)
const targetBad = t => t.enabled && !!(t.last_error || (t.probes || []).some(p => p.error || (!p.match && t.cert_id)));

function certCard(c) {
  const ts = (S.targets || []).filter(t => t.cert_id === c.id);
  let expiry;
  if (!c.serial) {
    // while issuing, the button says it all: no extra text here
    expiry = h('div', { class: 'expiry' }, h('div', { class: 'days' + (c.issuing || !zero(c.cancelled_at) ? '' : c.last_error ? ' bad' : '') },
      c.issuing ? null : !zero(c.cancelled_at) ? 'cancelled' : c.last_error ? 'failed' : 'not issued'));
  } else {
    const d = daysLeft(c.not_after), cls = expiryClass(d);
    expiry = h('div', { class: 'expiry' },
      h('div', { class: 'days ' + cls }, d < 0 ? 'expired' : d + ' days'),
      h('div', { class: 'meta' }, 'expires ' + fmt(c.not_after)),
      h('div', { class: 'bar ' + cls }, h('i', { style: `width:${Math.max(2, Math.min(100, d / 90 * 100))}%` })));
  }
  const folded = collapsedCerts.has(c.id);
  const bad = ts.filter(targetBad).length;
  return h('div', { class: 'card' + (folded ? ' folded' : '') },
    h('div', { class: 'head' },
      // The fold control is a real <details> disclosure with an empty summary, so its triangle is drawn by the
      // browser exactly like the arrows of the "Verbose" panels, in the same size and colour. Its own toggling
      // is cancelled: the state is kept by the page (and remembered), which redraws it.
      h('details', { class: 'verbose foldctl', open: !folded },
        h('summary', { 'aria-label': (folded ? 'Expand ' : 'Collapse ') + c.name, title: folded ? 'Show the targets and log' : 'Fold this certificate up',
          onclick: e => { e.preventDefault(); setCollapsed([c.id], !folded); } })),
      h('div', { class: 'grow' },
        h('div', { class: 'row wrap' }, h('h2', {}, c.name),
          !c.enabled ? chip('disabled') : null,
          c.source === 'import' ? chip('imported') : c.auto_renew ? null : chip('manual renewal', 'warn'),
          (c.issuer || '').includes('STAGING') ? chipTitled('test certificate: not trusted by browsers', 'warn', "Issued by the Let's Encrypt staging CA, which is for testing. Set the directory to production in Settings to reissue and redeploy it.") : null,
          reissueDirection(c) ? chip('will be reissued from ' + dirLabel(effectiveDir(c)), 'info') : null),
        h('div', { class: 'doms' }, c.domains.join(', ')),
        h('div', { class: 'meta' }, c.source === 'import'
          ? `${c.issuer || 'unknown issuer'} · serial ${(c.serial || '').slice(0, 12)}… · ${c.key_type} · imported ${fmt(c.imported_at)}`
          : c.serial
          ? `${c.issuer || 'unknown issuer'} · serial ${c.serial.slice(0, 12)}… · ${c.key_type} · ${c.dns_id ? (byId(S.dns_providers, c.dns_id) || {}).kind === '' ? authorityLabel(byId(S.dns_providers, c.dns_id)) + ' (' + byId(S.dns_providers, c.dns_id).name + ', names validated at the CA)' : authorityLabel(byId(S.dns_providers, c.dns_id) || {}) + ' via DNS-01 (' + ((byId(S.dns_providers, c.dns_id) || {}).name || '?') + ')' : 'no certificate provider'}`
          : 'not issued yet'),
        c.last_error ? h('div', { class: 'err' }, 'Last error: ' + c.last_error) : null,
        // folded: say what is hidden, so a problem under a closed certificate is still seen
        folded ? h('div', { class: 'row wrap foldsum' },
          chip(ts.length === 1 ? '1 target' : ts.length + ' targets'),
          bad ? chipTitled('Error', 'bad', (bad === 1 ? '1 target reports' : bad + ' targets report') + ' a problem. Expand the certificate to see which.')
            : (ts.length ? chip('OK', 'ok') : null)) : null),
      expiry,
      h('div', { class: 'row' },
        c.source === 'import'
          ? h('button', { class: 'btn small', title: 'Upload the new certificate; targets that were deployed to receive it', onclick: () => importForm(c) }, 'Replace')
          : c.issuing
          // spinner while it runs; on hover the same button becomes a red Stop
          ? h('button', { class: 'btn small stopbtn', title: issuingTooltip(c), 'aria-label': 'Stop issuing',
              onclick: () => act('POST', `/api/certs/${c.id}/cancel`, 'Stopping…') },
              h('span', { class: 'on' }, spinner(), ' Issuing…'), h('span', { class: 'off' }, '■ Stop'))
          : h('button', { class: 'btn small', onclick: () => act('POST', `/api/certs/${c.id}/renew`, 'Issuance started - the ACME log shows progress') },
              c.serial ? 'Renew now' : 'Issue now'),
        h('button', { class: 'btn small ghost', onclick: () => c.source === 'import' ? importedEditForm(c) : certForm(c) }, 'Edit'))),
    folded || c.source === 'import' ? null : logPanel(c),
    folded ? null : h('div', { class: 'targets' },
      ts.length ? ts.map(t => targetRow(t, c))
        : h('div', { class: 'trow' }, h('div', { class: 'meta' }, 'No targets yet - this certificate is not deployed anywhere.'),
          h('div'), h('div'), h('button', { class: 'btn small', onclick: () => targetForm(null, c.id) }, 'Add target'))));
}

function renderOverview() {
  const certs = S.certificates || [], targets = S.targets || [];
  const root = h('div');
  const attention = certs.filter(c => c.enabled && (c.last_error || !c.serial || daysLeft(c.not_after) <= S.settings.warn_days)).length;
  const badTargets = targets.filter(targetBad).length;
  root.append(
    h('div', { class: 'row between wrap', style: 'margin-bottom:14px' },
      h('div', {}, h('h1', {}, 'Certificates'), h('p', { class: 'sub', style: 'margin:0' },
        'Certificates issued and renewed by CertSmith, with the targets each one is deployed to.'
          + (S.settings.acme_directory === 'staging' ? " Let's Encrypt is set to staging: certificates it issues are for testing and are not trusted by clients."
            : S.settings.acme_directory === 'selfsigned' ? " Let's Encrypt is set to the built-in test CA: certificates it issues are not trusted by clients." : ''))),
      h('div', { class: 'row' },
        certs.length > 1 ? h('button', { class: 'btn ghost', onclick: () => setCollapsed(certs.map(c => c.id), !certs.every(c => collapsedCerts.has(c.id))) },
          certs.every(c => collapsedCerts.has(c.id)) ? 'Expand all' : 'Collapse all') : null,
        h('button', { id: 'probe-btn', class: 'btn', title: 'Connects to every target now and checks the certificate it is serving: the right one, still valid, chain complete. Changes nothing.',
          onclick: e => checkEndpoints(e.currentTarget) }, 'Check endpoints'),
        h('button', { class: 'btn primary', onclick: () => certForm(null) }, 'Add certificate'))),
    // spread: the native append() would print the text "null" for an absent banner
    ...((!S.settings.acme_email && S.settings.acme_directory !== 'selfsigned' && (!S.dns_providers.length || S.dns_providers.some(p => !isEAB(p) || !p.email))
         && !(certs.length && certs.every(c => c.source === 'import'))) // only imported certificates: nothing is issued
      ? [h('div', { class: 'banner warn' }, 'Set an account email in ', h('a', { href: '#', onclick: e => { e.preventDefault(); view = 'settings'; render(); } }, 'Settings'), ' before issuing certificates.')]
      : []),
    ...((updateInfo && updateInfo.available)
      ? [h('div', { class: 'banner info' }, 'Version ' + plainVersion(updateInfo.latest) + ' is available. ',
          h('a', { href: '#', onclick: e => { e.preventDefault(); view = 'settings'; render(); } }, 'See Settings'), ' for how to update.')]
      : []),
    ...(S.pending_dns || []).map(p => h('div', { class: 'banner warn' },
      'A DNS test may have left a TXT record in the zone: ', h('span', { class: 'mono' }, p.fqdn.replace(/\.$/, '') + ' = ' + p.value),
      ". Delete it in the DNS provider's console, then ",
      h('button', { class: 'linklike', onclick: async () => { await api('POST', '/api/dns/pending/' + p.id + '/dismiss'); refresh(); } }, 'dismiss this notice'), '.')),
    h('div', { class: 'tiles' },
      tile(certs.length, 'certificates', ''),
      tile(attention, 'need attention', attention ? 'warn' : 'ok'),
      tile(targets.length, 'deployment targets', ''),
      tile(badTargets, 'targets with problems', badTargets ? 'bad' : 'ok')));

  if (!certs.length) {
    root.append(h('div', { class: 'card' }, h('div', { class: 'empty' },
      h('h2', {}, 'Add your first certificate'),
      h('p', {}, "Certificates are validated through DNS. Add a certificate provider first (Let's Encrypt with DNS credentials, or another CA such as ZeroSSL or Sectigo), then add a certificate, then the targets that should receive it."),
      h('div', { class: 'row', style: 'justify-content:center' },
        S.dns_providers.length ? null : h('button', { class: 'btn', onclick: () => providerForm(null) }, 'Add certificate provider'),
        h('button', { class: 'btn primary', onclick: () => certForm(null) }, 'Add certificate')))));
  } else {
    certs.forEach(c => root.append(certCard(c)));
  }
  const watch = targets.filter(t => !t.cert_id);
  if (watch.length) {
    root.append(h('h2', { style: 'margin:22px 0 10px' }, 'Monitor-only endpoints'),
      h('div', { class: 'card' }, watch.map(t => targetRow(t, null))));
  }
  return root;
}

function tile(n, label, cls) { return h('div', { class: 'tile ' + cls }, h('div', { class: 'n' }, n), h('div', { class: 'l' }, label)); }

// Checks every endpoint now and says at the bottom of the screen when it has finished, and how it went.
async function checkEndpoints(btn) {
  btn.disabled = true;
  toast('Checking endpoints…', false, 0);
  try {
    const r = await api('POST', '/api/probe');
    await refresh();
    const n = r.checked || 0, plural = n === 1 ? 'endpoint' : 'endpoints';
    if (!n) toast('Endpoint check finished: no target has an address to check.', false, 5000);
    else if (!r.problems) toast(`Endpoint check finished: ${n} ${plural} checked, all serving the expected certificate.`, false, 5000);
    else toast(`Endpoint check finished: ${r.problems} of ${n} ${plural} need attention.`, true, 8000);
  } catch (e) { toast(e.message, true); } finally { btn.disabled = false; }
}

async function act(method, path, okMsg) {
  try { await api(method, path); toast(okMsg); await refresh(); setTimeout(refresh, 800); }
  catch (e) { toast(e.message, true); }
}

// ---- generic list views --------------------------------------------------------------
let targetFilter = '';
let targetSort = { key: 'name', dir: 1 };

function renderTargets() {
  const rows = (S.targets || []).map(t => {
    const c = byId(S.certificates, t.cert_id);
    const status = targetStatus(t, c);
    return { t, c, status, name: t.name, addr: targetAddress(t), cert: c ? c.name : '', statusText: status.textContent,
      type: (schema.targets.find(d => d.kind === t.kind) || {}).label || t.kind };
  });
  const body = h('tbody');
  const count = h('span', { class: 'meta' });
  const heads = [['name', 'Name'], ['addr', 'Address'], ['type', 'Type'], ['cert', 'Certificate'], ['statusText', 'Status']];
  const headCells = heads.map(([key, label]) => {
    const th = h('th', { class: 'sortable', title: 'Sort by ' + label.toLowerCase(), onclick: () => {
      targetSort = { key, dir: targetSort.key === key ? -targetSort.dir : 1 };
      draw();
    } }, label);
    th.dataset.key = key;
    return th;
  });

  const draw = () => {
    const terms = targetFilter.toLowerCase().split(/\s+/).filter(Boolean);
    const shown = rows.filter(r => terms.every(term => [r.name, r.addr, r.type, r.cert, r.statusText].join(' ').toLowerCase().includes(term)));
    shown.sort((a, b) => String(a[targetSort.key]).localeCompare(String(b[targetSort.key]), undefined, { numeric: true, sensitivity: 'base' }) * targetSort.dir);
    body.replaceChildren(...(shown.length ? shown.flatMap(r => [h('tr', { class: usesAPI(r.t.kind) ? 'hasverbose' : '' },
      h('td', {}, r.name), h('td', { class: 'mono' }, r.addr || '-'), h('td', {}, r.type), h('td', {}, r.cert || '-'), h('td', {}, r.status),
      h('td', { class: 'act' }, redeployButton(r.t), callsButton(r.t), h('button', { class: 'btn small ghost', onclick: () => targetForm(r.t) }, 'Edit'))),
      usesAPI(r.t.kind) ? h('tr', { class: 'verboserow' }, h('td', { colspan: 6 }, callsPanel(r.t))) : null].filter(Boolean))
      : [h('tr', {}, h('td', { colspan: 6, class: 'meta', style: 'text-align:center;padding:22px' }, 'No target matches "' + targetFilter + '"'))]));
    headCells.forEach(th => th.classList.toggle('sorted', th.dataset.key === targetSort.key));
    headCells.forEach(th => th.dataset.dir = th.dataset.key === targetSort.key ? (targetSort.dir > 0 ? '▲' : '▼') : '');
    count.textContent = shown.length === rows.length ? rows.length + (rows.length === 1 ? ' target' : ' targets') : shown.length + ' of ' + rows.length;
  };

  const search = h('input', { type: 'search', class: 'search', placeholder: 'Filter by name, IP or domain, type or status…', 'aria-label': 'Filter targets', spellcheck: 'false', autocomplete: 'off' });
  search.value = targetFilter;
  search.addEventListener('input', () => { targetFilter = search.value; draw(); });

  const node = h('div', {},
    h('div', { class: 'row between', style: 'margin-bottom:14px' },
      h('div', {}, h('h1', {}, 'Targets'), h('p', { class: 'sub', style: 'margin:0' }, 'Devices and services that receive certificates. Each target is updated automatically when its certificate is issued or renewed.')),
      h('button', { class: 'btn primary', onclick: () => targetForm(null) }, 'Add target')),
    rows.length ? h('div', {},
      h('div', { class: 'filterbar' }, search, count),
      h('table', { class: 'list' }, h('thead', {}, h('tr', {}, ...headCells, h('th', {}))), body))
      : h('div', { class: 'card empty' }, 'No targets yet.'));
  if (rows.length) draw();
  return node;
}

function renderDNS() {
  const ps = S.dns_providers || [];
  const le = ps.filter(p => !isEAB(p)), eab = ps.filter(isEAB);
  const imported = (S.certificates || []).filter(c => c.source === 'import');
  const usedBy = p => (S.certificates || []).filter(c => c.dns_id === p.id).map(c => c.name).join(', ') || '-';
  const table = (head, rows) => h('table', { class: 'list' },
    h('thead', {}, h('tr', {}, [...head, ''].map(x => h('th', {}, x)))), h('tbody', {}, rows));
  const edit = p => h('td', { class: 'act' }, h('button', { class: 'btn small ghost', onclick: () => providerForm(p) }, 'Edit'));
  const section = (title, intro, body) => h('section', { class: 'psection' },
    h('h2', {}, title), h('p', { class: 'meta', style: 'margin:2px 0 10px' }, intro), body);
  const none = text => h('div', { class: 'card empty' }, text);
  return h('div', {},
    h('div', { class: 'row between', style: 'margin-bottom:14px' },
      h('div', {}, h('h1', {}, 'Certificate providers'), h('p', { class: 'sub', style: 'margin:0' },
        'A provider defines the certificate authority that issues certificates and the DNS credentials used to validate domain ownership. Each certificate is assigned one provider. Certificates issued elsewhere are imported here too.')),
      h('button', { class: 'btn primary', onclick: () => providerForm(null) }, 'Add provider')),
    section("Let's Encrypt", 'Certificates from Let\'s Encrypt, using the directory selected under Settings. Each provider holds the DNS credentials used for domain validation.',
      le.length ? table(['Name', 'DNS provider', 'Used by'], le.map(p => h('tr', {}, h('td', {}, p.name), h('td', {}, dnsLabel(p)), h('td', {}, usedBy(p)), edit(p))))
        : none("No Let's Encrypt providers configured.")),
    section('EAB providers', 'Certificate authorities that use External Account Binding (EAB), such as ZeroSSL, Sectigo and Google Trust Services. Each provider holds the CA directory, its EAB key and, where required, DNS credentials.',
      eab.length ? table(['Name', 'Certificate authority', 'DNS provider', 'Used by'], eab.map(p => h('tr', {}, h('td', {}, p.name), h('td', {}, caLabel(p)), h('td', {}, dnsLabel(p)), h('td', {}, usedBy(p)), edit(p))))
        : none('No EAB providers configured. Select Add provider, then Another CA (External Account Binding), to add one.')),
    section('Imported certificates', 'Certificates that were issued outside CertSmith and uploaded as files. CertSmith deploys and monitors them but cannot renew them: upload the new certificate with Replace when it arrives.',
      imported.length ? table(['Name', 'Issued by', 'Names', 'Expires'], imported.map(c => h('tr', {},
          h('td', {}, c.name), h('td', {}, c.issuer || 'unknown'), h('td', {}, (c.domains || []).join(', ')), h('td', {}, fmt(c.not_after)),
          h('td', { class: 'act' }, h('button', { class: 'btn small', title: 'Upload the new certificate; targets that were deployed to receive it', onclick: () => importForm(c) }, 'Replace'), ' ',
            h('button', { class: 'btn small ghost', onclick: () => importedEditForm(c) }, 'Edit'))
        )))
        : none('No imported certificates. Select Add provider, then Import an existing certificate, to upload one.')));
}

// What each administrative action is called in the audit log.
const AUDIT_LABELS = {
  'signin': 'Signed in', 'signin.failed': 'Failed sign-in', 'signout': 'Signed out',
  'user.setup': 'First user created', 'user.create': 'User created', 'user.delete': 'User deleted',
  'user.password_change': 'Changed own password', 'user.password_reset': 'Reset a password',
  'settings.update': 'Settings changed',
  'ui_cert.regenerate': 'Web page certificate regenerated', 'ui_cert.renew': 'Web page certificate renewed automatically',
  'provider.create': 'Provider added', 'provider.update': 'Provider changed', 'provider.delete': 'Provider deleted',
  'provider.dns_test': 'DNS challenge tested', 'provider.check_account': 'CA account checked',
  'cert.create': 'Certificate added', 'cert.update': 'Certificate changed', 'cert.delete': 'Certificate deleted',
  'cert.import': 'Certificate imported', 'cert.replace': 'Imported certificate replaced',
  'cert.issue': 'Issuance started', 'cert.cancel': 'Issuance stopped',
  'target.create': 'Target added', 'target.update': 'Target changed', 'target.delete': 'Target deleted',
  'target.deploy': 'Deployment started', 'target.pause': 'Automatic deployment paused', 'target.resume': 'Automatic deployment resumed',
  'endpoints.check': 'Endpoints checked', 'update.check': 'Update check', 'signin.blocked': 'Sign-in blocked', 'event': 'Security event',
};
let eventsTab = 'certs', auditFilter = '', eventFilter = '';
let uiCert = {}; // the certificate this page itself is served with

// Two lists, because they answer different questions: what CertSmith did with certificates, and who
// did what to CertSmith.
function renderEvents() {
  const tab = (id, label, n) => h('button', { class: 'tabbtn' + (eventsTab === id ? ' on' : ''), role: 'tab', 'aria-selected': String(eventsTab === id),
    onclick: () => { eventsTab = id; render(); } }, label, h('span', { class: 'count' }, String(n)));
  const ev = S.events || [], au = S.audit || [];
  const head = h('div', {}, h('h1', {}, 'Events'),
    h('p', { class: 'sub' }, eventsTab === 'certs'
      ? 'Certificate operations performed by CertSmith: issuing, renewal, deployment, endpoint checks and alerts. Newest first.'
      : 'Administrative activity: sign-ins, user changes, settings, providers, certificates and targets, with the user and source address. Newest first.'),
    h('div', { class: 'tabs', role: 'tablist' }, tab('certs', 'Certificate operations', ev.length), tab('audit', 'Admin audit log', au.length)));
  // both lists share one filter box design: the rows are redrawn in place, so typing never loses focus
  const filterBox = (label, placeholder, get, set, redraw) => {
    const box = h('input', { type: 'search', class: 'search', placeholder, 'aria-label': label,
      spellcheck: 'false', autocomplete: 'off', style: 'margin-bottom:12px;width:100%;max-width:420px',
      oninput: e => { set(e.target.value); redraw(); } });
    box.value = get();
    return box;
  };
  if (eventsTab === 'certs') {
    const tbody = h('tbody');
    const drawEvents = () => {
      const terms = eventFilter.toLowerCase().split(/\s+/).filter(Boolean);
      const rows = ev.filter(e => terms.every(t => [e.subject, e.message, e.level, fmt(e.time)].join(' ').toLowerCase().includes(t)));
      tbody.replaceChildren(...(rows.length ? rows.map(e => h('tr', {},
        h('td', { class: 'meta', style: 'white-space:nowrap' }, fmt(e.time)),
        h('td', {}, e.subject),
        h('td', { class: 'lvl-' + e.level }, e.message)))
        : [h('tr', {}, h('td', { colspan: 3, class: 'meta', style: 'text-align:center;padding:22px' }, ev.length ? 'Nothing matches that filter.' : 'Nothing recorded yet.'))]));
    };
    drawEvents();
    return h('div', {}, head,
      filterBox('Filter the certificate operations log', 'Filter by subject or message…', () => eventFilter, v => { eventFilter = v; }, drawEvents),
      h('table', { class: 'list' },
        h('thead', {}, h('tr', {}, ['Time', 'Subject', 'Message'].map(x => h('th', {}, x)))), tbody));
  }
  const body = h('tbody');
  const draw = () => {
    const terms = auditFilter.toLowerCase().split(/\s+/).filter(Boolean);
    const rows = au.filter(a => terms.every(t => [a.user, a.action, AUDIT_LABELS[a.action], a.subject, a.detail, a.ip].join(' ').toLowerCase().includes(t)));
    body.replaceChildren(...(rows.length ? rows.map(a => h('tr', { class: a.action === 'signin.failed' ? 'failed' : '' },
      h('td', { class: 'meta nowrap' }, fmt(a.time)),
      h('td', {}, a.user || h('span', { class: 'meta' }, '-')),
      h('td', {}, AUDIT_LABELS[a.action] || a.action),
      h('td', {}, a.subject || ''),
      h('td', { class: 'meta' }, a.detail || ''),
      h('td', { class: 'meta mono nowrap' }, a.ip || ''))) : [h('tr', {}, h('td', { colspan: 6, class: 'meta', style: 'text-align:center;padding:22px' }, au.length ? 'Nothing matches that filter.' : 'Nothing recorded yet.'))]));
  };
  const filter = filterBox('Filter the audit log', 'Filter by user, action or name…', () => auditFilter, v => { auditFilter = v; }, draw);
  draw();
  return h('div', {}, head, filter, h('table', { class: 'list auditlist' },
    h('thead', {}, h('tr', {}, ['Time', 'User', 'Action', 'Subject', 'Details', 'From'].map(x => h('th', {}, x)))), body));
}

// ---- forms ------------------------------------------------------------------------------
// What the server shows in place of a saved secret. It cannot be revealed: the real
// value never leaves the server once it is stored.
const MASK = '********';

// Wraps a password input with a Show/Hide button. The button is only offered while the
// box holds something the person typed: a saved secret (the mask) has nothing to reveal.
function revealWrap(input) {
  const btn = h('button', { type: 'button', class: 'reveal', 'aria-pressed': 'false', 'aria-label': 'Show what I typed', tabindex: '-1' }, 'Show');
  const paint = () => { btn.style.display = input.value === MASK ? 'none' : ''; };
  btn.addEventListener('click', () => {
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    btn.textContent = showing ? 'Show' : 'Hide';
    btn.setAttribute('aria-pressed', String(!showing));
    btn.setAttribute('aria-label', showing ? 'Show what I typed' : 'Hide what I typed');
    input.focus();
  });
  input.addEventListener('input', paint);
  // a new value replaces the mask: hide the field again so a revealed secret is never left on screen
  input.addEventListener('focus', () => { if (input.value === MASK && input.type === 'text') input.type = 'password'; });
  paint();
  return h('div', { class: 'pwwrap' }, input, btn);
}

function fieldEl(f, value) {
  const t = f.type;
  const listeners = [];
  const fire = () => listeners.forEach(fn => fn());

  if (t === 'hidden') { // stored with the form but never shown (e.g. a trusted certificate fingerprint)
    const input = h('input', { type: 'hidden' });
    input.value = value == null ? '' : value;
    return { wrap: h('div', { style: 'display:none' }, input), input, onChange: fn => listeners.push(fn), get: () => input.value };
  }

  if (t === 'checks') { // tick boxes; the value is the comma separated list of ticked values
    const on = new Set(String(value == null ? '' : value).split(',').map(x => x.trim()).filter(Boolean));
    const boxes = (f.choices || []).map(c => {
      const cb = h('input', { type: 'checkbox' });
      cb.checked = on.has(c.value);
      cb.addEventListener('change', fire);
      return { c, cb };
    });
    const wrap = h('div', { class: 'field' }, h('label', {}, f.label + (f.required ? ' *' : '')),
      h('div', { class: 'checks' }, boxes.map(({ c, cb }) =>
        h('label', { class: 'chk' }, cb, h('span', {}, c.label, c.help ? h('small', {}, c.help) : null)))),
      f.help ? h('div', { class: 'help' }, f.help) : null);
    return { wrap, input: boxes[0] ? boxes[0].cb : null, onChange: fn => listeners.push(fn),
      get: () => boxes.filter(b => b.cb.checked).map(b => b.c.value).join(',') };
  }

  let input;
  if (t === 'textarea') input = h('textarea', { rows: 4, spellcheck: 'false' });
  else if (t === 'select') input = h('select', {}, (f.options || []).map(o => typeof o === 'object' ? h('option', { value: o.value }, o.label) : h('option', { value: o }, o)));
  else if (t === 'bool') input = h('input', { type: 'checkbox' });
  else input = h('input', { type: t === 'password' ? 'password' : t === 'number' ? 'number' : 'text', autocomplete: f.autocomplete || 'off', spellcheck: 'false' });
  if (t === 'bool') input.checked = value === true || value === 'true';
  else input.value = value == null ? '' : value;
  if (t === 'password') input.addEventListener('focus', () => { if (input.value === '********') input.select(); });
  input.dataset.key = f.key;
  input.addEventListener('input', fire);
  input.addEventListener('change', fire);
  const wrap = h('div', { class: 'field' + (t === 'bool' ? ' check' : '') },
    t === 'bool' ? h('label', {}, input, f.label) : [h('label', {}, f.label + (f.required ? ' *' : '')), t === 'password' ? revealWrap(input) : input],
    f.help ? h('div', { class: 'help' }, f.help) : null);
  return { wrap, input, onChange: fn => listeners.push(fn), get: () => t === 'bool' ? String(input.checked) : input.value };
}

// Builds a plugin's form from its descriptor: fields sharing a "row" sit side by
// side, "show_if" fields appear only when their condition holds, and "advanced"
// fields are tucked into a collapsed section.
function buildFields(fields, values) {
  const els = fields.map(f => ({ f, ...fieldEl(f, values && values[f.key] != null ? values[f.key] : f.default) }));
  const by = Object.fromEntries(els.map(e => [e.f.key, e]));
  const cond = expr => {
    const m = /^(\w+)([=~])(.*)$/.exec(expr || '');
    if (!m) return true;
    const cur = by[m[1]] ? by[m[1]].get() : '';
    return m[2] === '~' ? cur.split(',').includes(m[3]) : cur === m[3];
  };
  const listeners = [];
  const vis = () => els.forEach(e => { if (e.f.show_if) e.wrap.style.display = cond(e.f.show_if) ? '' : 'none'; });
  els.forEach(e => e.onChange(() => { vis(); listeners.forEach(fn => fn()); }));
  vis();

  const main = [], adv = [], rows = {};
  for (const e of els) {
    const into = e.f.advanced ? adv : main;
    if (e.f.row) {
      if (!rows[e.f.row]) { rows[e.f.row] = h('div', { class: 'fgrid fgrid-conn' }); into.push(rows[e.f.row]); }
      rows[e.f.row].append(e.wrap);
    } else into.push(e.wrap);
  }
  const nodes = [...main];
  if (adv.length) nodes.push(h('details', { class: 'adv' }, h('summary', {}, 'Advanced settings'), ...adv));
  return { nodes, by, cond, rows, onAnyChange: fn => listeners.push(fn),
    read: () => Object.fromEntries(els.map(e => [e.f.key, e.get()])) };
}

function modal(title, body, buttons) {
  modalOpen = true;
  const root = document.getElementById('modal-root');
  const close = () => { modalOpen = false; root.replaceChildren(); refresh(); };
  const bg = h('div', { class: 'modal-bg', onmousedown: e => { if (e.target === bg) close(); } },
    h('div', { class: 'modal', role: 'dialog', 'aria-label': title },
      h('h2', {}, title), h('div', { class: 'body' }, body),
      h('div', { class: 'foot' }, buttons(close))));
  root.replaceChildren(bg);
  const first = bg.querySelector('input,textarea,select');
  if (first) first.focus();
  return close;
}

async function submit(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { toast(e.message, true); } finally { btn.disabled = false; }
}

// DNS resolvers: one row each with an address and a port (53 unless changed), and a button to add another.
function resolverRows(initial) {
  const rows = h('div', { class: 'domrows' });
  const split = entry => {
    const m = /^\[(.+)\]:(\d+)$/.exec(entry) || /^([^:]+):(\d+)$/.exec(entry);
    return m ? [m[1], m[2]] : [entry.replace(/^\[|\]$/g, ''), '53'];
  };
  const make = entry => {
    const [h0, p0] = entry ? split(entry) : ['', '53'];
    const host = h('input', { type: 'text', placeholder: 'e.g. 1.1.1.1', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Resolver address' });
    const port = h('input', { type: 'number', min: '1', max: '65535', 'aria-label': 'Port' });
    host.value = h0; port.value = p0 || '53';
    const row = h('div', { class: 'domrow resrow' }, host, port,
      h('button', { type: 'button', class: 'btn small iconbtn', title: 'Remove this resolver', 'aria-label': 'Remove resolver',
        onclick: () => { row.remove(); if (!rows.children.length) rows.append(make('')); } }, '−'));
    return row;
  };
  (initial.length ? initial : ['']).forEach(e => rows.append(make(e)));
  const add = h('button', { type: 'button', class: 'btn small', onclick: () => { const n = make(''); rows.append(n); n.querySelector('input').focus(); } }, '+ Add resolver');
  return {
    node: h('div', {}, rows, add),
    // entries as host:port (IPv6 in brackets); empty rows are ignored, a bad port is an error
    get: () => [...rows.querySelectorAll('.resrow')].map(r => {
      const [hostIn, portIn] = r.querySelectorAll('input');
      const host = hostIn.value.trim();
      if (!host) return null;
      const port = parseInt(portIn.value || '53', 10);
      if (!(port >= 1 && port <= 65535)) throw new Error('Resolver port must be between 1 and 65535');
      return (host.includes(':') ? '[' + host + ']' : host) + ':' + port;
    }).filter(Boolean),
  };
}

// One domain per line, each with a delete button, and an "Add domain" button.
function domainRows(initial) {
  const rows = h('div', { class: 'domrows' });
  const make = value => {
    const input = h('input', { type: 'text', placeholder: 'example.com or *.example.com', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Domain name' });
    input.value = value || '';
    const row = h('div', { class: 'domrow' }, input,
      h('button', { type: 'button', class: 'btn small iconbtn', title: 'Remove this domain', 'aria-label': 'Remove domain',
        onclick: () => { row.remove(); if (!rows.children.length) rows.append(make('')); } }, '−'));
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') { e.preventDefault(); const n = make(''); row.after(n); n.querySelector('input').focus(); }
    });
    return row;
  };
  (initial.length ? initial : ['']).forEach(d => rows.append(make(d)));
  const add = h('button', { type: 'button', class: 'btn small', onclick: () => { const n = make(''); rows.append(n); n.querySelector('input').focus(); } }, '+ Add domain');
  return {
    node: h('div', {}, rows, add),
    // a pasted "a.com b.com" in one box is split too; duplicates and case are normalised
    get: () => [...new Set([...rows.querySelectorAll('input')].flatMap(i => i.value.split(/[\s,]+/)).map(x => x.trim().toLowerCase()).filter(Boolean))],
  };
}

// "Test DNS challenge": proves the credentials work end to end and shows what the zone actually serves.
function dnsTestPanel(getRequest) {
  const hold = h('input', { type: 'checkbox' });
  const out = h('div', { class: 'dnsreport' });
  const btn = h('button', { type: 'button', class: 'btn small', onclick: async () => {
    let req;
    try { req = getRequest(); } catch (e) { toast(e.message, true); return; }
    req.hold_seconds = hold.checked ? 45 : 0;
    btn.disabled = true;
    out.replaceChildren(h('div', { class: 'meta' }, spinner(), ' Testing - this can take up to a minute…', hold.checked ? " Look in your provider's DNS dashboard now." : ''));
    try {
      const r = await api('POST', '/api/dns/test', req);
      out.replaceChildren(h('div', { class: 'verdict ' + (r.ok ? 'ok' : 'bad') }, r.ok ? 'The DNS challenge works' : 'The DNS challenge does not work'),
        ...r.steps.map(st => h('div', { class: 'dstep ' + (st.info ? 'info' : st.ok ? 'ok' : 'bad') },
          h('span', { class: 'ic' }, st.info ? '•' : st.ok ? '✓' : '✗'), h('span', {}, st.msg))));
    } catch (e) { out.replaceChildren(h('div', { class: 'err' }, e.message)); } finally { btn.disabled = false; }
  } }, 'Test DNS challenge');
  const node = h('div', { class: 'field' }, h('label', {}, 'Check that DNS works'),
    h('div', { class: 'row wrap' }, btn, h('label', { class: 'chk', style: 'font-weight:400' }, hold, h('span', {}, 'Keep the test record for 45 s so I can see it in my provider dashboard'))),
    h('div', { class: 'help' }, "Creates a temporary TXT record, asks your zone's own nameservers whether they serve it, then removes it. No certificate is requested."), out);
  return { node };
}

const providerLabel = kind => (schema.dns.find(d => d.kind === kind) || {}).label || kind;

// A certificate provider is a CA plus the DNS credentials that prove the names. Let's Encrypt providers
// carry only the DNS credentials (their directory is in Settings); EAB providers also carry the CA.
const isEAB = p => !!p && p.authority === 'eab';
const caLabel = p => {
  const pre = (schema.eab_cas || []).find(c => c.id === p.ca && c.id !== 'custom');
  if (pre) return pre.label;
  try { return new URL(p.directory).hostname; } catch (_) { return 'Other CA'; }
};
const authorityLabel = p => isEAB(p) ? caLabel(p) : "Let's Encrypt";
// a provider at a CA that validates domains in the account has no DNS credentials at all
const dnsLabel = p => p.kind ? providerLabel(p.kind) : 'None (validated at the CA)';
// the ACME directory a certificate comes from: its provider's own CA, or the Let's Encrypt one chosen in Settings
const effectiveDir = c => { const p = byId(S.dns_providers, c.dns_id); return isEAB(p) ? p.directory : S.settings.acme_directory; };
const dirLabel = d => d === 'production' ? "Let's Encrypt" : d === 'staging' ? "Let's Encrypt (staging)" : d === 'selfsigned' ? 'the built-in test CA' : d;

// Cloudflare first, "other" last, the rest alphabetical.
function sortedDNS() {
  const rank = d => d.kind === 'cloudflare' ? 0 : d.kind === 'lego' ? 2 : 1;
  return [...schema.dns].sort((a, b) => rank(a) - rank(b) || a.label.localeCompare(b.label));
}

// The fields for uploading a certificate that somebody else issued (a PKCS#12 file, or PEM files).
// Shared by the Add provider dialog, where a new certificate is imported, and by Replace. It returns
// the node, payload() (the files, read) and check() (what the files contain, shown in the panel).
function importPanel(replacing) {
  const fmtSel = h('select', {}, h('option', { value: 'p12' }, 'PKCS#12 file (.p12 or .pfx)'),
    h('option', { value: 'pem' }, 'PEM files (certificate and private key)'));
  const file = accept => h('input', { type: 'file', accept });
  const p12 = file('.p12,.pfx,application/x-pkcs12');
  const pw = fieldEl({ key: 'pw', label: 'Password of the PKCS#12 file', type: 'password', autocomplete: 'off' }, '');
  const certF = file('.pem,.crt,.cer'), keyF = file('.pem,.key'), chainF = file('.pem,.crt,.cer');
  const row = (label, input, help) => h('div', { class: 'field' }, h('label', {}, label), input, help ? h('div', { class: 'help' }, help) : null);
  const p12Panel = h('div', {}, row('PKCS#12 file *', p12, 'The file that holds the certificate, its private key and usually its CA chain.'), pw.wrap);
  const pemPanel = h('div', {},
    row('Certificate file *', certF, 'PEM text starting with -----BEGIN CERTIFICATE-----. The CA chain may follow the certificate in the same file.'),
    row('Private key file *', keyF, 'PEM text starting with -----BEGIN PRIVATE KEY----- (or RSA or EC PRIVATE KEY). It must not be protected by a passphrase.'),
    row('CA chain file (optional)', chainF, 'Only needed when the chain is not already in the certificate file.'));
  const result = h('div');
  const paint = () => {
    p12Panel.style.display = fmtSel.value === 'p12' ? '' : 'none';
    pemPanel.style.display = fmtSel.value === 'pem' ? '' : 'none';
    result.replaceChildren();
  };
  fmtSel.addEventListener('change', paint);
  const readB64 = async f => {
    const buf = new Uint8Array(await f.files[0].arrayBuffer());
    let s = '';
    for (let i = 0; i < buf.length; i += 0x8000) s += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const readText = f => f.files[0] ? f.files[0].text() : Promise.resolve('');
  const payload = async () => {
    if (fmtSel.value === 'p12') {
      if (!p12.files[0]) throw new Error('Choose the PKCS#12 file');
      return { p12: await readB64(p12), password: pw.get() };
    }
    if (!certF.files[0]) throw new Error('Choose the certificate file');
    if (!keyF.files[0]) throw new Error('Choose the private key file');
    return { cert_pem: await readText(certF), key_pem: await readText(keyF), chain_pem: await readText(chainF) };
  };
  const show = s => {
    const rows = [
      ['Names', (s.names || []).join(', ')], ['Issued by', s.issuer || 'unknown'], ['Valid until', fmt(s.not_after)],
      ['Key', s.key_type],
      ['CA chain', s.chain_length ? s.chain_length + ' CA certificate' + (s.chain_length === 1 ? '' : 's') + ' will be sent with it'
        : s.root_supplied ? 'none to send: issued directly by the root CA' : 'none supplied'],
      ['Serial', String(s.serial || '').slice(0, 20) + '…'],
    ];
    result.replaceChildren(
      h('div', { class: 'certline', style: 'margin-top:12px' }, h('div', {}, chip('Readable', 'ok'), ' ', h('strong', {}, 'This is what will be imported')),
        ...rows.map(([k, v]) => h('div', { class: 'meta' }, h('strong', {}, k + ': '), v))),
      ...(s.warnings || []).map(w => h('div', { class: 'banner warn', style: 'margin:8px 0 0' }, w)));
  };
  paint();
  const intro = replacing
    ? 'Upload the new certificate for this entry. Targets that were deployed to receive it automatically, as they would a renewal.'
    : 'Use this for a certificate that was issued outside CertSmith: by a company CA, bought from a CA, or supplied with a product. CertSmith deploys it to your targets and warns before it expires, but cannot renew it: upload the new one with Replace when it arrives.';
  return {
    node: h('div', {}, h('p', { class: 'meta', style: 'margin:0 0 12px' }, intro), row('Format', fmtSel), p12Panel, pemPanel, result),
    payload,
    check: async () => { show((await api('POST', '/api/certs/import/check', await payload())).summary); },
  };
}

// Replace the certificate of an imported entry with a newly uploaded one.
function importForm(c) {
  const name = fieldEl({ key: 'name', label: 'Name', type: 'text', required: true }, c.name);
  name.input.disabled = true;
  const panel = importPanel(true);
  modal('Replace certificate', h('div', {}, name.wrap, panel.node),
    close => [h('div', { class: 'grow' }),
      h('button', { class: 'btn', onclick: close }, 'Cancel'),
      h('button', { class: 'btn', title: 'Reads the files and shows what they contain, without replacing', onclick: e => submit(e.target, panel.check) }, 'Check files'),
      h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
        await api('POST', '/api/certs/' + c.id + '/import', Object.assign({ name: c.name }, await panel.payload()));
        close(); toast('Certificate replaced');
      }) }, 'Replace certificate')]);
}

// An imported certificate's names, key and dates come from its file, so only its label and whether it
// is in use are edited here.
function importedEditForm(c) {
  const name = fieldEl({ key: 'name', label: 'Name', type: 'text', required: true }, c.name);
  const en = fieldEl({ key: 'enabled', label: 'Enabled', type: 'bool' }, c.enabled);
  modal('Edit imported certificate', h('div', {}, name.wrap,
    h('div', { class: 'field' }, h('label', {}, 'Names in the certificate'), h('div', { class: 'meta' }, (c.domains || []).join(', ')),
      h('div', { class: 'help' }, 'Fixed by the certificate. To change them, import a different certificate with Replace.')), en.wrap),
    close => [
      h('button', { class: 'btn danger', onclick: async e => {
        if (!confirm(`Delete certificate "${c.name}" and its stored key?`)) return;
        await submit(e.target, async () => { await api('DELETE', '/api/certs/' + c.id); close(); toast('Deleted'); });
      } }, 'Delete'),
      h('div', { class: 'grow' }),
      h('button', { class: 'btn', onclick: close }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
        if (!name.get().trim()) throw new Error('Give the certificate a name');
        await api('PUT', '/api/certs/' + c.id, { name: name.get().trim(), enabled: en.get() === 'true' });
        close(); toast('Saved');
      }) }, 'Save')]);
}

function certForm(c) {
  const isNew = !c;
  c = c || { name: '', domains: [], dns_id: '', key_type: 'rsa2048', enabled: true, auto_renew: true, propagation_seconds: 0 };
  const selfSigned = S.settings.acme_directory === 'selfsigned'; // the built-in test CA validates nothing

  const name = fieldEl({ key: 'name', label: 'Name', type: 'text', required: true, help: 'A label for this certificate, e.g. "lab wildcard".' }, c.name);
  const doms = domainRows(c.domains);

  // Names are always validated through DNS credentials (DNS-01): that covers plain host names and
  // wildcards alike, and needs nothing from this server but outbound access. Credentials are
  // managed on their own tab; here you pick one that is already saved.
  const optionFor = p => h('option', { value: p.id }, p.name + ' (' + authorityLabel(p) + ' · ' + dnsLabel(p) + ')');
  const leProviders = S.dns_providers.filter(p => !isEAB(p)), eabProviders = S.dns_providers.filter(isEAB);
  const dnsSel = h('select', {},
    selfSigned ? h('option', { value: '' }, 'None needed (built-in test CA)') : null,
    S.dns_providers.length || selfSigned ? null : h('option', { value: '', disabled: true }, '(none saved yet)'),
    leProviders.length ? h('optgroup', { label: "Let's Encrypt" }, leProviders.map(optionFor)) : null,
    eabProviders.length ? h('optgroup', { label: 'EAB providers' }, eabProviders.map(optionFor)) : null);
  dnsSel.value = c.dns_id || (S.dns_providers[0] ? S.dns_providers[0].id : '');
  let closeDialog = () => {};
  const noCreds = S.dns_providers.length || selfSigned ? null : h('div', { class: 'help' },
    'No certificate provider is saved yet, and every certificate needs one: ',
    h('button', { type: 'button', class: 'linklike', onclick: () => { closeDialog(); providerForm(null); } }, 'add a certificate provider'), ' first.');

  const prop = fieldEl({ key: 'prop', label: 'Max DNS propagation wait (seconds)', type: 'number',
    help: 'Optional. Empty uses the default (5 minutes). CertSmith continues as soon as the record is visible.' }, c.propagation_seconds || '');
  const key = fieldEl({ key: 'key_type', label: 'Key type', type: 'select', options: ['rsa2048', 'rsa3072', 'rsa4096', 'ec256', 'ec384'],
    help: 'RSA 2048 is the safest choice for appliances; ECDSA is smaller and faster where supported.' }, c.key_type);
  const auto = fieldEl({ key: 'auto_renew', label: 'Renew automatically', type: 'bool' }, c.auto_renew);
  const en = fieldEl({ key: 'enabled', label: 'Enabled', type: 'bool' }, c.enabled);

  const dnsTest = dnsTestPanel(() => {
    const domain = doms.get()[0];
    if (!domain) throw new Error('Add a domain name first');
    if (!dnsSel.value) throw new Error('Choose a certificate provider first');
    const chosen = byId(S.dns_providers, dnsSel.value);
    if (chosen && chosen.kind === '') throw new Error('This provider has no DNS credentials, so there is no DNS challenge to test');
    return { id: dnsSel.value, domain };
  });

  const body = h('div', {}, name.wrap,
    h('div', { class: 'field' }, h('label', {}, 'Domain names *'), doms.node,
      h('div', { class: 'help' }, 'One name per line (Enter adds another). Plain host names and wildcards such as *.example.com both work.')),
    h('div', { class: 'field' }, h('label', {}, 'Certificate provider *'), dnsSel, noCreds,
      h('div', { class: 'help' }, 'Which certificate authority issues it, and the DNS credentials CertSmith uses to prove you own the names (a temporary TXT record, DNS-01). Manage providers under Certificate providers.')),
    prop.wrap, dnsTest.node, key.wrap, auto.wrap, en.wrap);

  modal(isNew ? 'Add certificate' : 'Edit certificate', body, close => {
    closeDialog = close;
    return [
      !isNew ? h('button', { class: 'btn danger', onclick: async e => {
        if (!confirm(`Delete certificate "${c.name}" and its stored key?`)) return;
        await submit(e.target, async () => { await api('DELETE', '/api/certs/' + c.id); close(); toast('Deleted'); });
      } }, 'Delete') : null,
      h('div', { class: 'grow' }),
      h('button', { class: 'btn', onclick: close }, 'Cancel'),
      h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
        const domains = doms.get();
        if (!name.get().trim()) throw new Error('Give the certificate a name');
        if (!domains.length) throw new Error('Add at least one domain name');
        if (!dnsSel.value && !selfSigned) throw new Error('Choose a certificate provider (add one under Certificate providers first)');
        await api(isNew ? 'POST' : 'PUT', isNew ? '/api/certs' : '/api/certs/' + c.id, {
          name: name.get().trim(), domains, dns_id: dnsSel.value, key_type: key.get(), auto_renew: auto.get() === 'true', enabled: en.get() === 'true',
          propagation_seconds: +prop.get() || 0 });
        close(); toast(isNew ? 'Added - issuing now' : 'Saved');
      }) }, 'Save')];
  });
}

const VENDOR_ORDER = ['Fortinet', 'Proxmox', 'Generic'];

// Vendor drop-down, then the type for that vendor, then that type's form.
function pluginForm(kinds, current, extra, opts) {
  opts = opts || {};
  const locked = !!current.kind && !!current.id;
  const vendorOf = d => d.vendor || 'Other';
  const vendors = [...new Set(kinds.map(vendorOf))].sort((a, b) => {
    const ia = VENDOR_ORDER.indexOf(a), ib = VENDOR_ORDER.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
  });
  const initial = kinds.find(k => k.kind === current.kind) || kinds[0];
  const vendorSel = h('select', { disabled: locked }, vendors.map(v => h('option', { value: v }, v)));
  vendorSel.value = vendorOf(initial);
  const kindSel = h('select', { disabled: locked });
  const holder = h('div');
  let form;
  // the main product of each vendor first, the rest alphabetical
  const KIND_ORDER = ['fortigate', 'fortimanager', 'fortianalyzer', 'pve', 'webhook', 'files', 'watch'];
  const kindRank = d => { const i = KIND_ORDER.indexOf(d.kind); return i < 0 ? 99 : i; };
  const fillKinds = keep => {
    const ordered = kinds.filter(k => vendorOf(k) === vendorSel.value).sort((a, b) => kindRank(a) - kindRank(b) || a.label.localeCompare(b.label));
    kindSel.replaceChildren(...ordered.map(d => h('option', { value: d.kind }, d.label)));
    kindSel.value = [...kindSel.options].some(o => o.value === keep) ? keep : kindSel.options[0].value;
  };
  const draw = () => {
    const d = kinds.find(k => k.kind === kindSel.value);
    form = buildFields(d.fields, kindSel.value === current.kind ? current.config : null);
    if (d.auto_verify && form.by.verify) {
      // the address to check is already known: say so instead of making the user type it again
      const hint = h('div', { class: 'help autohint' });
      form.by.verify.wrap.append(hint);
      const update = () => {
        const host = (form.by.host ? form.by.host.get() : '').trim();
        const port = (form.by.port ? form.by.port.get() : '').trim() || d.auto_verify_port || '443';
        if (!host) hint.textContent = '';
        else if (!d.auto_verify_when || form.cond(d.auto_verify_when)) hint.textContent = '✓ Checked automatically: ' + host + ':' + port + '. Add more addresses above if needed.';
        else hint.textContent = 'Nothing is checked automatically for the ticked options. Add the address that serves the certificate above.';
      };
      form.onAnyChange(update);
      update();
    }
    holder.replaceChildren(d.help ? h('div', { class: 'help', style: 'margin:-4px 0 12px' }, d.help) : null, ...form.nodes);
    if (form.by.pin_sha256) { // a certificate the user chose to trust: say so, and let them undo it
      const trust = h('div', { class: 'trustline' });
      const paint = () => {
        const pin = form.by.pin_sha256.input.value.replace(/[:\s]/g, '').toLowerCase();
        trust.replaceChildren();
        if (!pin) return;
        trust.append('Trusting the certificate this device presented (SHA-256 ' + pin.slice(0, 16) + '…) ',
          h('button', { type: 'button', class: 'linklike', onclick: () => { form.by.pin_sha256.input.value = ''; paint(); } }, 'Forget'));
      };
      form.paintTrust = paint;
      paint();
      if (form.rows.conn) form.rows.conn.after(trust); else holder.append(trust);
    }
  };
  vendorSel.addEventListener('change', () => { fillKinds(); draw(); });
  kindSel.addEventListener('change', draw);
  fillKinds(initial.kind);
  draw();
  const top = kinds.length === 1 ? [] // nothing to choose between: no pickers
    : opts.vendors
      ? [h('div', { class: 'field' }, h('label', {}, 'Vendor'), vendorSel), h('div', { class: 'field' }, h('label', {}, 'Type'), kindSel)]
      : [h('div', { class: 'field' }, h('label', {}, opts.typeLabel || 'Type'), kindSel)];
  return { node: h('div', {}, ...top, extra, holder), read: () => ({ kind: kindSel.value, config: form.read() }),
    setValue: (k, v) => { form.by[k].input.value = v; if (form.paintTrust) form.paintTrust(); },
    getValue: k => (form.by[k] ? form.by[k].get() : '') };
}

// Add or edit a certificate provider. Let's Encrypt needs only DNS credentials (its directory is in
// Settings). Another CA, reached with External Account Binding, adds the CA, the key it issued, and an
// optional account email; it still needs DNS credentials, because names are always proven with DNS-01.
function providerForm(p, authority) {
  const isNew = !p;
  p = p || { name: '', kind: 'cloudflare', config: {}, authority: authority === 'eab' ? 'eab' : '' };
  const presets = schema.eab_cas || [];

  const name = fieldEl({ key: 'name', label: 'Name', type: 'text', required: true }, p.name);
  const authSel = h('select', { disabled: !isNew, title: isNew ? '' : 'The CA of an existing provider cannot be changed: add a new provider instead' },
    h('option', { value: 'letsencrypt' }, "Let's Encrypt"), h('option', { value: 'eab' }, 'Another CA (External Account Binding)'),
    // not a provider: a certificate somebody else issued is uploaded instead (the DNS fields give way to the upload fields)
    isNew ? h('option', { value: 'import' }, 'Import an existing certificate (upload files)') : null);
  authSel.value = isEAB(p) ? 'eab' : 'letsencrypt';
  const authField = h('div', { class: 'field' }, h('label', {}, 'Certificate authority'), authSel);

  // ---- the CA, when it is not Let's Encrypt
  const caSel = h('select', {}, presets.map(c => h('option', { value: c.id }, c.label)));
  caSel.value = presets.some(c => c.id === p.ca) ? p.ca : (isNew ? (presets[0] || {}).id : 'custom');
  const caHelp = h('div', { class: 'help' });
  const dirF = fieldEl({ key: 'directory', label: 'CA directory URL', type: 'text', required: true,
    help: "Where the CA's ACME service lives. If your CA's account page shows a different URL (Sectigo has one per product), use that." }, p.directory || '');
  const kidF = fieldEl({ key: 'eab_kid', label: 'EAB key ID', type: 'text', required: true, help: 'Also called the Key Identifier or KID.' }, p.eab_kid || '');
  const hmacF = fieldEl({ key: 'eab_hmac', label: 'EAB HMAC key', type: 'password', required: true,
    help: 'The MAC key the CA shows when it creates the key, often only once. It is stored encrypted and never shown again.', autocomplete: 'off' }, p.eab_hmac || '');
  const emailF = fieldEl({ key: 'email', label: 'Account email (optional)', type: 'text', help: 'Registered with the CA. Empty uses the address in Settings.' }, p.email || '');
  const showPreset = fromUser => {
    const c = presets.find(x => x.id === caSel.value) || {};
    caHelp.textContent = c.help || '';
    if (fromUser || (!dirF.input.value && c.directory)) dirF.input.value = c.directory || '';
  };
  caSel.addEventListener('change', () => showPreset(true));
  showPreset(false);

  const eabFields = () => ({ authority: 'eab', ca: caSel.value, directory: dirF.get().trim(), eab_kid: kidF.get().trim(), eab_hmac: hmacF.get(), email: emailF.get().trim() });
  const acctOut = h('div', { class: 'dnsreport' });
  const acctBtn = h('button', { type: 'button', class: 'btn small', onclick: async () => {
    acctBtn.disabled = true;
    acctOut.replaceChildren(h('div', { class: 'meta' }, spinner(), ' Contacting the CA…'));
    try {
      const r = await api('POST', '/api/dns/check-account', Object.assign({ id: isNew ? undefined : p.id }, eabFields()));
      acctOut.replaceChildren(h('div', { class: 'dstep ok' }, h('span', { class: 'ic' }, '✓'), h('span', {}, 'The CA accepted these credentials: ' + r.message)));
    } catch (e) { acctOut.replaceChildren(h('div', { class: 'dstep bad' }, h('span', { class: 'ic' }, '✗'), h('span', {}, e.message))); } finally { acctBtn.disabled = false; }
  } }, 'Check CA account');
  const eabPanel = h('div', {},
    h('div', { class: 'field' }, h('label', {}, 'Which CA'), caSel, caHelp), dirF.wrap, kidF.wrap, hmacF.wrap, emailF.wrap,
    h('div', { class: 'field' }, h('label', {}, 'Check the CA account'), acctBtn,
      h('div', { class: 'help' }, 'Signs in to the CA with these credentials (and creates the account there the first time). No certificate is requested.'), acctOut));
  const lePanel = h('div', { class: 'help', style: 'margin:-4px 0 12px' },
    "Let's Encrypt needs no account details here: it uses the directory and email set under Settings.");

  // ---- DNS credentials. Needed by every provider except one at a CA that validates domains in the
  // account ahead of time, where the CA never sets a challenge.
  const pf = pluginForm(sortedDNS(), p, null, { typeLabel: 'DNS provider' });
  const noDnsChk = h('input', { type: 'checkbox' });
  noDnsChk.checked = !isNew && isEAB(p) && p.kind === '';
  const noDnsField = h('div', { class: 'field check' }, h('label', {}, noDnsChk, 'This CA validates my domains in my account: no DNS credentials'),
    h('div', { class: 'help' }, 'Choose this if you validate your domains in the CA account ahead of time. CertSmith then answers no challenges. If the CA does ask for one, the issuance fails and says so.'));
  const dnsBlock = h('div', {},
    h('div', { class: 'sect' }, 'DNS credentials'),
    h('p', { class: 'meta', style: 'margin:0 0 12px' }, 'Used to publish the temporary TXT record that proves you own the names (DNS-01).'), pf.node);
  // The name is the person's own: nothing is filled in for them. A hint shows what a good one looks like.
  const imp = isNew ? importPanel(false) : null;
  const paint = () => {
    const importing = authSel.value === 'import';
    const eab = authSel.value === 'eab';
    eabPanel.style.display = eab ? '' : 'none';
    lePanel.style.display = eab || importing ? 'none' : '';
    const canSkip = eab && !!(presets.find(c => c.id === caSel.value) || {}).prevalidated;
    noDnsField.style.display = canSkip ? '' : 'none';
    if (!canSkip) noDnsChk.checked = false;
    const noDns = importing || (canSkip && noDnsChk.checked);
    dnsBlock.style.display = noDns ? 'none' : '';
    testBlock.style.display = noDns ? 'none' : '';
    if (imp) imp.node.style.display = importing ? '' : 'none';
    name.input.placeholder = importing ? 'A name you will recognise, for example Corporate wildcard'
      : 'A name you will recognise, for example Cloudflare (example.com)';
    checkBtn.style.display = importing ? '' : 'none';
    saveBtn.textContent = importing ? 'Import certificate' : 'Save';
    const m = body.closest('.modal');
    if (m) m.querySelector('h2').textContent = importing ? 'Import certificate' : isNew ? 'Add certificate provider' : 'Edit certificate provider';
  };
  authSel.addEventListener('change', paint);
  caSel.addEventListener('change', paint);
  noDnsChk.addEventListener('change', paint);

  const testDomain = fieldEl({ key: 'td', label: 'Domain to test with', type: 'text', help: 'A domain in the zone these DNS credentials manage, e.g. example.com.' }, '');
  const dnsTest = dnsTestPanel(() => {
    const cur = pf.read();
    return { id: isNew ? undefined : p.id, kind: cur.kind, config: cur.config, domain: testDomain.get() };
  });
  const testBlock = h('div', {}, h('div', { class: 'sect' }, 'Test'), testDomain.wrap, dnsTest.node);
  const body = h('div', {}, name.wrap, authField, eabPanel, lePanel, imp ? imp.node : null, noDnsField, dnsBlock, testBlock);
  const checkBtn = h('button', { class: 'btn', title: 'Reads the files and shows what they contain, without importing',
    onclick: e => submit(e.target, () => imp.check()) }, 'Check files');
  let closeDialog = () => {}; // set once the dialog exists
  const saveBtn = h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
    if (!name.get().trim()) throw new Error(authSel.value === 'import' ? 'Give the certificate a name' : 'Enter a name for this provider');
    if (authSel.value === 'import') {
      await api('POST', '/api/certs/import', Object.assign({ name: name.get().trim() }, await imp.payload()));
      closeDialog(); toast('Certificate imported');
      return;
    }
    const extra = authSel.value === 'eab' ? eabFields() : { authority: 'letsencrypt' };
    const noDns = authSel.value === 'eab' && noDnsChk.checked && noDnsField.style.display !== 'none';
    await api(isNew ? 'POST' : 'PUT', isNew ? '/api/dns' : '/api/dns/' + p.id, Object.assign({ name: name.get() }, noDns ? { kind: '', config: {} } : pf.read(), extra));
    closeDialog(); toast('Saved');
  }) }, 'Save');
  modal(isNew ? 'Add certificate provider' : 'Edit certificate provider', body, close => {
    closeDialog = close;
    return [
      !isNew ? h('button', { class: 'btn danger', onclick: async e => {
        if (!confirm(`Delete provider "${p.name}"?`)) return;
        await submit(e.target, async () => { await api('DELETE', '/api/dns/' + p.id); close(); toast('Deleted'); });
      } }, 'Delete') : null,
      h('div', { class: 'grow' }),
      h('button', { class: 'btn', onclick: close }, 'Cancel'),
      checkBtn, saveBtn];
  });
  paint(); // the dialog exists now: heading and buttons follow the choice
}

// Asks whether to trust the certificate a device presented. Resolves true when confirmed.
function confirmTrust(info, previousPin) {
  return new Promise(resolve => {
    const colon = fp => (fp.match(/.{1,2}/g) || []).join(':').toUpperCase();
    const prev = (previousPin || '').replace(/[:\s]/g, '').toLowerCase();
    const changed = !!prev && prev !== info.fingerprint;
    const row = (k, v) => h('tr', {}, h('th', {}, k), h('td', {}, v));
    const finish = ok => { bg.remove(); resolve(ok); };
    const bg = h('div', { class: 'modal-bg top' }, h('div', { class: 'modal', role: 'alertdialog', 'aria-label': 'Trust this certificate?' },
      h('h2', {}, changed ? 'This device is presenting a different certificate' : "Trust this device's certificate?"),
      h('div', { class: 'body' },
        h('p', {}, info.self_signed
          ? "The device uses a self-signed certificate, which is normal for a new appliance that has no real certificate yet."
          : 'The device presented a certificate that is not signed by an authority this server trusts, or that does not match the address used.'),
        changed ? h('p', { class: 'err' }, 'It is not the certificate you trusted before. Only continue if you replaced the certificate on the device.') : null,
        h('table', { class: 'kv' },
          row('Address', info.endpoint), row('Subject', info.subject), row('Issued by', info.issuer),
          row('Valid until', fmt(info.not_after) + (info.expired ? ' (expired)' : '')),
          info.names && info.names.length ? row('Names', info.names.join(', ')) : null,
          row('SHA-256', h('span', { class: 'mono fp' }, colon(info.fingerprint)))),
        h('p', { class: 'meta' }, 'Compare the fingerprint with the one on the device if you can. CertSmith remembers exactly this certificate. Once a normally trusted certificate is installed, that works too.')),
      h('div', { class: 'foot' },
        h('button', { class: 'btn', onclick: () => finish(false) }, 'Cancel'),
        h('button', { class: 'btn primary', onclick: () => finish(true) }, 'Trust this certificate'))));
    document.getElementById('modal-root').append(bg);
  });
}

// The API calls page for one target: what was really sent to the device (newest first), and the
// plugin's own account of what each call is for. Bodies, tokens and keys are never recorded.
// `pending` is the calls of a connection test on a target that is not saved yet.
function callsDialog(t, pending) {
  const kind = t.kind;
  const desc = schema.targets.find(d => d.kind === kind) || { label: kind, calls: [] };
  const when = stamp;
  const opName = { test: 'Connection test', deploy: 'Deployment' };
  const statusChip = c => !callFailed(c) ? chip(String(c.status), 'ok') : chip(c.status ? String(c.status) : 'no reply', 'bad');
  const log = h('div', { class: 'callslog' }, h('div', { class: 'meta' }, 'Loading…'));
  const render = calls => {
    if (!calls.length) { log.replaceChildren(h('div', { class: 'meta' }, 'Nothing has been sent to this device yet. Run a connection test or a deployment and its requests appear here.')); return; }
    log.replaceChildren(h('table', { class: 'calls' },
      h('thead', {}, h('tr', {}, ['When', 'For', 'Request', 'Answer', ''].map(x => h('th', {}, x)))),
      h('tbody', {}, calls.slice().reverse().map(c => h('tr', { class: callFailed(c) ? 'failed' : '' },
        h('td', { class: 'nowrap' }, when(c.time)),
        h('td', {}, chip(opName[c.op] || c.op)),
        h('td', {}, h('span', { class: 'mono' }, c.method + ' ' + c.path),
          c.detail ? h('div', { class: 'meta mono' }, c.detail) : null,
          h('div', { class: 'meta' }, c.host)),
        h('td', {}, statusChip(c), c.answer ? h('div', { class: callFailed(c) ? 'err small' : 'meta' }, c.answer) : null, c.error ? h('div', { class: 'err small' }, c.error) : null),
        h('td', { class: 'nowrap meta' }, c.ms + ' ms'))))));
  };
  if (t.id) api('GET', '/api/targets/' + t.id + '/calls').then(r => render(r.calls.concat(pending || []).sort((a, b) => new Date(a.time) - new Date(b.time)))).catch(e => log.replaceChildren(h('div', { class: 'err' }, e.message)));
  else render(pending || []);

  const docs = desc.calls || [];
  const docTable = op => {
    const rows = docs.filter(d => d.op === op);
    if (!rows.length) return null;
    return h('div', {}, h('h3', {}, opName[op]),
      h('table', { class: 'calls docs' }, h('tbody', {}, rows.map(d => h('tr', {},
        h('td', { class: 'nowrap' }, h('span', { class: 'mono' }, d.method + ' ' + d.path)),
        h('td', {}, d.purpose, d.when ? h('div', { class: 'meta' }, 'Sent when: ' + d.when) : null),
        h('td', { class: 'nowrap' }, d.changes ? chip('changes the device', 'warn') : chip('read only')))))));
  };
  const body = h('div', { class: 'callsdlg' },
    h('p', { class: 'meta' }, 'Everything CertSmith sends to this device is listed here with the answer it got. Certificates, private keys, tokens and request bodies are never recorded; ',
      'query values that look like credentials are hidden.'),
    h('h3', {}, 'What was sent'), log,
    h('h3', {}, 'What ' + desc.label + ' sends'),
    h('p', { class: 'meta' }, 'Descriptions of every call this plugin can make. A call only happens when its condition applies.'),
    docTable('test'), docTable('deploy'),
    h('p', { class: 'meta' }, 'Separately, CertSmith opens a plain TLS connection to the addresses it checks and reads the certificate being served. That is not an API call and sends nothing.'));
  const bg = h('div', { class: 'modal-bg top', onmousedown: e => { if (e.target === bg) bg.remove(); } },
    h('div', { class: 'modal wide', role: 'dialog', 'aria-label': 'API calls' },
      h('h2', {}, 'API calls' + (t.name ? ': ' + t.name : '')),
      h('div', { class: 'body' }, body),
      h('div', { class: 'foot' }, h('button', { class: 'btn', onclick: () => bg.remove() }, 'Close'))));
  document.getElementById('modal-root').append(bg);
}

function targetForm(t, presetCert, presetKind) {
  const isNew = !t;
  const has = k => schema.targets.some(d => d.kind === k);
  t = t || { name: '', kind: presetKind && has(presetKind) ? presetKind : has('fortigate') ? 'fortigate' : schema.targets[0].kind,
    cert_id: presetCert || (S.certificates[0] || {}).id || '', enabled: true, config: {} };
  const own = (presetKind || t.kind) === 'selfui'; // this page's own certificate: nothing is called over an API
  const name = fieldEl({ key: 'name', label: 'Name', type: 'text', required: true }, t.name || (presetKind === 'selfui' ? (schema.hostname || 'This server') + ' (This server)' : ''));
  // Types marked hidden are not offered in the general list. The Settings page opens the dialog for
  // one of them directly (shown alone, no vendor or type to choose), and an existing target of that
  // type still opens normally.
  const kinds = presetKind ? schema.targets.filter(d => d.kind === presetKind) : schema.targets.filter(d => !d.hidden || d.kind === t.kind);
  // "none" only makes sense for a monitor-only target; a preset type always needs a certificate
  const cert = h('select', {}, presetKind ? null : h('option', { value: '' }, '- none (monitor only) -'),
    (S.certificates || []).map(c => h('option', { value: c.id }, c.name + ' (' + c.domains[0] + ')')));
  cert.value = t.cert_id || '';
  const en = fieldEl({ key: 'enabled', label: 'Enabled', type: 'bool' }, t.enabled);
  const pf = pluginForm(kinds, Object.assign({ id: isNew ? '' : t.id }, t),
    h('div', {}, name.wrap, h('div', { class: 'field' }, h('label', {}, 'Certificate'), cert), en.wrap), { vendors: true });
  const testMsg = h('span', { class: 'testmsg' });

  // Runs the connection test. A device whose certificate cannot be verified is not
  // just reported as failed: the user is shown it and asked whether to trust it, and
  // the test is repeated.
  let testCalls = []; // the calls of the latest test, shown by the API calls button for a target not saved yet
  async function runTest() {
    testMsg.className = 'testmsg'; testMsg.textContent = 'Testing…';
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await api('POST', '/api/test-target', Object.assign({ id: isNew ? '' : t.id }, pf.read()));
        testCalls = r.calls || [];
        testMsg.className = 'testmsg ok'; testMsg.textContent = '✓ ' + r.message;
        return true;
      } catch (err) {
        testCalls = (err.data && err.data.calls) || [];
        if (err.data && err.data.untrusted && attempt === 0) {
          testMsg.textContent = 'Waiting for your decision…';
          if (await confirmTrust(err.data.untrusted, pf.getValue('pin_sha256'))) {
            pf.setValue('pin_sha256', err.data.untrusted.fingerprint);
            testMsg.textContent = 'Testing…';
            continue;
          }
          testMsg.className = 'testmsg bad'; testMsg.textContent = '✗ Certificate not trusted';
          return false;
        }
        testMsg.className = 'testmsg bad'; testMsg.textContent = '✗ ' + err.message;
        return false;
      }
    }
    return false;
  }

  modal(own ? 'Configure SSL certificate' : isNew ? 'Add target' : 'Edit target', pf.node, close => [
    !isNew ? h('button', { class: 'btn danger', onclick: async e => {
      if (!confirm(own ? "Stop managing this page's certificate? The certificate now in use stays until it expires, and the page keeps working."
        : `Delete target "${t.name}"? The certificate stays on the device.`)) return;
      await submit(e.target, async () => { await api('DELETE', '/api/targets/' + t.id); close(); toast('Deleted'); });
    } }, own ? 'Stop managing' : 'Delete') : null,
    !isNew && t.kind !== 'watch' ? h('button', { class: 'btn', title: 'Deploy the current certificate to this device now, with the settings as last saved',
      onclick: e => submit(e.target, async () => { await api('POST', '/api/targets/' + t.id + '/deploy'); close(); toast('Deployment started'); }) }, 'Deploy now') : null,
    testMsg,
    own ? null : h('button', { class: 'btn ghost', title: 'What the plugin sends to the device, and what was sent', onclick: () =>
      callsDialog({ id: isNew ? '' : t.id, kind: pf.read().kind, name: name.get() }, isNew ? testCalls : []) }, 'API calls'),
    own ? null : h('button', { class: 'btn', onclick: e => submit(e.target, runTest) }, 'Test connection'),
    h('button', { class: 'btn', onclick: close }, 'Cancel'),
    h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
      // test first, so an untrusted certificate or a wrong token is caught here and not at the first deployment
      if (!(await runTest()) && !confirm('The connection test did not pass. Save this target anyway?')) return;
      await api(isNew ? 'POST' : 'PUT', isNew ? '/api/targets' : '/api/targets/' + t.id,
        Object.assign({ name: name.get(), cert_id: cert.value, enabled: en.get() === 'true' }, pf.read()));
      close(); toast(isNew ? 'Added - deploying shortly' : 'Saved');
    }) }, 'Save')]);
}

// ---- users -------------------------------------------------------------------------------
function addUserForm() {
  const u = fieldEl({ key: 'u', label: 'Username', type: 'text', required: true }, '');
  const p = fieldEl({ key: 'p', label: 'New user\'s password (minimum 12 characters)', type: 'password', required: true, autocomplete: 'new-password' }, '');
  const p2 = fieldEl({ key: 'p2', label: 'Repeat the new user\'s password', type: 'password', required: true, autocomplete: 'new-password' }, '');
  const c = fieldEl({ key: 'c', label: 'Your own password, to confirm', type: 'password', required: true, autocomplete: 'current-password' }, '');
  modal('Add user', h('div', {}, u.wrap, p.wrap, p2.wrap,
    h('div', { class: 'sect' }, 'Confirm that it is you'),
    h('p', { class: 'meta', style: 'margin:0 0 12px' }, 'Adding a user asks for the password of the account you are signed in with, so a signed-in browser alone cannot create accounts.'),
    c.wrap), close => [h('div', { class: 'grow' }),
    h('button', { class: 'btn', onclick: close }, 'Cancel'),
    h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
      if (p.get() !== p2.get()) throw new Error('The two passwords for the new user do not match');
      await api('POST', '/api/users', { username: u.get(), password: p.get(), confirm: c.get() });
      close(); toast('User added');
    }) }, 'Add user')]);
}

function resetUserForm(name) {
  const p = fieldEl({ key: 'p', label: 'New password for ' + name + ' (minimum 12 characters)', type: 'password', required: true, autocomplete: 'new-password' }, '');
  const p2 = fieldEl({ key: 'p2', label: 'Repeat the new password', type: 'password', required: true, autocomplete: 'new-password' }, '');
  const c = fieldEl({ key: 'c', label: 'Your own password, to confirm', type: 'password', required: true, autocomplete: 'current-password' }, '');
  modal('Reset password', h('div', {}, p.wrap, p2.wrap,
    h('div', { class: 'sect' }, 'Confirm that it is you'), c.wrap), close => [h('div', { class: 'grow' }),
    h('button', { class: 'btn', onclick: close }, 'Cancel'),
    h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
      if (p.get() !== p2.get()) throw new Error('The two new passwords do not match');
      await api('POST', '/api/users/' + encodeURIComponent(name) + '/password', { password: p.get(), confirm: c.get() });
      close(); toast(name + ' was signed out and must use the new password');
    }) }, 'Reset password')]);
}

// A new self-signed certificate for this page. Confirmed with the password because a reverse proxy that
// pins the old certificate stops working until it is told about the new one.
function regenerateUICertForm() {
  const c = fieldEl({ key: 'c', label: 'Your password, to confirm', type: 'password', required: true, autocomplete: 'current-password' }, '');
  modal('Regenerate the self-signed certificate?', h('div', {},
    h('p', {}, 'CertSmith creates a new key and a new self-signed certificate for this page, valid for five years and covering the names and addresses this server has now. It applies to new connections straight away, and nobody is signed out.'),
    h('p', {}, 'Browsers ask again whether to trust the page. A reverse proxy that pins or trusts the current certificate must be given the new fingerprint, which is shown here afterwards.'),
    c.wrap), close => [h('div', { class: 'grow' }),
    h('button', { class: 'btn', onclick: close }, 'Cancel'),
    h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
      await api('POST', '/api/ui-cert/regenerate', { confirm: c.get() });
      close(); toast('New self-signed certificate created'); await refresh();
    }) }, 'Regenerate certificate')]);
}

function deleteUserForm(name) {
  const c = fieldEl({ key: 'c', label: 'Your password, to confirm', type: 'password', required: true, autocomplete: 'current-password' }, '');
  modal('Delete ' + name + '?', h('div', {}, h('p', {}, name + ' will no longer be able to sign in.'), c.wrap), close => [h('div', { class: 'grow' }),
    h('button', { class: 'btn', onclick: close }, 'Cancel'),
    h('button', { class: 'btn danger', onclick: e => submit(e.target, async () => {
      await api('DELETE', '/api/users/' + encodeURIComponent(name), { confirm: c.get() });
      close(); toast('User deleted');
    }) }, 'Delete user')]);
}

// ---- settings -----------------------------------------------------------------------------
function renderSettings() {
  const s = S.settings, m = s.smtp;
  const F = (key, label, type, value, extra) => fieldEl(Object.assign({ key, label, type }, extra || {}), value);
  const dir = F('acme_directory', "Let's Encrypt directory", 'select', s.acme_directory, {
    options: [{ value: 'production', label: 'Production' }, { value: 'staging', label: 'Staging (test certificates)' }, { value: 'selfsigned', label: 'Built-in test CA' }],
    help: "Production issues publicly trusted certificates. Staging issues untrusted test certificates without rate limits. The built-in test CA is for demonstrations only. Changing the directory reissues every Let's Encrypt certificate and redeploys it to targets that already have one." });
  const email = F('acme_email', 'Account email', 'text', s.acme_email, { help: "Contact address registered with Let's Encrypt, which sends expiry notices to it. Providers for other certificate authorities can use their own address; this one is the default." });
  const renew = F('renew_before_days', 'Renew when fewer than N days remain', 'number', s.renew_before_days);
  const warn = F('warn_days', 'Alert when fewer than N days remain', 'number', s.warn_days);
  const probe = F('probe_minutes', 'Check live endpoints every N minutes', 'number', s.probe_minutes);
  const keepDev = F('keep_on_device', 'Certificates to keep on each device', 'number', s.keep_on_device || 3,
    { help: 'After a deployment to a FortiGate, FortiManager or FortiAnalyzer, this many CertSmith certificates stay on the device: the one in use and the most recent older ones, so a previous certificate can be chosen again there if needed. Older ones that nothing uses are removed. Minimum 1.' });
  const resolvers = resolverRows(s.dns_resolvers || []);
  const resField = h('div', { class: 'field' }, h('label', {}, 'DNS resolvers'), resolvers.node,
    h('div', { class: 'help' }, "Optional. Resolvers used to locate the zone's authoritative nameservers. If empty, the server's own resolver is used. Add a second entry as a fallback."));
  const dnsCheck = F('dns_check', 'Record publication check', 'select', s.dns_check || 'auto', {
    options: [{ value: 'auto', label: 'Automatic (recommended)' }, { value: 'check', label: "Always query the zone's nameservers" }, { value: 'wait', label: 'Always wait a fixed time' }],
    help: "Automatic queries the zone's nameservers directly. If the network intercepts DNS (some gateways and firewalls answer from a cache), the response cannot be trusted and CertSmith waits for a fixed time instead." });
  const dnsWait = F('dns_wait_seconds', 'Fixed wait time (seconds)', 'number', s.dns_wait_seconds || 25,
    { help: 'Time to wait when the publication check is not used. Cloudflare typically publishes within a few seconds.' });
  // Which kinds of alert go to which channel. Until a choice has been saved, the earlier behaviour is
  // shown: every problem on both channels, successes only if the old switch was on.
  const alertTypes = schema.alert_types || [];
  const successIds = ['cert.issued', 'deploy.ok', 'alert.cleared'];
  const routed = (ch, t) => s.alert_routing ? (s.alert_routing[ch] || []).includes(t.id)
    : (t.problem || (!!s.notify_success && successIds.includes(t.id)));
  const alertBoxes = { email: {}, webhook: {} };
  const alertsCard = () => {
    const rows = [];
    let group = '';
    const colAll = ch => {
      const cb = h('input', { type: 'checkbox', 'aria-label': 'All alert types by ' + (ch === 'email' ? 'email' : 'webhook') });
      const sync = () => { const all = alertTypes.map(t => alertBoxes[ch][t.id]); cb.checked = all.every(x => x.checked); cb.indeterminate = !cb.checked && all.some(x => x.checked); };
      cb.addEventListener('change', () => { alertTypes.forEach(t => { alertBoxes[ch][t.id].checked = cb.checked; }); sync(); });
      return { cb, sync };
    };
    const all = { email: colAll('email'), webhook: colAll('webhook') };
    alertTypes.forEach(t => {
      if (t.group !== group) { group = t.group; rows.push(h('tr', { class: 'grouprow' }, h('th', { colspan: 3 }, group))); }
      const mk = ch => {
        const cb = h('input', { type: 'checkbox', 'aria-label': t.label + ' by ' + ch });
        cb.checked = routed(ch, t);
        cb.addEventListener('change', () => all[ch].sync());
        alertBoxes[ch][t.id] = cb;
        return h('td', { class: 'chcell' }, cb);
      };
      rows.push(h('tr', {}, h('td', {}, t.label), mk('email'), mk('webhook')));
    });
    all.email.sync(); all.webhook.sync();
    return card('Alert types', 'Select which events are sent to each channel. The channels are configured above. Use a column header to select or clear every type for that channel.',
      h('table', { class: 'alerttypes' },
        h('thead', {}, h('tr', {}, h('th', {}, 'Send an alert when…'),
          h('th', { class: 'chcell' }, h('label', {}, all.email.cb, h('span', {}, 'Email'))),
          h('th', { class: 'chcell' }, h('label', {}, all.webhook.cb, h('span', {}, 'Webhook'))))),
        h('tbody', {}, rows)));
  };
  const sm = {
    enabled: F('enabled', 'Send alerts by email', 'bool', m.enabled),
    host: F('host', 'SMTP host', 'text', m.host), port: F('port', 'Port', 'number', m.port || 587),
    security: F('security', 'Security', 'select', m.security, { options: ['starttls', 'tls', 'none'] }),
    username: F('username', 'Username (optional)', 'text', m.username), password: F('password', 'Password', 'password', m.password),
    from: F('from', 'From address', 'text', m.from), to: F('to', 'Recipients', 'text', (m.to || []).join(', '), { help: 'Comma separated.' }),
  };
  const hook = F('webhook_url', 'Webhook URL (optional)', 'text', s.webhook_url, { help: 'Slack, Mattermost, Microsoft Teams or any endpoint that accepts JSON with a "text" field.' });

  const proxies = F('trusted_proxies', 'Trusted proxies', 'textarea', (s.trusted_proxies || []).join('\n'),
    { help: 'One address or network per line, for example 192.0.2.5 or 192.0.2.0/24. Only a connection from one of these is believed when it says which client it forwards. Leave empty if nothing sits in front of CertSmith, or to treat every connection as the client itself.' });
  const updChk = F('update_check', 'Check for updates automatically', 'bool', !s.update_check_disabled,
    { help: 'Asks the release host (api.github.com) once a day whether a newer version has been published. Nothing about this installation is sent.' });

  const collect = () => ({
    acme_directory: dir.get(), acme_email: email.get(), renew_before_days: +renew.get() || 30, warn_days: +warn.get() || 14,
    probe_minutes: +probe.get() || 15, keep_on_device: +keepDev.get() || 3, dns_resolvers: resolvers.get(), dns_check: dnsCheck.get(), dns_wait_seconds: +dnsWait.get() || 25,
    notify_success: !!s.notify_success, webhook_url: hook.get().trim(), update_check_disabled: updChk.get() !== 'true',
    trusted_proxies: proxies.get().split(/[\s,]+/).filter(Boolean),
    alert_routing: { email: alertTypes.filter(t => alertBoxes.email[t.id].checked).map(t => t.id), webhook: alertTypes.filter(t => alertBoxes.webhook[t.id].checked).map(t => t.id) },
    smtp: { enabled: sm.enabled.get() === 'true', host: sm.host.get().trim(), port: +sm.port.get() || 587, security: sm.security.get(),
      username: sm.username.get(), password: sm.password.get(), from: sm.from.get().trim(),
      to: sm.to.get().split(',').map(x => x.trim()).filter(Boolean) },
  });
  const testMsg = h('span', { class: 'testmsg' });
  const curPw = fieldEl({ key: 'cur', label: 'Current password', type: 'password', autocomplete: 'current-password' }, '');
  const pw = fieldEl({ key: 'pw', label: 'New password (minimum 12 characters)', type: 'password', autocomplete: 'new-password' }, '');
  const pw2 = fieldEl({ key: 'pw2', label: 'Confirm new password', type: 'password', autocomplete: 'new-password' }, '');

  const card = (title, intro, ...kids) => h('section', { class: 'card pad' },
    h('h2', {}, title), intro ? h('p', { class: 'meta', style: 'margin:2px 0 14px' }, intro) : h('div', { style: 'height:12px' }), ...kids);
  const pair = (x, y) => h('div', { class: 'fgrid' }, x.wrap, y.wrap);

  const usersCard = () => card('Users', 'All users listed can sign in and have full administrative access. There are no separate roles.',
    h('div', { class: 'userlist' }, users.map(u => h('div', { class: 'userrow' },
      h('div', {}, h('strong', {}, u.name), ' ', u.name === me ? chip('you', 'ok') : null, h('div', { class: 'meta', title: 'Added ' + fmt(u.created) },
        u.last_login && !zero(u.last_login) ? 'last signed in ' + fmt(u.last_login) + (u.last_login_from ? ' from ' + u.last_login_from : '') : 'no sign-in recorded')),
      // your own password has one place: the form at the bottom of this card
      u.name === me
        ? h('div', { class: 'meta' }, 'Change yours below')
        : h('div', { class: 'row' },
            h('button', { class: 'btn small ghost', onclick: () => resetUserForm(u.name) }, 'Reset password'),
            h('button', { class: 'btn small danger', onclick: () => deleteUserForm(u.name) }, 'Delete'))))),
    h('button', { class: 'btn', onclick: addUserForm }, 'Add user'),
    h('div', { class: 'sect' }, 'Your password'),
    h('p', { class: 'meta', style: 'margin:0 0 12px' }, 'Changing the password ends your other signed-in sessions.'),
    curPw.wrap, pw.wrap, pw2.wrap,
    h('button', { class: 'btn', onclick: e => submit(e.target, async () => {
      if (!curPw.get()) throw new Error('Enter your current password first');
      if (pw.get() !== pw2.get()) throw new Error('The two new passwords do not match');
      await api('POST', '/api/password', { current: curPw.get(), password: pw.get() });
      curPw.input.value = pw.input.value = pw2.input.value = '';
      toast('Password changed. Other sessions were signed out.');
    }) }, 'Change password'));
  // The certificate CertSmith's own page is served with: self-signed until the user gives it a real one.
  // The colour theme is a preference of this browser, applied at once and kept in localStorage.
  const themeCard = () => {
    let cur = 'system';
    try { const t = localStorage.getItem('certsmith.theme'); if (t === 'light' || t === 'dark') cur = t; } catch (_) { /* follow the system */ }
    const apply = v => {
      if (v === 'light' || v === 'dark') document.documentElement.setAttribute('data-theme', v);
      else document.documentElement.removeAttribute('data-theme');
      try { if (v === 'system') localStorage.removeItem('certsmith.theme'); else localStorage.setItem('certsmith.theme', v); } catch (_) { /* not remembered */ }
    };
    const radio = (v, label) => {
      const input = h('input', { type: 'radio', name: 'theme', value: v });
      input.checked = v === cur;
      input.addEventListener('change', () => { if (input.checked) apply(v); });
      return h('label', {}, input, label);
    };
    return card('Appearance', 'The colour theme of this page. It applies at once, and is remembered in this browser only.',
      h('div', { class: 'radios', role: 'radiogroup', 'aria-label': 'Colour theme' },
        radio('light', 'Light'), radio('dark', 'Dark'), radio('system', 'Follow system')));
  };
  const webUICard = () => {
    const mine = S.targets.find(t => t.kind === 'selfui');
    const cert = mine && byId(S.certificates, mine.cert_id);
    const u = uiCert || {};
    const until = u.not_after && !zero(u.not_after) ? 'valid until ' + fmt(u.not_after).replace(/, \d\d:\d\d$/, '') : '';
    const fp = u.fingerprint ? 'SHA-256 ' + (u.fingerprint.match(/.{1,2}/g) || []).slice(0, 12).join(':').toUpperCase() + '…' : '';
    let current;
    if (!u.tls) {
      current = h('div', { class: 'certline' }, h('strong', {}, 'Not used. '),
        'This page is served over plain HTTP: HTTPS is provided by a reverse proxy in front of CertSmith, which holds the certificate.');
    } else if (u.error) {
      current = h('div', { class: 'certline' }, h('strong', {}, 'Unknown. '), 'The certificate file could not be read: ' + u.error);
    } else if (u.self_signed) {
      current = h('div', { class: 'certline' },
        h('div', {}, chip('self-signed', 'warn'), ' ', h('strong', {}, u.bootstrap ? 'Self-signed certificate created by CertSmith' : 'Self-signed certificate: ' + u.subject)),
        h('div', { class: 'meta' }, [until, fp].filter(Boolean).join(' · ')),
        u.bootstrap
          ? h('div', { class: 'meta' }, 'CertSmith renews this certificate by itself 30 days before it expires.')
          : h('div', { class: 'meta' }, 'This certificate was not created by CertSmith, so it is left alone and not renewed. Use Configure SSL certificate to install a trusted one.'),
        u.missing_names && u.missing_names.length
          ? h('div', { class: 'meta', style: 'color:var(--warn)' }, 'It does not list ' + u.missing_names.join(', ') + ', which this server now uses. Regenerate it to include them.') : null);
    } else {
      const managed = mine && cert && mine.deployed_serial && mine.deployed_serial === cert.serial;
      current = h('div', { class: 'certline' },
        h('div', {}, chip(managed ? 'managed by CertSmith' : 'installed', 'ok'), ' ', h('strong', {}, u.subject)),
        h('div', { class: 'meta' }, ['issued by ' + u.issuer, until].filter(Boolean).join(' · ')),
        u.names && u.names.length ? h('div', { class: 'meta' }, 'Names: ' + u.names.slice(0, 6).join(', ') + (u.names.length > 6 ? ' …' : '')) : null,
        h('div', { class: 'meta' }, managed ? `CertSmith renews it automatically (certificate "${cert.name}").` : 'It was installed outside CertSmith, or CertSmith has not deployed its own certificate to this page yet.'));
    }
    const state = mine && u.tls ? h('div', { class: 'meta', style: 'margin-top:6px' },
      'Configured certificate: ' + (cert ? cert.name : 'none chosen') + ' ', targetStatus(mine, cert)) : null;
    return card('HTTPS certificate',
      "This page uses a self-signed certificate until a certificate from a trusted authority is installed. " +
      "CertSmith can issue one for it and keep it renewed.",
      current, state,
      u.tls ? h('div', { class: 'row', style: 'margin-top:14px' },
        h('button', { class: 'btn', onclick: () => {
          if (mine) { targetForm(mine); return; }
          if (!S.certificates.length) { toast('Add a certificate first, for the name you will use to open this page', true); return; }
          targetForm(null, null, 'selfui');
        } }, 'Configure SSL certificate'),
        u.bootstrap ? h('button', { class: 'btn ghost', onclick: regenerateUICertForm }, 'Regenerate certificate') : null) : null);
  };

  // The installed version, and whether a newer release has been published. The status is redrawn in
  // place by "Check now" so that nothing the person has typed elsewhere on this page is lost.
  const softwareCard = () => {
    const ver = plainVersion(appVersion) || 'unknown';
    const build = String(appVersion).split('+')[1] || '';
    const status = h('div');
    const paint = info => {
      const kids = [];
      if (!info) {
        kids.push(h('div', { class: 'meta' }, 'Update checks are not available in this build.'));
      } else {
        if (info.available) {
          const link = safeLink(info.url);
          kids.push(h('div', { class: 'swline' }, chip('Update available', 'warn'), h('strong', {}, 'Version ' + plainVersion(info.latest)),
            link ? h('a', { href: link, target: '_blank', rel: 'noopener' }, 'Release notes') : null));
          kids.push(h('p', { class: 'meta', style: 'margin:6px 0 4px' },
            'To update, run this on the server that runs CertSmith, as root or with sudo. Settings and data are kept, and the previous version is restored if the new one does not start.'));
          kids.push(h('pre', { class: 'cmd' }, 'bash -c "$(wget -nv -O- https://raw.githubusercontent.com/' + info.repo + '/main/get.sh)"'));
        } else if (info.latest) {
          kids.push(h('div', { class: 'swline' }, chip('Up to date', 'ok'),
            h('span', { class: 'meta' }, 'The latest published release is ' + plainVersion(info.latest) + '.')));
        }
        if (info.error) kids.push(h('div', { class: 'meta', style: 'color:var(--warn)' }, 'Could not check for updates: ' + info.error));
        kids.push(h('div', { class: 'meta' }, info.checked_at && !zero(info.checked_at) ? 'Last checked ' + fmt(info.checked_at) + '.' : 'Not checked yet.'));
      }
      status.replaceChildren(...kids.filter(Boolean));
    };
    paint(updateInfo);
    const btn = h('button', { class: 'btn', type: 'button' }, 'Check now');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try { updateInfo = await api('POST', '/api/update/check'); paint(updateInfo); renderFooter(); }
      catch (err) { toast(err.message, true); }
      btn.disabled = false;
    });
    return card('Software', 'The installed version, and whether a newer release has been published.',
      h('div', { class: 'swline' }, h('strong', {}, 'Version ' + ver), build ? h('span', { class: 'meta' }, 'build ' + build) : null),
      status, h('div', { style: 'margin:10px 0 6px' }, btn), updChk.wrap);
  };

  // Settings are grouped under bars that fold, so the page can be reduced to the part being worked on.
  // The bars are native <details>, toggled in place (a redraw would throw away what is being typed), and
  // what is folded is remembered in this browser.
  const bars = [];
  const allBtn = h('button', { class: 'btn ghost', type: 'button' }, 'Collapse all');
  const syncAll = () => { allBtn.textContent = bars.every(d => !d.open) ? 'Expand all' : 'Collapse all'; };
  const group = (id, title, hint, ...kids) => {
    const d = h('details', { class: 'verbose setgroup', open: !settingsFolded.has(id) },
      h('summary', {}, h('span', { class: 'gtitle' }, title), h('span', { class: 'meta ghint' }, hint)),
      h('div', { class: 'gbody' }, ...kids));
    d.addEventListener('toggle', () => {
      if (d.open) settingsFolded.delete(id); else settingsFolded.add(id);
      try { localStorage.setItem('certsmith.settings.folded', JSON.stringify([...settingsFolded])); } catch (_) { /* not remembered */ }
      syncAll();
    });
    bars.push(d);
    return d;
  };
  // two stacks side by side when there is room, one above the other when there is not
  const two = (left, right) => h('div', { class: 'grid2' },
    h('div', { class: 'stack' }, ...left), h('div', { class: 'stack' }, ...right));
  allBtn.addEventListener('click', () => { const open = bars.every(d => !d.open); bars.forEach(d => { d.open = open; }); });

  return h('div', {},
    h('div', { class: 'row between wrap', style: 'margin-bottom:14px' },
      h('div', {}, h('h1', {}, 'Settings'),
        h('p', { class: 'sub', style: 'margin:0' }, "Configuration for Let's Encrypt, DNS validation, renewal and monitoring, alerting, the HTTPS certificate for this page, and users.")),
      allBtn),
    group('issuing', 'Issuing and renewal', "Let's Encrypt, DNS validation, renewal and monitoring",
      two([card("Let's Encrypt (ACME)", 'Applies to every Let\'s Encrypt provider. Other certificate authorities are configured under Certificate providers.', dir.wrap, email.wrap),
           card('Renewal & monitoring', 'Renewal threshold, expiry alert threshold, the interval for checking live endpoints, and how many certificates are kept on each device.', renew.wrap, warn.wrap, probe.wrap, keepDev.wrap)],
          [card('DNS validation', 'How CertSmith confirms that the DNS challenge record is published. Applies to every certificate provider.', resField, dnsCheck.wrap, dnsWait.wrap)])),
    group('alerts', 'Alerts', 'Email, webhook, and which events are sent where',
      two([card('Email alerts', 'Alerts sent by email when a certificate is close to expiry, issuing or deployment fails, or a device serves an unexpected certificate.',
             sm.enabled.wrap, pair(sm.host, sm.port), pair(sm.security, sm.username), pair(sm.password, sm.from), sm.to.wrap),
           card('Other alerts', 'Optional additional alert channel.', hook.wrap)],
          [alertsCard()])),
    group('server', 'This server', 'The HTTPS certificate of this page, and the installed version',
      two([webUICard()], [softwareCard()]),
      h('div', { class: 'usersrow' }, themeCard())),
    group('users', 'Users', 'Accounts and your own password',
      // users are a wide table with a password form: they get the full width
      h('div', { class: 'usersrow' }, usersCard()),
      h('div', { class: 'usersrow' }, card('Reverse proxy',
        'If CertSmith is reached through a reverse proxy, list its address here. Sign-in attempts are then counted, limited and recorded against the real client address instead of the proxy, so one person guessing passwords cannot lock everyone else out.',
        proxies.wrap))),
    h('div', { class: 'savebar' }, testMsg,
      h('button', { class: 'btn', onclick: async e => {
        testMsg.className = 'testmsg'; testMsg.textContent = 'Sending…';
        await submit(e.target, async () => {
          try { await api('POST', '/api/settings/test-alert', collect()); testMsg.className = 'testmsg ok'; testMsg.textContent = '✓ test alert sent'; }
          catch (err) { testMsg.className = 'testmsg bad'; testMsg.textContent = '✗ ' + err.message; }
        });
      } }, 'Send test alert'),
      h('button', { class: 'btn primary', onclick: e => submit(e.target, async () => {
        const next = collect();
        const switched = next.acme_directory !== S.settings.acme_directory;
        await api('PUT', '/api/settings', next);
        toast(switched ? "Saved. Let's Encrypt certificates will be reissued from " + next.acme_directory + ' and redeployed to targets already deployed to.' : 'Settings saved');
        await refresh();
      }) }, 'Save settings')));
}

// The Readme opens in front of the page, like the other dialogs, as wide as it needs to be. Clicking
// outside it (or Close) closes it. Its text is the same page that is served as help.html, so there is
// only one copy to keep right, and that page can still be opened on its own.
async function openReadme() {
  let doc;
  try {
    const r = await fetch('help.html', { credentials: 'same-origin' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    doc = new DOMParser().parseFromString(await r.text(), 'text/html').querySelector('main.doc');
    if (!doc) throw new Error('no content');
  } catch (e) { window.open('help.html', '_blank'); return; }
  const h1 = doc.querySelector('h1'); if (h1) h1.remove();   // the dialog has its own title
  const sub = doc.querySelector('.sub'); if (sub) sub.remove();
  const body = h('div', { class: 'doc inpage' });
  [...doc.childNodes].forEach(n => body.append(document.importNode(n, true)));
  // contents links scroll inside the dialog; they must not change the address of the app
  body.addEventListener('click', e => {
    const a = e.target.closest('a[href^="#"]');
    if (!a) return;
    e.preventDefault();
    const t = body.querySelector('#' + CSS.escape(a.getAttribute('href').slice(1)));
    if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  modal('Readme', body, close => [
    h('button', { class: 'btn', title: 'Open the Readme in a window of its own, to keep it beside the page',
      onclick: () => window.open('help.html', 'certsmith-help', 'popup=yes,width=1000,height=820,resizable=yes,scrollbars=yes') }, 'Open in a separate window'),
    h('div', { class: 'grow' }),
    h('button', { class: 'btn primary', onclick: close }, 'Close')]);
  const m = document.querySelector('#modal-root .modal');
  if (m) m.classList.add('readmewin');
}

// ---- boot ---------------------------------------------------------------------------------
document.getElementById('readme-btn').addEventListener('click', openReadme);
document.getElementById('logout-btn').addEventListener('click', async () => {
  try { await api('POST', '/api/logout'); } catch (_) { /* already signed out */ }
  showAuth('login');
});
boot();
let tick = 0;
setInterval(() => {
  tick++;
  if (document.hidden || authing || modalOpen) return;
  const busy = S && (S.certificates.some(c => c.issuing) || S.targets.some(t => t.deploying));
  if (busy || tick % 5 === 0) refresh({ background: true }); // every 2 s while something is running, otherwise every 10 s
}, 2000);

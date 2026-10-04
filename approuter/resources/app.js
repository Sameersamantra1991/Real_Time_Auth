/* ============================================================================
   FILE: app/app.js (mirrored to approuter/resources/app.js)
   Tiny dependency-free client for BookstoreService (OData V4 JSON).
   ----------------------------------------------------------------------------
   SECURITY COMMENTS (read while learning):
   [S1] CREDENTIALS IN MEMORY ONLY. `state.user/pass` are plain JS variables.
        localStorage/sessionStorage persist across tabs and any injected XSS
        script could read them -> credential theft. Memory dies with the tab.
   [S2] BASIC vs BEARER. Locally (kind=mocked) we send `Authorization: Basic
        base64(user:pass)`. In production the approuter owns a session cookie
        after XSUAA login and forwards a Bearer JWT itself — so when no
        username is set we send NO Authorization header and rely on the cookie
        (`credentials:'include'`). Same backend, both diagram branches.
   [S3] CSRF. Approuter sets csrfProtection:true, so cookie-session writes need
        an X-CSRF-Token handshake (fetch once, reuse). Basic-auth writes skip
        it — CAP trusts the per-request Authorization header, not cookies.
   [S4] XSS. Every server string passes through escapeHtml() before innerHTML.
        The backend ALSO rejects <script> titles (defense in depth), but the UI
        must never trust data — stored-XSS payloads render as text here.
   [S5] HONEST ERRORS. 401 = "log in again", 403 = "logged in, wrong role",
        400 = "server rejected your input". We surface all three distinctly.
   ========================================================================== */
'use strict';

const state = { user: null, pass: null, csrf: null }; // [S1] memory only
const $ = (id) => document.getElementById(id);
const API = ''; // same origin: local cds OR approuter — no hard-coded host

/* ---------- stepper: light up diagram phases as they succeed ---------- */
function markStep(name) {
  const el = document.querySelector(`#flowSteps [data-step="${name}"]`);
  if (el) el.classList.add('done');
}
function resetSteps() {
  document.querySelectorAll('#flowSteps li').forEach((li) => li.classList.remove('done'));
}

/* ---------- toasts: color teaches the status code ---------- */
function toast(msg, kind = 'ok') {
  const box = $('toasts');
  const div = document.createElement('div');
  div.className = 'toast ' + kind;
  div.textContent = msg; // textContent (not innerHTML) = XSS-safe by construction
  box.appendChild(div);
  setTimeout(() => div.remove(), 5200);
}

/* [S4] Escape before injecting into HTML. Covers &<>"' plus / and backtick. */
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"'`/=]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
    "'": '&#39;', '`': '&#x60;', '/': '&#x2F;', '=': '&#x3D;',
  }[c]));
}

/* ---------- request layer ---------- */
function authHeaders(extra = {}) {
  // [S2] Only attach Basic when the user typed demo credentials.
  const h = { Accept: 'application/json', ...extra };
  if (state.user) h.Authorization = 'Basic ' + btoa(`${state.user}:${state.pass}`);
  if (state.csrf) h['X-CSRF-Token'] = state.csrf; // [S3] approuter session writes
  return h;
}

async function api(path, opts = {}) {
  // [S2] credentials:'include' lets the prod XSUAA session cookie travel.
  const res = await fetch(API + path, { credentials: 'include', ...opts, headers: authHeaders(opts.headers) });
  if (res.status === 401) throw Object.assign(new Error('401 Unauthorized — missing/expired credential. Log in again.'), { code: 401 });
  if (res.status === 403) throw Object.assign(new Error('403 Forbidden — you are logged in but lack the role.'), { code: 403 });
  if (!res.ok) {
    let detail = '';
    try { detail = (await res.json()).error?.message || ''; } catch { /* non-JSON error body */ }
    throw Object.assign(new Error(`${res.status} — ${detail || res.statusText}`), { code: res.status });
  }
  markStep('validate'); // any 2xx proves "CAP Middleware xssec validates → Valid? Yes"
  return res.status === 204 ? null : res.json();
}

/* [S3] CSRF handshake for cookie-session writes; skipped for Basic (mocked). */
async function ensureCsrf() {
  if (state.user || state.csrf) return; // Basic auth OR token already cached
  try {
    const r = await fetch(API + '/bookstore/BookList?$top=1', { credentials: 'include', headers: { 'X-CSRF-Token': 'Fetch' } });
    const t = r.headers.get('X-CSRF-Token');
    if (t) state.csrf = t;
  } catch { /* local dev has no approuter CSRF — writes still work via Basic */ }
}

/* ---------- auth UI ---------- */
async function login(user, pass) {
  state.user = user; state.pass = pass; state.csrf = null;
  resetSteps();
  try {
    const data = await api('/bookstore/WhoAmI');
    const me = data.value[0];
    markStep('login'); markStep('token'); markStep('user');
    renderSession(me);
    await Promise.all([loadBooks(), loadIncidents()]);
    markStep('authz');
    $('flowHint').textContent = `Walking as ${me.id} — open Books as bob vs alice to feel 403.`;
    toast(`Welcome ${me.id} (${me.roles})`, 'ok');
  } catch (e) {
    state.user = state.pass = null;
    toast(e.message, e.code === 401 ? 'bad' : 'warn');
  }
}

function logout() {
  // [S1] Dropping the only copies. Prod: also hit /do/logout to kill the IdP session.
  state.user = state.pass = state.csrf = null;
  if (!document.getElementById('username').value) fetch('/do/logout', { credentials: 'include' }).catch(() => {});
  resetSteps();
  $('sessionPill').textContent = 'anonymous · not logged in';
  $('sessionPill').className = 'pill anon';
  $('logoutBtn').classList.add('hidden');
  $('loginCard').classList.remove('hidden');
  $('whoCard').classList.add('hidden');
}

function renderSession(me) {
  $('sessionPill').textContent = `${me.id} · ${me.roles}`;
  $('sessionPill').className = 'pill ok';
  $('logoutBtn').classList.remove('hidden');
  $('loginCard').classList.add('hidden');
  $('whoCard').classList.remove('hidden');
  // attrDump is a JSON string from the service — parse defensively for display.
  let attr = {};
  try { attr = JSON.parse(me.attrDump || '{}'); } catch { attr = { raw: me.attrDump }; }
  $('whoList').innerHTML = `
    <dt>id</dt><dd>${escapeHtml(me.id)}</dd>
    <dt>roles</dt><dd>${escapeHtml(me.roles)}</dd>
    <dt>tenant</dt><dd>${escapeHtml(me.tenant)}</dd>
    <dt>attr</dt><dd>${escapeHtml(JSON.stringify(attr))}</dd>`;
}

/* ---------- books (role-gated) ---------- */
async function loadBooks() {
  try {
    const data = await api('/bookstore/BookList?$orderby=ID');
    $('bookRows').innerHTML = data.value.map((b) => `
      <tr>
        <td>${escapeHtml(b.ID)}</td><td>${escapeHtml(b.title)}</td>
        <td>${escapeHtml(b.author)}</td><td>${escapeHtml(b.price)}</td>
        <td>${escapeHtml(b.country)}</td>
        <td><button class="link" data-del="${escapeHtml(b.ID)}">delete</button></td>
      </tr>`).join('') || '<tr><td colspan="6" class="muted">No books yet.</td></tr>';
    // Delete is wired per-row; UI shows the button to everyone on purpose:
    // the SERVER decides (403 for non-admin) — hiding it would be fake security.
    $('bookRows').querySelectorAll('[data-del]').forEach((btn) =>
      btn.addEventListener('click', () => deleteBook(btn.dataset.del)));
  } catch (e) { toast('Books: ' + e.message, e.code === 403 ? 'warn' : 'bad'); }
}

async function deleteBook(id) {
  if (!confirm(`Delete book ${id}? (admin only — bob will get 403)`)) return;
  try {
    await ensureCsrf();
    await api(`/bookstore/BookList(${encodeURIComponent(id)})`, { method: 'DELETE' });
    toast(`Book ${id} deleted`, 'ok');
    loadBooks();
  } catch (e) { toast('Delete: ' + e.message, e.code === 403 ? 'warn' : 'bad'); }
}

/* ---------- incidents (attribute-filtered server-side) ---------- */
async function loadIncidents() {
  try {
    const data = await api('/bookstore/IncidentList?$orderby=ID');
    $('incidentRows').innerHTML = data.value.map((t) => `
      <tr><td>${escapeHtml(t.ID)}</td><td>${escapeHtml(t.title)}</td>
      <td>${escapeHtml(t.department)}</td><td>${escapeHtml(t.owner)}</td>
      <td>${escapeHtml(t.status)}</td></tr>`).join('') ||
      '<tr><td colspan="5" class="muted">No tickets visible for your department.</td></tr>';
  } catch (e) { toast('Incidents: ' + e.message, e.code === 403 ? 'warn' : 'bad'); }
}

/* ---------- wiring ---------- */
document.getElementById('loginForm').addEventListener('submit', (e) => {
  e.preventDefault(); // stay on page: this is a fetch-driven SPA, no form POST
  login($('username').value.trim(), $('password').value);
});
document.querySelectorAll('.persona').forEach((b) =>
  b.addEventListener('click', () => {
    $('username').value = b.dataset.u; $('password').value = b.dataset.p;
    login(b.dataset.u, b.dataset.p);
  }));
$('logoutBtn').addEventListener('click', logout);

$('bookForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    // Client-picked ID keeps the demo simple; prod would use UUIDs server-side.
    ID: Date.now() % 100000,
    title: $('bTitle').value.trim(),
    author: $('bAuthor').value.trim(),
    price: Number($('bPrice').value),
    country: $('bCountry').value.trim().toUpperCase(),
  };
  try {
    await ensureCsrf();
    await api('/bookstore/BookList', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    toast('Book created', 'ok');
    e.target.reset();
    loadBooks();
  } catch (err) { toast('Create: ' + err.message, err.code === 403 ? 'warn' : 'bad'); }
});

document.querySelectorAll('.tab').forEach((t) =>
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.tabpanel').forEach((x) => x.classList.add('hidden'));
    t.classList.add('active');
    $('tab-' + t.dataset.tab).classList.remove('hidden');
  }));

$('pingBtn').addEventListener('click', async () => {
  try {
    await ensureCsrf();
    const r = await api('/bookstore/pingAdminOnly', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    $('pingOut').textContent = JSON.stringify(r, null, 2);
    $('pingOut').classList.remove('muted');
  } catch (e) {
    $('pingOut').textContent = e.message;
    toast('Admin action: ' + e.message, e.code === 403 ? 'warn' : 'bad');
  }
});

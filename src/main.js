import '@xterm/xterm/css/xterm.css';
import './styles.css';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import { readText, writeText } from '@tauri-apps/plugin-clipboard-manager';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { openUrl } from '@tauri-apps/plugin-opener';
import { api } from './api.js';
import { COLORS, confirmDialog, contextMenu, esc, icon, initials, modal, modalOpen, timeAgo, toast, uid } from './ui.js';
import { TermSession } from './terminal.js';
import { FileSession, listenForFileDrops, protocolLabel } from './files.js';
import { API_KINDS, ENVIRONMENTS, buildCopy, copyFormats, envColor, expiryInfo, identity, primaryField } from './apikeys.js';

// Opened in a plain browser during development: fake the backend so the UI still works.
if (import.meta.env.DEV && !('__TAURI_INTERNALS__' in window)) await import('./dev-mock.js');

const isMac = navigator.userAgent.includes('Mac');
if (isMac) document.body.classList.add('mac');
// Use the last theme straight away so the window doesn't flash dark before settings load.
try { document.documentElement.dataset.theme = localStorage.getItem('nimbus-theme') || 'dark'; } catch { /* storage unavailable */ }
const MOD = isMac ? '⌘' : 'Ctrl+Shift+';

const $ = (sel, root = document) => root.querySelector(sel);

const app = {
  snap: null,
  view: 'hosts', // hosts | passwords | keys | snippets | known | transfer | settings
  groupId: null,
  search: '',
  drawer: null, // { kind, id }
  pwGroupId: 'all', // Passwords view filter: 'all', 'none' or a password group id
  apiGroupId: 'all', // API Keys view filter, same values
  sessions: [],
  active: null, // null = home tab, else a TermSession or FileSession

  // --- lookups used by TermSession ---
  data() { return this.snap.data; },
  settings() { return this.snap.data.settings; },
  host(id) { return this.snap.data.hosts.find((h) => h.id === id); },
  group(id) { return this.snap.data.groups.find((g) => g.id === id); },
  key(id) { return this.snap.data.keys.find((k) => k.id === id); },
  snippet(id) { return this.snap.data.snippets.find((s) => s.id === id); },
  snippets() { return [...this.snap.data.snippets].sort(byName); },
  passwords() { return [...this.snap.data.passwords].sort(byName); },
  password(id) { return this.snap.data.passwords.find((p) => p.id === id); },
  pwGroup(id) { return this.snap.data.passwordGroups.find((g) => g.id === id); },
  apiKey(id) { return this.snap.data.apiKeys.find((a) => a.id === id); },
  apiGroup(id) { return this.snap.data.apiGroups.find((g) => g.id === id); },
  flags(id) { return this.snap.secrets[id] || {}; },
  modalOpen,

  // --- sessions ---
  /** Open a host: a terminal for SSH hosts, the file browser for FTP hosts. */
  connect(hostId) {
    const host = this.host(hostId);
    if (!host) return;
    if (!isSsh(host) && !isSerial(host)) return this.openFiles(hostId);
    this.open(new TermSession(this, host));
  },
  /** A Files tab: SFTP for SSH hosts, FTP/FTPS otherwise. */
  openFiles(hostId) {
    const host = this.host(hostId);
    if (host) this.open(new FileSession(this, host));
  },
  open(s) {
    this.sessions.push(s);
    this.activate(s);
    s.connect();
  },
  duplicate(s) {
    if (s.kind === 'files') this.openFiles(s.hostId);
    else this.connect(s.hostId);
  },
  activate(s) {
    if (this.active !== s) {
      this.active?.hide();
      this.active = s;
      if (s) s.show();
    }
    // Always sync which area is visible, so the home screen can't get stuck hidden.
    $('#home').hidden = !!s;
    $('#terminals').hidden = !s;
    renderTabs();
  },
  closeSession(s) {
    const i = this.sessions.indexOf(s);
    if (i < 0) return;
    this.sessions.splice(i, 1);
    if (this.active === s) this.activate(this.sessions[i] || this.sessions[i - 1] || null);
    s.dispose();
    renderTabs();
  },
  sessionChanged() { renderTabs(); },
  editHost(id) {
    this.activate(null);
    this.view = 'hosts';
    openDrawer('host', id);
  },

  /** Ask for a host's password and save it (used by the terminal's Password menu). */
  async setHostPassword(hostId) {
    const h = this.host(hostId);
    if (!h) return false;
    const r = await modal({
      title: 'Save password',
      html: `<p>Save the password for <strong>${esc(h.label || h.address)}</strong>. Nimbus uses it to log in when a key doesn't work, and you can type it into the terminal (for sudo) with ${isMac ? '⌘⇧P' : 'Ctrl+Shift+P'}.</p>
        <label class="field"><input type="password" name="pw" autofocus autocomplete="new-password"></label>`,
      buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Save', value: 'ok', kind: 'primary', submit: true }],
    });
    if (r.action !== 'ok' || !r.values.pw) return false;
    return !!(await run(() => api.saveHost(h, r.values.pw), 'Password saved'));
  },

  isAppShortcut(e) {
    return !!shortcutFor(e);
  },
};

const isSsh = (h) => !['ftp', 'ftps', 'serial'].includes(h.protocol);
const isSerial = (h) => h.protocol === 'serial';
const BAUDS = [300, 1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200, 230400, 460800, 921600];
/** "115200 8N1" style summary of a serial host's line settings. */
const serialSummary = (h) => `${h.baudRate || 9600} ${h.dataBits || 8}${{ odd: 'O', even: 'E' }[h.parity] || 'N'}${h.stopBits || 1}`;
const defaultPort = (h) => (isSsh(h) ? 22 : 21);

const byName = (a, b) => (a.label || a.name || '').localeCompare(b.label || b.name || '', undefined, { sensitivity: 'base', numeric: true });

function setSnap(snap) {
  app.snap = snap;
  renderSidebar();
  renderContent();
}

async function run(fn, okMessage) {
  try {
    const r = await fn();
    if (r && r.data) setSnap(r);
    if (okMessage) toast(okMessage, 'ok');
    return r ?? true;
  } catch (e) {
    toast(String(e), 'error');
    return null;
  }
}

function hostColor(h) {
  if (h.color) return h.color;
  const g = h.groupId && app.group(h.groupId);
  if (g?.color) return g.color;
  let n = 0;
  for (const c of h.id) n = (n * 31 + c.charCodeAt(0)) >>> 0;
  return COLORS[n % COLORS.length];
}

function hostSubtitle(h) {
  if (isSerial(h)) return `serial, ${h.address.replace(/^\/dev\/(cu\.|tty\.)?/, '')} · ${serialSummary(h)}`;
  const g = h.groupId && app.group(h.groupId);
  const user = h.username || g?.username;
  const port = h.port || (isSsh(h) ? g?.port : null);
  const proto = isSsh(h) ? 'ssh' : h.protocol;
  return `${proto}, ${user ? user + '@' : ''}${h.address}${port && port !== defaultPort(h) ? ':' + port : ''}`;
}

// ---------- tabs ----------
function renderTabs() {
  const tabs = $('#tabs');
  tabs.innerHTML =
    `<button class="tab home ${app.active ? '' : 'active'}" data-tab="home">${icon.server}<span class="label">Hosts</span></button>` +
    app.sessions
      .map((s, i) => {
        const h = app.host(s.hostId);
        const label = h ? h.label || h.address : s.label;
        const kind = s.kind === 'files' ? `<span class="kind">${protocolLabel(h)}</span>` : '';
        return `<button class="tab ${app.active === s ? 'active' : ''}" data-tab="${i}" title="${esc(label)}">
          <span class="dot ${s.state}"></span><span class="label">${esc(label)}</span>${kind}
          <span class="close" data-close="${i}" role="button" aria-label="Close tab">${icon.x}</span></button>`;
      })
      .join('');
}

$('#tabs').addEventListener('mousedown', (e) => {
  const tab = e.target.closest('.tab');
  if (!tab) return;
  if (e.button === 1 && tab.dataset.tab !== 'home') {
    e.preventDefault();
    app.closeSession(app.sessions[+tab.dataset.tab]);
  }
});
$('#tabs').addEventListener('click', (e) => {
  const close = e.target.closest('[data-close]');
  if (close) return app.closeSession(app.sessions[+close.dataset.close]);
  const tab = e.target.closest('.tab');
  if (!tab) return;
  app.activate(tab.dataset.tab === 'home' ? null : app.sessions[+tab.dataset.tab]);
});
$('#tabs').addEventListener('contextmenu', (e) => {
  const tab = e.target.closest('.tab');
  if (!tab || tab.dataset.tab === 'home') return;
  e.preventDefault();
  const s = app.sessions[+tab.dataset.tab];
  const h = app.host(s.hostId);
  contextMenu(e.clientX, e.clientY, [
    { label: 'Duplicate', icon: icon.copy, action: () => app.duplicate(s) },
    { label: 'Reconnect', icon: icon.refresh, action: () => { app.activate(s); s.connect(); } },
    ...(s.kind === 'term' ? [{ label: 'Open SFTP', icon: icon.folder, action: () => app.openFiles(s.hostId) }] : h && isSsh(h) ? [{ label: 'Open terminal', icon: icon.terminal, action: () => app.connect(s.hostId) }] : []),
    { label: 'Edit host', icon: icon.edit, action: () => app.editHost(s.hostId) },
    'sep',
    { label: 'Close other tabs', action: () => app.sessions.filter((x) => x !== s).forEach((x) => app.closeSession(x)) },
    { label: 'Close tab', icon: icon.x, action: () => app.closeSession(s) },
  ]);
});

// ---------- sidebar ----------
const NAV = [
  ['hosts', 'Hosts', icon.server, () => app.data().hosts.length],
  ['keys', 'Keychain', icon.key, () => app.data().keys.length],
  ['passwords', 'Passwords', icon.lock, () => app.data().passwords.length],
  ['apikeys', 'API Keys', icon.token, () => app.data().apiKeys.length, () => app.data().apiKeys.some((a) => expiryInfo(a.expires)?.level === 'expired')],
  ['snippets', 'Snippets', icon.code, () => app.data().snippets.length],
  ['known', 'Known Hosts', icon.shield, () => app.data().knownHosts.length],
  'sep',
  ['transfer', 'Import & Export', icon.swap],
  ['settings', 'Settings', icon.gear],
];

function renderSidebar() {
  $('#sidebar').innerHTML =
    `<div class="brand"><div class="logo">${icon.cloud}</div><span>Nimbus</span></div>` +
    NAV.map((n) =>
      n === 'sep'
        ? '<div class="nav-sep"></div>'
        : `<button class="nav-item ${app.view === n[0] ? 'active' : ''}" data-view="${n[0]}" title="${n[1]}">${n[2]}<span class="text">${n[1]}</span>${n[3] ? `<span class="count">${n[4]?.() ? '<span class="alert-dot" title="Something here has expired"></span>' : ''}${n[3]()}</span>` : ''}</button>`,
    ).join('') +
    `<div class="sidebar-foot">Stored only on this computer<br>v${esc(app.snap.version)}</div>`;
}

$('#sidebar').addEventListener('click', (e) => {
  const b = e.target.closest('[data-view]');
  if (!b) return;
  app.view = b.dataset.view;
  if (app.view === 'hosts') app.groupId = null;
  closeDrawer();
  renderSidebar();
  renderContent();
});

// ---------- content ----------
function renderContent() {
  const c = $('#content');
  const views = { hosts: viewHosts, passwords: viewPasswords, apikeys: viewApiKeys, keys: viewKeys, snippets: viewSnippets, known: viewKnown, transfer: viewTransfer, settings: viewSettings };
  const hadSearchFocus = document.activeElement?.id === 'search';
  c.innerHTML = (app.snap.warning ? `<div class="warnbox">${esc(app.snap.warning)}</div>` : '') + views[app.view]();
  if (app.view === 'passwords') renderPasswordList();
  if (app.view === 'apikeys') renderApiList();
  if (app.view === 'hosts') {
    renderResults();
    if (hadSearchFocus) {
      const s = $('#search');
      s.focus();
      s.setSelectionRange(s.value.length, s.value.length);
    }
  }
  if (app.view === 'settings') wireSettings();
}

function viewHosts() {
  const g = app.groupId && app.group(app.groupId);
  return `<div class="toolbar">
      <h1>Hosts</h1>
      <label class="search">${icon.search}<input id="search" placeholder="Search, or type user@host and press Enter" value="${esc(app.search)}" spellcheck="false" autocomplete="off"><kbd>${MOD}T</kbd></label>
      <div class="spacer"></div>
      <div class="view-toggle" role="group" aria-label="Layout">
        <button class="icon-btn ${hostsView() === 'grid' ? 'on' : ''}" data-act="hosts-view" data-id="grid" title="Grid">${icon.grid}</button>
        <button class="icon-btn ${hostsView() === 'list' ? 'on' : ''}" data-act="hosts-view" data-id="list" title="List">${icon.list}</button></div>
      <button class="btn primary" data-act="new-host">${icon.plus} Host</button>
      <button class="btn" data-act="new-group">${icon.folder} Group</button>
    </div>
    ${g ? `<div class="crumbs"><button data-act="root">All hosts</button>${icon.chevron}<span>${esc(g.name)}</span>
      <button class="icon-btn" data-act="edit-group" data-id="${esc(g.id)}" title="Edit group">${icon.edit}</button></div>` : ''}
    <div id="results"></div>`;
}

function hostCard(h) {
  const tags = (h.tags || []).slice(0, 2).map((t) => `<span class="tag">${esc(t)}</span>`).join('');
  const title = (h.lastConnected ? `Last connected ${timeAgo(h.lastConnected)}` : 'Click to connect') + (isSsh(h) ? '' : ' · opens the file browser');
  return `<div class="card clickable" data-host="${esc(h.id)}" title="${esc(title)}">
    <div class="avatar" style="--c:${esc(hostColor(h))}">${esc(initials(h.label || h.address))}</div>
    <div class="meta"><div class="title">${esc(h.label || h.address)}${tags}</div><div class="sub">${esc(hostSubtitle(h))}</div></div>
    <div class="actions">${isSsh(h) ? `<button class="icon-btn" data-act="sftp" data-id="${esc(h.id)}" title="Browse files (SFTP)">${icon.folder}</button>` : ''}
      <button class="icon-btn" data-act="edit-host" data-id="${esc(h.id)}" title="Edit">${icon.edit}</button></div>
  </div>`;
}

const hostsView = () => (app.settings().hostsView === 'list' ? 'list' : 'grid');

function hostRow(h, showGroup) {
  const tags = (h.tags || []).slice(0, 3).map((t) => `<span class="tag">${esc(t)}</span>`).join('');
  const g = h.groupId && app.group(h.groupId);
  const where = hostSubtitle(h).split(', ').slice(1).join(', ');
  const proto = isSerial(h) ? 'Serial' : isSsh(h) ? 'SSH' : h.protocol.toUpperCase();
  return `<tr class="hrow" data-host="${esc(h.id)}" title="${esc(h.lastConnected ? `Last connected ${timeAgo(h.lastConnected)}` : 'Click to connect')}">
    <td><div class="h-name"><div class="avatar sm" style="--c:${esc(hostColor(h))}">${esc(initials(h.label || h.address))}</div><span class="title">${esc(h.label || h.address)}</span>${tags}</div></td>
    <td class="h-addr">${esc(where)}</td>
    <td><span class="proto">${proto}</span></td>
    ${showGroup ? `<td class="faint">${g ? esc(g.name) : ''}</td>` : ''}
    <td class="faint">${h.lastConnected ? esc(timeAgo(h.lastConnected)) : 'Never'}</td>
    <td class="row-actions">${isSsh(h) ? `<button class="icon-btn" data-act="sftp" data-id="${esc(h.id)}" title="Browse files (SFTP)">${icon.folder}</button>` : ''}
      <button class="icon-btn" data-act="edit-host" data-id="${esc(h.id)}" title="Edit">${icon.edit}</button></td></tr>`;
}

const hostCols = (showGroup) =>
  `<colgroup><col style="width:${showGroup ? 28 : 34}%"><col style="width:${showGroup ? 28 : 32}%"><col style="width:10%">${showGroup ? '<col style="width:14%">' : ''}<col><col style="width:76px"></colgroup>`;

function hostsBlock(hosts, showGroup = false) {
  if (hostsView() === 'grid') return `<div class="grid">${hosts.map(hostCard).join('')}</div>`;
  return `<table class="list hosts-table">${hostCols(showGroup)}<thead><tr><th>Name</th><th>Address</th><th>Type</th>${showGroup ? '<th>Group</th>' : ''}<th>Last connected</th><th></th></tr></thead>
    <tbody>${hosts.map((h) => hostRow(h, showGroup)).join('')}</tbody></table>`;
}

function groupsBlock(groups) {
  if (hostsView() === 'grid') return `<div class="grid">${groups.map(groupCard).join('')}</div>`;
  return `<table class="list hosts-table">${hostCols(false)}<tbody>${groups
    .map((g) => {
      const n = app.data().hosts.filter((h) => h.groupId === g.id).length;
      const defaults = [g.username && `user ${g.username}`, g.port && `port ${g.port}`, g.keyId && app.key(g.keyId) && `key ${app.key(g.keyId).label}`].filter(Boolean).join(' · ');
      return `<tr class="hrow" data-group="${esc(g.id)}"><td><div class="h-name"><div class="avatar sm" style="--c:${esc(g.color || '#8b91a8')}">${icon.folder}</div><span class="title">${esc(g.name)}</span></div></td>
        <td class="faint">${n} host${n === 1 ? '' : 's'}</td><td class="faint" colspan="2">${esc(defaults)}</td>
        <td class="row-actions"><button class="icon-btn" data-act="edit-group" data-id="${esc(g.id)}" title="Edit">${icon.edit}</button></td></tr>`;
    })
    .join('')}</tbody></table>`;
}

function groupCard(g) {
  const n = app.data().hosts.filter((h) => h.groupId === g.id).length;
  return `<div class="card clickable" data-group="${esc(g.id)}">
    <div class="avatar" style="--c:${esc(g.color || '#8b91a8')}">${icon.folder}</div>
    <div class="meta"><div class="title">${esc(g.name)}</div><div class="sub">${n} host${n === 1 ? '' : 's'}</div></div>
    <div class="actions"><button class="icon-btn" data-act="edit-group" data-id="${esc(g.id)}" title="Edit">${icon.edit}</button></div>
  </div>`;
}

// [ssh|sftp|ftp|ftps://][user@]host[:port]
const QUICK = /^(?:(ssh|sftp|ftps?):\/\/)?(?:([^@\s/]+)@)?(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+)(?::(\d{1,5}))?\/?$/i;

function searchMatches() {
  const q = app.search.trim().toLowerCase();
  return app.data().hosts
    .filter((h) => [h.label, h.address, h.username, ...(h.tags || []), app.group(h.groupId)?.name].some((v) => v && v.toLowerCase().includes(q)))
    .sort(byName);
}

function renderResults() {
  const r = $('#results');
  if (!r) return;
  const d = app.data();
  const q = app.search.trim();
  if (q) {
    const hits = searchMatches();
    const quick = QUICK.exec(q);
    r.innerHTML =
      (hits.length ? `<div class="section-title">Results</div>${hostsBlock(hits, true)}` : '') +
      (quick && (q.includes('@') || !hits.length)
        ? `<div class="panel"><h2>Quick connect</h2><p>Press <strong>Enter</strong> to connect to <code>${esc(q)}</code>. It will be saved to your hosts so you can reconnect later.</p>
            <p class="hint">Start with <code>sftp://</code>, <code>ftp://</code> or <code>ftps://</code> to open the file browser instead of a terminal.</p></div>`
        : '') +
      (!hits.length && !quick ? `<div class="empty"><p>No hosts match “${esc(q)}”.</p></div>` : '');
    return;
  }
  if (app.groupId) {
    const hosts = d.hosts.filter((h) => h.groupId === app.groupId).sort(byName);
    r.innerHTML = hosts.length
      ? hostsBlock(hosts)
      : `<div class="empty"><p>This group is empty.</p><div class="row"><button class="btn primary" data-act="new-host">${icon.plus} Add a host here</button></div></div>`;
    return;
  }
  if (!d.hosts.length && !d.groups.length) {
    r.innerHTML = `<div class="empty"><div class="big">${icon.server}</div><h2>No hosts yet</h2>
      <p>Add the machines you SSH into. Everything stays on this computer, and you can move it to another one with Import &amp; Export.</p>
      <div class="row"><button class="btn primary" data-act="new-host">${icon.plus} New host</button>
      <button class="btn" data-act="import-ssh-config">${icon.file} Import ~/.ssh/config</button>
      <button class="btn" data-act="import-file">${icon.upload} Import a Nimbus file</button></div></div>`;
    return;
  }
  const groups = [...d.groups].sort(byName);
  const loose = d.hosts.filter((h) => !h.groupId || !app.group(h.groupId)).sort(byName);
  r.innerHTML =
    (groups.length ? `<div class="section-title">Groups</div>${groupsBlock(groups)}` : '') +
    (loose.length ? `<div class="section-title">Hosts</div>${hostsBlock(loose)}` : '');
}

function viewPasswords() {
  const d = app.data();
  const groups = [...d.passwordGroups].sort(byName);
  if (app.pwGroupId !== 'all' && app.pwGroupId !== 'none' && !app.pwGroup(app.pwGroupId)) app.pwGroupId = 'all';
  const count = (gid) => d.passwords.filter((p) => (gid === 'none' ? !p.groupId || !app.pwGroup(p.groupId) : p.groupId === gid)).length;
  const chip = (id, label, n, color) => `<button class="chip ${app.pwGroupId === id ? 'active' : ''}" data-act="pw-filter" data-id="${esc(id)}">
      ${color ? `<span class="swatch" style="--c:${esc(color)}"></span>` : ''}${esc(label)}<span class="n">${n}</span></button>`;
  const g = app.pwGroup(app.pwGroupId);
  return `<div class="toolbar"><h1>Passwords</h1>
      <label class="search">${icon.search}<input id="pw-search" placeholder="Search passwords" value="${esc(app.pwSearch || '')}" spellcheck="false" autocomplete="off"></label>
      <div class="spacer"></div>
      <button class="btn primary" data-act="new-password">${icon.plus} Password</button>
      <button class="btn" data-act="new-pw-group">${icon.folder} Group</button></div>
    ${d.passwords.length || groups.length
      ? `<div class="chips">${chip('all', 'All', d.passwords.length)}${groups.map((x) => chip(x.id, x.name, count(x.id), x.color || '#8b91a8')).join('')}${groups.length ? chip('none', 'No group', count('none')) : ''}
          ${g ? `<button class="icon-btn" data-act="edit-pw-group" data-id="${esc(g.id)}" title="Edit group">${icon.edit}</button>` : ''}</div>`
      : ''}
    <div id="pw-results"></div>`;
}

/** A link we can open for a saved "website or address": http(s) URLs, or a bare host/IP. */
function entryUrl(raw) {
  const v = (raw || '').trim();
  if (!v || /\s/.test(v)) return null;
  let candidate = v;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
    // Routers, NAS boxes and other local devices usually only serve plain http.
    const local = /^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-f:]+\]|localhost|[^/:]+\.(local|lan|home|internal))([:/]|$)/i.test(v);
    candidate = (local ? 'http://' : 'https://') + v;
  }
  try {
    const u = new URL(candidate);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

function passwordRow(p, showGroup) {
  const missing = !app.flags(p.id).password;
  const url = entryUrl(p.url);
  const g = p.groupId && app.pwGroup(p.groupId);
  const revealed = app.revealed?.id === p.id ? app.revealed.value : null;
  return `<tr class="clickable" data-password="${esc(p.id)}">
    <td><div class="pw-name"><div class="avatar sm" style="--c:${missing ? 'var(--danger)' : esc(g?.color || '#7b5cff')}">${esc(initials(p.name))}</div>
      <div><div class="title">${esc(p.name)}</div>${p.notes ? `<div class="sub">${esc(p.notes.split('\n')[0])}</div>` : ''}</div></div></td>
    <td>${p.username ? `<span class="cell-copy"><span class="selectable">${esc(p.username)}</span><button class="icon-btn" data-act="copy-user" data-id="${esc(p.id)}" title="Copy username">${icon.copy}</button></span>` : '<span class="faint">—</span>'}</td>
    <td>${missing ? '<span class="danger-text">Not saved</span>'
      : `<span class="cell-copy"><span class="mono ${revealed ? 'selectable' : 'dots'}">${revealed ? esc(revealed) : '••••••••'}</span>
         <button class="icon-btn" data-act="reveal-pass" data-id="${esc(p.id)}" title="${revealed ? 'Hide' : 'Show'}">${icon.eye}</button>
         <button class="icon-btn" data-act="copy-pass" data-id="${esc(p.id)}" title="Copy password">${icon.copy}</button></span>`}</td>
    <td class="pw-url">${url ? `<a href="${esc(url)}" data-act="open-url" data-id="${esc(p.id)}" title="Open ${esc(url)}">${esc(p.url)}</a>` : p.url ? `<span class="selectable">${esc(p.url)}</span>` : '<span class="faint">—</span>'}</td>
    ${showGroup ? `<td class="faint">${g ? esc(g.name) : ''}</td>` : ''}
    <td class="row-actions"><button class="icon-btn" data-act="edit-password" data-id="${esc(p.id)}" title="Edit">${icon.edit}</button></td></tr>`;
}

function renderPasswordList() {
  const r = $('#pw-results');
  if (!r) return;
  const q = (app.pwSearch || '').trim().toLowerCase();
  const all = app.passwords();
  if (!all.length) {
    r.innerHTML = `<div class="empty"><div class="big">${icon.lock}</div><h2>No passwords yet</h2>
      <p>Keep passwords here, encrypted on this computer. Copy them when you need them, or type one into a connected terminal with the Password button.</p>
      <div class="row"><button class="btn primary" data-act="new-password">${icon.plus} New password</button></div></div>`;
    return;
  }
  const gid = app.pwGroupId;
  const inGroup = (p) => gid === 'all' || (gid === 'none' ? !p.groupId || !app.pwGroup(p.groupId) : p.groupId === gid);
  const groupName = (p) => app.pwGroup(p.groupId)?.name || '';
  const list = all.filter(inGroup).filter((p) => !q || [p.name, p.username, p.url, p.notes, groupName(p)].some((v) => v && v.toLowerCase().includes(q)));
  if (!list.length) {
    r.innerHTML = `<div class="empty"><p>${q ? `No passwords match “${esc(q)}”.` : 'No passwords in this group yet.'}</p>
      ${q ? '' : `<div class="row"><button class="btn primary" data-act="new-password">${icon.plus} Add one</button></div>`}</div>`;
    return;
  }
  const groups = [...app.data().passwordGroups].sort(byName);
  // "All" with groups: one section per group (searching flattens it, with a Group column instead).
  const sectioned = gid === 'all' && groups.length && !q;
  const head = `<thead><tr><th>Name</th><th>Username</th><th>Password</th><th>Website or address</th>${gid === 'all' && q && groups.length ? '<th>Group</th>' : ''}<th></th></tr></thead>`;
  let body;
  if (sectioned) {
    const cols = 5;
    const section = (title, color, rows) => (rows.length
      ? `<tr class="group-row"><td colspan="${cols}">${color ? `<span class="swatch" style="--c:${esc(color)}"></span>` : ''}${esc(title)} <span class="n">${rows.length}</span></td></tr>${rows.map((p) => passwordRow(p, false)).join('')}`
      : '');
    body = groups.map((g) => section(g.name, g.color || '#8b91a8', list.filter((p) => p.groupId === g.id))).join('') +
      section('No group', null, list.filter((p) => !p.groupId || !app.pwGroup(p.groupId)));
  } else {
    body = list.map((p) => passwordRow(p, gid === 'all' && q && groups.length)).join('');
  }
  r.innerHTML = `<table class="list pw-table">${head}<tbody>${body}</tbody></table>`;
}

async function revealPassword(id) {
  if (app.revealed?.id === id) {
    app.revealed = null;
    return renderPasswordList();
  }
  try {
    const value = await api.revealPassword(id);
    app.revealed = { id, value };
    renderPasswordList();
    // Hide it again on its own after a while.
    clearTimeout(app.revealTimer);
    app.revealTimer = setTimeout(() => { if (app.revealed?.id === id) { app.revealed = null; renderPasswordList(); } }, 20000);
  } catch (e) {
    toast(String(e), 'error');
  }
}

const CLEAR_AFTER = 30;

async function copyPassword(id) {
  return copySecret(() => api.revealPassword(id), 'Password');
}

/** Copy something sensitive, then clear the clipboard after a while if it still holds it. */
async function copySecret(getText, what) {
  try {
    const text = await getText();
    await writeText(text);
    toast(`${what} copied. The clipboard clears in ${CLEAR_AFTER} s.`, 'ok');
    setTimeout(async () => {
      try {
        if ((await readText()) === text) await writeText('');
      } catch { /* clipboard changed or unavailable */ }
    }, CLEAR_AFTER * 1000);
  } catch (e) {
    toast(String(e), 'error');
  }
}

function generatePassword(len = 20) {
  const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789', '!@#$%^&*-_=+?'];
  const all = sets.join('');
  const pick = (chars) => {
    // Rejection sampling avoids modulo bias.
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / chars.length) * chars.length;
    do crypto.getRandomValues(buf); while (buf[0] >= limit);
    return chars[buf[0] % chars.length];
  };
  for (;;) {
    const pw = Array.from({ length: len }, () => pick(all)).join('');
    if (sets.every((set) => [...pw].some((c) => set.includes(c)))) return pw;
  }
}

// ---------- API keys ----------
function viewApiKeys() {
  const d = app.data();
  const groups = [...d.apiGroups].sort(byName);
  if (app.apiGroupId !== 'all' && app.apiGroupId !== 'none' && !app.apiGroup(app.apiGroupId)) app.apiGroupId = 'all';
  const count = (gid) => d.apiKeys.filter((a) => (gid === 'none' ? !a.groupId || !app.apiGroup(a.groupId) : a.groupId === gid)).length;
  const chip = (id, label, n, color) => `<button class="chip ${app.apiGroupId === id ? 'active' : ''}" data-act="api-filter" data-id="${esc(id)}">
      ${color ? `<span class="swatch" style="--c:${esc(color)}"></span>` : ''}${esc(label)}<span class="n">${n}</span></button>`;
  const g = app.apiGroup(app.apiGroupId);
  return `<div class="toolbar"><h1>API Keys</h1>
      <label class="search">${icon.search}<input id="api-search" placeholder="Search keys, services, environments" value="${esc(app.apiSearch || '')}" spellcheck="false" autocomplete="off"></label>
      <div class="spacer"></div>
      <button class="btn primary" data-act="new-api">${icon.plus} Credential</button>
      <button class="btn" data-act="new-api-group">${icon.folder} Group</button></div>
    ${d.apiKeys.length || groups.length
      ? `<div class="chips">${chip('all', 'All', d.apiKeys.length)}${groups.map((x) => chip(x.id, x.name, count(x.id), x.color || '#8b91a8')).join('')}${groups.length ? chip('none', 'No group', count('none')) : ''}
          ${g ? `<button class="icon-btn" data-act="edit-api-group" data-id="${esc(g.id)}" title="Edit group">${icon.edit}</button>` : ''}</div>`
      : ''}
    <div id="api-results"></div>`;
}

function apiRow(a) {
  const g = a.groupId && app.apiGroup(a.groupId);
  const main = primaryField(a);
  const saved = main && app.flags(a.id).fields?.includes(main.id);
  const shown = app.revealedApi?.id === a.id ? app.revealedApi.value : null;
  const url = entryUrl(a.baseUrl);
  const exp = expiryInfo(a.expires);
  const who = [a.service, identity(a)].filter(Boolean).join(' · ');
  return `<tr class="clickable" data-api="${esc(a.id)}">
    <td><div class="pw-name"><div class="avatar sm" style="--c:${esc(g?.color || '#14b8a6')}">${esc(initials(a.service || a.name))}</div>
      <div><div class="title">${esc(a.name)}</div>${who ? `<div class="sub">${esc(who)}</div>` : ''}</div></div></td>
    <td><span class="proto">${esc(API_KINDS[a.kind]?.label || 'Custom')}</span></td>
    <td>${a.environment ? `<span class="env" style="--c:${envColor(a.environment)}">${esc(a.environment)}</span>` : '<span class="faint">—</span>'}</td>
    <td>${!main ? '<span class="faint">—</span>' : !saved ? '<span class="danger-text">Not saved</span>'
      : `<span class="cell-copy"><span class="mono ${shown ? 'selectable' : 'dots'}">${shown ? esc(shown) : '••••••••'}</span>
         <button class="icon-btn" data-act="reveal-api" data-id="${esc(a.id)}" title="${shown ? 'Hide' : `Show ${esc(main.label)}`}">${icon.eye}</button>
         <button class="icon-btn" data-act="copy-api" data-id="${esc(a.id)}" title="Copy ${esc(main.label)}">${icon.copy}</button></span>`}</td>
    <td class="pw-url">${url ? `<a href="${esc(url)}" data-act="open-api-url" data-id="${esc(a.id)}" title="Open ${esc(url)}">${esc(a.baseUrl)}</a>` : a.baseUrl ? esc(a.baseUrl) : '<span class="faint">—</span>'}</td>
    <td>${exp ? `<span class="exp ${exp.level}">${esc(exp.text)}</span>` : '<span class="faint">—</span>'}</td>
    <td class="row-actions"><button class="icon-btn" data-act="api-copy-as" data-id="${esc(a.id)}" title="Copy as…">${icon.more}</button>
      <button class="icon-btn" data-act="edit-api" data-id="${esc(a.id)}" title="Edit">${icon.edit}</button></td></tr>`;
}

function renderApiList() {
  const r = $('#api-results');
  if (!r) return;
  const all = [...app.data().apiKeys].sort(byName);
  if (!all.length) {
    r.innerHTML = `<div class="empty"><div class="big">${icon.token}</div><h2>No API credentials yet</h2>
      <p>Keep API keys, tokens and OAuth client secrets in one place, encrypted on this computer. Copy them as a header, a curl command or .env lines when you need them.</p>
      <div class="row"><button class="btn primary" data-act="new-api">${icon.plus} New credential</button></div></div>`;
    return;
  }
  const q = (app.apiSearch || '').trim().toLowerCase();
  const gid = app.apiGroupId;
  const inGroup = (a) => gid === 'all' || (gid === 'none' ? !a.groupId || !app.apiGroup(a.groupId) : a.groupId === gid);
  const text = (a) => [a.name, a.service, a.environment, a.baseUrl, a.notes, API_KINDS[a.kind]?.label, app.apiGroup(a.groupId)?.name, ...a.fields.filter((f) => !f.secret).map((f) => f.value)];
  const list = all.filter(inGroup).filter((a) => !q || text(a).some((v) => v && String(v).toLowerCase().includes(q)));
  if (!list.length) {
    r.innerHTML = `<div class="empty"><p>${q ? `Nothing matches “${esc(q)}”.` : 'No credentials in this group yet.'}</p></div>`;
    return;
  }
  const groups = [...app.data().apiGroups].sort(byName);
  const head = `<thead><tr><th>Name</th><th>Type</th><th>Environment</th><th>Secret</th><th>Base URL</th><th>Expires</th><th></th></tr></thead>`;
  let body;
  if (gid === 'all' && groups.length && !q) {
    const section = (title, color, rows) => (rows.length
      ? `<tr class="group-row"><td colspan="7">${color ? `<span class="swatch" style="--c:${esc(color)}"></span>` : ''}${esc(title)} <span class="n">${rows.length}</span></td></tr>${rows.map(apiRow).join('')}`
      : '');
    body = groups.map((g) => section(g.name, g.color || '#8b91a8', list.filter((a) => a.groupId === g.id))).join('') +
      section('No group', null, list.filter((a) => !a.groupId || !app.apiGroup(a.groupId)));
  } else body = list.map(apiRow).join('');
  r.innerHTML = `<table class="list pw-table api-table">${head}<tbody>${body}</tbody></table>`;
}

/** Resolve any field of a saved credential, revealing secrets from the encrypted store. */
const apiGetter = (a) => async (fid) => {
  const f = a.fields.find((x) => x.id === fid);
  if (!f) return null;
  if (!f.secret) return f.value ?? null;
  if (!app.flags(a.id).fields?.includes(fid)) return null;
  return api.revealApiSecret(a.id, fid);
};

async function revealApi(id) {
  if (app.revealedApi?.id === id) {
    app.revealedApi = null;
    return renderApiList();
  }
  const a = app.apiKey(id);
  const main = a && primaryField(a);
  if (!main) return;
  try {
    app.revealedApi = { id, value: await api.revealApiSecret(id, main.id) };
    renderApiList();
    clearTimeout(app.revealApiTimer);
    app.revealApiTimer = setTimeout(() => { if (app.revealedApi?.id === id) { app.revealedApi = null; renderApiList(); } }, 20000);
  } catch (e) {
    toast(String(e), 'error');
  }
}

function apiCopyMenu(x, y, id, inEditor = false) {
  const a = app.apiKey(id);
  if (!a) return;
  const fields = a.fields.filter((f) => (f.secret ? app.flags(a.id).fields?.includes(f.id) : f.value));
  contextMenu(x, y, [
    ...copyFormats(a).map((f) => ({ label: `Copy as ${f.label}`, icon: icon.code, action: () => copySecret(() => buildCopy(f.id, a, apiGetter(a)), f.label) })),
    ...(fields.length ? ['sep'] : []),
    ...fields.map((f) => ({ label: `Copy ${f.label || f.id}`, icon: f.secret ? icon.lock : icon.copy, action: () => (f.secret ? copySecret(() => api.revealApiSecret(a.id, f.id), f.label || 'Value') : writeText(f.value).then(() => toast(`${f.label} copied`, 'ok'))) })),
    ...(inEditor ? [] : ['sep', { label: 'Edit', icon: icon.edit, action: () => openDrawer('apikey', id) }]),
  ]);
}

function viewKeys() {
  const keys = [...app.data().keys].sort(byName);
  const used = (id) => app.data().hosts.filter((h) => h.keyId === id).length + app.data().groups.filter((g) => g.keyId === id).length;
  return `<div class="toolbar"><h1>Keychain</h1><div class="spacer"></div>
      <button class="btn primary" data-act="new-key">${icon.plus} Key</button></div>
    ${keys.length
      ? `<div class="grid">${keys
          .map((k) => {
            const missing = !app.flags(k.id).privateKey;
            return `<div class="card clickable" data-key="${esc(k.id)}">
            <div class="avatar" style="--c:${missing ? 'var(--danger)' : '#f59e0b'}">${icon.key}</div>
            <div class="meta"><div class="title">${esc(k.label)}</div>
            <div class="sub">${missing ? 'Private key missing — re-add it' : `${esc(k.keyType)} · used by ${used(k.id)}`}</div></div>
            <div class="actions"><button class="icon-btn" data-act="copy-pub" data-id="${esc(k.id)}" title="Copy public key">${icon.copy}</button></div></div>`;
          })
          .join('')}</div>`
      : `<div class="empty"><div class="big">${icon.key}</div><h2>No keys yet</h2>
          <p>Add an existing private key or generate a new one. Hosts and groups can then use it to log in.</p>
          <div class="row"><button class="btn primary" data-act="new-key">${icon.plus} Add or generate a key</button></div></div>`}`;
}

function viewSnippets() {
  const list = app.snippets();
  return `<div class="toolbar"><h1>Snippets</h1><div class="spacer"></div>
      <button class="btn primary" data-act="new-snippet">${icon.plus} Snippet</button></div>
    ${list.length
      ? `<div class="grid">${list
          .map((s) => `<div class="card clickable" data-snippet="${esc(s.id)}">
            <div class="avatar" style="--c:#14b8a6">${icon.code}</div>
            <div class="meta"><div class="title">${esc(s.name)}</div><div class="sub mono">${esc(s.command)}</div></div></div>`)
          .join('')}</div>`
      : `<div class="empty"><div class="big">${icon.code}</div><h2>No snippets yet</h2>
          <p>Save commands you run often. In any terminal, use the Snippets button (top right) to paste one in.</p>
          <div class="row"><button class="btn primary" data-act="new-snippet">${icon.plus} New snippet</button></div></div>`}`;
}

function viewKnown() {
  const list = [...app.data().knownHosts].sort((a, b) => a.host.localeCompare(b.host));
  return `<div class="toolbar"><h1>Known Hosts</h1></div>
    <p class="hint" style="max-width:720px;margin:-10px 0 18px">Servers you've chosen to trust. Nimbus checks every connection against this list and warns you if a server's key changes. Remove an entry if a server was rebuilt on purpose.</p>
    ${list.length
      ? `<table class="list"><thead><tr><th>Host</th><th>Key type</th><th>Fingerprint</th><th>Trusted</th><th></th></tr></thead><tbody>${list
          .map((k) => `<tr><td>${esc(k.host)}</td><td>${esc(k.keyType)}</td><td class="fp selectable">${esc(k.fingerprint)}</td>
            <td>${esc(timeAgo(k.added))}</td><td><button class="icon-btn" data-act="forget-host" data-id="${esc(k.host)}" title="Remove">${icon.trash}</button></td></tr>`)
          .join('')}</tbody></table>`
      : `<div class="empty"><div class="big">${icon.shield}</div><h2>Nothing trusted yet</h2><p>When you first connect to a server you'll be asked to trust its key. It shows up here.</p></div>`}`;
}

const MIN_EXPORT_PW = 10;

/** Rough strength (0–4) for the export password hint: length plus character variety. */
function pwStrength(pw) {
  if (pw.length < MIN_EXPORT_PW) return pw ? 1 : 0;
  const kinds = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  return Math.min(4, 1 + (pw.length >= 14) + (pw.length >= 20) + (kinds >= 3));
}

function viewTransfer() {
  const d = app.data();
  return `<div class="toolbar"><h1>Import &amp; Export</h1></div>
    <div class="panel"><h2>${icon.download.replace('<svg', '<svg style="width:15px;height:15px;vertical-align:-2px"')} Export</h2>
      <p>Save your ${d.hosts.length} hosts, ${d.groups.length} groups, ${d.keys.length} keys, ${d.passwords.length} passwords, ${d.apiKeys.length} API credentials and ${d.snippets.length} snippets to one file you can carry to another computer.</p>
      <p class="hint">The whole file is encrypted with a password you choose here, and you'll need it to import the file. <strong>Nimbus can't recover a forgotten export password</strong>, so keep it somewhere safe.</p>
      <div style="max-width:420px">
        <label class="field"><span>Export password (at least ${MIN_EXPORT_PW} characters)</span><input type="password" id="exp-p1" autocomplete="new-password" spellcheck="false"></label>
        <div class="pw-meter" id="exp-meter"><div></div></div>
        <label class="field"><span>Repeat password</span><input type="password" id="exp-p2" autocomplete="new-password" spellcheck="false"></label>
      </div>
      <div class="row"><button class="btn primary" data-act="export">${icon.download} Export to file…</button></div>
    </div>
    <div class="panel"><h2>${icon.upload.replace('<svg', '<svg style="width:15px;height:15px;vertical-align:-2px"')} Import</h2>
      <p>Load a file exported from Nimbus on another computer. You'll see what's in it and choose to merge or replace before anything changes.</p>
      <div class="row"><button class="btn primary" data-act="import-file">${icon.upload} Import from file…</button>
      <button class="btn" data-act="import-ssh-config">${icon.file} Import ~/.ssh/config</button></div>
    </div>
    <div class="panel"><h2>Where your data lives</h2>
      <p>Hosts and settings are in <code class="selectable">${esc(app.snap.dataDir)}</code>. Passwords and private keys are encrypted with a key held in
      ${app.snap.vaultMode === 'keychain' ? 'your system keychain' : '<strong>a local key file</strong> (no system keychain was available)'}. Nothing is sent anywhere.</p>
    </div>`;
}

function viewSettings() {
  const s = app.settings();
  const agentHint = app.snap.platform === 'windows' ? 'Default: the OpenSSH agent pipe, then Pageant' : 'Default: $SSH_AUTH_SOCK';
  return `<div class="toolbar"><h1>Settings</h1></div>
    <form id="settings-form" class="panel" autocomplete="off">
      <h2>Appearance</h2><p>System follows your computer's light or dark mode.</p>
      <div class="segmented three" style="max-width:420px;margin-bottom:20px">${['system', 'light', 'dark'].map((t) => `<label><input type="radio" name="theme" value="${t}" ${(s.theme || 'system') === t ? 'checked' : ''}><span>${t[0].toUpperCase() + t.slice(1)}</span></label>`).join('')}</div>
      <h2>Terminal</h2><p>Changes apply to open terminals right away.</p>
      <div class="field-row"><label class="field"><span>Font</span><input name="fontFamily" value="${esc(s.fontFamily)}" spellcheck="false"></label>
      <label class="field"><span>Size</span><input type="number" name="fontSize" min="8" max="32" value="${s.fontSize}"></label></div>
      <div class="field-row"><label class="field"><span>Cursor</span><select name="cursorStyle">
        ${['block', 'bar', 'underline'].map((c) => `<option ${s.cursorStyle === c ? 'selected' : ''}>${c}</option>`).join('')}</select></label>
      <label class="field"><span>Scrollback</span><input type="number" name="scrollback" min="100" max="200000" step="1000" value="${s.scrollback}"></label></div>
      <label class="check"><input type="checkbox" name="cursorBlink" ${s.cursorBlink ? 'checked' : ''}><span>Blinking cursor</span></label>
      <label class="check"><input type="checkbox" name="copyOnSelect" ${s.copyOnSelect ? 'checked' : ''}><span>Copy text as soon as it's selected</span></label>
      <label class="check"><input type="checkbox" name="typePasswordEnter" ${s.typePasswordEnter ? 'checked' : ''}><span>Press Enter after typing a password<small>Applies to the terminal's Password button and ${MOD}P.</small></span></label>
      <h2 style="margin-top:18px">Connections</h2><p>&nbsp;</p>
      <div class="field-row"><label class="field"><span>SSH agent socket</span><input name="agentSocket" value="${esc(s.agentSocket || '')}" placeholder="${esc(agentHint)}" spellcheck="false"></label>
      <label class="field"><span>Keep-alive (s)</span><input type="number" name="keepaliveSecs" min="0" max="600" value="${s.keepaliveSecs}"></label></div>
      <p class="hint">Use the agent socket for 1Password, Secretive or a custom agent. Keep-alive 0 turns it off.</p>
    </form>`;
}

function wireSettings() {
  const form = $('#settings-form');
  let t;
  form.addEventListener('change', (e) => {
    if (e.target.name === 'theme') applyTheme(e.target.value);
  });
  form.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(async () => {
      const f = new FormData(form);
      const num = (k, lo, hi, dflt) => Math.min(hi, Math.max(lo, parseInt(f.get(k), 10) || dflt));
      const s = {
        ...app.settings(),
        theme: f.get('theme') || 'system',
        fontFamily: f.get('fontFamily') || app.settings().fontFamily,
        fontSize: num('fontSize', 8, 32, 13),
        cursorStyle: f.get('cursorStyle'),
        scrollback: num('scrollback', 100, 200000, 10000),
        cursorBlink: form.cursorBlink.checked,
        copyOnSelect: form.copyOnSelect.checked,
        typePasswordEnter: form.typePasswordEnter.checked,
        agentSocket: f.get('agentSocket').trim() || null,
        keepaliveSecs: num('keepaliveSecs', 0, 600, 30),
      };
      try {
        app.snap = await api.saveSettings(s);
        app.sessions.forEach((x) => x.applySettings(s));
      } catch (e) {
        toast(String(e), 'error');
      }
    }, 350);
  });
}

// ---------- content events ----------
const content = $('#content');

content.addEventListener('input', (e) => {
  if (e.target.id === 'api-search') {
    app.apiSearch = e.target.value;
    renderApiList();
  }
  if (e.target.id === 'pw-search') {
    app.pwSearch = e.target.value;
    renderPasswordList();
  }
  if (e.target.id === 'search') {
    app.search = e.target.value;
    renderResults();
  }
  if (e.target.id === 'exp-p1') {
    const n = pwStrength(e.target.value);
    const meter = $('#exp-meter');
    meter.dataset.level = n;
    meter.title = ['', 'Too short', 'OK', 'Good', 'Strong'][n];
  }
});
content.addEventListener('change', (e) => {
});

content.addEventListener('keydown', async (e) => {
  if (e.target.id !== 'search') return;
  if (e.key === 'Escape') {
    app.search = '';
    e.target.value = '';
    renderResults();
  }
  if (e.key !== 'Enter') return;
  const q = app.search.trim();
  if (!q) return;
  const hits = searchMatches();
  const quick = QUICK.exec(q);
  if (hits.length === 1 && !q.includes('@')) return app.connect(hits[0].id);
  if (!quick) return;
  const [, scheme = 'ssh', user, addr, port] = quick;
  const protocol = { ssh: 'ssh', sftp: 'ssh', ftp: 'ftp', ftps: 'ftps' }[scheme.toLowerCase()];
  const files = scheme.toLowerCase() === 'sftp';
  const address = addr.replace(/^\[|\]$/g, '');
  const go = (id) => (files ? app.openFiles(id) : app.connect(id));
  const existing = app.data().hosts.find((h) => h.address === address && (h.protocol || 'ssh') === protocol && (!user || h.username === user) && (!port || h.port === +port));
  if (existing) return go(existing.id);
  const host = { id: uid(), label: address, protocol, address, username: user || null, port: port ? +port : null, useAgent: true, tags: [] };
  if (await run(() => api.saveHost(host, null))) {
    app.search = '';
    renderContent();
    go(host.id);
  }
});

content.addEventListener('click', async (e) => {
  const actEl = e.target.closest('[data-act]');
  if (actEl) {
    e.preventDefault();
    e.stopPropagation();
    return onAction(actEl.dataset.act, actEl.dataset.id, actEl);
  }
  const card = e.target.closest('.card, .hrow');
  if (!card) return;
  if (card.dataset.host) app.connect(card.dataset.host);
  else if (card.dataset.group) { app.groupId = card.dataset.group; app.search = ''; renderContent(); }
  else if (card.dataset.key) openDrawer('key', card.dataset.key);
  else if (card.dataset.snippet) openDrawer('snippet', card.dataset.snippet);
  else if (card.dataset.password) openDrawer('password', card.dataset.password);
});
content.addEventListener('click', (e) => {
  // Password rows are table rows rather than cards.
  if (e.target.closest('[data-act], a, .selectable')) return;
  const row = e.target.closest('tr[data-password]');
  if (row) openDrawer('password', row.dataset.password);
  const apiRowEl = e.target.closest('tr[data-api]');
  if (apiRowEl) openDrawer('apikey', apiRowEl.dataset.api);
});

content.addEventListener('contextmenu', (e) => {
  const apiRowEl = e.target.closest('tr[data-api]');
  if (apiRowEl && !e.target.closest('.selectable')) {
    e.preventDefault();
    return apiCopyMenu(e.clientX, e.clientY, apiRowEl.dataset.api);
  }
  const card = e.target.closest('.card, .hrow');
  if (!card) return;
  e.preventDefault();
  if (card.dataset.host) {
    const id = card.dataset.host;
    const h = app.host(id);
    contextMenu(e.clientX, e.clientY, [
      { label: isSsh(h) ? 'Connect' : 'Open files', icon: isSsh(h) ? icon.play : icon.folder, action: () => app.connect(id) },
      ...(isSsh(h) ? [{ label: 'Open SFTP', icon: icon.folder, action: () => app.openFiles(id) }] : []),
      { label: 'Edit', icon: icon.edit, action: () => openDrawer('host', id) },
      { label: 'Duplicate', icon: icon.copy, action: () => run(() => api.duplicateHost(id)) },
      'sep',
      { label: 'Delete', icon: icon.trash, danger: true, action: () => deleteHost(id) },
    ]);
  } else if (card.dataset.group) {
    const id = card.dataset.group;
    contextMenu(e.clientX, e.clientY, [
      { label: 'Open', icon: icon.folder, action: () => { app.groupId = id; renderContent(); } },
      { label: 'Edit', icon: icon.edit, action: () => openDrawer('group', id) },
      'sep',
      { label: 'Delete group', icon: icon.trash, danger: true, action: () => deleteGroup(id) },
    ]);
  }
});

async function onAction(act, id, el) {
  switch (act) {
    case 'api-filter': app.apiGroupId = id; app.revealedApi = null; return renderContent();
    case 'new-api': return openDrawer('apikey', null);
    case 'edit-api': return openDrawer('apikey', id);
    case 'new-api-group': return openDrawer('apigroup', null);
    case 'edit-api-group': return openDrawer('apigroup', id);
    case 'reveal-api': return revealApi(id);
    case 'copy-api': {
      const a = app.apiKey(id);
      const main = a && primaryField(a);
      if (main) copySecret(() => api.revealApiSecret(id, main.id), main.label);
      return;
    }
    case 'api-copy-as': {
      const r = el.getBoundingClientRect();
      return apiCopyMenu(r.left, r.bottom + 4, id);
    }
    case 'open-api-url': {
      const url = entryUrl(app.apiKey(id)?.baseUrl);
      if (url) openUrl(url).catch((e) => toast(String(e), 'error'));
      return;
    }
    case 'sftp': return app.openFiles(id);
    case 'hosts-view':
      // Saved with the settings, so the Hosts screen reopens the way it was left.
      if (hostsView() !== id) run(() => api.saveSettings({ ...app.settings(), hostsView: id }));
      return;
    case 'pw-filter': app.pwGroupId = id; app.revealed = null; return renderContent();
    case 'new-pw-group': return openDrawer('pwgroup', null);
    case 'edit-pw-group': return openDrawer('pwgroup', id);
    case 'edit-password': return openDrawer('password', id);
    case 'reveal-pass': return revealPassword(id);
    case 'open-url': {
      const url = entryUrl(app.password(id)?.url);
      if (url) openUrl(url).catch((e) => toast(String(e), 'error'));
      return;
    }
    case 'new-host': return openDrawer('host', null);
    case 'edit-host': return openDrawer('host', id);
    case 'new-group': return openDrawer('group', null);
    case 'edit-group': return openDrawer('group', id);
    case 'root': app.groupId = null; return renderContent();
    case 'new-key': return openDrawer('key', null);
    case 'copy-pub': return copyPub(id);
    case 'new-snippet': return openDrawer('snippet', null);
    case 'new-password': return openDrawer('password', null);
    case 'copy-pass': return copyPassword(id);
    case 'copy-user':
      await writeText(app.password(id)?.username || '');
      return toast('Username copied', 'ok');
    case 'forget-host':
      if (await confirmDialog('Remove trusted key?', `You'll be asked to trust <strong>${esc(id)}</strong> again next time you connect.`, 'Remove'))
        run(() => api.deleteKnownHost(id));
      return;
    case 'export': return doExport();
    case 'import-file': return doImport();
    case 'import-ssh-config': return doSshConfig();
  }
}

async function copyPub(id) {
  const k = app.key(id);
  if (!k) return;
  await writeText(k.publicKey);
  toast('Public key copied — paste it into ~/.ssh/authorized_keys on the server', 'ok');
}

async function deleteHost(id) {
  const h = app.host(id);
  if (h && (await confirmDialog('Delete host?', `<strong>${esc(h.label)}</strong> and its saved password will be removed from this computer.`))) {
    await run(() => api.deleteHost(id));
    if (app.drawer?.id === id) closeDrawer();
  }
}

async function deleteGroup(id) {
  const g = app.group(id);
  if (!g) return;
  const n = app.data().hosts.filter((h) => h.groupId === id).length;
  if (await confirmDialog('Delete group?', `<strong>${esc(g.name)}</strong> will be removed. ${n ? `Its ${n} host${n === 1 ? '' : 's'} will be kept and moved out of the group.` : ''}`)) {
    await run(() => api.deleteGroup(id));
    if (app.groupId === id) app.groupId = null;
    closeDrawer();
    renderContent();
  }
}

// ---------- import / export ----------
async function doExport() {
  const pass = $('#exp-p1').value;
  if (pass.length < MIN_EXPORT_PW) return toast(`Use an export password of at least ${MIN_EXPORT_PW} characters`, 'error');
  if (pass !== $('#exp-p2').value) return toast('The two passwords don’t match', 'error');
  const date = new Date().toISOString().slice(0, 10);
  const path = await saveDialog({ defaultPath: `nimbus-export-${date}.nimbus.json`, filters: [{ name: 'Nimbus export', extensions: ['json'] }] });
  if (!path) return;
  if (await run(() => api.exportData(path, pass))) {
    $('#exp-p1').value = $('#exp-p2').value = '';
    $('#exp-meter').dataset.level = 0;
    toast('Exported and encrypted. You’ll need the password to import it.', 'ok');
  }
}

async function doImport() {
  const path = await openDialog({ multiple: false, filters: [{ name: 'Nimbus export', extensions: ['json'] }] });
  if (!path) return;
  // 1. The password: checked by decrypting the file before anything is shown or changed.
  let password = '';
  let p = null;
  let error = '';
  while (!p) {
    const r = await modal({
      title: 'Unlock the export',
      html: `<p>Enter the password this file was exported with.</p>
        <label class="field"><input type="password" name="pass" autofocus spellcheck="false" autocomplete="off"></label>
        ${error ? `<div class="dangerbox">${esc(error)}</div>` : ''}`,
      buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Unlock', value: 'ok', kind: 'primary', submit: true }],
    });
    if (r.action !== 'ok') return;
    password = r.values.pass || '';
    try {
      toast('Decrypting…');
      p = await api.importPreview(path, password);
    } catch (e) {
      error = String(e);
      // Problems other than the password (not an export, damaged, too new) won't fix themselves.
      if (!/password/i.test(error)) return toast(error, 'error');
    }
  }
  // 2. What's in it, and how to bring it in.
  const r = await modal({
    title: 'Import',
    html: `<p>This file was exported ${esc(new Date(p.exportedAt).toLocaleString())} and contains
        <strong>${p.hosts}</strong> hosts, <strong>${p.groups}</strong> groups, <strong>${p.keys}</strong> keys,
        <strong>${p.passwords}</strong> passwords, <strong>${p.apiKeys}</strong> API credentials, <strong>${p.snippets}</strong> snippets and <strong>${p.knownHosts}</strong> trusted host keys.</p>
      <div class="radio-cards">
        <label><input type="radio" name="mode" value="merge" checked><span>Merge<small>Add what's new and update anything imported before. Nothing is removed.</small></span></label>
        <label><input type="radio" name="mode" value="replace"><span>Replace everything<small>Your current hosts, groups, keys, passwords, API credentials and snippets are replaced by the file.</small></span></label>
      </div>`,
    buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Import', value: 'ok', kind: 'primary', submit: true }],
  });
  if (r.action !== 'ok') return;
  if (r.values.mode === 'replace' && !(await confirmDialog('Replace everything?', 'Your current hosts, groups, keys, passwords, API credentials and snippets will be replaced. Consider exporting them first.', 'Replace'))) return;
  const ok = await run(() => api.importApply(path, r.values.mode, password));
  if (ok) {
    toast(`Imported ${p.hosts} hosts, ${p.passwords} passwords and ${p.apiKeys} API credentials`, 'ok');
    app.view = 'hosts';
    app.groupId = null;
    renderSidebar();
    renderContent();
  }
}

async function doSshConfig() {
  try {
    const { report, state } = await api.importSshConfig();
    setSnap(state);
    const warn = report.warnings.length ? `<ul class="hint">${report.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : '';
    await modal({
      title: 'Imported ~/.ssh/config',
      html: `<p>Added <strong>${report.hostsAdded}</strong> hosts${report.keysAdded ? ` and <strong>${report.keysAdded}</strong> keys` : ''} to the “SSH config” group.
        ${report.hostsSkipped ? `${report.hostsSkipped} were skipped because they're already here.` : ''}</p>${warn}`,
      buttons: [{ label: 'Done', value: 'ok', kind: 'primary', submit: true }],
    });
  } catch (e) {
    toast(String(e), 'error');
  }
}

// ---------- drawer (editors) ----------
const drawer = $('#drawer');

function openDrawer(kind, id) {
  app.drawer = { kind, id };
  drawer.hidden = false;
  drawer.innerHTML = { host: hostForm, group: groupForm, key: keyForm, snippet: snippetForm, password: passwordForm, pwgroup: pwGroupForm, apigroup: apiGroupForm, apikey: apiKeyForm }[kind](id);
  wireDrawer(kind, id);
  drawer.querySelector('[autofocus]')?.focus();
}

function closeDrawer() {
  app.drawer = null;
  drawer.hidden = true;
  drawer.innerHTML = '';
}

const opt = (value, label, selected) => `<option value="${esc(value)}" ${selected ? 'selected' : ''}>${esc(label)}</option>`;

function swatches(name, current) {
  return `<div class="swatches"><label class="none" title="Automatic"><input type="radio" name="${name}" value="" ${!current ? 'checked' : ''}></label>${COLORS.map(
    (c) => `<label style="--c:${c}"><input type="radio" name="${name}" value="${c}" ${current === c ? 'checked' : ''}></label>`,
  ).join('')}</div>`;
}

function drawerShell(title, body, foot) {
  return `<form class="drawer-form" autocomplete="off" style="display:contents">
    <div class="drawer-head"><h2>${esc(title)}</h2><button type="button" class="icon-btn" data-dact="close" title="Close">${icon.x}</button></div>
    <div class="drawer-body">${body}</div>
    <div class="drawer-foot">${foot}</div></form>`;
}

function hostForm(id) {
  const h = (id && app.host(id)) || { groupId: app.groupId, useAgent: true, tags: [], protocol: 'ssh' };
  const d = app.data();
  const g = h.groupId && app.group(h.groupId);
  const hasPw = id && app.flags(id).password;
  const proto = h.protocol || 'ssh';
  const protoOpt = (v, label, sub) => `<label><input type="radio" name="protocol" value="${v}" ${proto === v ? 'checked' : ''}><span>${label}<small>${sub}</small></span></label>`;
  return drawerShell(
    id ? 'Edit host' : 'New host',
    `<div class="fieldset"><div class="legend">Connection</div>
      <div class="segmented four">${protoOpt('ssh', 'SSH', 'Terminal + SFTP')}${protoOpt('serial', 'Serial', 'USB / COM')}${protoOpt('ftp', 'FTP', 'Files')}${protoOpt('ftps', 'FTPS', 'Encrypted')}</div>
      <p class="hint proto-hint" data-for="serial">A device on a serial port: a router or switch console cable, an Arduino, a USB-serial adapter.</p>
      <p class="hint proto-hint" data-for="ftp">Plain FTP sends your password and files unencrypted. Use FTPS, or SSH (SFTP), when the server supports it.</p>
      <p class="hint proto-hint" data-for="ftps">FTP with TLS (“explicit FTPS”). If the server's certificate isn't from a known authority, you'll be asked to trust it once.</p>
    </div>
    <div class="fieldset"><div class="legend">Address</div>
      <label class="field"><span>Label</span><input name="label" value="${esc(h.label)}" placeholder="e.g. Web server" autofocus></label>
      <div class="field-row net-only"><label class="field"><span>Hostname or IP</span><input name="address" value="${esc(h.address)}" placeholder="server.example.com" spellcheck="false"></label>
      <label class="field"><span>Port</span><input type="number" name="port" min="1" max="65535" value="${h.port ?? ''}" data-ssh-port="${g?.port || 22}" placeholder="${proto === 'ssh' ? g?.port || 22 : 21}"></label></div>
      <label class="field"><span>Group</span><select name="groupId">${opt('', 'No group', !h.groupId)}${[...d.groups].sort(byName).map((x) => opt(x.id, x.name, x.id === h.groupId)).join('')}</select></label>
    </div>
    <div class="fieldset serial-only"><div class="legend">Serial port</div>
      <label class="field"><span>Port</span><div class="input-row"><input name="serialPort" list="serial-ports" value="${esc(isSerial(h) ? h.address : '')}" placeholder="${app.snap.platform === 'windows' ? 'COM3' : '/dev/cu.usbserial-…'}" spellcheck="false">
        <button type="button" class="btn small" data-dact="scan-ports" title="Look for connected devices">${icon.refresh} Scan</button></div></label>
      <datalist id="serial-ports"></datalist>
      <p class="hint ports-hint" style="margin:-4px 0 10px"></p>
      <div class="field-grid">
        <label class="field"><span>Baud rate</span><input type="number" name="baudRate" list="bauds" min="50" max="4000000" value="${h.baudRate ?? ''}" placeholder="9600"></label>
        <datalist id="bauds">${BAUDS.map((b) => `<option value="${b}">`).join('')}</datalist>
        <label class="field"><span>Data bits</span><select name="dataBits">${[8, 7, 6, 5].map((b) => opt(b, b, (h.dataBits || 8) === b)).join('')}</select></label>
        <label class="field"><span>Parity</span><select name="parity">${[['none', 'None'], ['even', 'Even'], ['odd', 'Odd']].map(([v, l]) => opt(v, l, (h.parity || 'none') === v)).join('')}</select></label>
        <label class="field"><span>Stop bits</span><select name="stopBits">${[1, 2].map((b) => opt(b, b, (h.stopBits || 1) === b)).join('')}</select></label>
        <label class="field"><span>Flow control</span><select name="flowControl">${[['none', 'None'], ['hardware', 'Hardware (RTS/CTS)'], ['software', 'Software (XON/XOFF)']].map(([v, l]) => opt(v, l, (h.flowControl || 'none') === v)).join('')}</select></label>
        <label class="field"><span>Enter sends</span><select name="newline">${[['cr', 'CR (\\r)'], ['lf', 'LF (\\n)'], ['crlf', 'CR LF']].map(([v, l]) => opt(v, l, (h.newline || 'cr') === v)).join('')}</select></label>
      </div>
      <label class="check"><input type="checkbox" name="localEcho" ${h.localEcho ? 'checked' : ''}><span>Local echo<small>Show what you type, for devices that don't echo it back.</small></span></label>
      <p class="hint">Most network gear uses 9600 8N1. Arduinos and many boards use 115200.</p>
    </div>
    <div class="fieldset"><div class="legend">Login</div>
      <label class="field net-only"><span>Username</span><input name="username" value="${esc(h.username || '')}" data-ssh-ph="${esc(g?.username || 'Ask when connecting')}" data-ftp-ph="${esc(g?.username || 'anonymous')}" placeholder="${esc(proto === 'ssh' ? g?.username || 'Ask when connecting' : g?.username || 'anonymous')}" spellcheck="false"></label>
      <label class="field"><span>Password</span><input type="password" name="password" data-net-ph="${hasPw ? '•••••••• saved — type to change' : 'Optional — asked when needed'}" data-serial-ph="${hasPw ? '•••••••• saved — type to change' : `Optional — for Type password (${isMac ? '⌘⇧P' : 'Ctrl+Shift+P'})`}" placeholder="${hasPw ? '•••••••• saved — type to change' : 'Optional — asked when needed'}" autocomplete="new-password"></label>
      ${hasPw ? `<label class="check"><input type="checkbox" name="clearPassword"><span>Forget saved password</span></label>` : ''}
      <div class="ssh-only">
      <label class="field"><span>Key</span><select name="keyId">${opt('', g?.keyId ? `From group (${app.key(g.keyId)?.label || 'key'})` : 'None', !h.keyId)}${[...d.keys].sort(byName).map((k) => opt(k.id, k.label, k.id === h.keyId)).join('')}</select></label>
      <label class="check"><input type="checkbox" name="useAgent" ${h.useAgent !== false ? 'checked' : ''}><span>Try keys from my SSH agent<small>ssh-agent, 1Password, Secretive, Pageant…</small></span></label>
      </div>
    </div>
    <div class="fieldset ssh-only"><div class="legend">Jump host</div>
      <label class="field"><select name="jumpHostId">${opt('', 'Connect directly', !h.jumpHostId)}${d.hosts.filter((x) => x.id !== id && isSsh(x)).sort(byName).map((x) => opt(x.id, `Via ${x.label}`, x.id === h.jumpHostId)).join('')}</select></label>
    </div>
    <div class="fieldset"><div class="legend">Appearance</div>${swatches('color', h.color)}</div>
    <div class="fieldset"><div class="legend">Notes</div>
      <label class="field"><span>Tags (comma separated)</span><input name="tags" value="${esc((h.tags || []).join(', '))}" placeholder="prod, web"></label>
      <label class="field"><textarea class="short" name="notes" placeholder="Anything worth remembering">${esc(h.notes || '')}</textarea></label>
    </div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="save-connect">${proto === 'ssh' || proto === 'serial' ? `${icon.play} Connect` : `${icon.folder} Open`}</button>
     <button type="submit" class="btn primary">Save</button>`,
  );
}

function groupForm(id) {
  const g = (id && app.group(id)) || {};
  return drawerShell(
    id ? 'Edit group' : 'New group',
    `<div class="fieldset"><label class="field"><span>Name</span><input name="name" value="${esc(g.name)}" placeholder="e.g. Production" autofocus></label>
      <div class="legend" style="margin-top:14px">Colour</div>${swatches('color', g.color)}</div>
    <div class="fieldset"><div class="legend">Defaults for hosts in this group</div>
      <p class="hint" style="margin:0 0 10px">Hosts use these when their own field is left blank.</p>
      <div class="field-row"><label class="field"><span>Username</span><input name="username" value="${esc(g.username || '')}" spellcheck="false"></label>
      <label class="field"><span>Port</span><input type="number" name="port" min="1" max="65535" value="${g.port ?? ''}" placeholder="22"></label></div>
      <label class="field"><span>Key</span><select name="keyId">${opt('', 'None', !g.keyId)}${[...app.data().keys].sort(byName).map((k) => opt(k.id, k.label, k.id === g.keyId)).join('')}</select></label>
    </div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="close">Cancel</button><button type="submit" class="btn primary">Save</button>`,
  );
}

function keyForm(id) {
  const k = id && app.key(id);
  const f = (id && app.flags(id)) || {};
  const body = k
    ? `<div class="fieldset"><label class="field"><span>Label</span><input name="label" value="${esc(k.label)}" autofocus></label></div>
      <div class="fieldset"><div class="legend">Public key</div>
        <div class="pubkey selectable">${esc(k.publicKey)}</div>
        <div class="inline-actions"><button type="button" class="btn small" data-dact="copy-pub">${icon.copy} Copy public key</button></div>
        <p class="hint">Add this line to <code>~/.ssh/authorized_keys</code> on each server that should accept this key.</p>
        <p class="hint">${esc(k.keyType)} · <span class="mono selectable">${esc(k.fingerprint)}</span></p></div>
      <div class="fieldset"><div class="legend">Passphrase</div>
        ${k.encrypted ? `<label class="field"><input type="password" name="passphrase" placeholder="${f.passphrase ? '•••••••• saved — type to change' : 'Not saved — asked when connecting'}" autocomplete="new-password"></label>
          ${f.passphrase ? '<label class="check"><input type="checkbox" name="clearPassphrase"><span>Forget saved passphrase</span></label>' : ''}`
        : '<p class="hint">This key has no passphrase.</p>'}</div>
      <div class="fieldset"><div class="legend">Private key</div>
        ${f.privateKey ? '<p class="hint">Stored encrypted on this computer.</p>' : '<div class="dangerbox">The private key is missing (it was imported without secrets). Paste it below.</div>'}
        <label class="field"><textarea name="privateKey" placeholder="Paste a replacement private key (optional)" spellcheck="false"></textarea></label></div>`
    : `<div class="fieldset"><label class="field"><span>Label</span><input name="label" placeholder="e.g. Work laptop" autofocus></label></div>
      <div class="fieldset"><div class="legend">Private key</div>
        <div class="inline-actions" style="margin:0 0 8px"><button type="button" class="btn small" data-dact="key-file">${icon.file} Choose file…</button>
          <button type="button" class="btn small" data-dact="key-gen">${icon.plus} Generate new Ed25519 key</button></div>
        <label class="field"><textarea name="privateKey" rows="9" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false"></textarea></label>
        <label class="field"><span>Passphrase (only if the key has one)</span><input type="password" name="passphrase" autocomplete="new-password"></label>
        <p class="hint">Leave the passphrase empty to be asked each time you connect, or fill it in to save it.</p></div>`;
  return drawerShell(
    k ? 'Edit key' : 'New key',
    body,
    `${k ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="close">Cancel</button><button type="submit" class="btn primary">Save</button>`,
  );
}

function passwordForm(id) {
  const fromFilter = app.pwGroup(app.pwGroupId) ? app.pwGroupId : null;
  const p = (id && app.password(id)) || { groupId: fromFilter };
  const saved = id && app.flags(id).password;
  return drawerShell(
    id ? 'Edit password' : 'New password',
    `<div class="fieldset">
      <label class="field"><span>Name</span><input name="name" value="${esc(p.name)}" placeholder="e.g. Ubuntu sudo, Router admin" autofocus></label>
      <label class="field"><span>Group</span><select name="groupId">${opt('', 'No group', !p.groupId)}${[...app.data().passwordGroups].sort(byName).map((g) => opt(g.id, g.name, g.id === p.groupId)).join('')}</select></label>
      <label class="field"><span>Username</span><input name="username" value="${esc(p.username || '')}" spellcheck="false"></label>
      <label class="field"><span>Password</span><input type="password" name="password" placeholder="${saved ? '•••••••• saved — type to change' : ''}" autocomplete="new-password" spellcheck="false"></label>
      <div class="inline-actions" style="margin:-4px 0 12px">
        ${saved ? `<button type="button" class="btn small" data-dact="pw-show">${icon.eye} Show</button>
          <button type="button" class="btn small" data-dact="pw-copy">${icon.copy} Copy</button>` : ''}
        <button type="button" class="btn small" data-dact="pw-gen">${icon.dice} Generate</button>
      </div>
      <label class="field"><span>Website or address</span><input name="url" value="${esc(p.url || '')}" placeholder="e.g. example.com or 192.168.1.1" spellcheck="false"></label>
      <label class="field"><span>Notes</span><textarea class="short" name="notes">${esc(p.notes || '')}</textarea></label>
      ${p.updated ? `<p class="hint">Last changed ${esc(timeAgo(p.updated))}</p>` : ''}
    </div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="close">Cancel</button><button type="submit" class="btn primary">Save</button>`,
  );
}

function pwGroupForm(id) {
  const g = (id && app.pwGroup(id)) || {};
  const n = id ? app.data().passwords.filter((p) => p.groupId === id).length : 0;
  return drawerShell(
    id ? 'Edit password group' : 'New password group',
    `<div class="fieldset"><label class="field"><span>Name</span><input name="name" value="${esc(g.name)}" placeholder="e.g. Servers, Network gear, Websites" autofocus></label>
      <div class="legend" style="margin-top:14px">Colour</div>${swatches('color', g.color)}
      ${id ? `<p class="hint" style="margin-top:14px">${n} password${n === 1 ? '' : 's'} in this group.</p>` : ''}</div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="close">Cancel</button><button type="submit" class="btn primary">Save</button>`,
  );
}

function apiGroupForm(id) {
  const g = (id && app.apiGroup(id)) || {};
  const n = id ? app.data().apiKeys.filter((a) => a.groupId === id).length : 0;
  return drawerShell(
    id ? 'Edit API group' : 'New API group',
    `<div class="fieldset"><label class="field"><span>Name</span><input name="name" value="${esc(g.name)}" placeholder="e.g. Payments, Cloud, Internal APIs" autofocus></label>
      <div class="legend" style="margin-top:14px">Colour</div>${swatches('color', g.color)}
      ${id ? `<p class="hint" style="margin-top:14px">${n} credential${n === 1 ? '' : 's'} in this group.</p>` : ''}</div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="close">Cancel</button><button type="submit" class="btn primary">Save</button>`,
  );
}

/** One field row in the credential editor. Template fields have a fixed label; extra ones are editable. */
function apiFieldHtml(f, entryId, extra) {
  const saved = entryId && f.secret && app.flags(entryId).fields?.includes(f.id);
  const input = f.options
    ? `<select data-fv>${f.options.map(([v, l]) => opt(v, l, (f.value || f.options[0][0]) === v)).join('')}</select>`
    : `<input data-fv type="${f.secret ? 'password' : 'text'}" value="${esc(f.secret ? '' : f.value || '')}" spellcheck="false" autocomplete="off"
        placeholder="${esc(saved ? '•••••••• saved — type to change' : f.placeholder || (f.optional ? 'Optional' : ''))}">`;
  return `<div class="api-field" data-fid="${esc(f.id)}" data-secret="${f.secret ? 1 : 0}" ${extra ? 'data-extra="1"' : ''}>
    ${extra
      ? `<div class="api-field-head"><input data-fl value="${esc(f.label || '')}" placeholder="Field name" spellcheck="false">
          <label class="mini-check" title="Store encrypted and hide it"><input type="checkbox" data-fs ${f.secret ? 'checked' : ''}> Secret</label>
          <button type="button" class="icon-btn" data-dact="api-del-field" title="Remove field">${icon.x}</button></div>`
      : `<span class="api-field-label">${esc(f.label)}${f.secret ? ` <span class="lock" title="Stored encrypted">${icon.lock}</span>` : ''}</span>`}
    <div class="input-row">${input}
      ${f.secret ? `<button type="button" class="icon-btn" data-dact="api-show" title="Show">${icon.eye}</button>` : ''}
      ${saved ? `<button type="button" class="icon-btn" data-dact="api-copy-field" title="Copy">${icon.copy}</button>
        <button type="button" class="icon-btn" data-dact="api-clear" title="Forget the saved value">${icon.trash}</button>` : ''}</div></div>`;
}

/** The fields for a credential of `kind`: the type's own fields, then any extra ones. */
function apiFieldsFor(kind, entry) {
  const tpl = API_KINDS[kind]?.fields || [];
  const existing = new Map((entry?.fields || []).map((f) => [f.id, f]));
  const fixed = tpl.map((t) => ({ ...t, value: existing.get(t.id)?.value ?? null }));
  const extras = (entry?.fields || []).filter((f) => !tpl.some((t) => t.id === f.id) && (kind === 'custom' || !Object.values(API_KINDS).some((k) => k.fields.some((t) => t.id === f.id))));
  return { fixed, extras };
}

function apiKeyForm(id) {
  const fromFilter = app.apiGroup(app.apiGroupId) ? app.apiGroupId : null;
  const a = (id && app.apiKey(id)) || { kind: 'apiKey', groupId: fromFilter, fields: [] };
  const exp = a.expires ? new Date(a.expires - new Date(a.expires).getTimezoneOffset() * 60000).toISOString().slice(0, 10) : '';
  return drawerShell(
    id ? 'Edit API credential' : 'New API credential',
    `<div class="fieldset">
      <label class="field"><span>Name</span><input name="name" value="${esc(a.name)}" placeholder="e.g. GitHub deploy token" autofocus></label>
      <div class="field-grid">
        <label class="field"><span>Service</span><input name="service" value="${esc(a.service || '')}" placeholder="e.g. Stripe" spellcheck="false"></label>
        <label class="field"><span>Environment</span><input name="environment" list="api-envs" value="${esc(a.environment || '')}" placeholder="None" spellcheck="false"></label>
      </div>
      <datalist id="api-envs">${ENVIRONMENTS.map((e) => `<option value="${e}">`).join('')}</datalist>
      <label class="field"><span>Group</span><select name="groupId">${opt('', 'No group', !a.groupId)}${[...app.data().apiGroups].sort(byName).map((g) => opt(g.id, g.name, g.id === a.groupId)).join('')}</select></label>
    </div>
    <div class="fieldset"><div class="legend">Credential</div>
      <label class="field"><span>Type</span><select name="kind">${Object.entries(API_KINDS).map(([k, v]) => opt(k, v.label, a.kind === k)).join('')}</select></label>
      <div class="api-fields"></div>
      <button type="button" class="btn small" data-dact="api-add-field">${icon.plus} Add field</button>
    </div>
    <div class="fieldset"><div class="legend">Details</div>
      <label class="field"><span>Base URL</span><input name="baseUrl" value="${esc(a.baseUrl || '')}" placeholder="https://api.example.com" spellcheck="false"></label>
      <label class="field"><span>Expires</span><input type="date" name="expires" value="${exp}"></label>
      <label class="field"><span>Notes</span><textarea class="short" name="notes" placeholder="Scopes, who owns it, where it's used…">${esc(a.notes || '')}</textarea></label>
      ${a.updated ? `<p class="hint">Last changed ${esc(timeAgo(a.updated))}</p>` : ''}
    </div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}
     ${id ? `<button type="button" class="btn" data-dact="api-copy-as">${icon.more} Copy as</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="close">Cancel</button><button type="submit" class="btn primary">Save</button>`,
  );
}

function snippetForm(id) {
  const s = (id && app.snippet(id)) || { run: true };
  return drawerShell(
    id ? 'Edit snippet' : 'New snippet',
    `<div class="fieldset"><label class="field"><span>Name</span><input name="name" value="${esc(s.name)}" placeholder="e.g. Disk usage" autofocus></label>
      <label class="field"><span>Command</span><textarea name="command" rows="6" placeholder="df -h" spellcheck="false">${esc(s.command)}</textarea></label>
      <label class="check"><input type="checkbox" name="run" ${s.run ? 'checked' : ''}><span>Press Enter after pasting<small>Untick to paste the command and let you edit it first.</small></span></label></div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="close">Cancel</button><button type="submit" class="btn primary">Save</button>`,
  );
}

function wireDrawer(kind, id) {
  const form = drawer.querySelector('form');
  let scanPorts = null; // host form: refreshes the serial port suggestions
  const val = (n) => form.elements[n]?.value?.trim() ?? '';
  const checked = (n) => !!form.elements[n]?.checked;
  const num = (n) => (val(n) ? Math.min(65535, Math.max(1, parseInt(val(n), 10))) || null : null);

  async function save(connectAfter = false) {
    if (kind === 'host') {
      const prev = (id && app.host(id)) || {};
      const protocol = form.querySelector('input[name=protocol]:checked')?.value || 'ssh';
      const serial = protocol === 'serial';
      if (serial && !val('serialPort')) return toast('Choose or type a serial port', 'error');
      if (!serial && !val('address')) return toast('Enter a hostname or IP address', 'error');
      const host = {
        ...prev,
        id: id || uid(),
        protocol,
        label: val('label'),
        address: serial ? val('serialPort') : val('address'),
        port: serial ? null : num('port'),
        ...(serial
          ? {
              baudRate: parseInt(val('baudRate'), 10) || null,
              dataBits: +val('dataBits'),
              parity: val('parity'),
              stopBits: +val('stopBits'),
              flowControl: val('flowControl'),
              newline: val('newline'),
              localEcho: checked('localEcho'),
            }
          : {}),
        groupId: val('groupId') || null,
        username: val('username') || null,
        keyId: val('keyId') || null,
        useAgent: checked('useAgent'),
        jumpHostId: val('jumpHostId') || null,
        color: form.querySelector('input[name=color]:checked')?.value || null,
        tags: val('tags').split(',').map((t) => t.trim()).filter(Boolean),
        notes: val('notes') || null,
      };
      const pw = form.elements.password.value;
      const password = pw ? pw : checked('clearPassword') ? '' : null;
      if (await run(() => api.saveHost(host, password), connectAfter ? null : 'Host saved')) {
        closeDrawer();
        if (connectAfter) app.connect(host.id);
      }
    } else if (kind === 'group') {
      const prev = (id && app.group(id)) || {};
      const group = { ...prev, id: id || uid(), name: val('name'), color: form.querySelector('input[name=color]:checked')?.value || null, username: val('username') || null, port: num('port'), keyId: val('keyId') || null };
      if (await run(() => api.saveGroup(group), 'Group saved')) closeDrawer();
    } else if (kind === 'key') {
      const prev = (id && app.key(id)) || {};
      const key = { ...prev, id: id || uid(), label: val('label') };
      const pem = form.elements.privateKey?.value.trim() || null;
      const passEl = form.elements.passphrase;
      const passphrase = passEl?.value ? passEl.value : checked('clearPassphrase') ? '' : id ? null : '';
      if (await run(() => api.saveKey(key, pem, passphrase), 'Key saved')) openDrawer('key', key.id);
    } else if (kind === 'password') {
      if (!val('name')) return toast('Give the password a name', 'error');
      const prev = (id && app.password(id)) || {};
      const entry = { ...prev, id: id || uid(), name: val('name'), groupId: val('groupId') || null, username: val('username') || null, url: val('url') || null, notes: form.elements.notes.value.trim() || null, updated: 0 };
      const pw = form.elements.password.value;
      if (!id && !pw) return toast('Enter or generate a password', 'error');
      if (await run(() => api.savePassword(entry, pw || null), 'Password saved')) closeDrawer();
    } else if (kind === 'apigroup') {
      if (!val('name')) return toast('Give the group a name', 'error');
      const group = { id: id || uid(), name: val('name'), color: form.querySelector('input[name=color]:checked')?.value || null };
      if (await run(() => api.saveApiGroup(group), 'Group saved')) {
        closeDrawer();
        if (!id) { app.apiGroupId = group.id; renderContent(); }
      }
    } else if (kind === 'apikey') {
      if (!val('name')) return toast('Give the credential a name', 'error');
      const fields = [];
      const secrets = {};
      for (const row of form.querySelectorAll('.api-field')) {
        const fid = row.dataset.fid;
        const extra = !!row.dataset.extra;
        const secret = extra ? row.querySelector('[data-fs]').checked : row.dataset.secret === '1';
        const label = extra ? row.querySelector('[data-fl]').value.trim() : row.querySelector('.api-field-label').textContent.trim();
        const v = row.querySelector('[data-fv]').value;
        if (extra && !label && !v) continue;
        fields.push({ id: fid, label: label || 'Field', secret, value: secret ? null : v.trim() || null });
        if (secret) secrets[fid] = row.dataset.clear ? '' : v ? v : null;
      }
      const prev = (id && app.apiKey(id)) || {};
      const day = val('expires');
      const entry = {
        ...prev, id: id || uid(), name: val('name'), kind: val('kind'), service: val('service') || null, environment: val('environment') || null,
        groupId: val('groupId') || null, baseUrl: val('baseUrl') || null, notes: form.elements.notes.value.trim() || null,
        // End of the chosen day, local time.
        expires: day ? new Date(`${day}T23:59:59`).getTime() : null, fields, updated: 0,
      };
      if (await run(() => api.saveApiKey(entry, secrets), 'Credential saved')) closeDrawer();
    } else if (kind === 'pwgroup') {
      if (!val('name')) return toast('Give the group a name', 'error');
      const group = { id: id || uid(), name: val('name'), color: form.querySelector('input[name=color]:checked')?.value || null };
      if (await run(() => api.savePasswordGroup(group), 'Group saved')) {
        closeDrawer();
        if (!id) { app.pwGroupId = group.id; renderContent(); }
      }
    } else if (kind === 'snippet') {
      if (!val('command')) return toast('Enter a command', 'error');
      const snippet = { id: id || uid(), name: val('name'), command: form.elements.command.value.replace(/\s+$/, ''), run: checked('run') };
      if (await run(() => api.saveSnippet(snippet), 'Snippet saved')) closeDrawer();
    }
  }

  if (kind === 'apikey') {
    const box = form.querySelector('.api-fields');
    const draw = () => {
      // Keep anything already typed when switching type, for fields both types share.
      const typed = new Map([...box.querySelectorAll('.api-field')].map((r) => [r.dataset.fid, r.querySelector('[data-fv]').value]));
      const entry = (id && app.apiKey(id)) || { fields: [] };
      const { fixed, extras } = apiFieldsFor(form.elements.kind.value, entry);
      box.innerHTML = fixed.map((f) => apiFieldHtml(f, id, false)).join('') + extras.map((f) => apiFieldHtml(f, id, true)).join('');
      for (const r of box.querySelectorAll('.api-field')) {
        const v = typed.get(r.dataset.fid);
        if (v) r.querySelector('[data-fv]').value = v;
      }
    };
    form.elements.kind.addEventListener('change', draw);
    draw();
  }

  if (kind === 'host') {
    // Show only the fields that apply to the chosen protocol.
    const sync = () => {
      const proto = form.querySelector('input[name=protocol]:checked')?.value || 'ssh';
      form.querySelectorAll('.ssh-only').forEach((el) => (el.hidden = proto !== 'ssh'));
      form.querySelectorAll('.net-only').forEach((el) => (el.hidden = proto === 'serial'));
      form.querySelectorAll('.serial-only').forEach((el) => (el.hidden = proto !== 'serial'));
      form.elements.password.placeholder = proto === 'serial' ? form.elements.password.dataset.serialPh : form.elements.password.dataset.netPh;
      if (proto === 'serial' && !scanned) { scanned = true; scanPorts(); }
      form.querySelectorAll('.proto-hint').forEach((el) => (el.hidden = el.dataset.for !== proto));
      form.elements.port.placeholder = proto === 'ssh' ? form.elements.port.dataset.sshPort : '21';
      form.elements.username.placeholder = proto === 'ssh' ? form.elements.username.dataset.sshPh : form.elements.username.dataset.ftpPh;
      const btn = form.querySelector('[data-dact=save-connect]');
      btn.innerHTML = proto === 'ssh' || proto === 'serial' ? `${icon.play} Connect` : `${icon.folder} Open`;
    };
    let scanned = false;
    // Fill the port suggestions with what's plugged in right now.
    scanPorts = async () => {
      const hint = form.querySelector('.ports-hint');
      try {
        const ports = await api.serialPorts();
        form.querySelector('#serial-ports').innerHTML = ports.map((p) => `<option value="${esc(p.name)}">${esc(p.description)}</option>`).join('');
        hint.textContent = ports.length
          ? `Found: ${ports.map((p) => p.name.replace(/^\/dev\//, '') + (p.description ? ` (${p.description})` : '')).join(', ')}`
          : 'No serial devices found. Plug one in and press Scan.';
        const input = form.elements.serialPort;
        if (!input.value && ports.length === 1) input.value = ports[0].name;
      } catch (e) {
        hint.textContent = String(e);
      }
    };
    form.addEventListener('change', (e) => { if (e.target.name === 'protocol') sync(); });
    sync();
  }

  form.addEventListener('submit', (e) => { e.preventDefault(); save(); });
  form.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.stopPropagation(); closeDrawer(); }
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); save(); }
  });
  form.addEventListener('click', async (e) => {
    const act = e.target.closest('[data-dact]')?.dataset.dact;
    if (!act) return;
    if (act === 'close') closeDrawer();
    else if (act === 'save-connect') save(true);
    else if (act === 'scan-ports') scanPorts?.();
    else if (act === 'api-add-field') {
      const box = form.querySelector('.api-fields');
      box.insertAdjacentHTML('beforeend', apiFieldHtml({ id: uid(), label: '', secret: true }, null, true));
      box.lastElementChild.querySelector('[data-fl]').focus();
    } else if (act === 'api-del-field') e.target.closest('.api-field').remove();
    else if (act === 'api-show') {
      const row = e.target.closest('.api-field');
      const input = row.querySelector('[data-fv]');
      if (input.type === 'password') {
        if (!input.value && id && app.flags(id).fields?.includes(row.dataset.fid)) {
          try { input.value = await api.revealApiSecret(id, row.dataset.fid); } catch (err) { return toast(String(err), 'error'); }
        }
        input.type = 'text';
      } else input.type = 'password';
    } else if (act === 'api-copy-field') {
      const row = e.target.closest('.api-field');
      copySecret(() => api.revealApiSecret(id, row.dataset.fid), row.querySelector('.api-field-label')?.textContent.trim() || 'Value');
    } else if (act === 'api-clear') {
      const row = e.target.closest('.api-field');
      row.dataset.clear = '1';
      const input = row.querySelector('[data-fv]');
      input.value = '';
      input.placeholder = 'Will be forgotten when you save';
    } else if (act === 'api-copy-as') {
      const r = e.target.closest('button').getBoundingClientRect();
      apiCopyMenu(r.left, r.top - 8, id, true);
    }
    else if (act === 'copy-pub') copyPub(id);
    else if (act === 'delete') {
      if (kind === 'host') deleteHost(id);
      else if (kind === 'group') deleteGroup(id);
      else if (kind === 'key') {
        const k = app.key(id);
        if (await confirmDialog('Delete key?', `<strong>${esc(k.label)}</strong> will be removed from this computer. Hosts using it will fall back to the agent or a password.`)) {
          if (await run(() => api.deleteKey(id))) closeDrawer();
        }
      } else if (kind === 'snippet') {
        if (await run(() => api.deleteSnippet(id))) closeDrawer();
      } else if (kind === 'apigroup') {
        const g = app.apiGroup(id);
        const n = app.data().apiKeys.filter((a) => a.groupId === id).length;
        if (await confirmDialog('Delete group?', `<strong>${esc(g?.name)}</strong> will be removed.${n ? ` Its ${n} credential${n === 1 ? '' : 's'} will be kept and moved out of the group.` : ''}`)) {
          if (await run(() => api.deleteApiGroup(id))) { closeDrawer(); app.apiGroupId = 'all'; renderContent(); }
        }
      } else if (kind === 'apikey') {
        if (await confirmDialog('Delete credential?', `<strong>${esc(app.apiKey(id)?.name)}</strong> and its saved secrets will be removed from this computer.`)) {
          if (await run(() => api.deleteApiKey(id))) closeDrawer();
        }
      } else if (kind === 'pwgroup') {
        const g = app.pwGroup(id);
        const n = app.data().passwords.filter((p) => p.groupId === id).length;
        if (await confirmDialog('Delete group?', `<strong>${esc(g?.name)}</strong> will be removed.${n ? ` Its ${n} password${n === 1 ? '' : 's'} will be kept and moved out of the group.` : ''}`)) {
          if (await run(() => api.deletePasswordGroup(id))) { closeDrawer(); app.pwGroupId = 'all'; renderContent(); }
        }
      } else if (kind === 'password') {
        if (await confirmDialog('Delete password?', `<strong>${esc(app.password(id)?.name)}</strong> will be removed from this computer.`)) {
          if (await run(() => api.deletePassword(id))) closeDrawer();
        }
      }
    } else if (act === 'pw-show') {
      const f = form.elements.password;
      if (f.type === 'password') {
        if (!f.value) {
          try { f.value = await api.revealPassword(id); } catch (err) { return toast(String(err), 'error'); }
        }
        f.type = 'text';
      } else f.type = 'password';
    } else if (act === 'pw-copy') {
      copyPassword(id);
    } else if (act === 'pw-gen') {
      const f = form.elements.password;
      f.value = generatePassword();
      f.type = 'text';
      f.focus();
      f.select();
    } else if (act === 'key-file') {
      const path = await openDialog({ multiple: false });
      if (!path) return;
      try {
        form.elements.privateKey.value = await api.readTextFile(path);
        if (!val('label')) form.elements.label.value = path.split(/[\\/]/).pop();
      } catch (err) {
        toast(String(err), 'error');
      }
    } else if (act === 'key-gen') {
      if (form.elements.privateKey.value.trim() && !(await confirmDialog('Replace the pasted key?', 'The key in the box will be replaced by a newly generated one.', 'Generate', 'primary'))) return;
      try {
        const label = val('label') || 'nimbus';
        form.elements.privateKey.value = await api.generateKey(label);
        if (!val('label')) form.elements.label.value = 'Nimbus key';
        toast('Generated. Save it, then copy the public key to your servers.', 'ok');
      } catch (err) {
        toast(String(err), 'error');
      }
    }
  });
}

// ---------- theme ----------
const darkQuery = matchMedia('(prefers-color-scheme: dark)');

function applyTheme(setting = app.settings().theme || 'system') {
  const resolved = setting === 'system' ? (darkQuery.matches ? 'dark' : 'light') : setting;
  document.documentElement.dataset.theme = resolved;
  try { localStorage.setItem('nimbus-theme', resolved); } catch { /* storage unavailable */ }
  // The native window chrome (macOS title bar buttons, Windows frame) follows too.
  try { getCurrentWindow().setTheme(setting === 'system' ? null : setting).catch(() => {}); } catch { /* browser preview */ }
  app.sessions.forEach((x) => x.applySettings(app.settings()));
}
darkQuery.addEventListener('change', () => { if ((app.snap?.data.settings.theme || 'system') === 'system') applyTheme(); });

// ---------- shortcuts ----------
function shortcutFor(e) {
  const mod = isMac ? e.metaKey && !e.ctrlKey && !e.altKey : e.ctrlKey && e.shiftKey && !e.altKey;
  if (e.ctrlKey && e.key === 'Tab') return e.shiftKey ? 'prev-tab' : 'next-tab';
  if (!mod) return null;
  if (e.code === 'KeyT') return 'new-tab';
  if (e.code === 'KeyW') return 'close-tab';
  if (e.code === 'KeyD') return 'duplicate-tab';
  if (e.code === 'KeyP' && e.shiftKey) return 'type-password';
  if (e.code === 'KeyO' && e.shiftKey) return 'open-sftp';
  if (/^Digit[1-9]$/.test(e.code)) return `tab-${e.code.slice(5)}`;
  if (isMac && (e.key === '}' || e.key === '{')) return e.key === '}' ? 'next-tab' : 'prev-tab';
  return null;
}

function doShortcut(name) {
  const list = [null, ...app.sessions];
  const i = list.indexOf(app.active);
  if (name === 'new-tab') {
    app.activate(null);
    app.view = 'hosts';
    closeDrawer();
    renderSidebar();
    renderContent();
    $('#search')?.focus();
  } else if (name === 'close-tab') {
    if (app.active) app.closeSession(app.active);
  } else if (name === 'type-password') {
    app.active?.quickTypePassword?.();
  } else if (name === 'open-sftp') {
    const h = app.active && app.host(app.active.hostId);
    if (h && app.active.kind === 'term') app.openFiles(h.id);
  } else if (name === 'duplicate-tab') {
    if (app.active) app.duplicate(app.active);
  } else if (name === 'next-tab') app.activate(list[(i + 1) % list.length]);
  else if (name === 'prev-tab') app.activate(list[(i - 1 + list.length) % list.length]);
  else if (name.startsWith('tab-')) {
    const n = +name.slice(4);
    const target = n === 9 ? list[list.length - 1] : list[n - 1];
    if (target !== undefined) app.activate(target);
  }
}

window.addEventListener(
  'keydown',
  (e) => {
    if (modalOpen()) return;
    const s = shortcutFor(e);
    if (!s) return;
    e.preventDefault();
    e.stopPropagation();
    doShortcut(s);
  },
  true,
);

// macOS menu accelerators (⌘T, ⌘W, …) arrive from the native menu instead of as key events.
listen('menu', (e) => { if (!modalOpen()) doShortcut(e.payload); });

// Any web link opens in the default browser, never inside Nimbus (the Rust side also blocks
// in-app navigation as a backstop).
document.addEventListener('click', (e) => {
  const link = e.target.closest('a[href]');
  if (!link || e.defaultPrevented) return;
  e.preventDefault();
  const href = link.getAttribute('href');
  if (/^(https?|mailto):/i.test(href)) openUrl(href).catch((err) => toast(String(err), 'error'));
});

// Don't let the webview's own context menu appear outside text fields.
document.addEventListener('contextmenu', (e) => {
  if (!e.target.closest('input, textarea, .selectable, .xterm')) e.preventDefault();
});

// ---------- boot ----------
(async () => {
  try {
    setSnap(await api.state());
    applyTheme();
    renderTabs();
    listenForFileDrops(app);
  } catch (e) {
    document.body.innerHTML = `<div class="empty"><h2>Nimbus couldn't start</h2><p class="selectable">${esc(String(e))}</p></div>`;
  }
})();

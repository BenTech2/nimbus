import '@xterm/xterm/css/xterm.css';
import './styles.css';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import { readText, writeText } from '@tauri-apps/plugin-clipboard-manager';
import { listen } from '@tauri-apps/api/event';
import { api } from './api.js';
import { COLORS, confirmDialog, contextMenu, esc, icon, initials, modal, modalOpen, timeAgo, toast, uid } from './ui.js';
import { TermSession } from './terminal.js';

// Opened in a plain browser during development: fake the backend so the UI still works.
if (import.meta.env.DEV && !('__TAURI_INTERNALS__' in window)) await import('./dev-mock.js');

const isMac = navigator.userAgent.includes('Mac');
if (isMac) document.body.classList.add('mac');
const MOD = isMac ? '⌘' : 'Ctrl+Shift+';

const $ = (sel, root = document) => root.querySelector(sel);

const app = {
  snap: null,
  view: 'hosts', // hosts | keys | snippets | known | transfer | settings
  groupId: null,
  search: '',
  drawer: null, // { kind, id }
  sessions: [],
  active: null, // null = home tab, else a TermSession

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
  flags(id) { return this.snap.secrets[id] || {}; },
  modalOpen,

  // --- sessions ---
  connect(hostId) {
    const host = this.host(hostId);
    if (!host) return;
    const s = new TermSession(this, host);
    this.sessions.push(s);
    this.activate(s);
    s.connect();
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
  const g = h.groupId && app.group(h.groupId);
  const user = h.username || g?.username;
  const port = h.port || g?.port;
  return `${h.protocol || 'ssh'}, ${user ? user + '@' : ''}${h.address}${port && port !== 22 ? ':' + port : ''}`;
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
        return `<button class="tab ${app.active === s ? 'active' : ''}" data-tab="${i}" title="${esc(label)}">
          <span class="dot ${s.state}"></span><span class="label">${esc(label)}</span>
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
  contextMenu(e.clientX, e.clientY, [
    { label: 'Duplicate', icon: icon.copy, action: () => app.connect(s.hostId) },
    { label: 'Reconnect', icon: icon.refresh, action: () => { app.activate(s); s.connect(); } },
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
        : `<button class="nav-item ${app.view === n[0] ? 'active' : ''}" data-view="${n[0]}" title="${n[1]}">${n[2]}<span class="text">${n[1]}</span>${n[3] ? `<span class="count">${n[3]()}</span>` : ''}</button>`,
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
  const views = { hosts: viewHosts, passwords: viewPasswords, keys: viewKeys, snippets: viewSnippets, known: viewKnown, transfer: viewTransfer, settings: viewSettings };
  const hadSearchFocus = document.activeElement?.id === 'search';
  c.innerHTML = (app.snap.warning ? `<div class="warnbox">${esc(app.snap.warning)}</div>` : '') + views[app.view]();
  if (app.view === 'passwords') renderPasswordList();
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
      <button class="btn primary" data-act="new-host">${icon.plus} Host</button>
      <button class="btn" data-act="new-group">${icon.folder} Group</button>
    </div>
    ${g ? `<div class="crumbs"><button data-act="root">All hosts</button>${icon.chevron}<span>${esc(g.name)}</span>
      <button class="icon-btn" data-act="edit-group" data-id="${esc(g.id)}" title="Edit group">${icon.edit}</button></div>` : ''}
    <div id="results"></div>`;
}

function hostCard(h) {
  const tags = (h.tags || []).slice(0, 2).map((t) => `<span class="tag">${esc(t)}</span>`).join('');
  const title = h.lastConnected ? `Last connected ${timeAgo(h.lastConnected)}` : 'Click to connect';
  return `<div class="card clickable" data-host="${esc(h.id)}" title="${esc(title)}">
    <div class="avatar" style="--c:${esc(hostColor(h))}">${esc(initials(h.label || h.address))}</div>
    <div class="meta"><div class="title">${esc(h.label || h.address)}${tags}</div><div class="sub">${esc(hostSubtitle(h))}</div></div>
    <div class="actions"><button class="icon-btn" data-act="edit-host" data-id="${esc(h.id)}" title="Edit">${icon.edit}</button></div>
  </div>`;
}

function groupCard(g) {
  const n = app.data().hosts.filter((h) => h.groupId === g.id).length;
  return `<div class="card clickable" data-group="${esc(g.id)}">
    <div class="avatar" style="--c:${esc(g.color || '#8b91a8')}">${icon.folder}</div>
    <div class="meta"><div class="title">${esc(g.name)}</div><div class="sub">${n} host${n === 1 ? '' : 's'}</div></div>
    <div class="actions"><button class="icon-btn" data-act="edit-group" data-id="${esc(g.id)}" title="Edit">${icon.edit}</button></div>
  </div>`;
}

const QUICK = /^(?:([^@\s]+)@)?(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9._-]+)(?::(\d{1,5}))?$/;

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
      (hits.length ? `<div class="section-title">Results</div><div class="grid">${hits.map(hostCard).join('')}</div>` : '') +
      (quick && (q.includes('@') || !hits.length)
        ? `<div class="panel"><h2>Quick connect</h2><p>Press <strong>Enter</strong> to connect to <code>${esc(q)}</code>. It will be saved to your hosts so you can reconnect later.</p></div>`
        : '') +
      (!hits.length && !quick ? `<div class="empty"><p>No hosts match “${esc(q)}”.</p></div>` : '');
    return;
  }
  if (app.groupId) {
    const hosts = d.hosts.filter((h) => h.groupId === app.groupId).sort(byName);
    r.innerHTML = hosts.length
      ? `<div class="grid">${hosts.map(hostCard).join('')}</div>`
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
    (groups.length ? `<div class="section-title">Groups</div><div class="grid">${groups.map(groupCard).join('')}</div>` : '') +
    (loose.length ? `<div class="section-title">Hosts</div><div class="grid">${loose.map(hostCard).join('')}</div>` : '');
}

function viewPasswords() {
  return `<div class="toolbar"><h1>Passwords</h1>
      <label class="search">${icon.search}<input id="pw-search" placeholder="Search passwords" value="${esc(app.pwSearch || '')}" spellcheck="false" autocomplete="off"></label>
      <div class="spacer"></div>
      <button class="btn primary" data-act="new-password">${icon.plus} Password</button></div>
    <div id="pw-results"></div>`;
}

function renderPasswordList() {
  const r = $('#pw-results');
  if (!r) return;
  const q = (app.pwSearch || '').trim().toLowerCase();
  const all = app.passwords();
  const list = q ? all.filter((p) => [p.name, p.username, p.url, p.notes].some((v) => v && v.toLowerCase().includes(q))) : all;
  if (!all.length) {
    r.innerHTML = `<div class="empty"><div class="big">${icon.lock}</div><h2>No passwords yet</h2>
      <p>Keep passwords here, encrypted on this computer. Copy them when you need them, or type one into a connected terminal with the Password button.</p>
      <div class="row"><button class="btn primary" data-act="new-password">${icon.plus} New password</button></div></div>`;
    return;
  }
  r.innerHTML = list.length
    ? `<div class="grid">${list
        .map((p) => {
          const missing = !app.flags(p.id).password;
          return `<div class="card clickable" data-password="${esc(p.id)}">
          <div class="avatar" style="--c:${missing ? 'var(--danger)' : '#7b5cff'}">${esc(initials(p.name))}</div>
          <div class="meta"><div class="title">${esc(p.name)}</div><div class="sub">${missing ? 'No password saved' : esc(p.username || p.url || '')}</div></div>
          <div class="actions">
            ${p.username ? `<button class="icon-btn" data-act="copy-user" data-id="${esc(p.id)}" title="Copy username">${icon.user}</button>` : ''}
            ${missing ? '' : `<button class="icon-btn" data-act="copy-pass" data-id="${esc(p.id)}" title="Copy password">${icon.copy}</button>`}
          </div></div>`;
        })
        .join('')}</div>`
    : `<div class="empty"><p>No passwords match “${esc(q)}”.</p></div>`;
}

const CLEAR_AFTER = 30;

async function copyPassword(id) {
  try {
    const pw = await api.revealPassword(id);
    await writeText(pw);
    toast(`Password copied. The clipboard clears in ${CLEAR_AFTER} s.`, 'ok');
    setTimeout(async () => {
      try {
        if ((await readText()) === pw) await writeText('');
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

function viewTransfer() {
  const d = app.data();
  return `<div class="toolbar"><h1>Import &amp; Export</h1></div>
    <div class="panel"><h2>${icon.download.replace('<svg', '<svg style="width:15px;height:15px;vertical-align:-2px"')} Export</h2>
      <p>Save your ${d.hosts.length} hosts, ${d.groups.length} groups, ${d.keys.length} keys, ${d.passwords.length} passwords and ${d.snippets.length} snippets to one file you can carry to another computer.</p>
      <label class="check"><input type="checkbox" id="exp-secrets"><span>Include saved passwords and private keys
        <small>They're encrypted inside the file with a passphrase you choose. Without this, the other computer will ask for passwords and you'll need to re-add keys.</small></span></label>
      <div id="exp-pass" hidden style="max-width:420px">
        <label class="field"><span>Export passphrase</span><input type="password" id="exp-p1" autocomplete="new-password"></label>
        <label class="field"><span>Repeat passphrase</span><input type="password" id="exp-p2" autocomplete="new-password"></label>
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
  form.addEventListener('input', () => {
    clearTimeout(t);
    t = setTimeout(async () => {
      const f = new FormData(form);
      const num = (k, lo, hi, dflt) => Math.min(hi, Math.max(lo, parseInt(f.get(k), 10) || dflt));
      const s = {
        ...app.settings(),
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
  if (e.target.id === 'pw-search') {
    app.pwSearch = e.target.value;
    renderPasswordList();
  }
  if (e.target.id === 'search') {
    app.search = e.target.value;
    renderResults();
  }
  if (e.target.id === 'exp-secrets') $('#exp-pass').hidden = !e.target.checked;
});
content.addEventListener('change', (e) => {
  if (e.target.id === 'exp-secrets') $('#exp-pass').hidden = !e.target.checked;
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
  const [, user, addr, port] = quick;
  const address = addr.replace(/^\[|\]$/g, '');
  const existing = app.data().hosts.find((h) => h.address === address && (!user || h.username === user) && (!port || h.port === +port));
  if (existing) return app.connect(existing.id);
  const host = { id: uid(), label: address, protocol: 'ssh', address, username: user || null, port: port ? +port : null, useAgent: true, tags: [] };
  if (await run(() => api.saveHost(host, null))) {
    app.search = '';
    renderContent();
    app.connect(host.id);
  }
});

content.addEventListener('click', async (e) => {
  const actEl = e.target.closest('[data-act]');
  if (actEl) {
    e.stopPropagation();
    return onAction(actEl.dataset.act, actEl.dataset.id);
  }
  const card = e.target.closest('.card');
  if (!card) return;
  if (card.dataset.host) app.connect(card.dataset.host);
  else if (card.dataset.group) { app.groupId = card.dataset.group; app.search = ''; renderContent(); }
  else if (card.dataset.key) openDrawer('key', card.dataset.key);
  else if (card.dataset.snippet) openDrawer('snippet', card.dataset.snippet);
  else if (card.dataset.password) openDrawer('password', card.dataset.password);
});

content.addEventListener('contextmenu', (e) => {
  const card = e.target.closest('.card');
  if (!card) return;
  e.preventDefault();
  if (card.dataset.host) {
    const id = card.dataset.host;
    contextMenu(e.clientX, e.clientY, [
      { label: 'Connect', icon: icon.play, action: () => app.connect(id) },
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

async function onAction(act, id) {
  switch (act) {
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
  const withSecrets = $('#exp-secrets').checked;
  let pass = null;
  if (withSecrets) {
    pass = $('#exp-p1').value;
    if (pass.length < 8) return toast('Use a passphrase of at least 8 characters', 'error');
    if (pass !== $('#exp-p2').value) return toast('The two passphrases don’t match', 'error');
  }
  const date = new Date().toISOString().slice(0, 10);
  const path = await saveDialog({ defaultPath: `nimbus-export-${date}.json`, filters: [{ name: 'Nimbus export', extensions: ['json'] }] });
  if (!path) return;
  if (await run(() => api.exportData(path, pass))) {
    toast(withSecrets ? 'Exported, with passwords and keys encrypted' : 'Exported (without passwords or keys)', 'ok');
  }
}

async function doImport() {
  const path = await openDialog({ multiple: false, filters: [{ name: 'Nimbus export', extensions: ['json'] }] });
  if (!path) return;
  let p;
  try {
    p = await api.importPreview(path);
  } catch (e) {
    return toast(String(e), 'error');
  }
  const r = await modal({
    title: 'Import hosts',
    html: `<p>This file was exported ${esc(new Date(p.exportedAt).toLocaleString())} and contains
        <strong>${p.hosts}</strong> hosts, <strong>${p.groups}</strong> groups, <strong>${p.keys}</strong> keys,
        <strong>${p.passwords}</strong> passwords, <strong>${p.snippets}</strong> snippets and <strong>${p.knownHosts}</strong> trusted host keys.</p>
      <div class="radio-cards">
        <label><input type="radio" name="mode" value="merge" checked><span>Merge<small>Add what's new and update anything imported before. Nothing is removed.</small></span></label>
        <label><input type="radio" name="mode" value="replace"><span>Replace everything<small>Your current hosts, groups, keys, passwords and snippets are replaced by the file.</small></span></label>
      </div>
      ${p.hasSecrets
        ? `<label class="field"><span>Passphrase for passwords and keys</span><input type="password" name="pass" autofocus placeholder="Leave empty to import without them"></label>`
        : '<p class="hint">This file has no passwords or private keys in it.</p>'}`,
    buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Import', value: 'ok', kind: 'primary', submit: true }],
  });
  if (r.action !== 'ok') return;
  if (r.values.mode === 'replace' && !(await confirmDialog('Replace everything?', 'Your current hosts, groups, keys and snippets will be replaced. Consider exporting them first.', 'Replace'))) return;
  const ok = await run(() => api.importApply(path, r.values.mode, r.values.pass || null));
  if (ok) {
    toast(`Imported ${p.hosts} hosts${p.hasSecrets && !r.values.pass ? ' (without passwords or keys)' : ''}`, 'ok');
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
  drawer.innerHTML = { host: hostForm, group: groupForm, key: keyForm, snippet: snippetForm, password: passwordForm }[kind](id);
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
  const h = (id && app.host(id)) || { groupId: app.groupId, useAgent: true, tags: [] };
  const d = app.data();
  const g = h.groupId && app.group(h.groupId);
  const hasPw = id && app.flags(id).password;
  return drawerShell(
    id ? 'Edit host' : 'New host',
    `<div class="fieldset"><div class="legend">Address</div>
      <label class="field"><span>Label</span><input name="label" value="${esc(h.label)}" placeholder="e.g. Web server" autofocus></label>
      <div class="field-row"><label class="field"><span>Hostname or IP</span><input name="address" value="${esc(h.address)}" placeholder="server.example.com" spellcheck="false"></label>
      <label class="field"><span>Port</span><input type="number" name="port" min="1" max="65535" value="${h.port ?? ''}" placeholder="${g?.port || 22}"></label></div>
      <label class="field"><span>Group</span><select name="groupId">${opt('', 'No group', !h.groupId)}${[...d.groups].sort(byName).map((x) => opt(x.id, x.name, x.id === h.groupId)).join('')}</select></label>
    </div>
    <div class="fieldset"><div class="legend">Login</div>
      <label class="field"><span>Username</span><input name="username" value="${esc(h.username || '')}" placeholder="${esc(g?.username || 'Ask when connecting')}" spellcheck="false"></label>
      <label class="field"><span>Password</span><input type="password" name="password" placeholder="${hasPw ? '•••••••• saved — type to change' : 'Optional — asked when needed'}" autocomplete="new-password"></label>
      ${hasPw ? `<label class="check"><input type="checkbox" name="clearPassword"><span>Forget saved password</span></label>` : ''}
      <label class="field"><span>Key</span><select name="keyId">${opt('', g?.keyId ? `From group (${app.key(g.keyId)?.label || 'key'})` : 'None', !h.keyId)}${[...d.keys].sort(byName).map((k) => opt(k.id, k.label, k.id === h.keyId)).join('')}</select></label>
      <label class="check"><input type="checkbox" name="useAgent" ${h.useAgent !== false ? 'checked' : ''}><span>Try keys from my SSH agent<small>ssh-agent, 1Password, Secretive, Pageant…</small></span></label>
    </div>
    <div class="fieldset"><div class="legend">Jump host</div>
      <label class="field"><select name="jumpHostId">${opt('', 'Connect directly', !h.jumpHostId)}${d.hosts.filter((x) => x.id !== id).sort(byName).map((x) => opt(x.id, `Via ${x.label}`, x.id === h.jumpHostId)).join('')}</select></label>
    </div>
    <div class="fieldset"><div class="legend">Appearance</div>${swatches('color', h.color)}</div>
    <div class="fieldset"><div class="legend">Notes</div>
      <label class="field"><span>Tags (comma separated)</span><input name="tags" value="${esc((h.tags || []).join(', '))}" placeholder="prod, web"></label>
      <label class="field"><textarea class="short" name="notes" placeholder="Anything worth remembering">${esc(h.notes || '')}</textarea></label>
    </div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
     <button type="button" class="btn" data-dact="save-connect">${icon.play} Connect</button>
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
  const p = (id && app.password(id)) || {};
  const saved = id && app.flags(id).password;
  return drawerShell(
    id ? 'Edit password' : 'New password',
    `<div class="fieldset">
      <label class="field"><span>Name</span><input name="name" value="${esc(p.name)}" placeholder="e.g. Ubuntu sudo, Router admin" autofocus></label>
      <label class="field"><span>Username</span><input name="username" value="${esc(p.username || '')}" spellcheck="false"></label>
      <label class="field"><span>Password</span><input type="password" name="password" placeholder="${saved ? '•••••••• saved — type to change' : ''}" autocomplete="new-password" spellcheck="false"></label>
      <div class="inline-actions" style="margin:-4px 0 12px">
        ${saved ? `<button type="button" class="btn small" data-dact="pw-show">${icon.eye} Show</button>
          <button type="button" class="btn small" data-dact="pw-copy">${icon.copy} Copy</button>` : ''}
        <button type="button" class="btn small" data-dact="pw-gen">${icon.dice} Generate</button>
      </div>
      <label class="field"><span>Website or address</span><input name="url" value="${esc(p.url || '')}" spellcheck="false"></label>
      <label class="field"><span>Notes</span><textarea class="short" name="notes">${esc(p.notes || '')}</textarea></label>
      ${p.updated ? `<p class="hint">Last changed ${esc(timeAgo(p.updated))}</p>` : ''}
    </div>`,
    `${id ? `<button type="button" class="btn danger" data-dact="delete">${icon.trash}</button>` : ''}<div class="spacer"></div>
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
  const val = (n) => form.elements[n]?.value?.trim() ?? '';
  const checked = (n) => !!form.elements[n]?.checked;
  const num = (n) => (val(n) ? Math.min(65535, Math.max(1, parseInt(val(n), 10))) || null : null);

  async function save(connectAfter = false) {
    if (kind === 'host') {
      if (!val('address')) return toast('Enter a hostname or IP address', 'error');
      const prev = (id && app.host(id)) || {};
      const host = {
        ...prev,
        id: id || uid(),
        protocol: prev.protocol || 'ssh',
        label: val('label'),
        address: val('address'),
        port: num('port'),
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
      const entry = { ...prev, id: id || uid(), name: val('name'), username: val('username') || null, url: val('url') || null, notes: form.elements.notes.value.trim() || null, updated: 0 };
      const pw = form.elements.password.value;
      if (!id && !pw) return toast('Enter or generate a password', 'error');
      if (await run(() => api.savePassword(entry, pw || null), 'Password saved')) closeDrawer();
    } else if (kind === 'snippet') {
      if (!val('command')) return toast('Enter a command', 'error');
      const snippet = { id: id || uid(), name: val('name'), command: form.elements.command.value.replace(/\s+$/, ''), run: checked('run') };
      if (await run(() => api.saveSnippet(snippet), 'Snippet saved')) closeDrawer();
    }
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

// ---------- shortcuts ----------
function shortcutFor(e) {
  const mod = isMac ? e.metaKey && !e.ctrlKey && !e.altKey : e.ctrlKey && e.shiftKey && !e.altKey;
  if (e.ctrlKey && e.key === 'Tab') return e.shiftKey ? 'prev-tab' : 'next-tab';
  if (!mod) return null;
  if (e.code === 'KeyT') return 'new-tab';
  if (e.code === 'KeyW') return 'close-tab';
  if (e.code === 'KeyD') return 'duplicate-tab';
  if (e.code === 'KeyP' && e.shiftKey) return 'type-password';
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
    app.active?.quickTypePassword();
  } else if (name === 'duplicate-tab') {
    if (app.active) app.connect(app.active.hostId);
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

// Don't let the webview's own context menu appear outside text fields.
document.addEventListener('contextmenu', (e) => {
  if (!e.target.closest('input, textarea, .selectable, .xterm')) e.preventDefault();
});

// ---------- boot ----------
(async () => {
  try {
    setSnap(await api.state());
    renderTabs();
  } catch (e) {
    document.body.innerHTML = `<div class="empty"><h2>Nimbus couldn't start</h2><p class="selectable">${esc(String(e))}</p></div>`;
  }
})();

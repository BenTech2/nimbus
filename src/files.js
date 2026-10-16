// One Files tab: this computer on the left, the server (SFTP or FTP/FTPS) on the right.
// Drag between the panes, double-click a file, or use the arrow buttons to copy.
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import { api } from './api.js';
import { confirmDialog, contextMenu, esc, icon, modal, toast, uid } from './ui.js';
import { hostKeyPrompt, kbdPrompt, secretPrompt, textPrompt } from './prompts.js';

const isMac = navigator.userAgent.includes('Mac');

export function protocolLabel(host) {
  return host?.protocol === 'ftp' ? 'FTP' : host?.protocol === 'ftps' ? 'FTPS' : 'SFTP';
}

function fmtSize(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

function fmtDate(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', ...(sameYear ? {} : { year: 'numeric' }) }) +
    (sameYear ? ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '');
}

/** One side of the browser. `sid` is "local" or the tab's remote session id. */
class Pane {
  constructor(tab, side) {
    this.tab = tab;
    this.side = side;
    this.path = null;
    this.parent = null;
    this.entries = [];
    this.selected = new Set();
    this.anchor = null;
    this.sort = { key: 'name', dir: 1 };
    this.showHidden = false;
    this.error = null;
    this.loading = false;
    this.el = tab.el.querySelector(`.fpane[data-side=${side}]`);
    this.listEl = this.el.querySelector('.flist');
    this.pathEl = this.el.querySelector('.fpath');
  }

  get sid() { return this.side === 'local' ? 'local' : this.tab.sid; }
  get other() { return this.side === 'local' ? this.tab.remote : this.tab.local; }

  async load(path = this.path ?? '', { keepSelection = false } = {}) {
    if (this.side === 'remote' && this.tab.state !== 'connected') return;
    this.loading = true;
    this.renderList();
    try {
      const l = await api.fsList(this.sid, path);
      this.path = l.path;
      this.parent = l.parent;
      this.entries = l.entries;
      this.error = null;
      if (!keepSelection) { this.selected.clear(); this.anchor = null; }
      else for (const p of [...this.selected]) if (!this.entries.some((e) => e.path === p)) this.selected.delete(p);
    } catch (e) {
      this.error = String(e);
      if (this.side === 'remote' && /not connected/i.test(this.error)) this.tab.setState('error', 'The connection was closed.');
    } finally {
      this.loading = false;
    }
    this.render();
  }

  visible() {
    const list = this.showHidden ? this.entries : this.entries.filter((e) => !e.name.startsWith('.'));
    const { key, dir } = this.sort;
    return [...list].sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      if (key === 'size' && a.size !== b.size) return (a.size - b.size) * dir;
      if (key === 'modified' && a.modified !== b.modified) return ((a.modified || 0) - (b.modified || 0)) * dir;
      return a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' }) * (key === 'name' ? dir : 1);
    });
  }

  selection() { return this.entries.filter((e) => this.selected.has(e.path)); }

  render() {
    if (document.activeElement !== this.pathEl) this.pathEl.value = this.path ?? '';
    this.el.querySelector('[data-pact=up]').disabled = this.parent == null;
    this.el.querySelector('[data-pact=hidden]').classList.toggle('on', this.showHidden);
    this.renderList();
    this.tab.renderButtons();
  }

  renderList() {
    if (this.loading && !this.entries.length) {
      this.listEl.innerHTML = '<div class="fempty"><div class="spinner"></div></div>';
      return;
    }
    if (this.error) {
      this.listEl.innerHTML = `<div class="fempty"><p class="selectable">${esc(this.error)}</p>
        <button class="btn small" data-pact="refresh">${icon.refresh} Try again</button></div>`;
      return;
    }
    const rows = this.visible();
    const arrow = (k) => (this.sort.key === k ? `<span class="sort">${this.sort.dir > 0 ? '▲' : '▼'}</span>` : '');
    this.listEl.innerHTML = `<div class="frow fhead"><span data-sort="name">Name${arrow('name')}</span><span data-sort="size">Size${arrow('size')}</span><span data-sort="modified">Modified${arrow('modified')}</span></div>` +
      (rows.length
        ? rows.map((e) => `<div class="frow ${e.isDir ? 'dir' : ''} ${this.selected.has(e.path) ? 'sel' : ''}" data-path="${esc(e.path)}" title="${esc(e.name)}">
            <span class="fname">${e.isDir ? icon.folder : icon.file}<span class="n">${esc(e.name)}</span>${e.isLink ? '<span class="link">↗</span>' : ''}</span>
            <span class="fsize">${e.isDir ? '' : fmtSize(e.size)}</span><span class="fdate">${fmtDate(e.modified)}</span></div>`).join('')
        : `<div class="fempty"><p>${this.entries.length ? 'Only hidden files here.' : 'This folder is empty.'}</p></div>`);
  }

  entryAt(target) {
    const row = target.closest('.frow[data-path]');
    return row ? this.entries.find((e) => e.path === row.dataset.path) : null;
  }

  click(e, entry) {
    if (!entry) { this.selected.clear(); this.anchor = null; return this.render(); }
    const multi = isMac ? e.metaKey : e.ctrlKey;
    if (e.shiftKey && this.anchor) {
      const rows = this.visible().map((x) => x.path);
      const [a, b] = [rows.indexOf(this.anchor), rows.indexOf(entry.path)].sort((x, y) => x - y);
      if (!multi) this.selected.clear();
      rows.slice(a, b + 1).forEach((p) => this.selected.add(p));
    } else if (multi) {
      this.selected.has(entry.path) ? this.selected.delete(entry.path) : this.selected.add(entry.path);
      this.anchor = entry.path;
    } else {
      this.selected = new Set([entry.path]);
      this.anchor = entry.path;
    }
    this.render();
  }

  open(entry) {
    if (entry.isDir || entry.isLink) return this.load(entry.path).then(() => {
      // A link that turned out to be a file can't be opened as a folder.
      if (this.error && entry.isLink && !entry.isDir) { this.error = null; this.load(this.parent ?? ''); this.tab.copy(this, [entry]); }
    });
    return this.tab.copy(this, [entry]);
  }

  async newFolder() {
    const r = await textPrompt({ title: 'New folder', message: `Create a folder in ${this.path || 'this folder'}`, value: '' });
    if (!r?.value?.trim()) return;
    try {
      await api.fsMkdir(this.sid, this.path, r.value.trim());
      await this.load(this.path);
    } catch (e) { toast(String(e), 'error'); }
  }

  async rename(entry) {
    const r = await textPrompt({ title: 'Rename', message: `New name for “${entry.name}”`, value: entry.name, selectStem: !entry.isDir });
    const to = r?.value?.trim();
    if (!to || to === entry.name) return;
    try {
      await api.fsRename(this.sid, this.path, entry.name, to);
      await this.load(this.path);
    } catch (e) { toast(String(e), 'error'); }
  }

  async remove(items) {
    if (!items.length) return;
    const what = items.length === 1 ? `<strong>${esc(items[0].name)}</strong>` : `<strong>${items.length} items</strong>`;
    const ok = this.side === 'local'
      ? await confirmDialog('Move to Trash?', `${what} will be moved to the ${isMac ? 'Trash' : 'Recycle Bin'}.`, 'Move to Trash')
      : await confirmDialog('Delete from the server?', `${what} will be permanently deleted from the server${items.some((i) => i.isDir) ? ', including everything inside' : ''}. This can't be undone.`);
    if (!ok) return;
    try {
      await api.fsDelete(this.sid, items.map((i) => ({ path: i.path, isDir: i.isDir })));
    } catch (e) { toast(String(e), 'error'); }
    await this.load(this.path, { keepSelection: true });
  }

  menu(e, entry) {
    if (entry && !this.selected.has(entry.path)) { this.selected = new Set([entry.path]); this.anchor = entry.path; this.render(); }
    const sel = this.selection();
    const toOther = this.side === 'local' ? 'Upload' : 'Download';
    const items = [];
    if (entry) {
      if (entry.isDir && sel.length === 1) items.push({ label: 'Open', icon: icon.folder, action: () => this.open(entry) });
      items.push({ label: `${toOther}${sel.length > 1 ? ` ${sel.length} items` : ''}`, icon: this.side === 'local' ? icon.upload : icon.download, action: () => this.tab.copy(this, sel) });
      if (sel.length === 1) items.push({ label: 'Rename…', icon: icon.edit, action: () => this.rename(entry) });
      items.push({ label: 'Copy path', icon: icon.copy, action: () => writeText(sel.map((x) => x.path).join('\n')).then(() => toast('Path copied', 'ok')) });
      items.push('sep', { label: this.side === 'local' ? 'Move to Trash' : 'Delete', icon: icon.trash, danger: true, action: () => this.remove(sel) });
    } else {
      items.push({ label: 'New folder…', icon: icon.folder, action: () => this.newFolder() }, { label: 'Refresh', icon: icon.refresh, action: () => this.load() });
    }
    contextMenu(e.clientX, e.clientY, items);
  }
}

export class FileSession {
  constructor(app, host) {
    this.app = app;
    this.kind = 'files';
    this.id = uid();
    this.hostId = host.id;
    this.label = host.label || host.address;
    this.state = 'idle';
    this.transfers = new Map();

    const remoteName = esc(this.label);
    const paneHtml = (side, title) => `<div class="fpane" data-side="${side}">
        <div class="fpane-head"><div class="ftitle">${side === 'local' ? icon.server : icon.cloud}<span>${title}</span>${side === 'remote' ? `<span class="badge">${protocolLabel(host)}</span>` : ''}</div>
          <div class="spacer"></div>
          ${side === 'remote' ? `<button class="btn small ftx" data-pact="send" title="Download the selection to this computer">${icon.download} Download</button>` : `<button class="btn small ftx" data-pact="send" title="Upload the selection to the server">${icon.upload} Upload</button>`}
          <button class="icon-btn" data-pact="hidden" title="Show hidden files">${icon.eye}</button>
          <button class="icon-btn" data-pact="mkdir" title="New folder">${icon.plus}</button>
          <button class="icon-btn" data-pact="refresh" title="Refresh">${icon.refresh}</button></div>
        <div class="fpath-row"><button class="icon-btn" data-pact="up" title="Up one folder">${icon.chevron}</button>
          <input class="fpath" spellcheck="false" autocomplete="off" title="Type a path and press Enter"></div>
        <div class="flist" tabindex="0"></div>
        ${side === 'remote' ? '<div class="fstatus" hidden></div>' : ''}
      </div>`;
    this.el = document.createElement('div');
    this.el.className = 'files-tab';
    this.el.hidden = true;
    this.el.innerHTML = `<div class="files-split">${paneHtml('local', 'This computer')}${paneHtml('remote', remoteName)}</div><div class="xfers" hidden></div>`;
    document.getElementById('terminals').appendChild(this.el);
    this.statusEl = this.el.querySelector('.fstatus');
    this.xfersEl = this.el.querySelector('.xfers');
    this.local = new Pane(this, 'local');
    this.remote = new Pane(this, 'remote');
    this.panes = [this.local, this.remote];
    this.wire();
    this.local.load('');
  }

  // ---------- connection ----------
  connect() {
    if (this.sid) api.fsClose(this.sid);
    this.sid = uid();
    const sid = this.sid;
    this.setState('connecting', 'Starting…');
    api.fsOpen(sid, this.hostId, (ev) => { if (sid === this.sid) this.onEvent(ev); }).catch((e) => this.setState('error', String(e)));
  }

  onEvent(ev) {
    if (ev.type === 'status') {
      this.setState(ev.state, ev.message);
      if (ev.state === 'connected') this.remote.load(this.remote.path ?? ev.home ?? '');
    } else if (ev.type === 'prompt') this.handlePrompt(ev);
    else if (ev.type === 'transfer') this.onTransfer(ev);
  }

  async handlePrompt({ id, kind, data }) {
    this.app.activate(this);
    const ctl = (this.promptCtl = {});
    let value = null;
    if (kind === 'hostkey') value = { accept: await hostKeyPrompt(data, ctl) };
    else if (kind === 'password' || kind === 'passphrase') value = await secretPrompt(kind, data, ctl);
    else if (kind === 'text') value = await textPrompt(data, ctl);
    else if (kind === 'kbdint') value = await kbdPrompt(data, ctl);
    if (this.promptCtl === ctl) this.promptCtl = null;
    await api.promptReply(id, value);
  }

  setState(state, message = '') {
    this.state = state;
    const host = this.app.host(this.hostId);
    const name = esc(host ? host.label || host.address : this.label);
    const busy = state === 'connecting' || state === 'authenticating';
    const ended = state === 'error' || state === 'closed';
    this.statusEl.hidden = !(busy || ended);
    if (busy) this.statusEl.innerHTML = `<div class="box"><div class="spinner"></div><div class="host">${name}</div><div class="msg">${esc(message)}</div></div>`;
    else if (ended) {
      this.statusEl.innerHTML = `<div class="box"><div class="host">${state === 'error' ? 'Couldn’t connect' : 'Disconnected'}</div><p class="msg selectable">${esc(message)}</p>
        <div class="row"><button class="btn primary" data-pact="reconnect">${icon.refresh} ${state === 'error' ? 'Try again' : 'Reconnect'}</button>
        <button class="btn" data-pact="edit">${icon.edit} Edit host</button></div></div>`;
      this.promptCtl?.cancel?.();
    }
    this.renderButtons();
    this.app.sessionChanged(this);
  }

  // ---------- copying ----------
  /** Copy entries from `from` into the other pane's folder (or `destDir`). */
  async copy(from, entries, destDir) {
    if (!entries.length) return;
    if (this.state !== 'connected') return toast('Not connected to the server', 'error');
    const to = from.other;
    const dest = destDir ?? to.path;
    if (dest == null || dest === '') return toast('Open a folder on the other side first', 'error');
    const upload = from.side === 'local';
    let items = entries.map((e) => ({ path: e.path, isDir: e.isDir, name: e.name }));
    // Ask before replacing anything that already exists there.
    try {
      const existing = dest === to.path ? to.entries : (await api.fsList(to.sid, dest)).entries;
      const names = new Set(existing.map((e) => e.name));
      const clash = items.filter((i) => names.has(i.name));
      if (clash.length) {
        const r = await modal({
          title: clash.length === 1 ? `Replace “${clash[0].name}”?` : `Replace ${clash.length} items?`,
          html: `<p>${clash.length === 1 ? 'An item with that name' : 'Items with these names'} already exist${clash.length === 1 ? 's' : ''} in <code>${esc(dest)}</code>.
            ${clash.length > 1 ? `<br><span class="hint">${clash.slice(0, 6).map((c) => esc(c.name)).join(', ')}${clash.length > 6 ? '…' : ''}</span>` : ''}</p>
            <p class="hint">Replacing a folder copies into it and overwrites files with the same names.</p>`,
          buttons: [{ label: 'Cancel', value: 'cancel' }, ...(items.length > clash.length ? [{ label: 'Skip those', value: 'skip' }] : []), { label: 'Replace', value: 'replace', kind: 'primary', submit: true }],
        });
        if (r.action === 'cancel') return;
        if (r.action === 'skip') items = items.filter((i) => !names.has(i.name));
      }
    } catch { /* destination unreadable: let the transfer report it */ }
    if (!items.length) return;
    const id = uid();
    const label = items.length === 1 ? items[0].name : `${items[0].name} and ${items.length - 1} more`;
    this.transfers.set(id, { id, upload, label, state: 'queued', done: 0, total: 0, files: 0, count: 0, dest });
    this.renderTransfers();
    try {
      await api.fsTransfer(this.sid, id, upload, items.map(({ path, isDir }) => ({ path, isDir })), dest);
    } catch (e) {
      Object.assign(this.transfers.get(id), { state: 'error', message: String(e) });
      this.renderTransfers();
    }
  }

  onTransfer(ev) {
    const t = this.transfers.get(ev.id);
    if (!t) return;
    Object.assign(t, ev, { label: ev.label || t.label });
    this.renderTransfers();
    if (ev.state === 'done' || ev.state === 'error' || ev.state === 'cancelled') {
      for (const p of this.panes) if (p.path === t.dest) p.load(p.path, { keepSelection: true });
      if (ev.state === 'done') setTimeout(() => { if (this.transfers.get(ev.id)?.state === 'done') { this.transfers.delete(ev.id); this.renderTransfers(); } }, 6000);
    }
  }

  renderTransfers() {
    const list = [...this.transfers.values()];
    this.xfersEl.hidden = !list.length;
    this.xfersEl.innerHTML = list.map((t) => {
      const pct = t.total ? Math.min(100, Math.round((t.done / t.total) * 100)) : t.state === 'done' ? 100 : 0;
      const status = {
        queued: 'Waiting…',
        running: `${t.count > 1 ? `${t.files} of ${t.count} files · ` : ''}${fmtSize(t.done)}${t.total ? ` of ${fmtSize(t.total)}` : ''}`,
        done: `Done${t.files > 1 ? ` · ${t.files} files` : ''}`,
        cancelled: 'Cancelled',
        error: esc(t.message || 'Failed'),
      }[t.state];
      const live = t.state === 'queued' || t.state === 'running';
      return `<div class="xfer ${t.state}"><span class="dir">${t.upload ? icon.upload : icon.download}</span>
        <div class="xmain"><div class="xlabel"><span class="n">${esc(t.label)}</span><span class="xstat selectable">${status}</span></div>
        <div class="bar"><div style="width:${pct}%"></div></div></div>
        <button class="icon-btn" data-xact="${live ? 'cancel' : 'clear'}" data-id="${esc(t.id)}" title="${live ? 'Cancel' : 'Remove from list'}">${icon.x}</button></div>`;
    }).join('');
  }

  renderButtons() {
    const connected = this.state === 'connected';
    this.local.el.querySelector('[data-pact=send]').disabled = !connected || !this.local.selected.size;
    this.remote.el.querySelector('[data-pact=send]').disabled = !connected || !this.remote.selected.size;
  }

  // ---------- events ----------
  wire() {
    for (const pane of this.panes) {
      const el = pane.el;
      el.addEventListener('click', (e) => {
        const act = e.target.closest('[data-pact]')?.dataset.pact;
        if (act) return this.paneAction(pane, act);
        const sort = e.target.closest('[data-sort]')?.dataset.sort;
        if (sort) {
          pane.sort = { key: sort, dir: pane.sort.key === sort ? -pane.sort.dir : 1 };
          return pane.renderList();
        }
        if (e.target.closest('.flist')) {
          if (this.dragged) return;
          pane.click(e, pane.entryAt(e.target));
        }
      });
      el.addEventListener('dblclick', (e) => {
        const entry = pane.entryAt(e.target);
        if (entry) pane.open(entry);
      });
      el.addEventListener('contextmenu', (e) => {
        if (!e.target.closest('.flist')) return;
        e.preventDefault();
        pane.menu(e, pane.entryAt(e.target));
      });
      pane.pathEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); pane.load(pane.pathEl.value.trim()); pane.listEl.focus(); }
        if (e.key === 'Escape') { pane.pathEl.value = pane.path ?? ''; pane.listEl.focus(); }
      });
      pane.pathEl.addEventListener('blur', () => { pane.pathEl.value = pane.path ?? ''; });
      pane.listEl.addEventListener('keydown', (e) => this.onKey(pane, e));
      pane.listEl.addEventListener('mousedown', (e) => this.dragStart(pane, e));
    }
    this.xfersEl.addEventListener('click', (e) => {
      const b = e.target.closest('[data-xact]');
      if (!b) return;
      if (b.dataset.xact === 'cancel') api.fsCancel(this.sid, b.dataset.id);
      else { this.transfers.delete(b.dataset.id); this.renderTransfers(); }
    });
  }

  paneAction(pane, act) {
    if (act === 'up' && pane.parent != null) pane.load(pane.parent);
    else if (act === 'refresh') pane.load(pane.path ?? '', { keepSelection: true });
    else if (act === 'mkdir') pane.newFolder();
    else if (act === 'hidden') { pane.showHidden = !pane.showHidden; pane.render(); }
    else if (act === 'send') this.copy(pane, pane.selection());
    else if (act === 'reconnect') this.connect();
    else if (act === 'edit') this.app.editHost(this.hostId);
  }

  onKey(pane, e) {
    const sel = pane.selection();
    const mod = isMac ? e.metaKey : e.ctrlKey;
    if (e.key === 'Enter' && sel.length === 1) { e.preventDefault(); pane.open(sel[0]); }
    else if ((e.key === 'Delete' || (isMac && e.key === 'Backspace' && e.metaKey)) && sel.length) { e.preventDefault(); pane.remove(sel); }
    else if (e.key === 'Backspace' && !mod && pane.parent != null) { e.preventDefault(); pane.load(pane.parent); }
    else if (e.key === 'F2' && sel.length === 1) { e.preventDefault(); pane.rename(sel[0]); }
    else if (mod && e.key.toLowerCase() === 'a') { e.preventDefault(); pane.visible().forEach((x) => pane.selected.add(x.path)); pane.render(); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const rows = pane.visible();
      if (!rows.length) return;
      let i = rows.findIndex((x) => x.path === pane.anchor);
      i = i < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)));
      pane.selected = new Set([rows[i].path]);
      pane.anchor = rows[i].path;
      pane.render();
      pane.listEl.querySelector('.frow.sel')?.scrollIntoView({ block: 'nearest' });
    }
  }

  /** Drag rows to the other pane (or onto a folder in it). Pointer-based, so it works on every OS. */
  dragStart(pane, e) {
    if (e.button !== 0) return;
    const entry = pane.entryAt(e.target);
    if (!entry) return;
    const start = { x: e.clientX, y: e.clientY };
    let ghost = null;
    let target = null;
    this.dragged = false;
    const move = (m) => {
      if (!ghost) {
        if (Math.hypot(m.clientX - start.x, m.clientY - start.y) < 6) return;
        if (!pane.selected.has(entry.path)) { pane.selected = new Set([entry.path]); pane.anchor = entry.path; pane.render(); }
        const n = pane.selected.size;
        ghost = document.createElement('div');
        ghost.className = 'drag-ghost';
        ghost.innerHTML = `${entry.isDir ? icon.folder : icon.file}<span>${n > 1 ? `${n} items` : esc(entry.name)}</span>`;
        document.body.appendChild(ghost);
        this.dragged = true;
      }
      ghost.style.left = `${m.clientX + 12}px`;
      ghost.style.top = `${m.clientY + 8}px`;
      document.querySelectorAll('.drop-target').forEach((x) => x.classList.remove('drop-target'));
      target = null;
      const over = document.elementFromPoint(m.clientX, m.clientY);
      const other = pane.other;
      if (over && other.el.contains(over) && this.state === 'connected') {
        const folder = other.entryAt(over);
        target = folder?.isDir ? folder.path : other.path;
        (folder?.isDir ? over.closest('.frow') : other.listEl).classList.add('drop-target');
      }
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up, true);
      document.querySelectorAll('.drop-target').forEach((x) => x.classList.remove('drop-target'));
      ghost?.remove();
      if (ghost && target != null) this.copy(pane, pane.selection(), target);
      setTimeout(() => { this.dragged = false; });
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up, true);
  }

  /** Files dropped from Finder / Explorer / a file manager onto the server pane. */
  dropPaths(paths, x, y) {
    const over = document.elementFromPoint(x, y);
    if (!over || !this.remote.el.contains(over)) return false;
    if (this.state !== 'connected') { toast('Not connected to the server', 'error'); return true; }
    const folder = this.remote.entryAt(over);
    const items = paths.map((p) => ({ path: p, isDir: false, name: p.split(/[\\/]/).pop() }));
    this.copy(this.local, items, folder?.isDir ? folder.path : this.remote.path);
    return true;
  }

  dragHover(x, y) {
    document.querySelectorAll('.drop-target').forEach((el) => el.classList.remove('drop-target'));
    const over = x == null ? null : document.elementFromPoint(x, y);
    if (over && this.remote.el.contains(over) && this.state === 'connected') {
      const folder = this.remote.entryAt(over);
      (folder?.isDir ? over.closest('.frow') : this.remote.listEl).classList.add('drop-target');
    }
  }

  // ---------- tab lifecycle (same shape as TermSession) ----------
  applySettings() {}
  show() { this.el.hidden = false; requestAnimationFrame(() => { if (!this.app.modalOpen()) this.remote.listEl.focus(); }); }
  hide() { this.el.hidden = true; }
  dispose() {
    this.promptCtl?.cancel?.();
    if (this.sid) api.fsClose(this.sid);
    this.sid = null;
    this.el.remove();
  }
}

/** Route OS file drops to whichever Files tab is showing. Call once at startup. */
export function listenForFileDrops(app) {
  let webview;
  try { webview = getCurrentWebview(); } catch { return; /* browser preview */ }
  webview.onDragDropEvent((ev) => {
    const s = app.active;
    if (!s || s.kind !== 'files') return;
    const { type, position, paths } = ev.payload;
    const x = position ? position.x / devicePixelRatio : null;
    const y = position ? position.y / devicePixelRatio : null;
    if (type === 'over' || type === 'enter') s.dragHover(x, y);
    else if (type === 'leave') s.dragHover(null);
    else if (type === 'drop') {
      s.dragHover(null);
      if (paths?.length && !s.dropPaths(paths, x, y)) toast('Drop files onto the server side to upload them', '');
    }
  }).catch(() => {});
}

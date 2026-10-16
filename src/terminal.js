// One terminal tab: an xterm.js view bound to a backend SSH session.
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { openUrl } from '@tauri-apps/plugin-opener';
import { writeText, readText } from '@tauri-apps/plugin-clipboard-manager';
import { api } from './api.js';
import { esc, icon, uid, toast } from './ui.js';
import { hostKeyPrompt, kbdPrompt, secretPrompt, textPrompt } from './prompts.js';

const THEMES = {
  dark: {
    background: '#10121a', foreground: '#e7e9f1', cursor: '#4f8cff', cursorAccent: '#10121a',
    selectionBackground: 'rgba(79, 140, 255, 0.35)',
    black: '#1d2030', red: '#f2555a', green: '#34c77b', yellow: '#f5b041', blue: '#4f8cff', magenta: '#b07bff', cyan: '#2fc6d6', white: '#c9cde0',
    brightBlack: '#5d6380', brightRed: '#ff7b7f', brightGreen: '#5be39a', brightYellow: '#ffd27a', brightBlue: '#7fb0ff', brightMagenta: '#cda4ff', brightCyan: '#6be3ef', brightWhite: '#ffffff',
  },
  // "White" and "bright white" are darkened so text a program prints in white stays readable.
  light: {
    background: '#ffffff', foreground: '#1f2333', cursor: '#2f6fec', cursorAccent: '#ffffff',
    selectionBackground: 'rgba(47, 111, 236, 0.22)',
    black: '#1f2333', red: '#cf2f36', green: '#17834b', yellow: '#9a6700', blue: '#2f6fec', magenta: '#8a3fd1', cyan: '#0b7f8c', white: '#6b7185',
    brightBlack: '#8b91a5', brightRed: '#e5484d', brightGreen: '#1f9d5c', brightYellow: '#b47d00', brightBlue: '#4f8cff', brightMagenta: '#a35ee8', brightCyan: '#1597a8', brightWhite: '#3a4058',
  },
};

export const termTheme = () => THEMES[document.documentElement.dataset.theme === 'light' ? 'light' : 'dark'];

const isMac = navigator.userAgent.includes('Mac');

const toBytes = (d) => (d instanceof ArrayBuffer ? new Uint8Array(d) : Array.isArray(d) ? Uint8Array.from(d) : d);

export class TermSession {
  constructor(app, host) {
    this.app = app;
    this.kind = 'term';
    this.serial = host.protocol === 'serial';
    this.id = uid();
    this.hostId = host.id;
    this.label = host.label || host.address;
    this.state = 'idle';
    this.message = '';
    this.everConnected = false;
    this.pending = '';
    this.inflight = false;

    this.el = document.createElement('div');
    this.el.className = 'term-pane';
    this.el.hidden = true;
    this.el.innerHTML = `
      <div class="term-host">
        <div class="term-tools">
          ${this.serial
            ? `<button class="btn small" data-act="break" title="Send a serial break (for example to reach a router's ROMMON)">${icon.zap} Break</button>`
            : `<button class="btn small" data-act="sftp" title="Browse files on this server (${isMac ? '⌘⇧O' : 'Ctrl+Shift+O'})">${icon.folder} SFTP</button>`}
          <button class="btn small" data-act="passwords" title="Type a saved password (${isMac ? '⌘⇧P' : 'Ctrl+Shift+P'})">${icon.lock} Password</button>
          <button class="btn small" data-act="snippets">${icon.code} Snippets</button></div>
        <div class="term-status" hidden></div>
      </div>
      <div class="term-banner" hidden></div>`;
    document.getElementById('terminals').appendChild(this.el);
    this.hostEl = this.el.querySelector('.term-host');
    this.statusEl = this.el.querySelector('.term-status');
    this.bannerEl = this.el.querySelector('.term-banner');

    const s = app.settings();
    this.term = new Terminal({
      fontFamily: s.fontFamily, fontSize: s.fontSize, cursorStyle: s.cursorStyle, cursorBlink: s.cursorBlink,
      scrollback: s.scrollback, theme: termTheme(), macOptionIsMeta: true, allowProposedApi: true,
      // Many serial devices end lines with a bare LF.
      convertEol: this.serial,
    });
    this.fit = new FitAddon();
    this.term.loadAddon(this.fit);
    this.term.loadAddon(new WebLinksAddon((e, uri) => { if (e.metaKey || e.ctrlKey) openUrl(uri); }));
    this.term.open(this.hostEl);
    this.term.onData((d) => this.onInput(d));
    this.term.onResize(({ cols, rows }) => { if (this.state === 'connected') api.resize(this.sid, cols, rows); });
    this.term.onSelectionChange(() => {
      if (this.app.settings().copyOnSelect && this.term.hasSelection()) writeText(this.term.getSelection());
    });
    this.term.attachCustomKeyEventHandler((e) => this.onKey(e));

    this.ro = new ResizeObserver(() => this.fitNow());
    this.ro.observe(this.hostEl);
    this.el.addEventListener('click', (e) => this.onClick(e));
  }

  connect() {
    if (this.everConnected) this.term.write('\r\n\x1b[90m── reconnecting ──\x1b[0m\r\n');
    this.sid = uid();
    const sid = this.sid;
    this.setState('connecting', 'Starting…');
    this.fitNow();
    api
      .connect(
        sid, this.hostId, this.term.cols, this.term.rows,
        (ev) => { if (sid === this.sid) this.onEvent(ev); },
        (data) => { if (sid === this.sid) this.term.write(toBytes(data)); },
      )
      .catch((e) => this.setState('error', String(e)));
  }

  onEvent(ev) {
    if (ev.type === 'status') {
      this.setState(ev.state, ev.message);
    } else if (ev.type === 'prompt') {
      this.handlePrompt(ev);
    }
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
    if (this.state !== 'closed') this.term.focus();
  }

  setState(state, message = '') {
    this.state = state;
    this.message = message;
    if (state === 'connected') this.everConnected = true;
    const busy = state === 'connecting' || state === 'authenticating';
    const ended = state === 'closed' || state === 'error';
    const host = this.app.host(this.hostId);
    const name = esc(host ? host.label || host.address : this.label);

    // Before the first successful connect there's nothing to look at, so use the full overlay.
    this.statusEl.hidden = !(busy || (ended && !this.everConnected));
    if (busy) {
      this.statusEl.innerHTML = `<div class="box"><div class="spinner"></div><div class="host">${name}</div><div class="msg">${esc(message)}</div></div>`;
    } else if (ended && !this.everConnected) {
      this.statusEl.innerHTML = `<div class="box"><div class="host">${state === 'error' ? 'Couldn’t connect' : 'Disconnected'}</div>
        <p class="msg selectable">${esc(message)}</p>
        <div class="row" style="display:flex;gap:8px;justify-content:center;margin-top:14px">
          <button class="btn primary" data-act="reconnect">${icon.refresh} Try again</button>
          <button class="btn" data-act="edit">${icon.edit} Edit host</button>
          <button class="btn ghost" data-act="close">Close</button></div></div>`;
    }
    this.bannerEl.hidden = !(ended && this.everConnected);
    this.bannerEl.className = `term-banner ${state === 'error' ? 'error' : ''}`;
    if (ended && this.everConnected) {
      this.bannerEl.innerHTML = `<span class="msg">${esc(message || 'Disconnected')} — press Enter to reconnect.</span>
        <button class="btn small primary" data-act="reconnect">${icon.refresh} Reconnect</button>
        <button class="btn small ghost" data-act="close">Close tab</button>`;
    }
    if (ended) this.promptCtl?.cancel?.();
    if (state === 'connected' && !this.el.hidden) this.term.focus();
    requestAnimationFrame(() => this.fitNow());
    this.app.sessionChanged(this);
  }

  onInput(d) {
    if (this.state === 'connected') {
      this.pending += d;
      this.flush();
    } else if ((this.state === 'closed' || this.state === 'error') && d === '\r') {
      this.connect();
    }
  }

  // One write in flight at a time keeps keystrokes in order; extra input batches up meanwhile.
  async flush() {
    if (this.inflight || !this.pending) return;
    const chunk = this.pending;
    this.pending = '';
    this.inflight = true;
    try {
      await api.write(this.sid, chunk);
    } finally {
      this.inflight = false;
      if (this.pending) this.flush();
    }
  }

  send(text) {
    if (this.state !== 'connected') return toast('This session is not connected', 'error');
    this.term.paste(text);
  }

  onKey(e) {
    if (e.type !== 'keydown') return true;
    if (this.app.isAppShortcut(e)) return false;
    // Windows/Linux: Ctrl+Shift+C / V, since plain Ctrl+C belongs to the remote shell.
    if (!isMac && e.ctrlKey && e.shiftKey && (e.code === 'KeyC' || e.code === 'KeyV')) {
      if (e.code === 'KeyC' && this.term.hasSelection()) writeText(this.term.getSelection());
      if (e.code === 'KeyV') readText().then((t) => t && this.term.paste(t)).catch(() => {});
      e.preventDefault();
      return false;
    }
    return true;
  }

  onClick(e) {
    const act = e.target.closest('[data-act]')?.dataset.act;
    if (act === 'reconnect') this.connect();
    else if (act === 'close') this.app.closeSession(this);
    else if (act === 'edit') this.app.editHost(this.hostId);
    else if (act === 'sftp') this.app.openFiles(this.hostId);
    else if (act === 'break') {
      if (this.state === 'connected') api.sendBreak(this.sid);
      else toast('This session is not connected', 'error');
      this.term.focus();
    }
    else if (act === 'snippets' || act === 'passwords') this.togglePop(act);
    else if (act === 'set-host-pw') this.saveHostPassword();
    else if (e.target.closest('.snip-pop [data-snip]')) {
      const s = this.app.snippet(e.target.closest('[data-snip]').dataset.snip);
      this.closePop();
      if (s) this.send(s.command + (s.run ? '\r' : ''));
      this.term.focus();
    } else if (e.target.closest('.snip-pop [data-pw]')) {
      this.typePassword(e.target.closest('[data-pw]').dataset.pw);
    } else if (!e.target.closest('.snip-pop')) this.closePop();
  }

  togglePop(kind) {
    const open = this.el.querySelector('.snip-pop');
    this.closePop();
    if (open?.dataset.kind === kind) return;
    const pop = document.createElement('div');
    pop.className = 'snip-pop';
    pop.dataset.kind = kind;
    pop.innerHTML = kind === 'snippets' ? this.snippetsHtml() : this.passwordsHtml();
    this.hostEl.appendChild(pop);
    this.el.querySelector('.term-tools').classList.add('open');
  }

  closePop() {
    this.el.querySelector('.snip-pop')?.remove();
    this.el.querySelector('.term-tools').classList.remove('open');
  }

  snippetsHtml() {
    const list = this.app.snippets();
    return list.length
      ? list.map((s) => `<button data-snip="${esc(s.id)}"><div>${esc(s.name)}</div><div class="cmd">${esc(s.command)}</div></button>`).join('')
      : `<div class="none">No snippets yet. Add them under Snippets on the Hosts tab.</div>`;
  }

  passwordsHtml() {
    const host = this.app.host(this.hostId);
    const name = esc(host ? host.label || host.address : this.label);
    const enter = this.app.settings().typePasswordEnter ? ' and press Enter' : '';
    const own = this.app.flags(this.hostId).password
      ? `<button data-pw="${esc(this.hostId)}"><div>${icon.lock} ${name} password</div><div class="cmd">Types it${enter} · ${isMac ? '⌘⇧P' : 'Ctrl+Shift+P'}</div></button>`
      : `<button data-act="set-host-pw"><div>${icon.plus} Save a password for ${name}…</div><div class="cmd">Then type it any time with ${isMac ? '⌘⇧P' : 'Ctrl+Shift+P'}</div></button>`;
    const list = this.app.passwords();
    return `<div class="pop-title">This host</div>${own}` +
      (list.length
        ? `<div class="pop-title">Passwords</div>` +
          list.map((p) => `<button data-pw="${esc(p.id)}"><div>${esc(p.name)}</div><div class="cmd">${esc(p.username || '')}</div></button>`).join('')
        : '');
  }

  /** ⌘⇧P: type this host's password straight away if one is saved, otherwise show the choices. */
  quickTypePassword() {
    if (this.app.flags(this.hostId).password) this.typePassword(this.hostId);
    else this.togglePop('passwords');
  }

  async typePassword(secretId) {
    this.closePop();
    if (this.state !== 'connected') return toast('This session is not connected', 'error');
    try {
      await api.typePassword(this.sid, secretId);
    } catch (e) {
      toast(String(e), 'error');
    }
    this.term.focus();
  }

  async saveHostPassword() {
    this.closePop();
    const ok = await this.app.setHostPassword(this.hostId);
    if (ok) this.togglePop('passwords');
    else this.term.focus();
  }

  applySettings(s) {
    Object.assign(this.term.options, {
      fontFamily: s.fontFamily, fontSize: s.fontSize, cursorStyle: s.cursorStyle, cursorBlink: s.cursorBlink, scrollback: s.scrollback,
      theme: termTheme(),
    });
    this.fitNow();
  }

  fitNow() {
    if (this.el.hidden) return;
    try { this.fit.fit(); } catch { /* not laid out yet */ }
  }

  show() {
    this.el.hidden = false;
    requestAnimationFrame(() => { this.fitNow(); if (!this.app.modalOpen()) this.term.focus(); });
  }

  hide() {
    this.el.hidden = true;
    this.closePop();
  }

  dispose() {
    this.promptCtl?.cancel?.();
    if (this.sid) api.close(this.sid);
    this.sid = null;
    this.ro.disconnect();
    this.term.dispose();
    this.el.remove();
  }
}

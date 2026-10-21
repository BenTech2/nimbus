// One remote desktop tab (Remote Desktop or VNC): the remote screen on a canvas, with the
// keyboard and mouse sent back. The backend (src-tauri/src/rdp.rs, vnc.rs, desktop.rs) does the
// protocol and sends changed rectangles of pixels; this draws them, acknowledges each batch, and
// keeps the remote desktop the size of the tab (when the server allows it).
import { getCurrentWindow } from '@tauri-apps/api/window';
import { api } from './api.js';
import { esc, icon, uid, toast } from './ui.js';
import { hostKeyPrompt, secretPrompt, textPrompt } from './prompts.js';

const isMac = navigator.userAgent.includes('Mac');

// KeyboardEvent.code → [scancode, extended]. Scancodes say which key, not which character, so
// the remote desktop's keyboard layout decides what gets typed (as with any RDP client).
const SCANCODES = (() => {
  const m = {};
  const add = (codes, start, ext = false) => codes.split(' ').forEach((c, i) => (m[c] = [start + i, ext]));
  add('Escape Digit1 Digit2 Digit3 Digit4 Digit5 Digit6 Digit7 Digit8 Digit9 Digit0 Minus Equal Backspace Tab', 0x01);
  add('KeyQ KeyW KeyE KeyR KeyT KeyY KeyU KeyI KeyO KeyP BracketLeft BracketRight Enter ControlLeft', 0x10);
  add('KeyA KeyS KeyD KeyF KeyG KeyH KeyJ KeyK KeyL Semicolon Quote Backquote ShiftLeft Backslash', 0x1e);
  add('KeyZ KeyX KeyC KeyV KeyB KeyN KeyM Comma Period Slash ShiftRight NumpadMultiply AltLeft Space CapsLock', 0x2c);
  add('F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 NumLock ScrollLock', 0x3b);
  add('Numpad7 Numpad8 Numpad9 NumpadSubtract Numpad4 Numpad5 Numpad6 NumpadAdd Numpad1 Numpad2 Numpad3 Numpad0 NumpadDecimal', 0x47);
  add('IntlBackslash F11 F12', 0x56);
  add('NumpadEqual', 0x59);
  add('F13 F14 F15 F16 F17 F18 F19 F20 F21 F22 F23', 0x64);
  add('F24', 0x76);
  add('KanaMode', 0x70);
  add('IntlRo', 0x73);
  add('Convert', 0x79);
  add('NonConvert', 0x7b);
  add('IntlYen', 0x7d);
  for (const [c, sc] of Object.entries({
    NumpadEnter: 0x1c, ControlRight: 0x1d, NumpadDivide: 0x35, PrintScreen: 0x37, AltRight: 0x38,
    Home: 0x47, ArrowUp: 0x48, PageUp: 0x49, ArrowLeft: 0x4b, ArrowRight: 0x4d, End: 0x4f, ArrowDown: 0x50,
    PageDown: 0x51, Insert: 0x52, Delete: 0x53, MetaLeft: 0x5b, MetaRight: 0x5c, ContextMenu: 0x5d,
    AudioVolumeMute: 0x20, AudioVolumeDown: 0x2e, AudioVolumeUp: 0x30, MediaPlayPause: 0x22, MediaStop: 0x24,
    MediaTrackPrevious: 0x10, MediaTrackNext: 0x19,
  })) m[c] = [sc, true];
  return m;
})();

// X11 keysyms for keys that don't type a character (VNC sends what a key types, not where it is).
const KEYSYMS = {
  Backspace: 0xff08, Tab: 0xff09, Enter: 0xff0d, NumpadEnter: 0xff8d, Escape: 0xff1b, Delete: 0xffff,
  Home: 0xff50, ArrowLeft: 0xff51, ArrowUp: 0xff52, ArrowRight: 0xff53, ArrowDown: 0xff54, PageUp: 0xff55,
  PageDown: 0xff56, End: 0xff57, Insert: 0xff63, ContextMenu: 0xff67, Pause: 0xff13, ScrollLock: 0xff14,
  PrintScreen: 0xff61, NumLock: 0xff7f, CapsLock: 0xffe5,
  ShiftLeft: 0xffe1, ShiftRight: 0xffe2, ControlLeft: 0xffe3, ControlRight: 0xffe4,
  AltLeft: 0xffe9, AltRight: 0xffea, MetaLeft: 0xffeb, MetaRight: 0xffec,
  ...Object.fromEntries(Array.from({ length: 24 }, (_, i) => [`F${i + 1}`, 0xffbe + i])),
};

/** The keysym for what this key press types. */
function keysym(e, code = e.code) {
  if (KEYSYMS[code]) return KEYSYMS[code];
  if ([...e.key].length === 1) {
    const c = e.key.codePointAt(0);
    return c < 0x100 ? c : 0x01000000 + c;
  }
  return 0; // a dead key: the character comes with the next key
}

// [scancode, extended, keysym]
const CTRL = [0x1d, false, 0xffe3];
const ALT = [0x38, false, 0xffe9];
const DEL = [0x53, true, 0xffff];
const WIN = [0x5b, true, 0xffeb];
// Lock keys are kept in step with sync events rather than sent as presses.
const LOCKS = new Set(['CapsLock', 'NumLock', 'ScrollLock']);
const MODIFIERS = new Set(['ShiftLeft', 'ShiftRight', 'ControlLeft', 'ControlRight', 'AltLeft', 'AltRight', 'MetaLeft', 'MetaRight']);

export class DesktopSession {
  constructor(app, host) {
    this.app = app;
    this.vnc = host.protocol === 'vnc';
    this.kind = this.vnc ? 'vnc' : 'rdp';
    this.id = uid();
    this.hostId = host.id;
    this.label = host.label || host.address;
    this.state = 'idle';
    this.message = '';
    this.everConnected = false;
    this.desk = { w: 0, h: 0 };
    this.pressed = new Map(); // code → [scancode, extended] sent down and not yet up
    this.queue = [];
    this.move = null;
    this.sending = false;
    this.wheel = { v: 0, h: 0 };

    this.el = document.createElement('div');
    this.el.className = 'term-pane rdp-pane';
    this.el.hidden = true;
    this.el.innerHTML = `
      <div class="rdp-host">
        <canvas class="rdp-screen" tabindex="0" aria-label="Remote desktop"></canvas>
        <div class="rdp-reveal"></div>
        <div class="rdp-bar" role="toolbar">
          <span class="rdp-name"></span>
          <button class="btn small" data-act="cad" title="Send Ctrl+Alt+Delete (to sign in, lock, or open Task Manager)">Ctrl+Alt+Del</button>
          <button class="btn small" data-act="win" title="Press the Windows (Super) key">${icon.grid} Start</button>
          <button class="btn small" data-act="passwords" title="Type a saved password (${isMac ? '⌘⇧P' : 'Ctrl+Shift+P'})">${icon.lock} Password</button>
          <button class="btn small" data-act="fullscreen" title="Full screen">${icon.expand} <span>Full screen</span></button>
          <button class="btn small ghost" data-act="disconnect" title="Disconnect">${icon.x}</button>
        </div>
        <div class="term-status" hidden></div>
      </div>
      <div class="term-banner" hidden></div>`;
    document.getElementById('terminals').appendChild(this.el);
    this.hostEl = this.el.querySelector('.rdp-host');
    this.canvas = this.el.querySelector('canvas');
    this.ctx = this.canvas.getContext('2d', { alpha: false, desynchronized: true });
    this.barEl = this.el.querySelector('.rdp-bar');
    this.statusEl = this.el.querySelector('.term-status');
    this.bannerEl = this.el.querySelector('.term-banner');
    this.el.querySelector('.rdp-name').textContent = this.label;

    this.ro = new ResizeObserver(() => this.layout(true));
    this.ro.observe(this.hostEl);
    this.el.addEventListener('click', (e) => this.onClick(e));
    this.bindInput();
    this.bindBar();
  }

  /** How many device pixels make one CSS pixel, as sent to the remote. */
  scale() {
    const h = this.app.host(this.hostId);
    return h && h.rdpHidpi === false ? 1 : window.devicePixelRatio || 1;
  }

  /** The tab's area in device pixels: what the remote desktop should be. */
  wantedSize() {
    const r = this.hostEl.getBoundingClientRect();
    const k = this.scale();
    return { w: Math.max(200, Math.round(r.width * k)), h: Math.max(200, Math.round(r.height * k)), scale: Math.round(k * 100) };
  }

  connect() {
    this.sid = uid();
    const sid = this.sid;
    this.releaseKeys();
    this.setState('connecting', 'Starting…');
    const { w, h, scale } = this.wantedSize();
    api[this.vnc ? 'vncConnect' : 'rdpConnect'](sid, this.hostId, w, h, scale, ...this.handlers(sid))
      .catch((e) => this.setState('error', String(e)));
  }

  handlers(sid) {
    return [
      (ev) => { if (sid === this.sid) this.onEvent(ev); },
      (data) => { if (sid === this.sid) this.onData(data); },
    ];
  }

  // ---------- screen ----------
  onData(data) {
    const buf = data instanceof ArrayBuffer ? data : Uint8Array.from(data).buffer;
    const v = new DataView(buf);
    switch (v.getUint8(0)) {
      case 1: { // changed rectangles
        const seq = v.getUint32(1, true);
        let at = 7;
        for (let n = v.getUint16(5, true); n > 0; n--) {
          const x = v.getUint16(at, true), y = v.getUint16(at + 2, true), w = v.getUint16(at + 4, true), h = v.getUint16(at + 6, true);
          at += 8;
          if (w && h) this.ctx.putImageData(new ImageData(new Uint8ClampedArray(buf, at, w * h * 4), w, h), x, y);
          at += w * h * 4;
        }
        api.desktopAck(this.sid, seq).catch(() => {});
        break;
      }
      case 2: { // the desktop's size
        this.desk = { w: v.getUint16(1, true), h: v.getUint16(3, true) };
        this.canvas.width = this.desk.w;
        this.canvas.height = this.desk.h;
        this.ctx.fillStyle = '#000';
        this.ctx.fillRect(0, 0, this.desk.w, this.desk.h);
        this.layout(false);
        if (this.cursorMsg) this.setCursor(this.cursorMsg);
        break;
      }
      case 3: this.setCursor(new Uint8Array(buf)); break;
      case 4: this.cursorMsg = null; this.canvas.style.cursor = 'none'; break;
      case 5: this.cursorMsg = null; this.canvas.style.cursor = 'default'; break;
    }
  }

  /** Fit the canvas in the tab, and ask the remote to match the tab's size. */
  layout(resizeRemote) {
    if (this.el.hidden || !this.desk.w) return;
    const r = this.hostEl.getBoundingClientRect();
    const k = this.scale();
    // 1:1 when the desktop matches the tab (the usual case); scaled down to fit while a resize
    // is on its way, or when the server can't resize.
    const fit = Math.min(1, r.width / (this.desk.w / k), r.height / (this.desk.h / k));
    this.canvas.style.width = `${(this.desk.w / k) * fit}px`;
    this.canvas.style.height = `${(this.desk.h / k) * fit}px`;
    if (resizeRemote && this.state === 'connected') {
      const want = this.wantedSize();
      if (want.w !== this.lastAsk?.w || want.h !== this.lastAsk?.h || want.scale !== this.lastAsk?.scale) {
        this.lastAsk = want;
        api.desktopResize(this.sid, want.w, want.h, want.scale).catch(() => {});
      }
    }
  }

  /** The remote's pointer shape, as the local cursor (no lag, unlike drawing it ourselves). */
  setCursor(m) {
    this.cursorMsg = m;
    const v = new DataView(m.buffer, m.byteOffset);
    const w = v.getUint16(1, true), h = v.getUint16(3, true), hx = v.getUint16(5, true), hy = v.getUint16(7, true);
    if (!w || !h) { this.canvas.style.cursor = 'none'; return; }
    const src = document.createElement('canvas');
    src.width = w;
    src.height = h;
    src.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(m.buffer, m.byteOffset + 9, w * h * 4), w, h), 0, 0);
    // Desktop pixels per CSS pixel on screen.
    const k = this.canvas.width / (this.canvas.getBoundingClientRect().width || this.canvas.width);
    const url = src.toDataURL();
    const [cx, cy] = [Math.round(hx / k), Math.round(hy / k)];
    if (Math.abs(k - 1) < 0.05) {
      this.canvas.style.cursor = `url(${url}) ${hx} ${hy}, default`;
      return;
    }
    // Sharp on HiDPI screens where the browser supports it; otherwise scaled to the right size.
    const before = this.canvas.style.cursor;
    this.canvas.style.cursor = `image-set(url(${url}) ${k.toFixed(2)}x) ${cx} ${cy}, default`;
    if (this.canvas.style.cursor !== before && this.canvas.style.cursor.includes('image-set')) return;
    const small = document.createElement('canvas');
    small.width = Math.max(1, Math.round(w / k));
    small.height = Math.max(1, Math.round(h / k));
    const sc = small.getContext('2d');
    sc.imageSmoothingQuality = 'high';
    sc.drawImage(src, 0, 0, small.width, small.height);
    this.canvas.style.cursor = `url(${small.toDataURL()}) ${cx} ${cy}, default`;
  }

  // ---------- keyboard and mouse ----------
  bindInput() {
    const c = this.canvas;
    const pos = (e) => {
      const r = c.getBoundingClientRect();
      const x = Math.round(((e.clientX - r.left) * c.width) / r.width);
      const y = Math.round(((e.clientY - r.top) * c.height) / r.height);
      return { x: Math.max(0, Math.min(c.width - 1, x)), y: Math.max(0, Math.min(c.height - 1, y)) };
    };
    c.addEventListener('pointermove', (e) => {
      if (!this.live()) return;
      // Coalesced: only the latest position is sent.
      this.move = { t: 'm', ...pos(e) };
      this.schedule();
    });
    c.addEventListener('pointerdown', (e) => {
      c.focus({ preventScroll: true });
      if (!this.live() || e.button > 4) return;
      e.preventDefault();
      c.setPointerCapture(e.pointerId);
      this.send({ t: 'b', ...pos(e), b: e.button, d: true });
    });
    c.addEventListener('pointerup', (e) => {
      if (!this.live() || e.button > 4) return;
      this.send({ t: 'b', ...pos(e), b: e.button, d: false });
    });
    c.addEventListener('wheel', (e) => {
      e.preventDefault();
      if (!this.live()) return;
      // 120 units is one notch; trackpads send many small steps, which add up.
      const unit = e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? 120 * 3 : 1.2;
      this.wheel.v -= e.deltaY * unit;
      this.wheel.h += e.deltaX * unit;
      const p = pos(e);
      for (const [axis, h] of [['v', false], ['h', true]]) {
        const whole = Math.trunc(this.wheel[axis]);
        if (!whole) continue;
        this.wheel[axis] -= whole;
        let left = whole;
        while (left) {
          const step = Math.max(-255, Math.min(255, left));
          this.send({ t: 'w', ...p, v: step, h });
          left -= step;
        }
      }
    }, { passive: false });
    c.addEventListener('contextmenu', (e) => e.preventDefault());
    c.addEventListener('keydown', (e) => this.onKey(e, true));
    c.addEventListener('keyup', (e) => this.onKey(e, false));
    c.addEventListener('focus', () => this.onFocus());
    c.addEventListener('blur', () => this.releaseKeys());
    this.onWindowFocus = () => { if (document.activeElement === c) this.onFocus(); };
    window.addEventListener('focus', this.onWindowFocus);
  }

  live() {
    return this.state === 'connected' && !!this.sid;
  }

  onKey(e, down) {
    if (this.state === 'closed' || this.state === 'error') {
      if (down && e.key === 'Enter') { e.preventDefault(); this.connect(); }
      return;
    }
    if (!this.live()) return;
    e.preventDefault();
    e.stopPropagation();
    this.syncLocks(e);
    if (LOCKS.has(e.code)) return;
    // A release always matches what was pressed (the keysym can differ once modifiers change).
    if (!down) { this.keyUp(e.code); return; }
    // On a Mac, ⌘ works as Ctrl (⌘C, ⌘V, ⌘Z… do what you'd expect); Start is on the toolbar.
    const code = isMac && e.code === 'MetaLeft' ? 'ControlLeft' : isMac && e.code === 'MetaRight' ? 'ControlRight' : e.code;
    const sc = SCANCODES[code];
    let key = sc ? [sc[0], sc[1], keysym(e, code)] : null;
    if (this.vnc) {
      // VNC goes by the keysym; keys without a scancode still type their character.
      if (!key && keysym(e)) key = [0, false, keysym(e)];
      if (!key || !key[2]) return; // a dead key: the character comes with the next key
    } else if (!key) {
      // A key with no scancode (rare layouts, IME): send the character itself.
      if (e.key.length === 1) {
        const c = e.key.charCodeAt(0);
        this.send({ t: 'u', c, d: true }, { t: 'u', c, d: false });
      }
      return;
    }
    // Pasting: offer this computer's clipboard to the remote first.
    if (e.code === 'KeyV' && (e.ctrlKey || e.metaKey)) this.queue.push({ t: 'c' });
    if (e.repeat && this.pressed.has(e.code)) key = this.pressed.get(e.code);
    this.pressed.set(e.code, key);
    this.send({ t: 'k', c: key[0], e: key[1], d: true, k: key[2] });
    // macOS doesn't report releasing a key pressed while ⌘ is held: release it now.
    if (isMac && e.metaKey && !MODIFIERS.has(e.code)) this.keyUp(e.code);
  }

  keyUp(code) {
    const key = this.pressed.get(code);
    if (!key) return;
    this.pressed.delete(code);
    this.send({ t: 'k', c: key[0], e: key[1], d: false, k: key[2] });
  }

  /** Let go of everything (the tab lost focus): no key stays stuck down on the remote. */
  releaseKeys() {
    if (this.live()) for (const code of [...this.pressed.keys()]) this.keyUp(code);
    this.pressed.clear();
  }

  syncLocks(e) {
    const f = (e.getModifierState('ScrollLock') ? 1 : 0) | (e.getModifierState('NumLock') ? 2 : 0) | (e.getModifierState('CapsLock') ? 4 : 0);
    if (f !== this.locks) {
      this.locks = f;
      this.queue.push({ t: 's', f });
    }
  }

  onFocus() {
    if (!this.live()) return;
    // The remote gets this computer's latest clipboard, ready to paste.
    this.send({ t: 'c' });
  }

  combo(...keys) {
    if (!this.live()) return toast('This session is not connected', 'error');
    const ev = keys.map(([c, e, k]) => ({ t: 'k', c, e, d: true, k }));
    keys.slice().reverse().forEach(([c, e, k]) => ev.push({ t: 'k', c, e, d: false, k }));
    this.send(...ev);
    this.canvas.focus({ preventScroll: true });
  }

  send(...events) {
    this.queue.push(...events);
    this.schedule();
  }

  schedule() {
    if (this.scheduled) return;
    this.scheduled = true;
    queueMicrotask(() => { this.scheduled = false; this.flush(); });
  }

  // One batch in flight at a time keeps events in order; more queue up meanwhile.
  async flush() {
    if (this.sending || !this.sid) return;
    if (this.move) { this.queue.push(this.move); this.move = null; }
    if (!this.queue.length) return;
    const batch = this.queue;
    this.queue = [];
    this.sending = true;
    try {
      await api.desktopInput(this.sid, batch);
    } catch { /* the session ended; its status says why */ } finally {
      this.sending = false;
      if (this.queue.length || this.move) this.flush();
    }
  }

  // ---------- toolbar ----------
  bindBar() {
    // The toolbar slides down when the pointer rests at the top edge, so it never covers the
    // remote's own title bars and buttons.
    const reveal = this.el.querySelector('.rdp-reveal');
    reveal.addEventListener('pointerenter', () => { this.revealTimer = setTimeout(() => this.showBar(), 220); });
    reveal.addEventListener('pointerleave', () => clearTimeout(this.revealTimer));
    this.barEl.addEventListener('pointerleave', () => { if (!this.el.querySelector('.snip-pop')) this.hideBar(800); });
    this.barEl.addEventListener('pointerenter', () => clearTimeout(this.hideTimer));
  }

  showBar(hideAfter = 0) {
    clearTimeout(this.hideTimer);
    this.barEl.classList.add('shown');
    if (hideAfter) this.hideBar(hideAfter);
  }

  hideBar(after = 0) {
    clearTimeout(this.hideTimer);
    this.hideTimer = setTimeout(() => { this.barEl.classList.remove('shown'); this.closePop(); }, after);
  }

  onClick(e) {
    const act = e.target.closest('[data-act]')?.dataset.act;
    if (act === 'reconnect') this.connect();
    else if (act === 'close' || act === 'disconnect') this.app.closeSession(this);
    else if (act === 'edit') this.app.editHost(this.hostId);
    else if (act === 'cad') this.combo(CTRL, ALT, DEL);
    else if (act === 'win') this.combo(WIN);
    else if (act === 'fullscreen') this.toggleFullscreen();
    else if (act === 'passwords') this.togglePop();
    else if (act === 'set-host-pw') this.saveHostPassword();
    else if (e.target.closest('.snip-pop [data-pw]')) this.typePassword(e.target.closest('[data-pw]').dataset.pw);
  }

  togglePop() {
    if (this.closePop()) return;
    const pop = document.createElement('div');
    pop.className = 'snip-pop rdp-pop';
    pop.innerHTML = this.passwordsHtml();
    this.hostEl.appendChild(pop);
  }

  closePop() {
    const pop = this.el.querySelector('.snip-pop');
    pop?.remove();
    return !!pop;
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

  quickTypePassword() {
    if (this.app.flags(this.hostId).password) this.typePassword(this.hostId);
    else { this.showBar(); this.togglePop(); }
  }

  async typePassword(secretId) {
    this.closePop();
    this.hideBar(300);
    if (!this.live()) return toast('This session is not connected', 'error');
    try {
      await api.desktopTypePassword(this.sid, secretId);
    } catch (e) {
      toast(String(e), 'error');
    }
    this.canvas.focus({ preventScroll: true });
  }

  async saveHostPassword() {
    this.closePop();
    if (await this.app.setHostPassword(this.hostId)) this.togglePop();
  }

  async toggleFullscreen() {
    if (!DesktopSession.watchingFullscreen) {
      // Leaving full screen another way (the green button, a keyboard shortcut) brings the
      // sidebar and tabs back too.
      DesktopSession.watchingFullscreen = true;
      window.addEventListener('resize', async () => {
        if (!document.body.classList.contains('rdp-fullscreen')) return;
        const still = await getCurrentWindow().isFullscreen().catch(() => true);
        if (!still) {
          document.body.classList.remove('rdp-fullscreen');
          document.querySelectorAll('.rdp-bar [data-act=fullscreen] span').forEach((x) => (x.textContent = 'Full screen'));
        }
      });
    }
    const on = !document.body.classList.contains('rdp-fullscreen');
    document.body.classList.toggle('rdp-fullscreen', on);
    this.barEl.querySelector('[data-act=fullscreen] span').textContent = on ? 'Exit full screen' : 'Full screen';
    try { await getCurrentWindow().setFullscreen(on); } catch { /* browser preview */ }
    this.hideBar(on ? 1200 : 0);
    this.canvas.focus({ preventScroll: true });
  }

  // ---------- status ----------
  onEvent(ev) {
    if (ev.type === 'status') this.setState(ev.state, ev.message);
    else if (ev.type === 'prompt') this.handlePrompt(ev);
  }

  async handlePrompt({ id, kind, data }) {
    this.app.activate(this);
    const ctl = (this.promptCtl = {});
    let value = null;
    if (kind === 'hostkey') value = { accept: await hostKeyPrompt(data, ctl) };
    else if (kind === 'password' || kind === 'passphrase') value = await secretPrompt(kind, data, ctl);
    else if (kind === 'text') value = await textPrompt(data, ctl);
    if (this.promptCtl === ctl) this.promptCtl = null;
    await api.promptReply(id, value);
  }

  setState(state, message = '') {
    const was = this.state;
    this.state = state;
    this.message = message;
    if (state === 'connected') this.everConnected = true;
    const busy = state === 'connecting' || state === 'authenticating';
    const ended = state === 'closed' || state === 'error';
    const host = this.app.host(this.hostId);
    const name = esc(host ? host.label || host.address : this.label);

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
    this.el.classList.toggle('ended', ended);
    this.bannerEl.hidden = !(ended && this.everConnected);
    this.bannerEl.className = `term-banner ${state === 'error' ? 'error' : ''}`;
    if (ended && this.everConnected) {
      this.bannerEl.innerHTML = `<span class="msg">${esc(message || 'Disconnected')} — press Enter to reconnect.</span>
        <button class="btn small primary" data-act="reconnect">${icon.refresh} Reconnect</button>
        <button class="btn small ghost" data-act="close">Close tab</button>`;
    }
    if (ended) {
      this.promptCtl?.cancel?.();
      this.pressed.clear();
      if (document.body.classList.contains('rdp-fullscreen') && this.app.active === this) this.toggleFullscreen();
    }
    if (state === 'connected' && was !== 'connected') {
      this.lastAsk = null;
      this.locks = undefined;
      if (!this.el.hidden && !this.app.modalOpen()) this.canvas.focus({ preventScroll: true });
      // Show where the toolbar lives, then tuck it away.
      this.showBar(2200);
      requestAnimationFrame(() => this.layout(true));
    }
    this.app.sessionChanged(this);
  }

  // ---------- moving to another window ----------
  cantMove() {
    return this.promptCtl ? 'Answer the login prompt first' : null;
  }

  handoffPayload() {
    return { kind: this.kind, hostId: this.hostId, label: this.label, sid: this.sid, state: this.state, message: this.message, everConnected: this.everConnected };
  }

  async adoptFrom(p) {
    this.sid = p.sid;
    this.everConnected = p.everConnected;
    this.setState(p.state, p.message);
    // The backend sends the size, pointer and a full frame once attached.
    await api.tabAttach(p.sid, ...this.handlers(p.sid));
    this.lastAsk = null;
    requestAnimationFrame(() => this.layout(true));
  }

  release() {
    this.promptCtl?.cancel?.();
    this.releaseKeys();
    this.sid = null;
    this.teardown();
  }

  // ---------- tab plumbing ----------
  applySettings() {}

  show() {
    this.el.hidden = false;
    requestAnimationFrame(() => {
      this.layout(true);
      if (!this.app.modalOpen() && this.state === 'connected') this.canvas.focus({ preventScroll: true });
    });
  }

  hide() {
    this.releaseKeys();
    this.el.hidden = true;
    this.closePop();
    if (document.body.classList.contains('rdp-fullscreen')) this.toggleFullscreen();
  }

  teardown() {
    this.ro.disconnect();
    window.removeEventListener('focus', this.onWindowFocus);
    clearTimeout(this.hideTimer);
    clearTimeout(this.revealTimer);
    this.el.remove();
  }

  dispose() {
    this.promptCtl?.cancel?.();
    this.releaseKeys();
    if (document.body.classList.contains('rdp-fullscreen') && this.app.active === this) this.toggleFullscreen();
    if (this.sid) api.close(this.sid);
    this.sid = null;
    this.teardown();
  }
}

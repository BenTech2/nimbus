// Browser preview only (npm run dev, opened in a normal browser rather than the Tauri window).
// Fakes the Rust backend in memory so the UI can be clicked through and styled.
// Never included in a production build.
import { mockIPC } from '@tauri-apps/api/mocks';

const id = () => crypto.randomUUID();
const g1 = id(), g2 = id(), g3 = id(), k1 = id();
const data = {
  version: 1,
  groups: [
    { id: g1, name: 'Production', color: '#f2555a', username: 'deploy' },
    { id: g2, name: 'Home lab', color: '#34c77b', username: 'pi' },
    { id: g3, name: 'Clients', color: '#7b5cff' },
  ],
  hosts: [
    ['web-01', '10.0.1.11', g1], ['web-02', '10.0.1.12', g1], ['db-primary', '10.0.2.5', g1],
    ['Raspberry Pi', '192.168.1.40', g2], ['NAS', '192.168.1.10', g2],
    ['Bastion', 'bastion.example.com', null], ['Local test server', '127.0.0.1', null], ['Media FTP', 'nas.local', g2, 'ftps'], ['Core switch console', '/dev/cu.usbserial-A10K3', null, 'serial'],
  ].map(([label, address, groupId, protocol = 'ssh']) => ({ id: id(), label, address, groupId, protocol, useAgent: true, tags: [], port: label === 'Bastion' ? 2022 : null, username: label === 'Bastion' ? 'ben' : null })),
  keys: [{ id: k1, label: 'Laptop ed25519', keyType: 'ssh-ed25519', publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyExampleOnlyExampleOnly0000 laptop', fingerprint: 'SHA256:3fq0Wl3JmX2b8yXkq1m7ZJbq0vJgGg3m4zU9bq2gXyE', encrypted: false }],
  snippets: [
    { id: id(), name: 'Disk usage', command: 'df -h', run: true },
    { id: id(), name: 'Follow syslog', command: 'sudo journalctl -f', run: false },
  ],
  passwords: [
    { id: 'pw1', name: 'Ubuntu sudo', groupId: 'pg1', username: 'ben', url: null, notes: null, updated: Date.now() - 86400000 },
    { id: 'pw2', name: 'Router admin', groupId: 'pg2', username: 'admin', url: '192.168.1.1', notes: 'Upstairs closet', updated: Date.now() - 86400000 * 9 },
    { id: 'pw3', name: 'GitHub', username: 'ben@example.com', url: 'github.com', notes: null, updated: Date.now() - 86400000 * 30 },
    { id: 'pw4', name: 'Proxmox', groupId: 'pg1', username: 'root', url: 'https://pve.local:8006', notes: null, updated: Date.now() - 86400000 * 2 },
  ],
  passwordGroups: [{ id: 'pg1', name: 'Servers', color: '#34c77b' }, { id: 'pg2', name: 'Network gear', color: '#f59e0b' }],
  apiGroups: [{ id: 'ag1', name: 'Payments', color: '#7b5cff' }],
  apiKeys: [
    { id: 'ak1', name: 'Stripe live', groupId: 'ag1', kind: 'bearer', service: 'Stripe', environment: 'Production', baseUrl: 'https://api.stripe.com', fields: [{ id: 'token', label: 'Token', secret: true }], expires: null, updated: Date.now() - 86400000 * 4 },
    { id: 'ak2', name: 'Stripe test', groupId: 'ag1', kind: 'bearer', service: 'Stripe', environment: 'Development', baseUrl: 'https://api.stripe.com', fields: [{ id: 'token', label: 'Token', secret: true }], expires: Date.now() + 86400000 * 5, updated: Date.now() - 86400000 },
    { id: 'ak3', name: 'GitHub Actions app', kind: 'oauth2', service: 'GitHub', environment: 'Production', baseUrl: 'https://api.github.com', fields: [{ id: 'clientId', label: 'Client ID', secret: false, value: 'Iv1.8a61f9b3a7aba766' }, { id: 'clientSecret', label: 'Client secret', secret: true }, { id: 'tokenUrl', label: 'Token URL', secret: false, value: 'https://github.com/login/oauth/access_token' }, { id: 'scopes', label: 'Scopes', secret: false, value: 'repo workflow' }], expires: null, updated: Date.now() - 86400000 * 20 },
    { id: 'ak4', name: 'OpenWeather', kind: 'apiKey', service: 'OpenWeather', environment: null, baseUrl: 'api.openweathermap.org/data/2.5', fields: [{ id: 'key', label: 'API key', secret: true }, { id: 'name', label: 'Header or parameter name', secret: false, value: 'appid' }, { id: 'in', label: 'Send it as', secret: false, value: 'query' }], expires: Date.now() - 86400000 * 2, updated: Date.now() - 86400000 * 60 },
  ],
  knownHosts: [{ host: '10.0.1.11:22', keyType: 'ssh-ed25519', fingerprint: 'SHA256:Zq1a8m0XqfTnS3tU2kq7Ff3n9m0Q5wqzY6Yk0dQ1abc', added: Date.now() - 86400000 * 3 }],
  settings: { theme: 'system', hostsView: 'grid', fontSize: 13, fontFamily: '"SF Mono", Menlo, Consolas, monospace', cursorStyle: 'block', cursorBlink: true, scrollback: 10000, copyOnSelect: false, keepaliveSecs: 30, typePasswordEnter: true, agentSocket: null },
};
const apiSecrets = { ak1: { token: 'sk_live_51Hx…REDACTED' }, ak2: { token: 'sk_test_51Hx9fake' }, ak3: { clientSecret: 'ghs_example_secret' }, ak4: { key: 'b6907d289e10d714a6e88b30761fae22' } };
const secrets = { ak1: { fields: ['token'] }, ak2: { fields: ['token'] }, ak3: { fields: ['clientSecret'] }, ak4: { fields: ['key'] }, [k1]: { privateKey: true }, pw1: { password: true }, pw2: { password: true }, pw3: { password: true }, pw4: { password: true } };
const plain = { pw1: 'correct-horse-battery', pw2: 'Rout3r!admin', pw3: 'gh-9fK2m!xQ', pw4: 'pve-Root#1' };

// ---------- fake file systems for the Files tab ----------
const now = Date.now();
const tree = (o) => Object.entries(o).map(([name, v]) => (typeof v === 'number' ? { name, size: v, modified: now - v * 1000 } : { name, children: tree(v), modified: now - 86400000 }));
const fsys = {
  local: { sep: '/', home: '/Users/ben', root: { name: '', children: tree({ Users: { ben: { Documents: { 'notes.md': 2400, 'budget.xlsx': 48211 }, Downloads: { 'ubuntu-24.04.iso': 2700000000, 'photo.jpg': 3400000 }, Desktop: {}, '.zshrc': 900, 'deploy.sh': 1200 } } }) } },
  remote: { sep: '/', home: '/home/deploy', root: { name: '', children: tree({ etc: { nginx: { 'nginx.conf': 2600 }, hosts: 220 }, var: { log: { 'syslog': 880000, 'auth.log': 120000 } }, home: { deploy: { apps: { api: { 'server.js': 5300 } }, backups: { 'db-2024-10-01.sql.gz': 98000000 }, '.bashrc': 3700, 'docker-compose.yml': 1400, 'notes.txt': 310 } } }) } },
};
const fsFor = (sid) => (sid === 'local' ? fsys.local : fsys.remote);
const walk = (fs, path) => {
  let node = fs.root;
  for (const part of path.split('/').filter(Boolean)) { node = node.children?.find((c) => c.name === part); if (!node) throw `No such file or folder: ${path}`; }
  return node;
};
const join = (dir, name) => (dir.endsWith('/') ? dir : dir + '/') + name;
const parentOf = (p) => { const t = p.replace(/\/+$/, ''); const i = t.lastIndexOf('/'); return t === '' ? null : i <= 0 ? '/' : t.slice(0, i); };
function fsList(sid, path) {
  const fs = fsFor(sid);
  const p = path || fs.home;
  const node = walk(fs, p);
  if (!node.children) throw `${p} is not a folder`;
  return { path: p, parent: parentOf(p), entries: node.children.map((c) => ({ name: c.name, path: join(p, c.name), isDir: !!c.children, isLink: false, size: c.children ? 0 : c.size, modified: c.modified })) };
}
const fsEvents = new Map();
function fakeTransfer(sid, tid, upload, items, dest) {
  const ev = fsEvents.get(sid);
  const from = upload ? fsys.local : fsys.remote, to = upload ? fsys.remote : fsys.local;
  const size = (n) => (n.children ? n.children.reduce((a, c) => a + size(c), 0) : n.size);
  const nodes = items.map((i) => walk(from, i.path));
  const total = nodes.reduce((a, n) => a + size(n), 0);
  const label = nodes.length > 1 ? `${nodes[0].name} and ${nodes.length - 1} more` : nodes[0].name;
  let done = 0;
  const step = Math.max(total / 25, 1);
  ev({ type: 'transfer', id: tid, state: 'queued', upload, dest });
  const t = setInterval(() => {
    if (cancelled.has(tid)) { clearInterval(t); return ev({ type: 'transfer', id: tid, state: 'cancelled', upload, dest }); }
    done = Math.min(total, done + step);
    ev({ type: 'transfer', id: tid, state: 'running', label, done, total, files: 0, count: nodes.length });
    if (done >= total) {
      clearInterval(t);
      const target = walk(to, dest);
      for (const n of nodes) { target.children = target.children.filter((c) => c.name !== n.name); target.children.push(structuredClone({ ...n, modified: Date.now() })); }
      ev({ type: 'transfer', id: tid, state: 'done', files: nodes.length, upload, dest });
    }
  }, 120);
}
const cancelled = new Set();
const snap = () => ({ data: structuredClone(data), secrets: structuredClone(secrets), vaultMode: 'keychain', dataDir: '~/Library/Application Support/app.nimbus.ssh', warning: null, platform: 'macos', version: '0.1.0' });
const upsert = (list, item) => { const i = list.findIndex((x) => x.id === item.id); i < 0 ? list.push(item) : (list[i] = item); };

const prompts = new Map();
const sessions = new Map();

function fakeSession(sid, hostId, events, out) {
  const host = data.hosts.find((h) => h.id === hostId);
  const ev = (m) => events.onmessage(m);
  const write = (s) => out.onmessage(new TextEncoder().encode(s).buffer);
  const user = host.username || data.groups.find((g) => g.id === host.groupId)?.username || 'ben';
  const ask = (kind, d) => new Promise((res) => { const pid = id(); prompts.set(pid, res); ev({ type: 'prompt', id: pid, kind, data: d }); });
  (async () => {
    ev({ type: 'status', state: 'connecting', message: `Connecting to ${host.address}:${host.port || 22}…` });
    await new Promise((r) => setTimeout(r, 500));
    if (host.address === 'bastion.example.com') return ev({ type: 'status', state: 'error', message: `Could not connect to ${host.address}:2022: Connection refused (os error 61)` });
    if (host.protocol === 'serial') {
      ev({ type: 'status', state: 'connected', message: '' });
      write('\r\nUser Access Verification\r\n\r\nPassword: ');
      sessions.set(sid, (d) => { if (d.includes('\r')) write('\r\nSwitch> '); else if (d === '\x03') write('^C'); });
      return;
    }
    const target = `${host.address}:${host.port || 22}`;
    if (!data.knownHosts.some((k) => k.host === target)) {
      const a = await ask('hostkey', { host: target, keyType: 'ssh-ed25519', fingerprint: 'SHA256:pV1nq3XcN8m2Yt4kq0LwE7rB9sQ1fH6dJ2aZ5uT8cGo', previous: null });
      if (!a?.accept) return ev({ type: 'status', state: 'error', message: `Host key for ${target} was not trusted, so the connection was cancelled` });
      data.knownHosts.push({ host: target, keyType: 'ssh-ed25519', fingerprint: 'SHA256:pV1nq3XcN8m2Yt4kq0LwE7rB9sQ1fH6dJ2aZ5uT8cGo', added: Date.now() });
    }
    ev({ type: 'status', state: 'authenticating', message: `Authenticating as ${user}…` });
    await new Promise((r) => setTimeout(r, 300));
    ev({ type: 'status', state: 'connected', message: '' });
    host.lastConnected = Date.now();
    write(`Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-45-generic x86_64)\r\n\r\n  System load:  0.08   Memory usage: 23%   Processes: 142\r\n\r\nLast login: ${new Date().toUTCString()}\r\n`);
    const prompt = () => write(`\x1b[1;32m${user}@${host.label.toLowerCase().replace(/\s+/g, '-')}\x1b[0m:\x1b[1;34m~\x1b[0m$ `);
    prompt();
    let line = '';
    sessions.set(sid, (d) => {
      for (const ch of d) {
        if (ch === '\r') {
          write('\r\n');
          if (line === 'exit') { sessions.delete(sid); return ev({ type: 'status', state: 'closed', message: 'Connection closed' }); }
          if (line === 'ls') write('\x1b[1;34mapps\x1b[0m  \x1b[1;34mbackups\x1b[0m  docker-compose.yml  notes.txt\r\n');
          else if (line === 'df -h') write('Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/sda1        80G   31G   46G  41% /\r\n');
          else if (line) write(`${line.split(' ')[0]}: command not found\r\n`);
          line = '';
          prompt();
        } else if (ch === '\x7f') { if (line) { line = line.slice(0, -1); write('\b \b'); } }
        else { line += ch; write(ch); }
      }
    });
  })();
}

mockIPC(
  (cmd, a) => {
    switch (cmd) {
      case 'get_state': return snap();
      case 'save_host': upsert(data.hosts, { ...a.host, id: a.host.id || id() }); if (a.password) secrets[a.host.id] = { ...secrets[a.host.id], password: true }; return snap();
      case 'duplicate_host': { const h = data.hosts.find((x) => x.id === a.id); data.hosts.push({ ...h, id: id(), label: h.label + ' copy' }); return snap(); }
      case 'delete_host': data.hosts = data.hosts.filter((h) => h.id !== a.id); return snap();
      case 'save_group': upsert(data.groups, a.group); return snap();
      case 'delete_group': data.groups = data.groups.filter((g) => g.id !== a.id); data.hosts.forEach((h) => { if (h.groupId === a.id) h.groupId = null; }); return snap();
      case 'save_key': upsert(data.keys, { ...a.key, keyType: 'ssh-ed25519', publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINewKeyExampleOnly0000000000000000000 nimbus', fingerprint: 'SHA256:newkeyexample' }); secrets[a.key.id] = { privateKey: true }; return snap();
      case 'generate_key': return '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n';
      case 'delete_key': data.keys = data.keys.filter((k) => k.id !== a.id); return snap();
      case 'save_snippet': upsert(data.snippets, a.snippet); return snap();
      case 'delete_snippet': data.snippets = data.snippets.filter((s) => s.id !== a.id); return snap();
      case 'save_password': upsert(data.passwords, { ...a.entry, updated: Date.now() }); if (a.password) { secrets[a.entry.id] = { password: true }; plain[a.entry.id] = a.password; } return snap();
      case 'delete_password': data.passwords = data.passwords.filter((p) => p.id !== a.id); return snap();
      case 'reveal_password': return plain[a.id];
      case 'ssh_type_password': sessions.get(a.sessionId)?.(`<typed ${a.secretId === 'pw1' || a.secretId === 'pw2' ? 'entry' : 'host'} password>` + (data.settings.typePasswordEnter ? '\r' : '')); return null;
      case 'plugin:clipboard-manager|read_text': return '';
      case 'delete_known_host': data.knownHosts = data.knownHosts.filter((k) => k.host !== a.host); return snap();
      case 'save_settings': data.settings = a.settings; return snap();
      case 'save_api_key': {
        upsert(data.apiKeys, { ...a.entry, updated: Date.now() });
        const cur = (apiSecrets[a.entry.id] ||= {});
        for (const [k, v] of Object.entries(a.secrets)) { if (v === '') delete cur[k]; else if (v != null) cur[k] = v; }
        secrets[a.entry.id] = { fields: Object.keys(cur) };
        return snap();
      }
      case 'delete_api_key': data.apiKeys = data.apiKeys.filter((x) => x.id !== a.id); return snap();
      case 'reveal_api_secret': { const v = apiSecrets[a.id]?.[a.fieldId]; if (v == null) throw 'Nothing saved for that field'; return v; }
      case 'save_api_group': upsert(data.apiGroups, a.group); return snap();
      case 'delete_api_group': data.apiGroups = data.apiGroups.filter((g) => g.id !== a.id); return snap();
      case 'save_password_group': upsert(data.passwordGroups, a.group); return snap();
      case 'delete_password_group': data.passwordGroups = data.passwordGroups.filter((g) => g.id !== a.id); data.passwords.forEach((p) => { if (p.groupId === a.id) p.groupId = null; }); return snap();
      case 'fs_open': {
        const ev = (m) => a.events.onmessage(m);
        fsEvents.set(a.sessionId, ev);
        const host = data.hosts.find((h) => h.id === a.hostId);
        ev({ type: 'status', state: 'connecting', message: `Connecting to ${host.address}…` });
        setTimeout(() => ev({ type: 'status', state: 'connected', message: '', home: host.protocol === 'ssh' ? '/home/deploy' : '/' }), 600);
        return null;
      }
      case 'fs_close': return null;
      case 'fs_list': return fsList(a.sessionId, a.path);
      case 'fs_mkdir': { const n = walk(fsFor(a.sessionId), a.dir); if (n.children.some((c) => c.name === a.name)) throw `“${a.name}” already exists`; n.children.push({ name: a.name, children: [], modified: Date.now() }); return null; }
      case 'fs_rename': { const n = walk(fsFor(a.sessionId), a.dir); if (n.children.some((c) => c.name === a.to)) throw `“${a.to}” already exists`; n.children.find((c) => c.name === a.from).name = a.to; return null; }
      case 'fs_delete': for (const it of a.items) { const fs = fsFor(a.sessionId); const p = walk(fs, parentOf(it.path)); p.children = p.children.filter((c) => join(parentOf(it.path), c.name) !== it.path); } return null;
      case 'fs_transfer': fakeTransfer(a.sessionId, a.transferId, a.upload, a.items, a.dest); return null;
      case 'fs_cancel': cancelled.add(a.transferId); return null;
      case 'plugin:opener|open_url': console.info('[mock] open', a.url); return null;
      case 'import_ssh_config': return { report: { hostsAdded: 0, hostsSkipped: 2, keysAdded: 0, warnings: [] }, state: snap() };
      case 'ssh_connect': fakeSession(a.sessionId, a.hostId, a.events, a.data); return null;
      case 'ssh_write': sessions.get(a.sessionId)?.(a.data); return null;
      case 'ssh_resize': case 'ssh_close': return null;
      case 'ssh_break': sessions.get(a.sessionId)?.('\x03'); return null;
      case 'serial_ports': return [{ name: '/dev/cu.usbserial-A10K3', description: 'FT232R USB UART (FTDI)' }, { name: '/dev/cu.Bluetooth-Incoming-Port', description: 'Bluetooth' }];
      case 'prompt_reply': prompts.get(a.id)?.(a.value); prompts.delete(a.id); return null;
      case 'plugin:clipboard-manager|write_text': return null;
      default: console.warn('[mock] unhandled', cmd, a); return null;
    }
  },
  { shouldMockEvents: true },
);
console.info('[nimbus] browser preview with mock backend');

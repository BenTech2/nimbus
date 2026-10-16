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
    ['Bastion', 'bastion.example.com', null], ['Local test server', '127.0.0.1', null],
  ].map(([label, address, groupId]) => ({ id: id(), label, address, groupId, protocol: 'ssh', useAgent: true, tags: [], port: label === 'Bastion' ? 2022 : null, username: label === 'Bastion' ? 'ben' : null })),
  keys: [{ id: k1, label: 'Laptop ed25519', keyType: 'ssh-ed25519', publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyExampleOnlyExampleOnly0000 laptop', fingerprint: 'SHA256:3fq0Wl3JmX2b8yXkq1m7ZJbq0vJgGg3m4zU9bq2gXyE', encrypted: false }],
  snippets: [
    { id: id(), name: 'Disk usage', command: 'df -h', run: true },
    { id: id(), name: 'Follow syslog', command: 'sudo journalctl -f', run: false },
  ],
  passwords: [
    { id: 'pw1', name: 'Ubuntu sudo', username: 'ben', url: null, notes: null, updated: Date.now() - 86400000 },
    { id: 'pw2', name: 'Router admin', username: 'admin', url: 'http://192.168.1.1', notes: null, updated: Date.now() - 86400000 * 9 },
  ],
  knownHosts: [{ host: '10.0.1.11:22', keyType: 'ssh-ed25519', fingerprint: 'SHA256:Zq1a8m0XqfTnS3tU2kq7Ff3n9m0Q5wqzY6Yk0dQ1abc', added: Date.now() - 86400000 * 3 }],
  settings: { fontSize: 13, fontFamily: '"SF Mono", Menlo, Consolas, monospace', cursorStyle: 'block', cursorBlink: true, scrollback: 10000, copyOnSelect: false, keepaliveSecs: 30, typePasswordEnter: true, agentSocket: null },
};
const secrets = { [k1]: { privateKey: true }, pw1: { password: true }, pw2: { password: true } };
const plain = { pw1: 'correct-horse-battery', pw2: 'Rout3r!admin' };
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
      case 'import_ssh_config': return { report: { hostsAdded: 0, hostsSkipped: 2, keysAdded: 0, warnings: [] }, state: snap() };
      case 'ssh_connect': fakeSession(a.sessionId, a.hostId, a.events, a.data); return null;
      case 'ssh_write': sessions.get(a.sessionId)?.(a.data); return null;
      case 'ssh_resize': case 'ssh_close': return null;
      case 'prompt_reply': prompts.get(a.id)?.(a.value); prompts.delete(a.id); return null;
      case 'plugin:clipboard-manager|write_text': return null;
      default: console.warn('[mock] unhandled', cmd, a); return null;
    }
  },
  { shouldMockEvents: true },
);
console.info('[nimbus] browser preview with mock backend');

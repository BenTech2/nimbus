# Nimbus

A simple SSH connection manager, with no cloud, accounts or vault
service. Your hosts live on your computer, and you move them to another computer with one
export file.

Runs natively on **macOS, Windows and Linux** (Tauri: Rust core + the OS's own webview,
~10–15 MB installers).

## Features

- **Hosts and groups**: card grid, colours, tags, notes, search.
  Groups can set a default username, port and key for every host inside them.
- **Quick connect**: type `user@host` or `user@host:port` in the search box and press Enter.
- **Tabs**: many sessions at once. ⌘T home, ⌘W close tab, ⌘1–9 switch, ⌘D duplicate,
  Ctrl+Tab cycle (on Windows and Linux use Ctrl+Shift instead of ⌘).
- **Authentication**: saved key → SSH agent (ssh-agent, 1Password, Secretive, Pageant)
  → password / keyboard-interactive (2FA prompts work). Anything missing is asked for, with
  an option to save it.
- **Keychain**: add a key from a file, paste one, or generate an Ed25519 key and copy its public
  half to your servers.
- **Jump hosts**: connect through a bastion (chains work too).
- **Known hosts**: you confirm a server's fingerprint the first time, and you're warned
  loudly if it changes later.
- **Passwords**: a simple password manager. Store name / username / password / URL / notes,
  generate strong passwords, copy them (the clipboard clears itself after 30 s), search.
- **Type password into a session**: the terminal's **Password** button (or ⌘⇧P / Ctrl+Shift+P)
  types the host's saved password, or any Passwords entry, as keystrokes and presses Enter.
  Use it at a `sudo` prompt. The password goes straight from the encrypted store to the SSH
  connection, never through the UI or the clipboard. Turn off the automatic Enter in Settings.
- **Snippets**: saved commands you can paste into any terminal from the Snippets button.
- **Import `~/.ssh/config`**: picks up Host, HostName, User, Port, IdentityFile and ProxyJump.
- **Export / import**: one JSON file with hosts, groups, keys, passwords, snippets and trusted host keys.
  Passwords and private keys are included only if you set a passphrase. They are then encrypted
  with scrypt + AES-256-GCM inside the file. On import you can merge or replace.

## Where data is stored

| | macOS | Windows | Linux |
|---|---|---|---|
| Folder | `~/Library/Application Support/app.nimbus.ssh` | `%APPDATA%\app.nimbus.ssh` | `~/.local/share/app.nimbus.ssh` |

- `nimbus-data.json`: hosts, groups, public keys, snippets, known hosts, settings (plain JSON)
- `secrets.bin`: passwords, private keys and passphrases, encrypted with AES-256-GCM. The
  encryption key is held in the OS keychain (Keychain / Credential Manager / Secret Service).
  If no keychain is available, it falls back to a local `master.key` file and the app says so.

To move to a new computer, use **Import & Export**. Don't copy `secrets.bin` by hand, because
its key stays in the old computer's keychain.

## Develop

Needs Node 20+ and Rust (`rustup`). On Linux, also install the
[Tauri system packages](https://tauri.app/start/prerequisites/) (webkit2gtk etc.).

```sh
npm install
npm run tauri dev          # run the app
npm run dev                # UI only, in a browser, with a fake backend (src/dev-mock.js)
npm run tauri build        # installer for the current OS (.dmg / .msi+.exe / .deb+.AppImage)
```

Each OS's installer has to be built on that OS (or in CI, e.g. GitHub Actions with
`tauri-apps/tauri-action` on macOS, Windows and Ubuntu runners).

Backend tests (`src-tauri/src/tests.rs`). The SSH tests run against a real `sshd` on
127.0.0.1:2222 when `NIMBUS_TEST_SSHD` points at a folder with the test keys `client` and
`client_enc` (passphrase `secretpass`):

```sh
cd src-tauri && NIMBUS_TEST_SSHD=/path/to/keys cargo test
```

## Layout

```
src/                 UI (vanilla JS + xterm.js)
  main.js            views, editors, tabs, shortcuts
  terminal.js        one terminal tab ↔ one SSH session
  prompts.js         host-key / password / 2FA dialogs
src-tauri/src/       Rust core
  ssh.rs             connect, host-key check, auth, jump hosts, PTY pump (russh)
  store.rs           data model + persistence
  vault.rs           at-rest encryption + export passphrase encryption
  transfer.rs        export / import file
  sshconfig.rs       ~/.ssh/config import
  keys.rs            read / generate private keys
```

## Not yet

- **RDP.** Hosts already carry a `protocol` field so RDP entries can sit in the same
  list and groups. Planned first step: an "RDP" host type that opens the system's RDP client
  (Windows App on macOS, `mstsc` on Windows, Remmina/xfreerdp on Linux) with the saved
  address and username. An embedded RDP view (e.g. via IronRDP) would come after.
- SFTP file browser, port forwarding, agent forwarding, split panes, light theme.

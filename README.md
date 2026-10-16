# Nimbus

A simple SSH, SFTP, FTP and serial connection manager, with no cloud, accounts or vault
service. Your hosts live on your computer, and you move them to another computer with one
export file.

Runs natively on **macOS, Windows and Linux** (Tauri: Rust core + the OS's own webview,
~10–15 MB installers).

## Features

- **Hosts and groups**: card grid, or a compact list (the switch by the New Host
  button; Nimbus remembers your choice). Colours, tags, notes, search.
  Groups can set a default username, port and key for every host inside them.
- **Serial consoles**: add a host of type Serial for a router or switch console cable, an Arduino
  or any USB-serial adapter. Pick the port (Scan lists what's plugged in), baud rate, data bits,
  parity, stop bits and flow control, what Enter sends (CR / LF / CR LF) and local echo. It opens
  in a terminal tab with a **Break** button; Snippets and Type password work there too.
  On Linux your user needs to be in the `dialout` group to open serial ports.
- **Quick connect**: type `user@host` or `user@host:port` in the search box and press Enter.
  Start with `sftp://`, `ftp://` or `ftps://` to open the file browser instead.
- **Light and dark themes**: follow the system, or pick one in Settings.
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
- **File browser (SFTP, FTP, FTPS)**: two panes, this computer on the left and the server on the
  right. Drag files and folders between them (or drop them in from Finder / Explorer), double-click
  a file to copy it across, rename, new folder, delete, show hidden files. Transfers show progress
  and can be cancelled. Open it from an SSH host (folder icon, right-click → Open SFTP, the terminal's
  SFTP button, or ⌘⇧O), or add an FTP / FTPS host, which opens straight into the file browser.
  - SFTP uses the host's normal SSH login, keys and jump hosts.
  - FTPS uses explicit TLS. A certificate your computer doesn't recognise (self-signed, as on most
    NAS boxes) is shown once to trust, like an SSH host key, and you're warned if it changes.
  - Deleting on this computer moves things to the Trash / Recycle Bin. Deleting on the server is
    permanent and asks first.
- **Passwords**: a simple password manager in a list view. Store name / username / password /
  website / notes, sort them into coloured groups, generate strong passwords, show or copy them
  (the clipboard clears itself after 30 s), search, and click a website or address to open it.
- **API Keys**: a home for API credentials, Postman-style. Each one has a type (API key, Bearer
  token, Basic auth, OAuth 2.0 client credentials, or Custom fields), a service, an environment
  (Production / Staging / Development…), a group, a base URL, an expiry date and notes. Secret
  fields are encrypted like passwords; add your own extra fields and choose which are secret.
  Copy the key on its own, or **Copy as** an Authorization header, a curl command, `.env` lines or
  JSON. Expired and soon-to-expire credentials are flagged.
- **Type password into a session**: the terminal's **Password** button (or ⌘⇧P / Ctrl+Shift+P)
  types the host's saved password, or any Passwords entry, as keystrokes and presses Enter.
  Use it at a `sudo` prompt. The password goes straight from the encrypted store to the SSH
  connection, never through the UI or the clipboard. Turn off the automatic Enter in Settings.
- **Snippets**: saved commands you can paste into any terminal from the Snippets button.
- **Import `~/.ssh/config`**: picks up Host, HostName, User, Port, IdentityFile and ProxyJump.
- **Export / import**: one file with hosts, groups, keys, passwords, API credentials, snippets and
  trusted host keys / certificates. Exports are always encrypted with a password you choose
  (scrypt + AES-256-GCM over the whole file, so not even host names are readable), and that
  password is needed to import. A forgotten export password can't be recovered.
- **Links** (password and API websites, links in the terminal with ⌘/Ctrl-click) open in your
  default browser; Nimbus never loads outside pages in its own window.

## Where data is stored

| | macOS | Windows | Linux |
|---|---|---|---|
| Folder | `~/Library/Application Support/app.nimbus.ssh` | `%APPDATA%\app.nimbus.ssh` | `~/.local/share/app.nimbus.ssh` |

- `nimbus-data.json`: hosts, groups, public keys, snippets, password and API key names, known
  hosts, settings (plain JSON, no secrets)
- `secrets.bin`: passwords, private keys, passphrases and API secrets, encrypted with AES-256-GCM. The
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

Each OS's installer has to be built on that OS. `.github/workflows/build.yml` builds them all on
GitHub (push a `v*` tag): macOS (Apple Silicon and Intel), Windows, Linux x86-64 and Linux ARM64.

### Linux ARM64 (Steam Frame and other ARM devices)

```sh
npm run build:linux-arm64   # needs Docker; output in dist-linux-arm64/
```

This builds inside an ARM64 Ubuntu 22.04 container: natively on an Apple Silicon Mac, emulated
(slower) elsewhere. You get an `.AppImage`, a `.deb` and an `.rpm`.

On a **Steam Frame** (SteamOS, Snapdragon, ARM64): switch to Desktop Mode, copy the `.AppImage`
over, make it executable (right-click → Properties → Permissions, or `chmod +x`), and run it.
The AppImage carries its own copy of the web view, so nothing needs installing. To use a USB
serial adapter on Linux, your user needs to be in the `dialout` group.

Backend tests (`src-tauri/src/tests.rs`). The FTP and FTPS tests start their own FTP server
inside the test. The SSH and SFTP tests run against a real `sshd` on 127.0.0.1:2222 (with
`Subsystem sftp internal-sftp`) when `NIMBUS_TEST_SSHD` points at a folder with the test keys
`client` and `client_enc` (passphrase `secretpass`):

```sh
cd src-tauri && NIMBUS_TEST_SSHD=/path/to/keys cargo test
```

## Layout

```
src/                 UI (vanilla JS + xterm.js)
  main.js            views, editors, tabs, shortcuts
  terminal.js        one terminal tab ↔ one SSH session
  files.js           one file browser tab (local pane + SFTP/FTP pane, transfers)
  prompts.js         host-key / password / 2FA dialogs
src-tauri/src/       Rust core
  ssh.rs             connect, host-key check, auth, jump hosts, PTY pump (russh)
  files.rs           local disk, SFTP and FTP/FTPS browsing and transfers
  serial.rs          serial port sessions
src/apikeys.js       API credential types and "Copy as" formats
docker/, scripts/    the Linux ARM64 build
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
- Port forwarding, agent forwarding, split panes, editing a remote file in place.

import { invoke, Channel } from '@tauri-apps/api/core';

// Thin wrappers over the Rust commands in src-tauri/src/lib.rs.
export const api = {
  state: () => invoke('get_state'),
  saveHost: (host, password) => invoke('save_host', { host, password }),
  duplicateHost: (id) => invoke('duplicate_host', { id }),
  deleteHost: (id) => invoke('delete_host', { id }),
  saveGroup: (group) => invoke('save_group', { group }),
  deleteGroup: (id) => invoke('delete_group', { id }),
  saveKey: (key, privateKey, passphrase) => invoke('save_key', { key, privateKey, passphrase }),
  generateKey: (label) => invoke('generate_key', { label }),
  readTextFile: (path) => invoke('read_text_file', { path }),
  deleteKey: (id) => invoke('delete_key', { id }),
  saveSnippet: (snippet) => invoke('save_snippet', { snippet }),
  deleteSnippet: (id) => invoke('delete_snippet', { id }),
  savePassword: (entry, password) => invoke('save_password', { entry, password }),
  deletePassword: (id) => invoke('delete_password', { id }),
  revealPassword: (id) => invoke('reveal_password', { id }),
  typePassword: (sessionId, secretId) => invoke('ssh_type_password', { sessionId, secretId }),
  deleteKnownHost: (host) => invoke('delete_known_host', { host }),
  saveSettings: (settings) => invoke('save_settings', { settings }),
  exportData: (path, passphrase) => invoke('export_data', { path, passphrase }),
  importPreview: (path) => invoke('import_preview', { path }),
  importApply: (path, mode, passphrase) => invoke('import_apply', { path, mode, passphrase }),
  importSshConfig: () => invoke('import_ssh_config'),
  promptReply: (id, value) => invoke('prompt_reply', { id, value }),

  connect(sessionId, hostId, cols, rows, onEvent, onData) {
    const events = new Channel();
    events.onmessage = onEvent;
    const data = new Channel();
    data.onmessage = onData;
    return invoke('ssh_connect', { sessionId, hostId, cols, rows, events, data });
  },
  write: (sessionId, data) => invoke('ssh_write', { sessionId, data }),
  resize: (sessionId, cols, rows) => invoke('ssh_resize', { sessionId, cols, rows }),
  close: (sessionId) => invoke('ssh_close', { sessionId }),
};

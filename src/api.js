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
  exportData: (path, password) => invoke('export_data', { path, password }),
  importPreview: (path, password) => invoke('import_preview', { path, password }),
  importApply: (path, mode, password) => invoke('import_apply', { path, mode, password }),
  importSshConfig: () => invoke('import_ssh_config'),
  promptReply: (id, value) => invoke('prompt_reply', { id, value }),
  savePasswordGroup: (group) => invoke('save_password_group', { group }),
  saveApiKey: (entry, secrets) => invoke('save_api_key', { entry, secrets }),
  deleteApiKey: (id) => invoke('delete_api_key', { id }),
  revealApiSecret: (id, fieldId) => invoke('reveal_api_secret', { id, fieldId }),
  saveApiGroup: (group) => invoke('save_api_group', { group }),
  deleteApiGroup: (id) => invoke('delete_api_group', { id }),
  deletePasswordGroup: (id) => invoke('delete_password_group', { id }),

  // AI agents (MCP server)
  mcpStatus: () => invoke('mcp_status'),
  mcpConfigure: (enabled, port) => invoke('mcp_configure', { enabled, port }),
  mcpCreateAgent: (name) => invoke('mcp_create_agent', { name }),
  mcpRegenerateToken: (id) => invoke('mcp_regenerate_token', { id }),
  mcpSaveAgent: (agent) => invoke('mcp_save_agent', { agent }),
  mcpDeleteAgent: (id) => invoke('mcp_delete_agent', { id }),
  mcpDecide: (id, decision) => invoke('mcp_decide', { id, decision }),
  mcpActivity: () => invoke('mcp_activity'),
  mcpClearActivity: () => invoke('mcp_clear_activity'),

  // Tabs moving between windows.
  tabHandoff: (sessionId, payload, target, x, y, width, height) => invoke('tab_handoff', { sessionId, payload, target, x, y, width, height }),
  tabClaim: (sessionId) => invoke('tab_claim', { sessionId }),
  tabAttach(sessionId, onEvent, onData = () => {}) {
    const events = new Channel();
    events.onmessage = onEvent;
    const data = new Channel();
    data.onmessage = onData;
    return invoke('tab_attach', { sessionId, events, data });
  },
  tabMove: (sessionId, target) => invoke('tab_move', { sessionId, target }),
  tabWindowMove: (label, x, y) => invoke('tab_window_move', { label, x, y }),
  tabDragOver: (exclude, x, y, done) => invoke('tab_drag_over', { exclude, x, y, done }),
  closeTabWindow: () => invoke('close_tab_window'),
  focusWindow: (label) => invoke('focus_window', { label }),

  // Files tab. sessionId "local" is this computer.
  fsOpen(sessionId, hostId, onEvent) {
    const events = new Channel();
    events.onmessage = onEvent;
    return invoke('fs_open', { sessionId, hostId, events });
  },
  fsClose: (sessionId) => invoke('fs_close', { sessionId }),
  fsList: (sessionId, path) => invoke('fs_list', { sessionId, path }),
  fsMkdir: (sessionId, dir, name) => invoke('fs_mkdir', { sessionId, dir, name }),
  fsRename: (sessionId, dir, from, to) => invoke('fs_rename', { sessionId, dir, from, to }),
  fsDelete: (sessionId, items) => invoke('fs_delete', { sessionId, items }),
  fsTransfer: (sessionId, transferId, upload, items, dest) => invoke('fs_transfer', { sessionId, transferId, upload, items, dest }),
  fsCancel: (sessionId, transferId) => invoke('fs_cancel', { sessionId, transferId }),

  connect(sessionId, hostId, cols, rows, onEvent, onData) {
    const events = new Channel();
    events.onmessage = onEvent;
    const data = new Channel();
    data.onmessage = onData;
    return invoke('ssh_connect', { sessionId, hostId, cols, rows, events, data });
  },
  write: (sessionId, data) => invoke('ssh_write', { sessionId, data }),
  resize: (sessionId, cols, rows) => invoke('ssh_resize', { sessionId, cols, rows }),
  sendBreak: (sessionId) => invoke('ssh_break', { sessionId }),
  serialPorts: () => invoke('serial_ports'),
  close: (sessionId) => invoke('ssh_close', { sessionId }),
};

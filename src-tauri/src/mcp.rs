//! MCP server: lets AI agents (Claude Desktop, Claude Code, Grok, Cursor, …) run commands on
//! hosts and call APIs with stored credentials, without handing them the secrets.
//!
//! How it's kept safe:
//! - Off until the user turns it on. It listens on 127.0.0.1 only, and refuses requests that come
//!   from a web page (an Origin header) or name another host (DNS rebinding).
//! - Every agent has its own random token. Nimbus keeps only the token's hash.
//! - An agent sees only the hosts, passwords and API credentials granted to it, and no notes.
//! - Secrets stay inside Nimbus. Commands log in with the saved key or password, Nimbus answers
//!   `sudo` itself, and API requests get their credentials added by Nimbus, only for the
//!   credential's own site, with the secret scrubbed from whatever comes back.
//! - Commands and requests wait for the user's OK in Nimbus unless the user set that agent to
//!   "allow". Seeing a secret is off by default, and always asks.
//! - No tool changes Nimbus itself: agents can't edit hosts, credentials, settings or their
//!   own access, and can't trust a new host key.
//! - Every call is written to the activity log.
//!
//! Transport: MCP "streamable HTTP" (JSON responses only) at http://127.0.0.1:<port>/mcp, plus a
//! stdio bridge (`Nimbus --mcp`) for clients that only start local commands.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use base64::Engine;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use russh::{ChannelMsg, Disconnect};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::rustls;

use crate::ssh::{connect_host, display_name, Ctx, Prompts};
use crate::store::{new_id, now_ms, ApiCredential, Host, McpAgent, PasswordEntry, Store};

const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_BODY: usize = 4 * 1024 * 1024;
/// Per stream (stdout / stderr / response body) handed back to the agent.
const MAX_OUTPUT: usize = 256 * 1024;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// "Allow for 30 minutes" in the approval dialog.
const REMEMBER_FOR: Duration = Duration::from_secs(30 * 60);
const LOG_KEEP: usize = 500;

// ---------- tokens ----------

pub fn new_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    format!("nimbus_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

pub fn token_hash(token: &str) -> String {
    Sha256::digest(token.trim().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn token_hint(token: &str) -> String {
    let t = token.trim();
    t[t.len().saturating_sub(4)..].to_string()
}

// ---------- the hub: approvals, activity, tools ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Decision {
    Deny,
    Once,
    /// Allow the same kind of action on the same target for `REMEMBER_FOR`.
    Remember,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub time: i64,
    pub agent_id: String,
    pub agent: String,
    pub tool: String,
    /// Host, credential or other thing acted on.
    pub target: String,
    /// The command, request line or field; never a secret value.
    pub detail: String,
    /// "ok", "failed", "denied" or "refused" (not allowed for this agent).
    pub outcome: String,
    pub message: String,
}

/// What the hub tells the UI.
pub enum HubEvent {
    /// Ask the user to approve something; answered with `Hub::decide`.
    Approval(Value),
    /// An approval stopped waiting (timed out, or the server was turned off).
    ApprovalClosed(String),
    Activity(Activity),
}

pub struct Hub {
    store: Arc<Mutex<Store>>,
    events: mpsc::UnboundedSender<HubEvent>,
    pending: Mutex<HashMap<String, oneshot::Sender<Decision>>>,
    remembered: Mutex<HashMap<String, Instant>>,
    log: Mutex<VecDeque<Activity>>,
    log_path: Option<PathBuf>,
    http: Mutex<Option<reqwest::Client>>,
    approval_timeout: Duration,
}

/// Something an agent may use with `http_request` / `get_secret`.
enum Cred {
    Password(PasswordEntry),
    Api(ApiCredential),
}

impl Cred {
    fn id(&self) -> &str {
        match self {
            Cred::Password(p) => &p.id,
            Cred::Api(a) => &a.id,
        }
    }
    fn name(&self) -> &str {
        match self {
            Cred::Password(p) => &p.name,
            Cred::Api(a) => &a.name,
        }
    }
    /// The site requests may go to.
    fn base_url(&self) -> Option<&str> {
        match self {
            Cred::Password(p) => p.url.as_deref(),
            Cred::Api(a) => a.base_url.as_deref(),
        }
    }
}

type ToolResult = Result<String, String>;

impl Hub {
    pub fn new(store: Arc<Mutex<Store>>, events: mpsc::UnboundedSender<HubEvent>) -> Hub {
        let log_path = Some(store.lock().unwrap().dir().join("mcp-activity.log"));
        let mut log = VecDeque::new();
        if let Some(text) = log_path.as_ref().and_then(|p| fs::read_to_string(p).ok()) {
            for line in text.lines() {
                if let Ok(a) = serde_json::from_str::<Activity>(line) {
                    log.push_back(a);
                }
            }
            while log.len() > LOG_KEEP {
                log.pop_front();
            }
            // Keep the file from growing forever.
            if text.lines().count() > LOG_KEEP * 2 {
                let kept: String = log.iter().filter_map(|a| serde_json::to_string(a).ok()).map(|l| l + "\n").collect();
                let _ = crate::store::write_atomic(log_path.as_ref().unwrap(), kept.as_bytes());
            }
        }
        Hub {
            store,
            events,
            pending: Mutex::new(HashMap::new()),
            remembered: Mutex::new(HashMap::new()),
            log: Mutex::new(log),
            log_path,
            http: Mutex::new(None),
            approval_timeout: APPROVAL_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub fn for_tests(store: Arc<Mutex<Store>>, events: mpsc::UnboundedSender<HubEvent>, approval_timeout: Duration) -> Hub {
        let mut h = Hub::new(store, events);
        h.log_path = None;
        h.approval_timeout = approval_timeout;
        h
    }

    pub fn activity(&self) -> Vec<Activity> {
        self.log.lock().unwrap().iter().rev().cloned().collect()
    }

    pub fn clear_activity(&self) {
        self.log.lock().unwrap().clear();
        if let Some(p) = &self.log_path {
            let _ = fs::remove_file(p);
        }
    }

    /// The user answered an approval dialog.
    pub fn decide(&self, id: &str, decision: Decision) {
        if let Some(tx) = self.pending.lock().unwrap().remove(id) {
            let _ = tx.send(decision);
        }
    }

    /// Refuse everything still waiting (the server is being turned off).
    pub fn deny_all(&self) {
        for (id, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(Decision::Deny);
            let _ = self.events.send(HubEvent::ApprovalClosed(id));
        }
        self.remembered.lock().unwrap().clear();
    }

    /// Forget "allow for 30 minutes" answers for one agent (its access changed or it was removed).
    pub fn forget_agent(&self, agent_id: &str) {
        let prefix = format!("{agent_id}|");
        self.remembered.lock().unwrap().retain(|k, _| !k.starts_with(&prefix));
    }

    fn record(&self, agent: &McpAgent, tool: &str, target: &str, detail: &str, result: &ToolResult, refused: bool) {
        let (outcome, message) = match result {
            Ok(_) => ("ok", String::new()),
            Err(m) if m.starts_with(DENIED) || m.starts_with(TIMED_OUT) => ("denied", m.clone()),
            Err(m) if refused => ("refused", m.clone()),
            Err(m) => ("failed", m.clone()),
        };
        let a = Activity {
            time: now_ms(),
            agent_id: agent.id.clone(),
            agent: agent.name.clone(),
            tool: tool.into(),
            target: target.into(),
            detail: detail.chars().take(2000).collect(),
            outcome: outcome.into(),
            message: message.chars().take(500).collect(),
        };
        if let Some(p) = &self.log_path {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", serde_json::to_string(&a).unwrap_or_default());
            }
        }
        let mut log = self.log.lock().unwrap();
        log.push_back(a.clone());
        while log.len() > LOG_KEEP {
            log.pop_front();
        }
        drop(log);
        let _ = self.events.send(HubEvent::Activity(a));
    }

    /// Ask the user, unless they already said "allow for 30 minutes" for this agent + action + target.
    async fn approve(&self, agent: &McpAgent, action: &str, target_id: &str, details: Value, rememberable: bool) -> Result<(), String> {
        let key = format!("{}|{action}|{target_id}", agent.id);
        if rememberable {
            let mut r = self.remembered.lock().unwrap();
            match r.get(&key) {
                Some(until) if *until > Instant::now() => return Ok(()),
                Some(_) => {
                    r.remove(&key);
                }
                None => {}
            }
        }
        let id = new_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id.clone(), tx);
        let mut req = json!({
            "id": id,
            "agent": agent.name,
            "action": action,
            "remember": rememberable,
            "timeoutSecs": self.approval_timeout.as_secs(),
        });
        if let (Some(obj), Value::Object(d)) = (req.as_object_mut(), details) {
            obj.extend(d);
        }
        let _ = self.events.send(HubEvent::Approval(req));
        let answer = tokio::time::timeout(self.approval_timeout, rx).await;
        self.pending.lock().unwrap().remove(&id);
        match answer {
            Ok(Ok(Decision::Once)) => Ok(()),
            Ok(Ok(Decision::Remember)) => {
                if rememberable {
                    self.remembered.lock().unwrap().insert(key, Instant::now() + REMEMBER_FOR);
                }
                Ok(())
            }
            Ok(_) => Err(format!("{DENIED} Don't retry it unless the user asks you to.")),
            Err(_) => {
                let _ = self.events.send(HubEvent::ApprovalClosed(id));
                Err(format!("{TIMED_OUT} Ask the user to watch for the Nimbus approval dialog, then try again."))
            }
        }
    }

    /// The agent behind a token, if it's allowed in right now.
    pub fn agent_for_token(&self, token: &str) -> Option<McpAgent> {
        let hash = token_hash(token);
        let s = self.store.lock().unwrap();
        s.data.mcp.agents.iter().find(|a| !a.token_hash.is_empty() && a.token_hash == hash).cloned()
    }

    fn agent(&self, id: &str) -> Result<McpAgent, String> {
        let mut s = self.store.lock().unwrap();
        let a = s.data.mcp.agents.iter_mut().find(|a| a.id == id).ok_or("This agent was removed from Nimbus")?;
        if a.paused {
            return Err("This agent is paused in Nimbus (Settings → AI agents)".into());
        }
        // Note use without writing the file on every call.
        let now = now_ms();
        let stale = a.last_used.is_none_or(|t| now - t > 60_000);
        a.last_used = Some(now);
        let a = a.clone();
        if stale {
            let _ = s.save();
        }
        Ok(a)
    }

    // ----- what an agent can see -----

    fn hosts_for(s: &Store, a: &McpAgent) -> Vec<Host> {
        s.data
            .hosts
            .iter()
            .filter(|h| h.is_ssh())
            .filter(|h| a.hosts.contains(&h.id) || h.group_id.as_ref().is_some_and(|g| a.host_groups.contains(g)))
            .filter_map(|h| s.effective_host(&h.id))
            .collect()
    }

    fn creds_for(s: &Store, a: &McpAgent) -> Vec<Cred> {
        let pw = s
            .data
            .passwords
            .iter()
            .filter(|p| a.passwords.contains(&p.id) || p.group_id.as_ref().is_some_and(|g| a.password_groups.contains(g)))
            .cloned()
            .map(Cred::Password);
        let api = s
            .data
            .api_keys
            .iter()
            .filter(|k| a.api_keys.contains(&k.id) || k.group_id.as_ref().is_some_and(|g| a.api_groups.contains(g)))
            .cloned()
            .map(Cred::Api);
        pw.chain(api).collect()
    }

    fn find_host(&self, a: &McpAgent, q: &str) -> Result<Host, String> {
        let s = self.store.lock().unwrap();
        let hosts = Self::hosts_for(&s, a);
        pick(hosts, q, |h| &h.id, |h| vec![h.label.clone(), h.address.clone()], "host", "list_hosts")
    }

    fn find_cred(&self, a: &McpAgent, q: &str) -> Result<Cred, String> {
        let s = self.store.lock().unwrap();
        let creds = Self::creds_for(&s, a);
        pick(creds, q, |c| c.id(), |c| vec![c.name().to_string()], "credential", "list_credentials")
    }

    // ----- MCP -----

    fn tools(&self, a: &McpAgent) -> Value {
        let mut tools = vec![
            json!({
                "name": "list_hosts",
                "title": "List hosts",
                "description": "List the SSH hosts the user has let you use in Nimbus. Use a host's id or name with run_command.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": { "readOnlyHint": true },
            }),
            json!({
                "name": "run_command",
                "title": "Run a command over SSH",
                "description": "Run a shell command on one of your hosts over SSH and get its output and exit code. Nimbus logs in with the credentials it has saved; you never see them. The user may have to approve the command in Nimbus first, so this can take a while. Each call is a fresh, non-interactive session (no TTY unless sudo is true), so commands that wait for input will hang until the timeout.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": { "type": "string", "description": "Host id or name, from list_hosts" },
                        "command": { "type": "string", "description": "Shell command to run" },
                        "sudo": { "type": "boolean", "description": "Run it with sudo. Nimbus answers the sudo password prompt with the host's saved password." },
                        "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 900, "description": "Stop waiting after this long (default 60)" },
                    },
                    "required": ["host", "command"],
                },
                "annotations": { "destructiveHint": true, "openWorldHint": true },
            }),
            json!({
                "name": "list_credentials",
                "title": "List credentials",
                "description": "List the passwords and API credentials the user has let you use, without their secret values. Use one with http_request: Nimbus adds the secret to the request for you.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": { "readOnlyHint": true },
            }),
            json!({
                "name": "http_request",
                "title": "Call an API with a stored credential",
                "description": "Make an HTTP request with one of your credentials. Nimbus adds the authentication itself (API key header or parameter, Bearer token, Basic auth, or an OAuth 2.0 client-credentials token) and removes the secret from the response, so you never see it. Requests may only go to the credential's own site (its base URL or website). To place a value yourself, write {{field}} in a header, the body or the URL, where field is a field id or label from list_credentials (for passwords: username or password). Redirects are not followed. The user may have to approve the request first.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential": { "type": "string", "description": "Credential id or name, from list_credentials" },
                        "method": { "type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], "description": "Default GET" },
                        "url": { "type": "string", "description": "Full URL on the credential's site, or a path like /v1/items relative to its base URL" },
                        "headers": { "type": "object", "additionalProperties": { "type": "string" } },
                        "body": { "type": "string", "description": "Request body (send JSON as a string and set Content-Type)" },
                        "auth": { "type": "boolean", "description": "Let Nimbus add the credential's authentication (default true). Set false when you place it with {{field}} yourself." },
                        "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 120 },
                    },
                    "required": ["credential", "url"],
                },
                "annotations": { "openWorldHint": true },
            }),
        ];
        if a.reveal {
            tools.push(json!({
                "name": "get_secret",
                "title": "Ask to see a secret",
                "description": "Ask the user to show you a secret value (a password, or one secret field of an API credential). The user must approve every request in Nimbus. Prefer http_request or run_command, which use secrets without revealing them; only use this when there's no other way.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential": { "type": "string", "description": "Credential id or name, from list_credentials" },
                        "field": { "type": "string", "description": "API credentials: which secret field (id or label). Default: the main key, token or secret." },
                        "reason": { "type": "string", "description": "Why you need it. Shown to the user." },
                    },
                    "required": ["credential", "reason"],
                },
            }));
        }
        json!({ "tools": tools })
    }

    /// Handle one JSON-RPC message from `agent_id`. Notifications get no reply.
    pub async fn rpc(&self, agent_id: &str, msg: Value) -> Option<Value> {
        let id = msg.get("id").cloned()?;
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let agent = match self.agent(agent_id) {
            Ok(a) => a,
            Err(e) => return Some(rpc_error(id, -32001, &e)),
        };
        let result = match method {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
                let version = PROTOCOL_VERSIONS.iter().find(|v| **v == asked).unwrap_or(&PROTOCOL_VERSIONS[0]);
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "nimbus", "title": "Nimbus", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "Nimbus is the user's SSH and credential manager. You can only use the hosts and credentials the user granted to you. Secrets stay inside Nimbus: run_command logs in for you, and http_request adds the credential to API calls. The user may have to approve actions in the Nimbus window, and may decline them; if they do, don't keep retrying.",
                })
            }
            "ping" => json!({}),
            "tools/list" => self.tools(&agent),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                let r = self.call(&agent, name, &args).await;
                match r {
                    Some(Ok(text)) => json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
                    Some(Err(text)) => json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
                    None => return Some(rpc_error(id, -32602, &format!("Unknown tool {name}"))),
                }
            }
            "resources/list" => json!({ "resources": [] }),
            "prompts/list" => json!({ "prompts": [] }),
            _ => return Some(rpc_error(id, -32601, &format!("Method not found: {method}"))),
        };
        Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    async fn call(&self, a: &McpAgent, name: &str, args: &Value) -> Option<ToolResult> {
        let arg = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
        Some(match name {
            "list_hosts" => {
                let s = self.store.lock().unwrap();
                let list: Vec<Value> = Self::hosts_for(&s, a)
                    .iter()
                    .map(|h| {
                        let group = h.group_id.as_deref().and_then(|g| s.group(g)).map(|g| g.name.clone());
                        json!({
                            "id": h.id,
                            "name": display_name(h),
                            "address": h.address,
                            "port": h.port.unwrap_or(22),
                            "username": h.username,
                            "group": group,
                            "tags": h.tags,
                            "sudoPasswordSaved": s.secret(&h.id).password.is_some(),
                        })
                    })
                    .collect();
                Ok(if list.is_empty() {
                    "No hosts have been shared with you yet. The user can grant hosts in Nimbus → Settings → AI agents.".into()
                } else {
                    serde_json::to_string_pretty(&list).unwrap_or_default()
                })
            }
            "list_credentials" => {
                let s = self.store.lock().unwrap();
                let list: Vec<Value> = Self::creds_for(&s, a)
                    .iter()
                    .map(|c| match c {
                        Cred::Password(p) => json!({
                            "id": p.id,
                            "type": "password",
                            "name": p.name,
                            "username": p.username,
                            "url": p.url,
                            "fields": ["username", "password"],
                        }),
                        Cred::Api(k) => {
                            let saved = s.secret(&k.id).fields;
                            json!({
                                "id": k.id,
                                "type": "api",
                                "kind": k.kind,
                                "name": k.name,
                                "service": k.service,
                                "environment": k.environment,
                                "baseUrl": k.base_url,
                                "expires": k.expires,
                                "fields": k.fields.iter().map(|f| if f.secret {
                                    json!({ "id": f.id, "label": f.label, "secret": true, "saved": saved.contains_key(&f.id) })
                                } else {
                                    json!({ "id": f.id, "label": f.label, "value": f.value })
                                }).collect::<Vec<_>>(),
                            })
                        }
                    })
                    .collect();
                Ok(if list.is_empty() {
                    "No credentials have been shared with you yet. The user can grant them in Nimbus → Settings → AI agents.".into()
                } else {
                    serde_json::to_string_pretty(&list).unwrap_or_default()
                })
            }
            "run_command" => {
                let (host_q, command) = (arg("host"), args.get("command").and_then(Value::as_str).unwrap_or("").to_string());
                let sudo = args.get("sudo").and_then(Value::as_bool).unwrap_or(false);
                let timeout = args.get("timeout_seconds").and_then(Value::as_u64).unwrap_or(60).clamp(1, 900);
                let host = match self.find_host(a, &host_q) {
                    Ok(h) => h,
                    Err(e) => {
                        let r = Err(e);
                        self.record(a, name, &host_q, &command, &r, true);
                        return Some(r);
                    }
                };
                let target = format!("{} ({})", display_name(&host), host.address);
                let detail = if sudo { format!("sudo {command}") } else { command.clone() };
                let r = self.run_command(a, &host, &command, sudo, Duration::from_secs(timeout)).await;
                self.record(a, name, &target, &detail, &r, false);
                r
            }
            "http_request" => {
                let cred_q = arg("credential");
                let method = arg("method").to_uppercase();
                let method = if method.is_empty() { "GET".to_string() } else { method };
                let url = arg("url");
                let cred = match self.find_cred(a, &cred_q) {
                    Ok(c) => c,
                    Err(e) => {
                        let r = Err(e);
                        self.record(a, name, &cred_q, &format!("{method} {url}"), &r, true);
                        return Some(r);
                    }
                };
                let target = cred.name().to_string();
                let r = self.http_request(a, &cred, &method, &url, args).await;
                self.record(a, name, &target, &format!("{method} {url}"), &r, false);
                r
            }
            "get_secret" => {
                let cred_q = arg("credential");
                let field = arg("field");
                let r = self.get_secret(a, &cred_q, &field, &arg("reason")).await;
                let refused = !a.reveal;
                let target = self.find_cred(a, &cred_q).map(|c| c.name().to_string()).unwrap_or(cred_q);
                self.record(a, name, &target, if field.is_empty() { "main secret" } else { &field }, &r, refused);
                r
            }
            _ => return None,
        })
    }

    async fn run_command(&self, a: &McpAgent, host: &Host, command: &str, sudo: bool, timeout: Duration) -> ToolResult {
        if command.trim().is_empty() {
            return Err("The command is empty".into());
        }
        if command.len() > 64 * 1024 {
            return Err("That command is too long (over 64 KB)".into());
        }
        let password = self.store.lock().unwrap().secret(&host.id).password;
        if sudo && password.is_none() {
            return Err(format!(
                "No password is saved for {} in Nimbus, so it can't answer sudo. Run it without sudo, or ask the user to save the host's password.",
                display_name(host)
            ));
        }
        if a.commands != "allow" {
            let details = json!({
                "kind": "command",
                "title": format!("{} wants to run a command", a.name),
                "target": format!("{} · {}@{}", display_name(host), host.username.as_deref().unwrap_or("?"), host.address),
                "body": command,
                "sudo": sudo,
            });
            self.approve(a, "run_command", &host.id, details, true).await?;
        }
        let out = exec(self.store.clone(), host.clone(), command, if sudo { password.clone() } else { None }, timeout)
            .await
            .map_err(|e| format!("{e:#}"))?;
        let scrub = |s: String| match &password {
            Some(p) if p.len() >= 4 => s.replace(p.as_str(), "[redacted by Nimbus]"),
            _ => s,
        };
        let mut text = match (out.exit_code, &out.signal) {
            _ if out.timed_out => format!("Timed out after {} s (the command was stopped)", timeout.as_secs()),
            (Some(c), _) => format!("Exit code {c}"),
            (None, Some(sig)) => format!("Killed by signal {sig}"),
            (None, None) => "Finished (no exit code reported)".into(),
        };
        if out.sudo_failed {
            text.push_str("\nsudo didn't accept the password saved in Nimbus for this host.");
        }
        let stdout = scrub(out.stdout);
        let stderr = scrub(out.stderr);
        if !stdout.is_empty() {
            text.push_str(&format!("\n\n--- stdout{} ---\n{stdout}", if out.truncated { " (truncated)" } else { "" }));
        }
        if !stderr.is_empty() {
            text.push_str(&format!("\n\n--- stderr ---\n{stderr}"));
        }
        if stdout.is_empty() && stderr.is_empty() {
            text.push_str("\n(no output)");
        }
        Ok(text)
    }

    async fn http_request(&self, a: &McpAgent, cred: &Cred, method: &str, raw_url: &str, args: &Value) -> ToolResult {
        let base_raw = cred.base_url().ok_or_else(|| {
            format!("“{}” has no website / base URL in Nimbus, so it can't be sent anywhere. Ask the user to add one.", cred.name())
        })?;
        let base = parse_site(base_raw).ok_or_else(|| format!("The base URL saved for “{}” isn't a valid web address", cred.name()))?;
        if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(&method) {
            return Err(format!("Unsupported method {method}"));
        }

        // Every value the agent may reference, and every secret to scrub from the response.
        let (values, mut secrets) = self.cred_values(cred);
        let fill = |s: &str| -> Result<String, String> { fill_placeholders(s, &values) };

        let url_text = if raw_url.starts_with('/') {
            format!("{}{}", base.as_str().trim_end_matches('/'), raw_url)
        } else if raw_url.is_empty() {
            base.to_string()
        } else {
            raw_url.to_string()
        };
        let mut url = reqwest::Url::parse(&fill(&url_text)?).map_err(|_| format!("“{raw_url}” isn't a valid URL"))?;
        if !same_site(&base, &url) {
            return Err(format!(
                "“{}” may only be used with {}. Requests to {} aren't allowed, so the credential can't be sent somewhere else.",
                cred.name(),
                site_label(&base),
                site_label(&url)
            ));
        }

        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(h) = args.get("headers").and_then(Value::as_object) {
            for (k, v) in h {
                let v = fill(v.as_str().unwrap_or(""))?;
                let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).map_err(|_| format!("Bad header name {k}"))?;
                let value = reqwest::header::HeaderValue::from_str(&v).map_err(|_| format!("Bad value for header {k}"))?;
                headers.insert(name, value);
            }
        }
        let body = match args.get("body").and_then(Value::as_str) {
            Some(b) => Some(fill(b)?),
            None => None,
        };

        if a.requests != "allow" {
            let details = json!({
                "kind": "request",
                "title": format!("{} wants to call an API", a.name),
                "target": format!("{} · uses “{}”", site_label(&base), cred.name()),
                "body": format!("{method} {raw_url}{}", args.get("body").and_then(Value::as_str).map(|b| format!("\n\n{}", b.chars().take(2000).collect::<String>())).unwrap_or_default()),
            });
            self.approve(a, "http_request", cred.id(), details, true).await?;
        }

        // Nimbus's own authentication, unless the agent placed it or turned it off.
        let auto = args.get("auth").and_then(Value::as_bool).unwrap_or(true) && !headers.contains_key(reqwest::header::AUTHORIZATION);
        if auto {
            self.add_auth(cred, &values, &mut headers, &mut url, &mut secrets).await?;
        }

        let client = self.http_client()?;
        let timeout = args.get("timeout_seconds").and_then(Value::as_u64).unwrap_or(30).clamp(1, 120);
        let mut req = client
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url.clone())
            .headers(headers)
            .timeout(Duration::from_secs(timeout));
        if let Some(b) = body {
            req = req.body(b);
        }
        let resp = req.send().await.map_err(|e| format!("The request failed: {}", scrub(&e.to_string(), &secrets)))?;
        let status = resp.status();
        let mut text = format!("HTTP {} {}\n", status.as_u16(), status.canonical_reason().unwrap_or(""));
        for (k, v) in resp.headers() {
            if k == reqwest::header::SET_COOKIE {
                continue;
            }
            text.push_str(&format!("{k}: {}\n", scrub(&String::from_utf8_lossy(v.as_bytes()), &secrets)));
        }
        if status.is_redirection() {
            text.push_str("(Redirects aren't followed. Make a new request to the Location if it's on the same site.)\n");
        }
        let mut body = Vec::new();
        let mut truncated = false;
        let mut resp = resp;
        while let Some(chunk) = resp.chunk().await.map_err(|e| format!("Reading the response failed: {e}"))? {
            if body.len() + chunk.len() > MAX_OUTPUT {
                body.extend_from_slice(&chunk[..MAX_OUTPUT - body.len()]);
                truncated = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }
        if !body.is_empty() {
            match String::from_utf8(body) {
                Ok(s) => text.push_str(&format!("\n{}", scrub(&s, &secrets))),
                Err(e) => text.push_str(&format!("\n(binary response, {} bytes, not shown)", e.into_bytes().len())),
            }
            if truncated {
                text.push_str(&format!("\n(response truncated at {} KB)", MAX_OUTPUT / 1024));
            }
        }
        Ok(text)
    }

    /// Placeholder values for a credential (by field id and label, lower-cased) and its secret values.
    fn cred_values(&self, cred: &Cred) -> (HashMap<String, String>, Vec<String>) {
        let s = self.store.lock().unwrap();
        let mut values = HashMap::new();
        let mut secrets = Vec::new();
        match cred {
            Cred::Password(p) => {
                if let Some(u) = &p.username {
                    values.insert("username".into(), u.clone());
                }
                if let Some(pw) = s.secret(&p.id).password {
                    values.insert("password".into(), pw.clone());
                    secrets.push(pw);
                }
            }
            Cred::Api(k) => {
                let saved = s.secret(&k.id).fields;
                for f in &k.fields {
                    let v = if f.secret { saved.get(&f.id).cloned() } else { f.value.clone() };
                    if let Some(v) = v {
                        if f.secret {
                            secrets.push(v.clone());
                        }
                        values.insert(f.id.to_lowercase(), v.clone());
                        if !f.label.is_empty() {
                            values.insert(f.label.to_lowercase(), v);
                        }
                    }
                }
            }
        }
        (values, secrets)
    }

    async fn add_auth(
        &self,
        cred: &Cred,
        values: &HashMap<String, String>,
        headers: &mut reqwest::header::HeaderMap,
        url: &mut reqwest::Url,
        secrets: &mut Vec<String>,
    ) -> Result<(), String> {
        use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION};
        let v = |k: &str| values.get(&k.to_lowercase()).cloned();
        let need = |k: &str, what: &str| v(k).ok_or_else(|| format!("No {what} is saved for “{}” in Nimbus", cred.name()));
        let header = |s: String| HeaderValue::from_str(&s).map_err(|_| "The saved credential can't be used in a header".to_string());
        let basic = |user: String, pass: String, secrets: &mut Vec<String>| -> Result<HeaderValue, String> {
            let b64 = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            secrets.push(b64.clone());
            header(format!("Basic {b64}"))
        };
        match cred {
            Cred::Password(_) => {
                let h = basic(v("username").unwrap_or_default(), need("password", "password")?, secrets)?;
                headers.insert(AUTHORIZATION, h);
            }
            Cred::Api(k) => match k.kind.as_str() {
                "apiKey" => {
                    let key = need("key", "API key")?;
                    let name = v("name").filter(|n| !n.trim().is_empty()).unwrap_or_else(|| "X-API-Key".into());
                    if v("in").as_deref() == Some("query") {
                        url.query_pairs_mut().append_pair(&name, &key);
                    } else {
                        let n = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| format!("“{name}” isn't a valid header name"))?;
                        headers.insert(n, header(key)?);
                    }
                }
                "bearer" => {
                    headers.insert(AUTHORIZATION, header(format!("Bearer {}", need("token", "token")?))?);
                }
                "basic" => {
                    let h = basic(v("username").unwrap_or_default(), need("password", "password")?, secrets)?;
                    headers.insert(AUTHORIZATION, h);
                }
                "oauth2" => {
                    let token = match v("accessToken") {
                        Some(t) => t,
                        None => {
                            let t = self.client_credentials(cred.name(), values).await?;
                            secrets.push(t.clone());
                            t
                        }
                    };
                    headers.insert(AUTHORIZATION, header(format!("Bearer {token}"))?);
                }
                _ => {} // Custom: the agent places fields with {{field}}.
            },
        }
        Ok(())
    }

    /// OAuth 2.0 client-credentials grant against the credential's own token URL.
    async fn client_credentials(&self, name: &str, values: &HashMap<String, String>) -> Result<String, String> {
        let v = |k: &str| values.get(&k.to_lowercase()).cloned();
        let token_url = v("tokenUrl").ok_or_else(|| format!("“{name}” has no access token or token URL saved in Nimbus"))?;
        let (id, secret) = (v("clientId").unwrap_or_default(), v("clientSecret").unwrap_or_default());
        let mut form = vec![("grant_type", "client_credentials".to_string())];
        if let Some(scopes) = v("scopes").filter(|s| !s.trim().is_empty()) {
            form.push(("scope", scopes));
        }
        let body: String = form.iter().map(|(k, v)| format!("{k}={}", urlencode(v))).collect::<Vec<_>>().join("&");
        let resp = self
            .http_client()?
            .post(&token_url)
            .basic_auth(id, Some(secret))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| format!("Getting an OAuth token from {token_url} failed: {e}"))?;
        let status = resp.status();
        let bytes = resp.bytes().await.unwrap_or_default();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        match json.get("access_token").and_then(Value::as_str) {
            Some(t) if status.is_success() => Ok(t.to_string()),
            _ => Err(format!("{token_url} didn't issue a token (HTTP {})", status.as_u16())),
        }
    }

    async fn get_secret(&self, a: &McpAgent, cred_q: &str, field: &str, reason: &str) -> ToolResult {
        if !a.reveal {
            return Err("This agent isn't allowed to see secrets. Use http_request or run_command, which use them without revealing them.".into());
        }
        let cred = self.find_cred(a, cred_q)?;
        let (label, value) = {
            let s = self.store.lock().unwrap();
            match &cred {
                Cred::Password(p) => ("Password".to_string(), s.secret(&p.id).password),
                Cred::Api(k) => {
                    let f = if field.is_empty() {
                        let want = match k.kind.as_str() {
                            "apiKey" => "key",
                            "bearer" => "token",
                            "basic" => "password",
                            "oauth2" => "clientSecret",
                            _ => "",
                        };
                        k.fields.iter().find(|f| f.id == want).or_else(|| k.fields.iter().find(|f| f.secret))
                    } else {
                        let q = field.to_lowercase();
                        k.fields.iter().find(|f| f.id.to_lowercase() == q || f.label.to_lowercase() == q)
                    };
                    let f = f.ok_or_else(|| format!("“{}” has no field “{field}”", k.name))?;
                    let value = if f.secret { s.secret(&k.id).fields.get(&f.id).cloned() } else { f.value.clone() };
                    (if f.label.is_empty() { f.id.clone() } else { f.label.clone() }, value)
                }
            }
        };
        let value = value.ok_or_else(|| format!("Nothing is saved for {label} of “{}”", cred.name()))?;
        let details = json!({
            "kind": "reveal",
            "title": format!("{} wants to see a secret", a.name),
            "target": format!("{label} of “{}”", cred.name()),
            "body": if reason.is_empty() { "(no reason given)".to_string() } else { reason.to_string() },
        });
        self.approve(a, "get_secret", cred.id(), details, false).await?;
        Ok(value)
    }

    fn http_client(&self) -> Result<reqwest::Client, String> {
        let mut slot = self.http.lock().unwrap();
        if let Some(c) = slot.as_ref() {
            return Ok(c.clone());
        }
        let c = build_http_client().map_err(|e| format!("Couldn't set up HTTPS: {e:#}"))?;
        *slot = Some(c.clone());
        Ok(c)
    }
}

const DENIED: &str = "The user declined this in Nimbus.";
const TIMED_OUT: &str = "Nobody approved this in Nimbus within 2 minutes, so it wasn't done.";

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Find one item by id, or by a name (case-insensitive) that only one item has.
fn pick<T>(
    items: Vec<T>,
    q: &str,
    id: impl Fn(&T) -> &str,
    names: impl Fn(&T) -> Vec<String>,
    what: &str,
    list_tool: &str,
) -> Result<T, String> {
    let q = q.trim();
    if q.is_empty() {
        return Err(format!("Say which {what} (an id or name from {list_tool})"));
    }
    if let Some(i) = items.iter().position(|x| id(x) == q) {
        return Ok(items.into_iter().nth(i).unwrap());
    }
    let ql = q.to_lowercase();
    let hits: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, x)| names(x).iter().any(|n| n.to_lowercase() == ql))
        .map(|(i, _)| i)
        .collect();
    match hits.len() {
        1 => Ok(items.into_iter().nth(hits[0]).unwrap()),
        0 => Err(format!("No {what} called “{q}” has been shared with you. Use {list_tool} to see what you can use.")),
        _ => Err(format!("More than one {what} is called “{q}”. Use its id from {list_tool}.")),
    }
}

/// `{{field}}` → the credential's value for that field id or label (case-insensitive).
fn fill_placeholders(s: &str, values: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        let Some(len) = rest[start + 2..].find("}}") else { break };
        let key = rest[start + 2..start + 2 + len].trim().to_lowercase();
        out.push_str(&rest[..start]);
        match values.get(&key) {
            Some(v) => out.push_str(v),
            None => return Err(format!("This credential has no saved value for {{{{{key}}}}}")),
        }
        rest = &rest[start + 2 + len + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn scrub(s: &str, secrets: &[String]) -> String {
    let mut out = s.to_string();
    for sec in secrets.iter().filter(|x| x.len() >= 4) {
        out = out.replace(sec.as_str(), "[redacted by Nimbus]");
    }
    out
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A saved website / base URL, with https:// assumed when it has no scheme.
pub(crate) fn parse_site(raw: &str) -> Option<reqwest::Url> {
    let raw = raw.trim();
    let candidate = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
    let u = reqwest::Url::parse(&candidate).ok()?;
    (matches!(u.scheme(), "http" | "https") && u.host_str().is_some()).then_some(u)
}

/// Same host and port; and never downgraded from https to http.
pub(crate) fn same_site(base: &reqwest::Url, url: &reqwest::Url) -> bool {
    if !matches!(url.scheme(), "http" | "https") || (base.scheme() == "https" && url.scheme() != "https") {
        return false;
    }
    let host = |u: &reqwest::Url| u.host_str().map(|h| h.trim_end_matches('.').to_lowercase());
    host(base).is_some() && host(base) == host(url) && base.port_or_known_default() == url.port_or_known_default()
}

fn site_label(u: &reqwest::Url) -> String {
    match u.port() {
        Some(p) => format!("{}://{}:{p}", u.scheme(), u.host_str().unwrap_or("")),
        None => format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")),
    }
}

pub(crate) fn build_http_client() -> anyhow::Result<reqwest::Client> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())?;
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("Nimbus/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

// ---------- SSH exec for agents ----------

pub struct ExecOutput {
    pub exit_code: Option<u32>,
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub sudo_failed: bool,
}

/// A connection context that answers every login prompt with "cancel": an agent can't trust a
/// new host key or type a password. Returns which prompt was refused, for a useful error.
fn quiet_ctx(store: Arc<Mutex<Store>>) -> (Ctx, Arc<Mutex<Option<String>>>) {
    let prompts = Arc::new(Prompts::default());
    let refused = Arc::new(Mutex::new(None));
    let (p, r) = (prompts.clone(), refused.clone());
    let events = Channel::new(move |body| {
        if let InvokeResponseBody::Json(text) = body {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if v.get("type").and_then(Value::as_str) == Some("prompt") {
                    *r.lock().unwrap() = v.get("kind").and_then(Value::as_str).map(String::from);
                    if let Some(id) = v.get("id").and_then(Value::as_str) {
                        p.reply(id, Value::Null);
                    }
                }
            }
        }
        Ok(())
    });
    (Ctx { store, prompts, events: events.into() }, refused)
}

fn push_capped(buf: &mut Vec<u8>, data: &[u8], truncated: &mut bool) {
    let room = MAX_OUTPUT.saturating_sub(buf.len());
    if data.len() > room {
        *truncated = true;
    }
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Run one command on a host. With `sudo_password`, the command runs under sudo in a PTY and
/// Nimbus types the password when (and only when) sudo asks for it.
pub async fn exec(store: Arc<Mutex<Store>>, host: Host, command: &str, sudo_password: Option<String>, timeout: Duration) -> anyhow::Result<ExecOutput> {
    let (ctx, refused) = quiet_ctx(store);
    let mut jumps = Vec::new();
    let name = display_name(&host);
    let handle = match tokio::time::timeout(Duration::from_secs(40), connect_host(&ctx, host, 0, &mut jumps)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            return Err(match refused.lock().unwrap().as_deref() {
                Some("hostkey") => anyhow!(
                    "Nimbus doesn't trust {name}'s host key yet, or the key has changed. Agents can't accept host keys: ask the user to connect to {name} in Nimbus once and check the key."
                ),
                Some(_) => anyhow!(
                    "{name} needs a username, password, passphrase or 2FA code that isn't saved in Nimbus, and agents can't answer login prompts. Ask the user to save the login for {name} in Nimbus (or use a key)."
                ),
                None => e,
            })
        }
        Err(_) => anyhow::bail!("Timed out connecting to {name}"),
    };

    let mut ch = handle.channel_open_session().await?;
    let marker = format!("[nimbus-sudo-{}]", &new_id()[..8]);
    let full = match &sudo_password {
        Some(_) => {
            ch.request_pty(false, "dumb", 200, 50, 0, 0, &[]).await?;
            format!("sudo -p {} -- sh -c {}", shell_quote(&marker), shell_quote(command))
        }
        None => command.to_string(),
    };
    ch.exec(true, full).await?;

    let deadline = tokio::time::Instant::now() + timeout;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let mut out = ExecOutput { exit_code: None, signal: None, stdout: String::new(), stderr: String::new(), truncated: false, timed_out: false, sudo_failed: false };
    let mut asked = 0;
    let mut scan_from = 0usize;
    loop {
        let msg = match tokio::time::timeout_at(deadline, ch.wait()).await {
            Ok(m) => m,
            Err(_) => {
                out.timed_out = true;
                let _ = ch.signal(russh::Sig::KILL).await;
                let _ = ch.close().await;
                break;
            }
        };
        match msg {
            Some(ChannelMsg::Data { data }) => {
                push_capped(&mut stdout, &data, &mut out.truncated);
                if let Some(pw) = &sudo_password {
                    // Look for sudo's prompt in what's arrived since the last one found.
                    let mut found = 0;
                    while let Some(i) = stdout[scan_from..].windows(marker.len()).position(|w| w == marker.as_bytes()) {
                        found += 1;
                        scan_from += i + marker.len();
                    }
                    if found > 0 {
                        asked += found;
                        if asked == 1 {
                            ch.data_bytes(format!("{pw}\n").into_bytes()).await?;
                        } else {
                            // Wrong password: don't keep guessing.
                            out.sudo_failed = true;
                            ch.data_bytes(&b"\x03"[..]).await?;
                        }
                    }
                }
            }
            Some(ChannelMsg::ExtendedData { data, .. }) => push_capped(&mut stderr, &data, &mut out.truncated),
            Some(ChannelMsg::ExitStatus { exit_status }) => out.exit_code = Some(exit_status),
            Some(ChannelMsg::ExitSignal { signal_name, .. }) => out.signal = Some(format!("{signal_name:?}")),
            Some(ChannelMsg::Close) | None => break,
            _ => {}
        }
    }
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    for j in jumps.into_iter().rev() {
        let _ = j.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    out.stdout = String::from_utf8_lossy(&stdout).into_owned();
    out.stderr = String::from_utf8_lossy(&stderr).into_owned();
    if sudo_password.is_some() {
        // The PTY turns \n into \r\n and echoes sudo's prompt; tidy both away.
        out.stdout = out.stdout.replace(&marker, "").replace("\r\n", "\n");
        if out.stdout.starts_with('\n') {
            out.stdout.remove(0);
        }
    }
    Ok(out)
}

// ---------- HTTP server ----------

pub struct Server {
    pub port: u16,
    stop: Option<oneshot::Sender<()>>,
    conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Server {
    /// Stop listening and drop every open connection (in-flight calls are abandoned).
    pub fn stop(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        for c in self.conns.lock().unwrap().drain(..) {
            c.abort();
        }
    }
}

pub async fn start(hub: Arc<Hub>, port: u16) -> anyhow::Result<Server> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow!("Port {port} is already in use by another program. Pick a different port.")
        } else {
            anyhow!("Couldn't listen on port {port}: {e}")
        }
    })?;
    let port = listener.local_addr()?.port();
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let conns: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
    let conns2 = conns.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let hub = hub.clone();
                    let task = tokio::spawn(async move {
                        let service = hyper::service::service_fn(move |req| handle(hub.clone(), port, req));
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                    let mut c = conns2.lock().unwrap();
                    c.retain(|h| !h.is_finished());
                    c.push(task.abort_handle());
                }
            }
        }
    });
    Ok(Server { port, stop: Some(stop_tx), conns })
}

fn reply(status: StatusCode, body: Value) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(if body.is_null() { vec![] } else { body.to_string().into_bytes() })));
    *r.status_mut() = status;
    if !body.is_null() {
        r.headers_mut().insert("content-type", "application/json".parse().unwrap());
    }
    r
}

fn plain_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    reply(status, json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32000, "message": message } }))
}

/// Requests must be addressed to this machine by name (no DNS rebinding) and must not come
/// from a web page.
fn local_request(req: &Request<Incoming>, port: u16) -> bool {
    let host_ok = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")].iter().any(|ok| h.eq_ignore_ascii_case(ok)));
    let origin_ok = match req.headers().get("origin").and_then(|o| o.to_str().ok()) {
        None => true,
        Some(o) => reqwest::Url::parse(o).ok().is_some_and(|u| matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))),
    };
    host_ok && origin_ok
}

async fn handle(hub: Arc<Hub>, port: u16, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if !local_request(&req, port) {
        return Ok(plain_error(StatusCode::FORBIDDEN, "Requests from web pages or other host names are refused"));
    }
    if req.uri().path().trim_end_matches('/') != "/mcp" {
        return Ok(plain_error(StatusCode::NOT_FOUND, "Nimbus's MCP endpoint is /mcp"));
    }
    if req.method() == hyper::Method::DELETE {
        return Ok(reply(StatusCode::OK, Value::Null));
    }
    if req.method() != hyper::Method::POST {
        let mut r = plain_error(StatusCode::METHOD_NOT_ALLOWED, "Use POST");
        r.headers_mut().insert("allow", "POST, DELETE".parse().unwrap());
        return Ok(r);
    }
    let token = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")))
        .unwrap_or("")
        .to_string();
    let Some(agent) = (!token.is_empty()).then(|| hub.agent_for_token(&token)).flatten() else {
        // Slow down anything guessing tokens.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut r = plain_error(StatusCode::UNAUTHORIZED, "Nimbus doesn't recognise this agent's token");
        r.headers_mut().insert("www-authenticate", "Bearer".parse().unwrap());
        return Ok(r);
    };
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return Ok(plain_error(StatusCode::PAYLOAD_TOO_LARGE, "Request too large")),
    };
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return Ok(reply(StatusCode::BAD_REQUEST, json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }))),
    };
    let out = match msg {
        Value::Array(batch) => {
            let mut replies = Vec::new();
            for m in batch {
                if let Some(r) = hub.rpc(&agent.id, m).await {
                    replies.push(r);
                }
            }
            (!replies.is_empty()).then_some(Value::Array(replies))
        }
        m => hub.rpc(&agent.id, m).await,
    };
    Ok(match out {
        Some(v) => reply(StatusCode::OK, v),
        None => reply(StatusCode::ACCEPTED, Value::Null),
    })
}

// ---------- stdio bridge (`Nimbus --mcp`) ----------

/// POST one message to the running app's MCP endpoint. Returns (status, body).
async fn post(port: u16, token: &str, body: String) -> anyhow::Result<(u16, Vec<u8>)> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    let req = Request::post("/mcp")
        .header("host", format!("127.0.0.1:{port}"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Full::new(Bytes::from(body)))?;
    let resp = sender.send_request(req).await?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, body))
}

/// Relay newline-delimited JSON-RPC between stdio and the running Nimbus app. Requests run
/// concurrently, so a long command doesn't hold up pings or other calls.
pub async fn bridge<R, W>(port: u16, token: String, input: R, mut output: W) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = input.lines();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    let mut open = true;
    let mut running = 0usize;
    while open || running > 0 {
        tokio::select! {
            line = lines.next_line(), if open => match line? {
                None => open = false,
                Some(l) if l.trim().is_empty() => {}
                Some(l) => {
                    let id = serde_json::from_str::<Value>(&l).ok().and_then(|v| v.get("id").cloned());
                    let (tx, token) = (tx.clone(), token.clone());
                    running += 1;
                    tokio::spawn(async move {
                        let reply = match post(port, &token, l).await {
                            Ok((200, body)) => serde_json::from_slice::<Value>(&body).ok().map(|v| v.to_string()),
                            Ok((202, _)) => None,
                            Ok((status, body)) => {
                                let msg = serde_json::from_slice::<Value>(&body)
                                    .ok()
                                    .and_then(|v| v.pointer("/error/message").and_then(Value::as_str).map(String::from))
                                    .unwrap_or_else(|| format!("Nimbus answered HTTP {status}"));
                                let msg = if status == 401 {
                                    "Nimbus didn't accept this agent's token. Copy the setup again from Nimbus → Settings → AI agents.".to_string()
                                } else { msg };
                                id.clone().map(|id| rpc_error(id, -32000, &msg).to_string())
                            }
                            Err(_) => id.clone().map(|id| rpc_error(id, -32000, "Nimbus isn't running, or AI agent access is turned off (Nimbus → Settings → AI agents).").to_string()),
                        };
                        let _ = tx.send(reply.unwrap_or_default());
                    });
                }
            },
            Some(r) = rx.recv() => {
                running -= 1;
                if !r.is_empty() {
                    output.write_all(r.as_bytes()).await?;
                    output.write_all(b"\n").await?;
                    output.flush().await?;
                }
            }
        }
    }
    Ok(())
}

/// Entry point for `Nimbus --mcp`. Settings come from NIMBUS_MCP_TOKEN and NIMBUS_MCP_PORT
/// (or `--token` / `--port`).
pub fn stdio_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let token = flag("--token").or_else(|| std::env::var("NIMBUS_MCP_TOKEN").ok()).unwrap_or_default();
    let port = flag("--port")
        .or_else(|| std::env::var("NIMBUS_MCP_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(crate::store::MCP_DEFAULT_PORT);
    if token.trim().is_empty() {
        eprintln!("nimbus --mcp: set NIMBUS_MCP_TOKEN to the agent token from Nimbus → Settings → AI agents");
        return 2;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nimbus --mcp: {e}");
            return 1;
        }
    };
    match rt.block_on(bridge(port, token.trim().to_string(), tokio::io::BufReader::new(tokio::io::stdin()), tokio::io::stdout())) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("nimbus --mcp: {e:#}");
            1
        }
    }
}

/// Where this copy of Nimbus lives, for the stdio setup snippet. An AppImage runs from a
/// temporary mount, so use the AppImage file itself.
pub fn exe_path() -> String {
    std::env::var("APPIMAGE")
        .ok()
        .filter(|p| !p.is_empty())
        .or_else(|| std::env::current_exe().ok().map(|p| p.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

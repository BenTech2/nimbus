//! What Remote Desktop (rdp.rs) and VNC (vnc.rs) tabs share: the messages from the UI, the way
//! the screen is streamed to the tab's canvas, the clipboard, and reaching the server (directly
//! or through an SSH jump host).
//!
//! The screen is sent as changed rectangles of RGBA pixels on the tab's data channel. The UI
//! acknowledges each batch once drawn; while two are unacknowledged, further changes are merged
//! and sent when it catches up, so a slow machine sees fewer, larger updates rather than a
//! growing backlog.
//!
//! Binary messages on the data channel (little-endian):
//!   1 frame:    seq u32, count u16, then per rect: x u16, y u16, w u16, h u16, w*h*4 RGBA bytes
//!   2 size:     width u16, height u16 (the desktop was (re)sized; a full frame follows)
//!   3 pointer:  width u16, height u16, hotspot x u16, hotspot y u16, RGBA bytes
//!   4 pointer hidden
//!   5 pointer default

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use serde::Deserialize;
use tauri::ipc::InvokeResponseBody;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::ssh::{self, Ctx, Relay};
use crate::store::Host;

/// What the UI sends a running desktop session (wrapped in `Input::Desktop`).
#[derive(Debug)]
pub enum Cmd {
    Input(Vec<Ev>),
    /// The tab's area is now this many device pixels, at this scale (100 = 100%).
    Resize { width: u32, height: u32, scale: u32 },
    /// The UI has drawn the frame with this sequence number.
    Ack(u32),
    /// The tab moved to another window: send everything again.
    Refresh,
    /// Type this text (a saved password) as characters; "\r" presses Enter.
    Type(String),
}

/// One keyboard or mouse event from the UI. Positions are in desktop pixels.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "t")]
pub enum Ev {
    /// Pointer moved.
    #[serde(rename = "m")]
    Move { x: u16, y: u16 },
    /// Button 0 left, 1 middle, 2 right, 3 back, 4 forward; `d` is down.
    #[serde(rename = "b")]
    Button { x: u16, y: u16, b: u8, d: bool },
    /// Wheel turned by `v` (120 per notch; positive is up, or right when `h`).
    #[serde(rename = "w")]
    Wheel { x: u16, y: u16, v: i16, h: bool },
    /// A key: `c` its scancode (`e` for the extended E0 keys), for RDP; `k` the X11 keysym of
    /// what it types, for VNC.
    #[serde(rename = "k")]
    Key {
        c: u8,
        e: bool,
        d: bool,
        #[serde(default)]
        k: u32,
    },
    /// A character the keyboard can't express as a key (IME, emoji, …), as UTF-16.
    #[serde(rename = "u")]
    Unicode { c: u16, d: bool },
    /// Caps / Num / Scroll Lock state, so the remote matches this keyboard.
    #[serde(rename = "s")]
    Sync { f: u8 },
    /// Offer this computer's clipboard to the remote now (sent on focus and before a paste).
    #[serde(rename = "c")]
    Clipboard,
}

/// This computer's clipboard. A trait so tests can use one in memory.
pub trait Clipboard: Send + Sync {
    fn read(&self) -> Option<String>;
    fn write(&self, text: String);
}

/// The clipboard as last synced, so the same text isn't offered back and forth.
#[derive(Default)]
pub struct ClipState {
    pub offered: Option<String>,
    pub received: Option<String>,
}

impl ClipState {
    /// This computer's clipboard text if it's new to the remote (or always, when `always`).
    /// `None` means there's nothing to offer.
    pub fn fresh(&mut self, cb: &dyn Clipboard, always: bool) -> Option<Option<String>> {
        let text = cb.read().filter(|t| !t.is_empty());
        if !always && (text.is_none() || text == self.offered || text == self.received) {
            return None;
        }
        self.offered = text.clone();
        Some(text)
    }
}

/// Frames the UI hasn't drawn yet before we stop sending and start merging.
pub const IN_FLIGHT_MAX: u32 = 2;
/// Merge into one rectangle beyond this many changed areas.
const MAX_RECTS: usize = 32;
/// Wait for the size to settle before resizing the remote desktop.
pub const RESIZE_SETTLE: Duration = Duration::from_millis(350);

/// A rectangle of the desktop, edges inclusive.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub left: u16,
    pub top: u16,
    pub right: u16,
    pub bottom: u16,
}

impl Rect {
    /// From a position and size; `None` when empty.
    pub fn at(x: u16, y: u16, w: u16, h: u16) -> Option<Rect> {
        (w > 0 && h > 0).then(|| Rect { left: x, top: y, right: x.saturating_add(w - 1), bottom: y.saturating_add(h - 1) })
    }

    fn width(&self) -> u16 {
        self.right - self.left + 1
    }

    fn height(&self) -> u16 {
        self.bottom - self.top + 1
    }

    fn area(&self) -> u64 {
        u64::from(self.width()) * u64::from(self.height())
    }
}

fn bounds(rects: &[Rect]) -> Rect {
    let mut b = rects[0];
    for r in &rects[1..] {
        b.left = b.left.min(r.left);
        b.top = b.top.min(r.top);
        b.right = b.right.max(r.right);
        b.bottom = b.bottom.max(r.bottom);
    }
    b
}

/// What the UI is shown: changed areas waiting to be sent, and how far behind the UI is.
pub struct Screen {
    dirty: Vec<Rect>,
    full: bool,
    in_flight: u32,
    seq: u32,
    last_sent: Instant,
    /// The last pointer message, sent again when the tab moves window.
    pub pointer: Option<Vec<u8>>,
}

impl Default for Screen {
    fn default() -> Self {
        Screen { dirty: Vec::new(), full: true, in_flight: 0, seq: 0, last_sent: Instant::now(), pointer: None }
    }
}

impl Screen {
    pub fn add(&mut self, r: Rect) {
        if self.full {
            return;
        }
        self.dirty.push(r);
        if self.dirty.len() > MAX_RECTS {
            let b = bounds(&self.dirty);
            self.dirty = vec![b];
        }
    }

    /// Everything is sent again next time (new size, new window).
    pub fn reset(&mut self) {
        self.dirty.clear();
        self.full = true;
        self.in_flight = 0;
    }

    /// The UI drew frame `seq` (and so everything before it).
    pub fn ack(&mut self, seq: u32) {
        let behind = self.seq.wrapping_sub(seq);
        self.in_flight = self.in_flight.min(behind);
    }

    /// The UI dropped an acknowledgement (a window closing mid-frame): carry on.
    pub fn unstick(&mut self) {
        if self.in_flight >= IN_FLIGHT_MAX && self.last_sent.elapsed() > Duration::from_secs(2) {
            self.in_flight = 0;
        }
    }

    pub fn set_pointer(&mut self, msg: Vec<u8>, out: &Relay<InvokeResponseBody>) {
        self.pointer = Some(msg.clone());
        let _ = out.send(InvokeResponseBody::Raw(msg));
    }

    /// The tab arrived in another window: its size, pointer and a full frame.
    pub fn refresh(&mut self, w: u16, h: u16, data: &[u8], out: &Relay<InvokeResponseBody>) {
        self.reset();
        let _ = out.send(size_msg(w, h));
        let _ = out.send(InvokeResponseBody::Raw(self.pointer.clone().unwrap_or_else(|| vec![5u8])));
        self.flush(w, h, data, out);
    }

    /// Send what changed, unless the UI is still busy with earlier frames. `data` is the
    /// desktop as RGBA, `w` × `h`.
    pub fn flush(&mut self, w: u16, h: u16, data: &[u8], out: &Relay<InvokeResponseBody>) {
        if !out.is_live() {
            // Moving to another window: it gets a full frame when it arrives.
            self.reset();
            return;
        }
        if self.in_flight >= IN_FLIGHT_MAX || (!self.full && self.dirty.is_empty()) || w == 0 || h == 0 {
            return;
        }
        let clamp = |r: &Rect| -> Option<Rect> {
            let r = Rect { left: r.left, top: r.top, right: r.right.min(w - 1), bottom: r.bottom.min(h - 1) };
            (r.left <= r.right && r.top <= r.bottom).then_some(r)
        };
        let mut rects: Vec<Rect> = if self.full {
            vec![Rect { left: 0, top: 0, right: w - 1, bottom: h - 1 }]
        } else {
            self.dirty.iter().filter_map(clamp).collect()
        };
        self.dirty.clear();
        self.full = false;
        if rects.is_empty() {
            return;
        }
        // Overlapping or scattered small areas: one rectangle is cheaper to send and draw.
        let b = bounds(&rects);
        if rects.len() > 1 && rects.iter().map(Rect::area).sum::<u64>() * 10 >= b.area() * 7 {
            rects = vec![b];
        }

        let bytes: usize = rects.iter().map(|r| r.area() as usize * 4 + 8).sum();
        let mut msg = Vec::with_capacity(7 + bytes);
        self.seq = self.seq.wrapping_add(1);
        msg.push(1u8);
        msg.extend_from_slice(&self.seq.to_le_bytes());
        msg.extend_from_slice(&(rects.len() as u16).to_le_bytes());
        let stride = usize::from(w) * 4;
        for r in &rects {
            let (rw, rh) = (r.width(), r.height());
            for v in [r.left, r.top, rw, rh] {
                msg.extend_from_slice(&v.to_le_bytes());
            }
            for row in r.top..=r.bottom {
                let start = usize::from(row) * stride + usize::from(r.left) * 4;
                let at = msg.len();
                msg.extend_from_slice(&data[start..start + usize::from(rw) * 4]);
                // The desktop is opaque; some codecs leave alpha at 0.
                for a in msg[at + 3..].iter_mut().step_by(4) {
                    *a = 255;
                }
            }
        }
        let _ = out.send(InvokeResponseBody::Raw(msg));
        self.in_flight += 1;
        self.last_sent = Instant::now();
    }
}

pub fn size_msg(w: u16, h: u16) -> InvokeResponseBody {
    let mut m = vec![2u8];
    m.extend_from_slice(&w.to_le_bytes());
    m.extend_from_slice(&h.to_le_bytes());
    InvokeResponseBody::Raw(m)
}

/// A pointer shape: `rgba` is `w` × `h` straight (not premultiplied) RGBA.
pub fn pointer_msg(w: u16, h: u16, hx: u16, hy: u16, rgba: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(9 + rgba.len());
    m.push(3u8);
    for v in [w, h, hx, hy] {
        m.extend_from_slice(&v.to_le_bytes());
    }
    m.extend_from_slice(rgba);
    m
}

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}

/// A connection to the host's address and port: directly, or tunnelled through its SSH jump
/// host (whose connections are kept in `jumps` and closed with [`close_jumps`]).
pub async fn open_stream(
    ctx: &Ctx,
    host: &Host,
    port: u16,
    jumps: &mut Vec<russh::client::Handle<ssh::Client>>,
) -> anyhow::Result<(Box<dyn Stream>, SocketAddr)> {
    let target = format!("{}:{port}", host.address);
    close_jumps(jumps).await;
    if let Some(jump_id) = host.jump_host_id.as_deref().filter(|s| !s.is_empty()) {
        let jump = ctx
            .store
            .lock()
            .unwrap()
            .effective_host(jump_id)
            .ok_or_else(|| anyhow!("The jump host for “{}” no longer exists", ssh::display_name(host)))?;
        let handle = ssh::connect_host(ctx, jump, 1, jumps).await?;
        ctx.status("connecting", format!("Tunnelling to {target}…"));
        let channel = handle
            .channel_open_direct_tcpip(host.address.clone(), u32::from(port), "127.0.0.1", 0)
            .await
            .map_err(|e| anyhow!("The jump host could not reach {target}: {e}"))?;
        jumps.push(handle);
        // An in-memory pipe in front of the SSH channel, which can be shared between tasks.
        let (ours, theirs) = tokio::io::duplex(256 * 1024);
        let mut channel = channel.into_stream();
        tauri::async_runtime::spawn(async move {
            let mut theirs = theirs;
            let _ = tokio::io::copy_bidirectional(&mut theirs, &mut channel).await;
        });
        return Ok((Box::new(ours), SocketAddr::from(([127, 0, 0, 1], 0))));
    }
    let tcp = match tokio::time::timeout(Duration::from_secs(20), tokio::net::TcpStream::connect((host.address.as_str(), port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(anyhow!("Could not connect to {target}: {e}")),
        Err(_) => return Err(anyhow!("Timed out connecting to {target}")),
    };
    let _ = tcp.set_nodelay(true);
    let addr = tcp.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    Ok((Box::new(tcp), addr))
}

pub async fn close_jumps(jumps: &mut Vec<russh::client::Handle<ssh::Client>>) {
    for j in jumps.drain(..).rev() {
        let _ = j.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    }
}

/// Ask to trust a server's TLS certificate; saves it under `key` when trusted.
pub async fn trust_certificate(ctx: &Ctx, key: &str, shown: &str, fingerprint: &str, previous: Option<&str>, note: &str) -> bool {
    let answer = ctx
        .ask(
            "hostkey",
            serde_json::json!({ "host": shown, "keyType": "TLS certificate", "fingerprint": fingerprint, "previous": previous, "note": note }),
        )
        .await;
    let ok = answer.and_then(|v| v.get("accept").and_then(serde_json::Value::as_bool)).unwrap_or(false);
    if ok {
        let kh = crate::store::KnownHost {
            host: key.to_string(),
            key_type: "TLS certificate".into(),
            fingerprint: fingerprint.to_string(),
            added: crate::store::now_ms(),
        };
        ctx.save_store(|s| s.set_known_host(kh));
    }
    ok
}

/// Mark the host as just connected.
pub fn connected(ctx: &Ctx, host_id: &str) {
    ctx.status("connected", "");
    let id = host_id.to_string();
    ctx.save_store(|s| {
        if let Some(h) = s.data.hosts.iter_mut().find(|h| h.id == id) {
            h.last_connected = Some(crate::store::now_ms());
        }
    });
}

pub fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        let t = c.to_string();
        if !s.contains(&t) {
            s.push_str(": ");
            s.push_str(&t);
        }
        src = c.source();
    }
    s
}

/// Erase a future's type, so the compiler checks it's `Send` here rather than in each caller
/// (IronRDP's connection futures trip a compiler limitation otherwise).
pub fn boxed<'a, T>(f: impl std::future::Future<Output = T> + Send + 'a) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>> {
    Box::pin(f)
}

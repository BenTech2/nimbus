//! Serial console sessions: a local serial port (USB adapter, built-in COM port) shown in a
//! terminal tab, with the same input / status / data channels as an SSH session.

use std::io::{ErrorKind, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail};
use serde::Serialize;
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use tauri::ipc::InvokeResponseBody;
use tokio::sync::mpsc;

use crate::ssh::{Ctx, Input, Relay};
use crate::store::{now_ms, Host};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortInfo {
    pub name: String,
    /// e.g. "FT232R USB UART (FTDI)", or "Bluetooth" / "Built-in".
    pub description: String,
}

/// Serial ports on this computer. On macOS each device appears twice (`/dev/tty.*` and
/// `/dev/cu.*`); only the `cu` one is listed, as it's the one to open for an outgoing connection.
pub fn list_ports() -> anyhow::Result<Vec<PortInfo>> {
    let mut ports: Vec<PortInfo> = serialport::available_ports()?
        .into_iter()
        .filter(|p| !(cfg!(target_os = "macos") && p.port_name.starts_with("/dev/tty.")))
        .map(|p| {
            let description = match p.port_type {
                serialport::SerialPortType::UsbPort(u) => {
                    let parts: Vec<String> = [u.product, u.manufacturer.map(|m| format!("({m})"))].into_iter().flatten().collect();
                    if parts.is_empty() { format!("USB {:04x}:{:04x}", u.vid, u.pid) } else { parts.join(" ") }
                }
                serialport::SerialPortType::BluetoothPort => "Bluetooth".into(),
                serialport::SerialPortType::PciPort => "Built-in".into(),
                serialport::SerialPortType::Unknown => String::new(),
            };
            PortInfo { name: p.port_name, description }
        })
        .collect();
    ports.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ports)
}

/// Port settings from a host, with the usual 9600 8N1, no flow control as defaults.
pub fn describe(h: &Host) -> String {
    let parity = match h.parity.as_deref() {
        Some("odd") => "O",
        Some("even") => "E",
        _ => "N",
    };
    format!("{} baud, {}{}{}", h.baud_rate.unwrap_or(9600), h.data_bits.unwrap_or(8), parity, h.stop_bits.unwrap_or(1))
}

fn open(h: &Host) -> anyhow::Result<Box<dyn SerialPort>> {
    let path = h.address.trim();
    if path.is_empty() {
        bail!("Choose a serial port for “{}”", h.label);
    }
    let builder = serialport::new(path, h.baud_rate.unwrap_or(9600))
        .data_bits(match h.data_bits.unwrap_or(8) {
            5 => DataBits::Five,
            6 => DataBits::Six,
            7 => DataBits::Seven,
            _ => DataBits::Eight,
        })
        .parity(match h.parity.as_deref() {
            Some("odd") => Parity::Odd,
            Some("even") => Parity::Even,
            _ => Parity::None,
        })
        .stop_bits(if h.stop_bits == Some(2) { StopBits::Two } else { StopBits::One })
        .flow_control(match h.flow_control.as_deref() {
            Some("hardware") => FlowControl::Hardware,
            Some("software") => FlowControl::Software,
            _ => FlowControl::None,
        })
        // Short, so the reader notices a closed session quickly.
        .timeout(Duration::from_millis(100));
    builder.open().map_err(|e| match e.kind() {
        serialport::ErrorKind::NoDevice => anyhow!("{path} isn't connected. Check the cable, or pick the port again in the host's settings."),
        serialport::ErrorKind::Io(ErrorKind::PermissionDenied) if cfg!(target_os = "linux") => {
            anyhow!("Permission denied opening {path}. Add yourself to the “dialout” group (sudo usermod -aG dialout $USER), then log out and back in.")
        }
        serialport::ErrorKind::Io(ErrorKind::PermissionDenied) => anyhow!("{path} is busy or not allowed. Close any other program using it."),
        _ => anyhow!("Could not open {path}: {e}"),
    })
}

/// What Enter (a carriage return from the terminal) is sent as.
pub fn translate_enter(bytes: &[u8], newline: Option<&str>) -> Vec<u8> {
    let with: &[u8] = match newline {
        Some("lf") => b"\n",
        Some("crlf") => b"\r\n",
        _ => return bytes.to_vec(),
    };
    let mut out = Vec::with_capacity(bytes.len() + 4);
    for &b in bytes {
        if b == b'\r' { out.extend_from_slice(with) } else { out.push(b) }
    }
    out
}

pub async fn run_serial(ctx: Ctx, host_id: String, data: Relay<InvokeResponseBody>, mut rx: mpsc::UnboundedReceiver<Input>) {
    match serial_inner(&ctx, &host_id, &data, &mut rx).await {
        Ok(msg) => ctx.status("closed", msg),
        Err(e) => ctx.status("error", format!("{e:#}")),
    }
}

async fn serial_inner(
    ctx: &Ctx,
    host_id: &str,
    data: &Relay<InvokeResponseBody>,
    rx: &mut mpsc::UnboundedReceiver<Input>,
) -> anyhow::Result<String> {
    let host = ctx.store.lock().unwrap().effective_host(host_id).ok_or_else(|| anyhow!("This host no longer exists"))?;
    ctx.status("connecting", format!("Opening {} ({})…", host.address, describe(&host)));
    let h = host.clone();
    let port = tokio::task::spawn_blocking(move || open(&h)).await??;
    let mut reader = port.try_clone()?;
    let writer = Arc::new(Mutex::new(port));
    ctx.status("connected", "");
    let id = host_id.to_string();
    ctx.save_store(|s| {
        if let Some(h) = s.data.hosts.iter_mut().find(|h| h.id == id) {
            h.last_connected = Some(now_ms());
        }
    });

    // Reading blocks, so it gets its own thread; it reports a lost device back here.
    let stop = Arc::new(AtomicBool::new(false));
    let (lost_tx, mut lost_rx) = mpsc::unbounded_channel::<String>();
    let (stop2, out) = (stop.clone(), data.clone());
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while !stop2.load(Ordering::SeqCst) {
            match reader.read(&mut buf) {
                Ok(0) => std::thread::sleep(Duration::from_millis(20)),
                Ok(n) => {
                    let _ = out.send(InvokeResponseBody::Raw(buf[..n].to_vec()));
                }
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(e) => {
                    let _ = lost_tx.send(format!("The device was disconnected ({e})"));
                    break;
                }
            }
        }
    });

    let result = loop {
        tokio::select! {
            lost = lost_rx.recv() => break Err(anyhow!(lost.unwrap_or_else(|| "The device was disconnected".into()))),
            input = rx.recv() => match input {
                Some(Input::Data(bytes)) => {
                    if host.local_echo {
                        // Show what was typed, with Enter moving to a new line.
                        let echo: Vec<u8> = bytes.iter().flat_map(|&b| if b == b'\r' { vec![b'\r', b'\n'] } else { vec![b] }).collect();
                        let _ = data.send(InvokeResponseBody::Raw(echo));
                    }
                    let bytes = translate_enter(&bytes, host.newline.as_deref());
                    let w = writer.clone();
                    let r = tokio::task::spawn_blocking(move || w.lock().unwrap().write_all(&bytes)).await?;
                    if let Err(e) = r {
                        if e.kind() != ErrorKind::TimedOut {
                            break Err(anyhow!("The device was disconnected ({e})"));
                        }
                    }
                }
                Some(Input::Break) => {
                    let w = writer.clone();
                    let r = tokio::task::spawn_blocking(move || -> serialport::Result<()> {
                        let p = w.lock().unwrap();
                        p.set_break()?;
                        std::thread::sleep(Duration::from_millis(300));
                        p.clear_break()
                    })
                    .await?;
                    if let Err(e) = r {
                        let _ = data.send(InvokeResponseBody::Raw(format!("\r\n[Nimbus: couldn't send a break: {e}]\r\n").into_bytes()));
                    }
                }
                Some(Input::Resize(..)) | Some(Input::Desktop(_)) => {}
                Some(Input::Close) | None => break Ok("Port closed".to_string()),
            },
        }
    };
    stop.store(true, Ordering::SeqCst);
    result
}

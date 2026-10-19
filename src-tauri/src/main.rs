// No console window on Windows. `Nimbus --mcp` still gets the pipes its MCP client gives it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--mcp") {
        std::process::exit(nimbus_lib::mcp_stdio());
    }
    nimbus_lib::run()
}

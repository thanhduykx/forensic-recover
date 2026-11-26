#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::TauriScanState;
use std::sync::{Arc, Mutex};

fn main() {
    let state = Arc::new(Mutex::new(TauriScanState::default()));
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::list_sources,
            commands::inspect_source_cmd,
            commands::check_destination_cmd,
            commands::start_scan_cmd,
            commands::cancel_scan_cmd,
            commands::get_scan_status_cmd,
            commands::list_recovered_items_cmd,
            commands::recover_items_cmd,
            commands::scan_ios_backup_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Forensic Recover Tauri application");
}

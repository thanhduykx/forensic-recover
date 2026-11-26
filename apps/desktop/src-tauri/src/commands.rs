use recover_core::companion::{list_adb_devices, probe_libimobiledevice};
use recover_core::models::{
    RecoveredItem, ScanConfig, ScanProgress, ScanSession, SourceInspectInfo,
};
use recover_core::ScanFacade;
use serde::Serialize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::State;

#[derive(Default)]
pub struct TauriScanState {
    pub running: bool,
    pub progress: Option<ScanProgress>,
    pub last_error: Option<String>,
    pub session: Option<ScanSession>,
    pub items: Vec<RecoveredItem>,
    pub cancel_flag: Option<Arc<AtomicBool>>,
}

#[derive(Serialize)]
pub struct SourceListDto {
    pub sources: Vec<String>,
    pub vss_snapshots: Vec<String>,
    pub adb_devices: Vec<recover_core::companion::AdbDeviceInfo>,
    pub ios_udids: Option<String>,
}

#[derive(Serialize)]
pub struct DestCheckDto {
    pub safe: bool,
    pub warnings: Vec<String>,
    pub destination_free_bytes: u64,
}

#[derive(Serialize)]
pub struct StatusDto {
    pub running: bool,
    pub progress: Option<ScanProgress>,
    pub last_error: Option<String>,
    pub session: Option<ScanSession>,
    pub items_count: usize,
}

#[derive(Serialize)]
pub struct ExportDto {
    pub exported: Vec<String>,
}

#[tauri::command]
pub fn list_sources() -> SourceListDto {
    let mut sources = Vec::new();
    #[cfg(windows)]
    {
        for i in 0..8 {
            sources.push(format!(r"\\.\PhysicalDrive{i}"));
        }
        for letter in b'C'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            if Path::new(&root).exists() {
                sources.push(format!(r"\\.\{}:", letter as char));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if (name.starts_with("sd") && name.len() == 3)
                    || (name.starts_with("nvme") && !name.contains('p'))
                {
                    sources.push(format!("/dev/{name}"));
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for i in 0..8 {
            let p = format!("/dev/rdisk{i}");
            if Path::new(&p).exists() {
                sources.push(p);
            }
        }
    }
    SourceListDto {
        sources,
        vss_snapshots: recover_core::io::list_vss_snapshots(),
        adb_devices: list_adb_devices(),
        ios_udids: probe_libimobiledevice(),
    }
}

#[tauri::command]
pub fn inspect_source_cmd(source: String) -> Result<SourceInspectInfo, String> {
    ScanFacade::inspect(&source).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn check_destination_cmd(source: String, out_dir: String) -> Result<DestCheckDto, String> {
    ScanFacade::check_destination(&source, Path::new(&out_dir), true)
        .map(|chk| DestCheckDto {
            safe: chk.safe,
            warnings: chk.warnings,
            destination_free_bytes: chk.destination_free_bytes,
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn start_scan_cmd(
    state: State<'_, Arc<Mutex<TauriScanState>>>,
    source: String,
    out_dir: String,
    types: Vec<String>,
    include_allocated: bool,
    bifragment_gap_mb: u64,
) -> Result<serde_json::Value, String> {
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut guard = state.lock().map_err(|_| "State poisoned")?;
        if guard.running {
            return Err("Scan already running".into());
        }
        guard.running = true;
        guard.last_error = None;
        guard.cancel_flag = Some(Arc::clone(&cancel));
        guard.items.clear();
    }

    let cfg = ScanConfig {
        source,
        out_dir,
        types,
        include_allocated,
        bifragment_gap_bytes: bifragment_gap_mb * 1024 * 1024,
        export_all: false,
        ..Default::default()
    };

    let shared = Arc::clone(state.inner());
    std::thread::spawn(move || {
        let prog_state = Arc::clone(&shared);
        let cb = move |p: &ScanProgress| {
            if let Ok(mut g) = prog_state.lock() {
                g.progress = Some(p.clone());
            }
        };
        match ScanFacade::scan(&cfg, Some(cancel), Some(&cb)) {
            Ok(res) => {
                if let Ok(mut g) = shared.lock() {
                    g.running = false;
                    g.session = Some(res.session);
                    g.items = res.items;
                }
            }
            Err(e) => {
                if let Ok(mut g) = shared.lock() {
                    g.running = false;
                    g.last_error = Some(e.to_string());
                }
            }
        }
    });

    Ok(serde_json::json!({ "started": true }))
}

#[tauri::command]
pub fn cancel_scan_cmd(state: State<'_, Arc<Mutex<TauriScanState>>>) -> Result<(), String> {
    let guard = state.lock().map_err(|_| "State poisoned")?;
    if let Some(ref flag) = guard.cancel_flag {
        flag.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[tauri::command]
pub fn get_scan_status_cmd(
    state: State<'_, Arc<Mutex<TauriScanState>>>,
) -> Result<StatusDto, String> {
    let guard = state.lock().map_err(|_| "State poisoned")?;
    Ok(StatusDto {
        running: guard.running,
        progress: guard.progress.clone(),
        last_error: guard.last_error.clone(),
        session: guard.session.clone(),
        items_count: guard.items.len(),
    })
}

#[tauri::command]
pub fn list_recovered_items_cmd(
    state: State<'_, Arc<Mutex<TauriScanState>>>,
) -> Result<Vec<RecoveredItem>, String> {
    let guard = state.lock().map_err(|_| "State poisoned")?;
    Ok(guard.items.clone())
}

#[tauri::command]
pub fn recover_items_cmd(
    source: String,
    out_dir: String,
    item_ids: Vec<String>,
) -> Result<ExportDto, String> {
    let paths = ScanFacade::export_selected(&source, Path::new(&out_dir), &item_ids)
        .map_err(|e| e.to_string())?;
    Ok(ExportDto {
        exported: paths.iter().map(|p| p.display().to_string()).collect(),
    })
}

#[tauri::command]
pub fn scan_ios_backup_cmd(
    state: State<'_, Arc<Mutex<TauriScanState>>>,
    backup_dir: String,
    out_dir: String,
) -> Result<serde_json::Value, String> {
    let res = ScanFacade::scan_ios_backup(Path::new(&backup_dir), Path::new(&out_dir), false)
        .map_err(|e| e.to_string())?;
    let mut guard = state.lock().map_err(|_| "State poisoned")?;
    guard.session = Some(res.session.clone());
    guard.items = res.items.clone();
    Ok(serde_json::json!({
        "session": res.session,
        "items_count": res.items.len(),
    }))
}

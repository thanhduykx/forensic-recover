use recover_core::companion::{list_adb_devices, probe_libimobiledevice};
use recover_core::models::{RecoveredItem, ScanConfig, ScanProgress, ScanSession};
use recover_core::ScanFacade;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct ServerState {
    progress: Option<ScanProgress>,
    running: bool,
    last_error: Option<String>,
    last_out_dir: Option<String>,
    session: Option<ScanSession>,
    items: Vec<RecoveredItem>,
    cancel_flag: Option<Arc<AtomicBool>>,
}

#[derive(Deserialize)]
struct CheckDestReq {
    source: String,
    out_dir: String,
    allow_same_volume_image: Option<bool>,
}

#[derive(Deserialize)]
struct InspectReq {
    source: String,
}

#[derive(Deserialize)]
struct StartScanReq {
    source: String,
    out_dir: String,
    types: Option<Vec<String>>,
    include_allocated: Option<bool>,
    bifragment_gap_mb: Option<u64>,
    export_all: Option<bool>,
}

#[derive(Deserialize)]
struct ExportReq {
    source: String,
    out_dir: String,
    item_ids: Vec<String>,
}

#[derive(Deserialize)]
struct IosBackupReq {
    backup_dir: String,
    out_dir: String,
    export_all: Option<bool>,
}

#[derive(Serialize)]
struct SourceListResp {
    sources: Vec<String>,
    vss_snapshots: Vec<String>,
    adb_devices: Vec<recover_core::companion::AdbDeviceInfo>,
    ios_udids: Option<String>,
}

/// Runs a pure-Rust, zero-external-dep HTTP + JSON IPC server for the 3-step Desktop UI
/// and Android/iOS USB Companion calls on `127.0.0.1:<port>`.
pub fn serve_ui(port: u16, dist_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr)?;
    let static_root = dist_dir.unwrap_or_else(find_desktop_dist);
    let state = Arc::new(Mutex::new(ServerState::default()));

    println!("Forensic Recover Local UI & Companion IPC listening at http://{addr}");
    if static_root.is_dir() {
        println!("Serving frontend bundle from {}", static_root.display());
    } else {
        println!(
            "Frontend dist not found at {}; run `npm run build` in apps/desktop for full UI.",
            static_root.display()
        );
    }

    for stream in listener.incoming().flatten() {
        let st = Arc::clone(&state);
        let root = static_root.clone();
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &st, &root);
        });
    }
    Ok(())
}

fn find_desktop_dist() -> PathBuf {
    let candidates = [
        PathBuf::from("apps/desktop/dist"),
        PathBuf::from("../../apps/desktop/dist"),
        PathBuf::from("../apps/desktop/dist"),
    ];
    for c in candidates {
        if c.is_dir() {
            return c;
        }
    }
    PathBuf::from("apps/desktop/dist")
}

fn handle_connection(
    mut stream: TcpStream,
    state: &Arc<Mutex<ServerState>>,
    static_root: &Path,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line)? == 0 {
        return Ok(());
    }
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let raw_path = parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or("/");

    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .min(8 * 1024 * 1024);
    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        reader.read_exact(&mut body)?;
    }

    if path.starts_with("/api/") {
        let (status, json_body) = route_api(method, path, &body, state);
        return write_http_response(&mut stream, status, "application/json", json_body.as_bytes());
    }

    // Serve preview images from active `last_out_dir`
    if let Some(rel_preview) = path.strip_prefix("/previews/") {
        let out_dir = state
            .lock()
            .ok()
            .and_then(|s| s.last_out_dir.clone());
        if let Some(dir) = out_dir {
            let safe_leaf = Path::new(rel_preview)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let full = Path::new(&dir).join("previews").join(safe_leaf);
            if full.is_file() {
                if let Ok(bytes) = std::fs::read(&full) {
                    return write_http_response(&mut stream, "200 OK", "image/jpeg", &bytes);
                }
            }
        }
        return write_http_response(&mut stream, "404 Not Found", "text/plain", b"Preview not found");
    }

    // Static assets from `apps/desktop/dist`
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    let clean_rel = rel.replace("..", "");
    let file_path = static_root.join(&clean_rel);
    if file_path.is_file() {
        let mime = guess_mime(&file_path);
        let bytes = std::fs::read(&file_path)?;
        return write_http_response(&mut stream, "200 OK", mime, &bytes);
    }

    // Fallback minimal diagnostic page if dist wasn't built
    let fallback = format!(
        "<!doctype html><html><body><h2>Forensic Recover IPC Active</h2><p>API ready at <code>/api/health</code>. Static UI dist not found at <code>{}</code>.</p></body></html>",
        static_root.display()
    );
    write_http_response(&mut stream, "200 OK", "text/html; charset=utf-8", fallback.as_bytes())
}

fn route_api(
    method: &str,
    path: &str,
    body: &[u8],
    state: &Arc<Mutex<ServerState>>,
) -> (&'static str, String) {
    match (method, path) {
        ("GET", "/api/health") => ("200 OK", r#"{"ok":true,"offline":true,"read_only_source":true}"#.into()),
        ("GET", "/api/sources") => {
            let sources = enumerate_candidate_sources();
            let resp = SourceListResp {
                sources,
                vss_snapshots: recover_core::io::list_vss_snapshots(),
                adb_devices: list_adb_devices(),
                ios_udids: probe_libimobiledevice(),
            };
            ("200 OK", serde_json::to_string(&resp).unwrap_or_default())
        }
        ("POST", "/api/inspect") => {
            let Ok(req) = serde_json::from_slice::<InspectReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            match ScanFacade::inspect(&req.source) {
                Ok(info) => ("200 OK", serde_json::to_string(&info).unwrap_or_default()),
                Err(e) => ("400 Bad Request", serde_json::json!({ "error": e.to_string() }).to_string()),
            }
        }
        ("POST", "/api/check-destination") => {
            let Ok(req) = serde_json::from_slice::<CheckDestReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            match ScanFacade::check_destination(
                &req.source,
                Path::new(&req.out_dir),
                req.allow_same_volume_image.unwrap_or(true),
            ) {
                Ok(chk) => (
                    "200 OK",
                    serde_json::json!({
                        "safe": chk.safe,
                        "warnings": chk.warnings,
                        "destination_free_bytes": chk.destination_free_bytes
                    })
                    .to_string(),
                ),
                Err(e) => ("400 Bad Request", serde_json::json!({ "safe": false, "error": e.to_string() }).to_string()),
            }
        }
        ("POST", "/api/scan") => {
            let Ok(req) = serde_json::from_slice::<StartScanReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            let cancel = Arc::new(AtomicBool::new(false));
            {
                let mut st = state.lock().unwrap();
                if st.running {
                    return ("409 Conflict", r#"{"error":"A scan is already running"}"#.into());
                }
                st.running = true;
                st.last_error = None;
                st.last_out_dir = Some(req.out_dir.clone());
                st.cancel_flag = Some(Arc::clone(&cancel));
                st.items.clear();
            }
            let cfg = ScanConfig {
                source: req.source,
                out_dir: req.out_dir,
                types: req.types.unwrap_or_default(),
                include_allocated: req.include_allocated.unwrap_or(false),
                bifragment_gap_bytes: req.bifragment_gap_mb.unwrap_or(16) * 1024 * 1024,
                export_all: req.export_all.unwrap_or(false),
                ..Default::default()
            };
            let st_bg = Arc::clone(state);
            std::thread::spawn(move || {
                let st_prog = Arc::clone(&st_bg);
                let cb = move |p: &ScanProgress| {
                    if let Ok(mut g) = st_prog.lock() {
                        g.progress = Some(p.clone());
                    }
                };
                match ScanFacade::scan(&cfg, Some(cancel), Some(&cb)) {
                    Ok(res) => {
                        if let Ok(mut g) = st_bg.lock() {
                            g.running = false;
                            g.session = Some(res.session);
                            g.items = res.items;
                        }
                    }
                    Err(e) => {
                        if let Ok(mut g) = st_bg.lock() {
                            g.running = false;
                            g.last_error = Some(e.to_string());
                        }
                    }
                }
            });
            ("202 Accepted", r#"{"started":true}"#.into())
        }
        ("POST", "/api/cancel") => {
            if let Ok(st) = state.lock() {
                if let Some(ref flag) = st.cancel_flag {
                    flag.store(true, Ordering::Relaxed);
                }
            }
            ("200 OK", r#"{"cancelled":true}"#.into())
        }
        ("GET", "/api/status") => {
            let st = state.lock().unwrap();
            let resp = serde_json::json!({
                "running": st.running,
                "progress": st.progress,
                "last_error": st.last_error,
                "session": st.session,
                "items_count": st.items.len(),
            });
            ("200 OK", resp.to_string())
        }
        ("GET", "/api/items") => {
            let st = state.lock().unwrap();
            ("200 OK", serde_json::to_string(&st.items).unwrap_or_default())
        }
        ("POST", "/api/export") => {
            let Ok(req) = serde_json::from_slice::<ExportReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            match ScanFacade::export_selected(&req.source, Path::new(&req.out_dir), &req.item_ids) {
                Ok(paths) => {
                    let strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
                    ("200 OK", serde_json::json!({ "exported": strs }).to_string())
                }
                Err(e) => ("400 Bad Request", serde_json::json!({ "error": e.to_string() }).to_string()),
            }
        }
        ("POST", "/api/ios-backup") => {
            let Ok(req) = serde_json::from_slice::<IosBackupReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            match ScanFacade::scan_ios_backup(
                Path::new(&req.backup_dir),
                Path::new(&req.out_dir),
                req.export_all.unwrap_or(false),
            ) {
                Ok(res) => {
                    let mut st = state.lock().unwrap();
                    st.last_out_dir = Some(req.out_dir);
                    st.session = Some(res.session.clone());
                    st.items = res.items.clone();
                    (
                        "200 OK",
                        serde_json::json!({
                            "session": res.session,
                            "items_count": res.items.len()
                        })
                        .to_string(),
                    )
                }
                Err(e) => ("400 Bad Request", serde_json::json!({ "error": e.to_string() }).to_string()),
            }
        }
        _ => ("404 Not Found", r#"{"error":"Endpoint not found"}"#.into()),
    }
}

fn enumerate_candidate_sources() -> Vec<String> {
    let mut list = Vec::new();
    #[cfg(windows)]
    {
        for i in 0..8 {
            list.push(format!(r"\\.\PhysicalDrive{i}"));
        }
        for letter in b'C'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            if Path::new(&root).exists() {
                list.push(format!(r"\\.\{}:", letter as char));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("sd") && name.len() == 3
                    || name.starts_with("nvme") && !name.contains('p')
                {
                    list.push(format!("/dev/{name}"));
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for i in 0..8 {
            let p = format!("/dev/rdisk{i}");
            if Path::new(&p).exists() {
                list.push(p);
            }
        }
    }
    list
}

fn guess_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        _ => "application/octet-stream",
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

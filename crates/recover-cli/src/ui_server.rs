use chrono::DateTime;
use recover_core::companion::{list_adb_devices, probe_libimobiledevice};
use recover_core::models::{RecoveredItem, ScanConfig, ScanProgress, ScanSession};
use recover_core::ScanFacade;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct ServerState {
    progress: Option<ScanProgress>,
    running: bool,
    last_error: Option<String>,
    last_out_dir: Option<String>,
    report_html_path: Option<String>,
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
struct SuggestOutReq {
    source: String,
}

#[derive(Deserialize)]
struct OpenFolderReq {
    path: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveInfo {
    pub id: String,
    pub letter: String,
    pub label: String,
    pub drive_type: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub is_system: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosBackupCandidate {
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestOutResp {
    pub out_dir: String,
    pub needs_external_drive: bool,
    pub message: Option<String>,
}

#[derive(Serialize)]
struct SourceListResp {
    sources: Vec<String>,
    drives: Vec<DriveInfo>,
    ios_backups: Vec<IosBackupCandidate>,
    is_admin: bool,
    demo_available: bool,
    vss_snapshots: Vec<String>,
    adb_devices: Vec<recover_core::companion::AdbDeviceInfo>,
    ios_udids: Option<String>,
}

/// Runs a pure-Rust, zero-external-dep HTTP + JSON IPC server for the 3-step Desktop UI
/// and Android/iOS USB Companion calls on `127.0.0.1:<port>`.
pub fn serve_ui(port: u16, dist_dir: Option<PathBuf>, auto_open_browser: bool) -> anyhow::Result<()> {
    let listener = bind_with_fallback(port)?;
    let actual_port = listener.local_addr()?.port();
    let url = format!("http://127.0.0.1:{actual_port}");
    let static_root = dist_dir.unwrap_or_else(find_desktop_dist);
    let state = Arc::new(Mutex::new(ServerState::default()));

    println!("============================================================");
    println!("  Forensic Recover — Offline Data Recovery");
    println!("  Giao dien web: {url}");
    println!("  Giu cua so nay mo khi dang su dung. Dong cua so de thoat.");
    println!("============================================================");
    if static_root.is_dir() {
        println!("UI bundle: {}", static_root.display());
    } else {
        println!(
            "Canh bao: Khong tim thay thu muc giao dien tai {}",
            static_root.display()
        );
    }

    if auto_open_browser {
        let open_url = url.clone();
        std::thread::spawn(move || {
            // Brief pause ensures accept loop is already active.
            std::thread::sleep(std::time::Duration::from_millis(150));
            open_in_browser(&open_url);
        });
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

fn bind_with_fallback(preferred_port: u16) -> anyhow::Result<TcpListener> {
    if preferred_port == 0 {
        return Ok(TcpListener::bind("127.0.0.1:0")?);
    }
    for offset in 0..=15u16 {
        let candidate = preferred_port.saturating_add(offset);
        if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{candidate}")) {
            return Ok(listener);
        }
    }
    Ok(TcpListener::bind("127.0.0.1:0")?)
}

fn open_in_browser(url: &str) {
    #[cfg(windows)]
    {
        let _ = Command::new("cmd")
            .args(["/C", "start", "", url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

fn find_desktop_dist() -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("desktop-ui"));
            candidates.push(dir.join("apps").join("desktop").join("dist"));
        }
    }
    candidates.extend([
        PathBuf::from("desktop-ui"),
        PathBuf::from("dist/desktop-ui"),
        PathBuf::from("apps/desktop/dist"),
        PathBuf::from("../../apps/desktop/dist"),
        PathBuf::from("../apps/desktop/dist"),
    ]);
    for c in candidates {
        if c.join("index.html").is_file() {
            return c;
        }
    }
    PathBuf::from("apps/desktop/dist")
}

fn find_demo_fixture() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("demo-sample.img"));
            candidates.push(dir.join("mini_deleted.img"));
        }
    }
    candidates.extend([
        PathBuf::from("dist/demo-sample.img"),
        PathBuf::from("crates/recover-core/tests/fixtures/mini_deleted.img"),
        PathBuf::from("../recover-core/tests/fixtures/mini_deleted.img"),
        PathBuf::from("../../crates/recover-core/tests/fixtures/mini_deleted.img"),
    ]);
    for c in candidates {
        if c.is_file() {
            return Some(std::fs::canonicalize(&c).unwrap_or(c));
        }
    }
    None
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

    let origin = headers.get("origin").map(|s| s.as_str());

    if method == "OPTIONS" {
        return write_http_response(&mut stream, "204 No Content", "text/plain", b"", origin);
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
        return write_http_response(
            &mut stream,
            status,
            "application/json",
            json_body.as_bytes(),
            origin,
        );
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
                    return write_http_response(&mut stream, "200 OK", "image/jpeg", &bytes, origin);
                }
            }
        }
        return write_http_response(
            &mut stream,
            "404 Not Found",
            "text/plain",
            b"Preview not found",
            origin,
        );
    }

    // Static assets from `apps/desktop/dist` or `desktop-ui`
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    let clean_rel = rel.replace("..", "");
    let file_path = static_root.join(&clean_rel);
    if file_path.is_file() {
        let mime = guess_mime(&file_path);
        let bytes = std::fs::read(&file_path)?;
        return write_http_response(&mut stream, "200 OK", mime, &bytes, origin);
    }

    let fallback = format!(
        "<!doctype html><html><body><h2>Forensic Recover IPC Active</h2><p>API ready at <code>/api/health</code>. Static UI dist not found at <code>{}</code>.</p></body></html>",
        static_root.display()
    );
    write_http_response(
        &mut stream,
        "200 OK",
        "text/html; charset=utf-8",
        fallback.as_bytes(),
        origin,
    )
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
            let drives = enumerate_drives();
            let sources = enumerate_candidate_sources(&drives);
            let resp = SourceListResp {
                sources,
                drives,
                ios_backups: find_ios_backups(),
                is_admin: is_running_as_admin(),
                demo_available: find_demo_fixture().is_some(),
                vss_snapshots: recover_core::io::list_vss_snapshots(),
                adb_devices: list_adb_devices(),
                ios_udids: probe_libimobiledevice(),
            };
            ("200 OK", serde_json::to_string(&resp).unwrap_or_default())
        }
        ("POST", "/api/suggest-out-dir") => {
            let Ok(req) = serde_json::from_slice::<SuggestOutReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            let drives = enumerate_drives();
            let suggestion = suggest_safe_output_dir(&req.source, &drives);
            ("200 OK", serde_json::to_string(&suggestion).unwrap_or_default())
        }
        ("POST", "/api/demo-source") => {
            let Some(demo_path) = find_demo_fixture() else {
                return (
                    "404 Not Found",
                    serde_json::json!({ "error": "Không tìm thấy file ảnh mẫu demo-sample.img." }).to_string(),
                );
            };
            let src = strip_windows_verbatim_prefix(&demo_path.to_string_lossy());
            let drives = enumerate_drives();
            let suggestion = suggest_safe_output_dir(&src, &drives);
            (
                "200 OK",
                serde_json::json!({
                    "source": src,
                    "suggested_out_dir": suggestion.out_dir
                })
                .to_string(),
            )
        }
        ("POST", "/api/pick-file") => match pick_native_file() {
            Ok(Some(p)) => ("200 OK", serde_json::json!({ "path": p, "cancelled": false }).to_string()),
            Ok(None) => ("200 OK", serde_json::json!({ "path": null, "cancelled": true }).to_string()),
            Err(e) => ("500 Internal Server Error", serde_json::json!({ "error": e }).to_string()),
        },
        ("POST", "/api/pick-folder") => match pick_native_folder() {
            Ok(Some(p)) => ("200 OK", serde_json::json!({ "path": p, "cancelled": false }).to_string()),
            Ok(None) => ("200 OK", serde_json::json!({ "path": null, "cancelled": true }).to_string()),
            Err(e) => ("500 Internal Server Error", serde_json::json!({ "error": e }).to_string()),
        },
        ("POST", "/api/open-folder") => {
            let Ok(req) = serde_json::from_slice::<OpenFolderReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            let target = Path::new(&req.path);
            let (allowed_dir, allowed_report) = {
                let st = state.lock().unwrap();
                (st.last_out_dir.clone(), st.report_html_path.clone())
            };
            if !is_allowed_open_target(target, allowed_dir.as_deref(), allowed_report.as_deref()) {
                return (
                    "403 Forbidden",
                    serde_json::json!({
                        "error": "Chỉ được phép mở thư mục kết quả hoặc file báo cáo HTML của phiên khôi phục hiện tại."
                    })
                    .to_string(),
                );
            }
            if !target.exists() {
                return (
                    "404 Not Found",
                    serde_json::json!({ "error": format!("Đường dẫn không tồn tại: {}", req.path) }).to_string(),
                );
            }
            match open_path_in_os(target) {
                Ok(()) => ("200 OK", r#"{"opened":true}"#.into()),
                Err(e) => ("500 Internal Server Error", serde_json::json!({ "error": e }).to_string()),
            }
        }
        ("POST", "/api/inspect") => {
            let Ok(req) = serde_json::from_slice::<InspectReq>(body) else {
                return ("400 Bad Request", r#"{"error":"Invalid JSON"}"#.into());
            };
            match ScanFacade::inspect(&req.source) {
                Ok(info) => ("200 OK", serde_json::to_string(&info).unwrap_or_default()),
                Err(e) => ("400 Bad Request", serde_json::json!({ "error": humanize_error(&e.to_string()) }).to_string()),
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
                Err(e) => (
                    "400 Bad Request",
                    serde_json::json!({ "safe": false, "error": humanize_error(&e.to_string()) }).to_string(),
                ),
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
                    return ("409 Conflict", r#"{"error":"Đang có một tiến trình quét chạy."}"#.into());
                }
                st.running = true;
                st.last_error = None;
                st.progress = None;
                st.session = None;
                st.report_html_path = None;
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
                            g.report_html_path = Some(res.report_html_path.display().to_string());
                            g.session = Some(res.session);
                            g.items = res.items;
                        }
                    }
                    Err(e) => {
                        if let Ok(mut g) = st_bg.lock() {
                            g.running = false;
                            g.last_error = Some(humanize_error(&e.to_string()));
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
                "last_out_dir": st.last_out_dir,
                "report_html_path": st.report_html_path,
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
                Err(e) => (
                    "400 Bad Request",
                    serde_json::json!({ "error": humanize_error(&e.to_string()) }).to_string(),
                ),
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
                    st.report_html_path = Some(res.report_html_path.display().to_string());
                    st.session = Some(res.session.clone());
                    st.items = res.items.clone();
                    (
                        "200 OK",
                        serde_json::json!({
                            "session": res.session,
                            "items_count": res.items.len(),
                            "exported_count": res.exported_paths.len(),
                            "report_html_path": res.report_html_path.display().to_string()
                        })
                        .to_string(),
                    )
                }
                Err(e) => (
                    "400 Bad Request",
                    serde_json::json!({ "error": humanize_error(&e.to_string()) }).to_string(),
                ),
            }
        }
        _ => ("404 Not Found", r#"{"error":"Endpoint not found"}"#.into()),
    }
}

fn humanize_error(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("access is denied") || lower.contains("os error 5") || lower.contains("permission denied") {
        return format!(
            "Không đủ quyền đọc trực tiếp ổ đĩa (Access Denied). Hãy đóng ứng dụng và mở lại bằng file MO-UNG-DUNG-ADMIN.bat (Run as Administrator). Chi tiết: {raw}"
        );
    }
    if lower.contains("same volume") || lower.contains("physicaldrive") && lower.contains("scanned source") {
        return format!(
            "Thư mục lưu đang nằm trên CÙNG ổ đĩa với ổ cần quét. Để tránh ghi đè dữ liệu đã xóa, hãy chọn thư mục lưu nằm trên một ổ đĩa khác. Chi tiết: {raw}"
        );
    }
    if lower.contains("cannot find the file") || lower.contains("os error 2") || lower.contains("not found") {
        return format!("Không tìm thấy nguồn dữ liệu hoặc file đã bị ngắt kết nối. Chi tiết: {raw}");
    }
    raw.to_string()
}

fn strip_windows_verbatim_prefix(p: &str) -> String {
    p.strip_prefix(r"\\?\").unwrap_or(p).to_string()
}

fn extract_drive_letter(path: &str) -> Option<String> {
    let cleaned = path
        .trim()
        .trim_start_matches(r"\\?\")
        .trim_start_matches(r"\\.\");
    let b = cleaned.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        Some(format!("{}:", (b[0] as char).to_ascii_uppercase()))
    } else {
        None
    }
}

fn timestamp_tag() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y%m%d_%H%M%S").to_string())
        .unwrap_or_else(|| "session".to_string())
}

/// Computes a safe, human-friendly output directory on a DIFFERENT drive from `source`
/// when scanning a raw volume/drive, without creating any directories on disk yet.
pub fn suggest_safe_output_dir(source: &str, drives: &[DriveInfo]) -> SuggestOutResp {
    let ts = timestamp_tag();
    let src_trimmed = source.trim();
    let is_regular_file = Path::new(src_trimmed).is_file();
    let is_ios_dir = Path::new(src_trimmed).is_dir();

    // Case 1: Scanning a regular `.img`/`.dd` file or iOS backup folder -> safe on user Desktop (or parent)
    if is_regular_file || is_ios_dir {
        let stem = Path::new(src_trimmed)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("scan")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(20)
            .collect::<String>();
        let tag = if stem.is_empty() { "scan".to_string() } else { stem };
        let base = user_desktop_or_home()
            .or_else(|| Path::new(src_trimmed).parent().map(Path::to_path_buf))
            .unwrap_or_else(std::env::temp_dir);
        let out = base.join(format!("KhoiPhuc_{tag}_{ts}"));
        return SuggestOutResp {
            out_dir: strip_windows_verbatim_prefix(&out.to_string_lossy()),
            needs_external_drive: false,
            message: None,
        };
    }

    // Case 2: Raw drive/volume (`\\.\E:`, `E:`, `\\.\PhysicalDriveN`, `/dev/sdb`)
    let src_letter = extract_drive_letter(src_trimmed);
    let tag = src_letter
        .as_deref()
        .map(|l| l.trim_end_matches(':').to_string())
        .unwrap_or_else(|| "Drive".to_string());

    // Try user Desktop first if it is on a DIFFERENT drive letter than source
    if let Some(desktop) = user_desktop_or_home() {
        let desktop_str = desktop.to_string_lossy().to_string();
        let desktop_letter = extract_drive_letter(&desktop_str);
        let same_drive = match (&src_letter, &desktop_letter) {
            (Some(s), Some(d)) => s.eq_ignore_ascii_case(d),
            _ => false,
        };
        if !same_drive && !src_trimmed.to_ascii_lowercase().starts_with(r"\\.\physicaldrive0") {
            let out = desktop.join(format!("KhoiPhuc_{tag}_{ts}"));
            return SuggestOutResp {
                out_dir: strip_windows_verbatim_prefix(&out.to_string_lossy()),
                needs_external_drive: false,
                message: None,
            };
        }
    }

    // Otherwise pick the largest-free-space drive with a DIFFERENT letter from source
    let mut candidates: Vec<&DriveInfo> = drives
        .iter()
        .filter(|d| match &src_letter {
            Some(s) => !d.letter.eq_ignore_ascii_case(s),
            None => !d.is_system,
        })
        .collect();
    candidates.sort_by_key(|a| std::cmp::Reverse(a.free_bytes));

    if let Some(best) = candidates.first() {
        let out = PathBuf::from(format!("{}\\", best.letter)).join(format!("KhoiPhuc_{tag}_{ts}"));
        return SuggestOutResp {
            out_dir: out.to_string_lossy().to_string(),
            needs_external_drive: false,
            message: None,
        };
    }

    SuggestOutResp {
        out_dir: String::new(),
        needs_external_drive: true,
        message: Some(
            "Máy tính chỉ có 1 ổ đĩa trùng với ổ đang chọn. Vui lòng cắm thêm USB hoặc ổ cứng ngoài để lưu file khôi phục (không lưu đè lên ổ nguồn)."
                .to_string(),
        ),
    }
}

fn user_desktop_or_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let desktop = PathBuf::from(&profile).join("Desktop");
            if desktop.is_dir() {
                return Some(desktop);
            }
            let p = PathBuf::from(profile);
            if p.is_dir() {
                return Some(p);
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let desktop = PathBuf::from(&home).join("Desktop");
            if desktop.is_dir() {
                return Some(desktop);
            }
            return Some(PathBuf::from(home));
        }
    }
    None
}

fn is_running_as_admin() -> bool {
    #[cfg(windows)]
    {
        Command::new("net")
            .arg("session")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        std::env::var("USER").map(|u| u == "root").unwrap_or(false)
    }
}

fn enumerate_drives() -> Vec<DriveInfo> {
    #[cfg(windows)]
    {
        if let Some(parsed) = enumerate_windows_drives_ps() {
            if !parsed.is_empty() {
                return parsed;
            }
        }
        // Fallback: enumerate mounted drive letters
        let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let mut out = Vec::new();
        for letter in b'C'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            if Path::new(&root).exists() {
                let l = format!("{}:", letter as char);
                out.push(DriveInfo {
                    id: format!(r"\\.\{l}"),
                    is_system: l.eq_ignore_ascii_case(&sys_drive),
                    letter: l,
                    label: "Ổ đĩa cục bộ".to_string(),
                    drive_type: "fixed".to_string(),
                    total_bytes: 0,
                    free_bytes: 0,
                });
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn enumerate_windows_drives_ps() -> Option<Vec<DriveInfo>> {
    let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let script = r#"
$ErrorActionPreference = 'Stop'
$disks = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2,3 } | Select-Object DeviceID,VolumeName,DriveType,Size,FreeSpace)
$json = ConvertTo-Json -InputObject $disks -Compress
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
"#;
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if b64.is_empty() {
        return None;
    }
    let raw = decode_base64_utf8(&b64)?;
    let raw = raw.trim();
    if raw.is_empty() || raw == "null" {
        return None;
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct PsDisk {
        #[serde(rename = "DeviceID")]
        device_id: Option<String>,
        volume_name: Option<String>,
        drive_type: Option<u32>,
        size: Option<u64>,
        free_space: Option<u64>,
    }

    let items: Vec<PsDisk> = if raw.starts_with('[') {
        serde_json::from_str(raw).ok()?
    } else {
        vec![serde_json::from_str(raw).ok()?]
    };

    let mut drives = Vec::new();
    for item in items {
        let Some(letter) = item.device_id else {
            continue;
        };
        let drive_type = match item.drive_type.unwrap_or(3) {
            2 => "removable",
            3 => "fixed",
            4 => "network",
            _ => "other",
        };
        let label = item
            .volume_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                if drive_type == "removable" {
                    "USB / Thẻ nhớ".to_string()
                } else {
                    "Ổ đĩa cục bộ".to_string()
                }
            });
        drives.push(DriveInfo {
            id: format!(r"\\.\{letter}"),
            is_system: letter.eq_ignore_ascii_case(&sys_drive),
            letter,
            label,
            drive_type: drive_type.to_string(),
            total_bytes: item.size.unwrap_or(0),
            free_bytes: item.free_space.unwrap_or(0),
        });
    }
    // Put removable (USB/SD) first so users recovering from USB see it immediately!
    drives.sort_by(|a, b| {
        let rank = |d: &DriveInfo| match (d.drive_type.as_str(), d.is_system) {
            ("removable", _) => 0,
            (_, false) => 1,
            _ => 2,
        };
        rank(a).cmp(&rank(b)).then_with(|| a.letter.cmp(&b.letter))
    });
    Some(drives)
}

fn find_ios_backups() -> Vec<IosBackupCandidate> {
    let mut roots = Vec::new();
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            roots.push(PathBuf::from(appdata).join("Apple Computer").join("MobileSync").join("Backup"));
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            roots.push(PathBuf::from(profile).join("Apple").join("MobileSync").join("Backup"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            roots.push(
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("MobileSync")
                    .join("Backup"),
            );
        }
    }

    let mut found = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() && p.join("Manifest.db").is_file() {
                found.push(IosBackupCandidate {
                    name: entry.file_name().to_string_lossy().to_string(),
                    path: p.to_string_lossy().to_string(),
                });
            }
        }
    }
    found
}

fn pick_native_file() -> Result<Option<String>, String> {
    #[cfg(windows)]
    {
        let script = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$dlg = New-Object System.Windows.Forms.OpenFileDialog
$dlg.Title = 'Chon file anh dia (.img / .dd / .raw)'
$dlg.Filter = 'Disk Image (*.img;*.dd;*.raw;*.bin)|*.img;*.dd;*.raw;*.bin|All Files (*.*)|*.*'
if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
  [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($dlg.FileName))
}
$owner.Dispose()
"#;
        let out = Command::new("powershell")
            .args(["-STA", "-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|e| format!("Không mở được hộp thoại chọn file: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(format!("Không mở được hộp thoại chọn file: {err}"));
        }
        let b64 = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if b64.is_empty() {
            Ok(None)
        } else {
            decode_base64_utf8(&b64)
                .map(Some)
                .ok_or_else(|| "Không giải mã được đường dẫn file đã chọn.".to_string())
        }
    }
    #[cfg(not(windows))]
    {
        Err("Native file picker chỉ hỗ trợ trên Windows.".to_string())
    }
}

fn pick_native_folder() -> Result<Option<String>, String> {
    #[cfg(windows)]
    {
        // Note: Do NOT set `UseDescriptionForTitle` — it does not exist in .NET Framework 4.x (Windows PowerShell 5.1).
        let script = r#"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
$dlg.Description = 'Chon thu muc'
$dlg.ShowNewFolderButton = $true
if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {
  [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($dlg.SelectedPath))
}
$owner.Dispose()
"#;
        let out = Command::new("powershell")
            .args(["-STA", "-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|e| format!("Không mở được hộp thoại chọn thư mục: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(format!("Không mở được hộp thoại chọn thư mục: {err}"));
        }
        let b64 = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if b64.is_empty() {
            Ok(None)
        } else {
            decode_base64_utf8(&b64)
                .map(Some)
                .ok_or_else(|| "Không giải mã được đường dẫn thư mục đã chọn.".to_string())
        }
    }
    #[cfg(not(windows))]
    {
        Err("Native folder picker chỉ hỗ trợ trên Windows.".to_string())
    }
}

fn is_allowed_open_target(
    target: &Path,
    allowed_dir: Option<&str>,
    allowed_report: Option<&str>,
) -> bool {
    let Ok(canon_target) = std::fs::canonicalize(target) else {
        return false;
    };
    if let Some(report) = allowed_report {
        if let Ok(canon_report) = std::fs::canonicalize(report) {
            if canon_target == canon_report {
                return true;
            }
        }
    }
    if let Some(dir) = allowed_dir {
        if let Ok(canon_dir) = std::fs::canonicalize(dir) {
            if canon_target == canon_dir && canon_target.is_dir() {
                return true;
            }
            if canon_target.starts_with(&canon_dir) {
                if canon_target.is_dir() {
                    return true;
                }
                let ext = canon_target
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if matches!(ext.as_str(), "html" | "htm" | "json") {
                    return true;
                }
            }
        }
    }
    false
}

fn decode_base64_utf8(input: &str) -> Option<String> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !clean.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.as_chunks::<4>().0 {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((c << 6) | d);
            }
        }
    }
    let s = String::from_utf8(out).ok()?;
    Some(s.trim_start_matches('\u{feff}').to_string())
}

fn open_path_in_os(target: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        if target.is_dir() {
            Command::new("explorer")
                .arg(target)
                .spawn()
                .map_err(|e| format!("Không mở được Explorer: {e}"))?;
        } else {
            // Avoid `cmd /C start` so `&` and spaces in paths cannot trigger shell metacharacter parsing.
            Command::new("rundll32")
                .arg("url.dll,FileProtocolHandler")
                .arg(target)
                .spawn()
                .map_err(|e| format!("Không mở được file: {e}"))?;
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(target)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(target)
            .spawn()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn enumerate_candidate_sources(drives: &[DriveInfo]) -> Vec<String> {
    let mut list: Vec<String> = drives.iter().map(|d| d.id.clone()).collect();
    #[cfg(windows)]
    {
        for i in 0..4 {
            list.push(format!(r"\\.\PhysicalDrive{i}"));
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

fn is_local_origin(origin: &str) -> bool {
    let lower = origin.to_ascii_lowercase();
    lower.starts_with("http://127.0.0.1:")
        || lower == "http://127.0.0.1"
        || lower.starts_with("http://localhost:")
        || lower == "http://localhost"
        || lower == "tauri://localhost"
        || lower == "http://tauri.localhost"
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    request_origin: Option<&str>,
) -> std::io::Result<()> {
    let cors_header = match request_origin {
        Some(orig) if is_local_origin(orig) => format!(
            "Access-Control-Allow-Origin: {orig}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n"
        ),
        _ => String::new(),
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{cors_header}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_drives(letters: &[(&str, bool, u64)]) -> Vec<DriveInfo> {
        letters
            .iter()
            .map(|(l, sys, free)| DriveInfo {
                id: format!(r"\\.\{l}"),
                letter: (*l).to_string(),
                label: "Test".to_string(),
                drive_type: if *sys { "fixed" } else { "removable" }.to_string(),
                total_bytes: free * 2,
                free_bytes: *free,
                is_system: *sys,
            })
            .collect()
    }

    #[test]
    fn test_suggest_out_dir_cross_drive_for_usb() {
        let drives = mock_drives(&[("C:", true, 100_000), ("E:", false, 32_000)]);
        let resp = suggest_safe_output_dir(r"\\.\E:", &drives);
        assert!(!resp.needs_external_drive);
        assert!(!resp.out_dir.is_empty());
        assert!(
            !resp.out_dir.to_ascii_uppercase().starts_with("E:"),
            "Output dir must never be on the scanned E: drive: {}",
            resp.out_dir
        );
    }

    #[test]
    fn test_suggest_out_dir_cross_drive_for_system_drive() {
        let drives = mock_drives(&[("C:", true, 100_000), ("D:", false, 500_000)]);
        let resp = suggest_safe_output_dir(r"\\.\C:", &drives);
        assert!(!resp.needs_external_drive);
        assert!(
            resp.out_dir.to_ascii_uppercase().starts_with("D:"),
            "Expected D: when scanning C:, got {}",
            resp.out_dir
        );
    }

    #[test]
    fn test_suggest_out_dir_single_drive_requires_external() {
        let drives = mock_drives(&[("C:", true, 100_000)]);
        let resp = suggest_safe_output_dir(r"\\.\C:", &drives);
        assert!(resp.needs_external_drive);
        assert!(resp.out_dir.is_empty());
        assert!(resp.message.is_some());
    }

    #[test]
    fn test_humanize_access_denied() {
        let msg = humanize_error("Access is denied. (os error 5)");
        assert!(msg.contains("MO-UNG-DUNG-ADMIN.bat"));
    }

    #[test]
    fn test_http_api_health_and_demo_scan_flow() {
        let state = Arc::new(Mutex::new(ServerState::default()));
        let (st, body) = route_api("GET", "/api/health", b"", &state);
        assert_eq!(st, "200 OK");
        assert!(body.contains(r#""ok":true"#));

        // Verify demo-source endpoint locates mini_deleted.img in workspace
        let (st_demo, demo_body) = route_api("POST", "/api/demo-source", b"{}", &state);
        assert_eq!(st_demo, "200 OK", "demo-source failed: {demo_body}");
        let v: serde_json::Value = serde_json::from_str(&demo_body).unwrap();
        let src = v["source"].as_str().unwrap().to_string();
        assert!(Path::new(&src).is_file());

        // Trigger scan into a temp dir and wait for completion
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let out_dir = std::env::temp_dir().join(format!("recover_ui_test_{nonce}"));
        let scan_req = serde_json::json!({
            "source": src,
            "out_dir": out_dir.to_string_lossy(),
            "types": ["jpg", "png"],
            "export_all": false
        })
        .to_string();
        let (st_scan, scan_body) = route_api("POST", "/api/scan", scan_req.as_bytes(), &state);
        assert_eq!(st_scan, "202 Accepted", "scan start failed: {scan_body}");

        // Poll until done (max 10s)
        let start = std::time::Instant::now();
        loop {
            let (_, status_body) = route_api("GET", "/api/status", b"", &state);
            let sv: serde_json::Value = serde_json::from_str(&status_body).unwrap();
            if !sv["running"].as_bool().unwrap_or(true) {
                assert!(sv["last_error"].is_null(), "scan errored: {}", sv["last_error"]);
                assert!(sv["items_count"].as_u64().unwrap_or(0) > 0, "expected demo items");
                assert!(sv["report_html_path"].as_str().is_some());
                break;
            }
            assert!(start.elapsed() < std::time::Duration::from_secs(10), "scan timed out");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let _ = std::fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn test_decode_base64_utf8_vietnamese_path() {
        // UTF-8 Base64 of "C:\Users\Duy\Ảnh khôi phục\Dữ liệu"
        let b64 = "QzpcVXNlcnNcRHV5XMOgW2gg"; // quick sanity
        assert!(decode_base64_utf8(b64).is_some());
        // Exact UTF-8 bytes for "Ảnh khôi phục"
        let b64_vn = "4bqibmgga2jDtGkgcGjhu6Vj";
        assert_eq!(decode_base64_utf8(b64_vn).as_deref(), Some("Ảnh khôi phục"));
    }

    #[test]
    fn test_is_local_origin_cors_guard() {
        assert!(is_local_origin("http://127.0.0.1:1420"));
        assert!(is_local_origin("http://localhost:5173"));
        assert!(is_local_origin("tauri://localhost"));
        assert!(!is_local_origin("https://evil.example"));
        assert!(!is_local_origin("http://127.0.0.1.evil.com"));
    }

    #[test]
    fn test_open_folder_restricts_arbitrary_paths() {
        let state = Arc::new(Mutex::new(ServerState::default()));
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let out_dir = std::env::temp_dir().join(format!("recover_open_guard_{nonce}"));
        std::fs::create_dir_all(&out_dir).unwrap();
        let report_html = out_dir.join("report.html");
        let fake_exe = out_dir.join("malicious.exe");
        std::fs::write(&report_html, b"<html>ok</html>").unwrap();
        std::fs::write(&fake_exe, b"MZ").unwrap();

        {
            let mut st = state.lock().unwrap();
            st.last_out_dir = Some(out_dir.to_string_lossy().to_string());
            st.report_html_path = Some(report_html.to_string_lossy().to_string());
        }

        // Arbitrary path outside out_dir must be rejected with 403
        let req_outside = serde_json::json!({ "path": std::env::temp_dir().to_string_lossy() }).to_string();
        let (status, _) = route_api("POST", "/api/open-folder", req_outside.as_bytes(), &state);
        assert_eq!(status, "403 Forbidden");

        // Executable even inside out_dir must be rejected with 403
        let req_exe = serde_json::json!({ "path": fake_exe.to_string_lossy() }).to_string();
        let (status_exe, _) = route_api("POST", "/api/open-folder", req_exe.as_bytes(), &state);
        assert_eq!(status_exe, "403 Forbidden");

        // Allowed targets check (without spawning Explorer during unit tests)
        assert!(is_allowed_open_target(
            &out_dir,
            Some(&out_dir.to_string_lossy()),
            Some(&report_html.to_string_lossy())
        ));
        assert!(is_allowed_open_target(
            &report_html,
            Some(&out_dir.to_string_lossy()),
            Some(&report_html.to_string_lossy())
        ));

        let _ = std::fs::remove_dir_all(&out_dir);
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_drive_enum_utf8_base64() {
        let drives = enumerate_windows_drives_ps();
        assert!(drives.is_some(), "PowerShell Base64 drive enumeration failed");
        assert!(!drives.unwrap().is_empty(), "Expected at least one Windows drive");
    }
}

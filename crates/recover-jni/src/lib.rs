use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use recover_core::models::ScanConfig;
use recover_core::ScanFacade;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static CANCEL_TOKENS: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

fn cancel_registry() -> &'static Mutex<HashMap<String, Arc<AtomicBool>>> {
    CANCEL_TOKENS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Deserialize)]
pub struct JniScanRequest {
    pub session_key: Option<String>,
    pub source: String,
    pub out_dir: String,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default)]
    pub include_allocated: bool,
    #[serde(default = "default_gap_mb")]
    pub bifragment_gap_mb: u64,
    #[serde(default)]
    pub export_all: bool,
}

fn default_gap_mb() -> u64 {
    16
}

#[derive(Debug, Serialize)]
pub struct JniResponse<T: Serialize> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

pub fn inspect_source_json(source: &str) -> String {
    match catch_unwind(AssertUnwindSafe(|| ScanFacade::inspect(source))) {
        Ok(Ok(info)) => serde_json::to_string(&JniResponse {
            ok: true,
            data: Some(info),
            error: None,
        })
        .unwrap_or_else(|e| error_json(&e.to_string())),
        Ok(Err(e)) => error_json(&e.to_string()),
        Err(_) => error_json("Rust panic isolated at JNI inspect boundary"),
    }
}

pub fn run_scan_json(config_json: &str) -> String {
    match catch_unwind(AssertUnwindSafe(|| run_scan_inner(config_json))) {
        Ok(Ok(val)) => serde_json::to_string(&JniResponse {
            ok: true,
            data: Some(val),
            error: None,
        })
        .unwrap_or_else(|e| error_json(&e.to_string())),
        Ok(Err(e)) => error_json(&e),
        Err(_) => error_json("Rust panic isolated at JNI scan boundary"),
    }
}

fn run_scan_inner(config_json: &str) -> Result<serde_json::Value, String> {
    let req: JniScanRequest =
        serde_json::from_str(config_json).map_err(|e| format!("Invalid scan JSON: {e}"))?;
    let key = req
        .session_key
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let flag = Arc::new(AtomicBool::new(false));
    if let Ok(mut reg) = cancel_registry().lock() {
        reg.insert(key.clone(), Arc::clone(&flag));
    }

    let cfg = ScanConfig {
        source: req.source,
        out_dir: req.out_dir,
        types: req.types,
        include_allocated: req.include_allocated,
        bifragment_gap_bytes: req.bifragment_gap_mb * 1024 * 1024,
        export_all: req.export_all,
        ..Default::default()
    };

    let res = ScanFacade::scan(&cfg, Some(flag), None).map_err(|e| e.to_string());
    if let Ok(mut reg) = cancel_registry().lock() {
        reg.remove(&key);
    }

    let scan_res = res?;
    Ok(serde_json::json!({
        "session": scan_res.session,
        "items": scan_res.items,
        "exported_paths": scan_res.exported_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "report_json": scan_res.report_json_path.display().to_string(),
        "report_html": scan_res.report_html_path.display().to_string(),
    }))
}

pub fn cancel_scan_by_key(session_key: &str) -> bool {
    if let Ok(reg) = cancel_registry().lock() {
        if let Some(flag) = reg.get(session_key) {
            flag.store(true, Ordering::Relaxed);
            return true;
        }
    }
    false
}

pub fn export_items_json(source: &str, out_dir: &str, ids_json: &str) -> String {
    match catch_unwind(AssertUnwindSafe(|| {
        let ids: Vec<String> = serde_json::from_str(ids_json).unwrap_or_default();
        ScanFacade::export_selected(source, Path::new(out_dir), &ids)
    })) {
        Ok(Ok(paths)) => serde_json::to_string(&JniResponse {
            ok: true,
            data: Some(
                paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>(),
            ),
            error: None,
        })
        .unwrap_or_else(|e| error_json(&e.to_string())),
        Ok(Err(e)) => error_json(&e.to_string()),
        Err(_) => error_json("Rust panic isolated at JNI export boundary"),
    }
}

fn error_json(msg: &str) -> String {
    serde_json::to_string(&JniResponse::<serde_json::Value> {
        ok: false,
        data: None,
        error: Some(msg.to_string()),
    })
    .unwrap_or_else(|_| r#"{"ok":false,"error":"serialization failure"}"#.to_string())
}

fn read_jstring(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s)
        .map(|js| js.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn to_jstring(env: &mut JNIEnv, val: &str) -> jstring {
    env.new_string(val)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_forensic_recover_bridge_NativeRecoveryBridge_nativeInspectSource<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    source: JString<'local>,
) -> jstring {
    let src = read_jstring(&mut env, &source);
    let json = inspect_source_json(&src);
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_forensic_recover_bridge_NativeRecoveryBridge_nativeRunScan<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jstring {
    let cfg = read_jstring(&mut env, &config_json);
    let json = run_scan_json(&cfg);
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_forensic_recover_bridge_NativeRecoveryBridge_nativeCancelScan<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    session_key: JString<'local>,
) -> jboolean {
    let key = read_jstring(&mut env, &session_key);
    if cancel_scan_by_key(&key) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_forensic_recover_bridge_NativeRecoveryBridge_nativeExportItems<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    source: JString<'local>,
    out_dir: JString<'local>,
    ids_json: JString<'local>,
) -> jstring {
    let src = read_jstring(&mut env, &source);
    let out = read_jstring(&mut env, &out_dir);
    let ids = read_jstring(&mut env, &ids_json);
    let json = export_items_json(&src, &out, &ids);
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_forensic_recover_bridge_NativeRecoveryBridge_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jni_json_error_isolation() {
        let bad = inspect_source_json("/nonexistent/forensic_device_xyz");
        let parsed: serde_json::Value = serde_json::from_str(&bad).unwrap();
        assert_eq!(parsed["ok"], false);
        assert!(parsed["error"].as_str().unwrap().len() > 5);

        let bad_scan = run_scan_json("{invalid");
        let parsed_scan: serde_json::Value = serde_json::from_str(&bad_scan).unwrap();
        assert_eq!(parsed_scan["ok"], false);
    }

    #[test]
    fn test_jni_cancel_registry() {
        let flag = Arc::new(AtomicBool::new(false));
        cancel_registry()
            .lock()
            .unwrap()
            .insert("sess-1".into(), Arc::clone(&flag));
        assert!(cancel_scan_by_key("sess-1"));
        assert!(flag.load(Ordering::Relaxed));
        assert!(!cancel_scan_by_key("missing"));
    }

    #[test]
    fn test_jni_scan_and_export_selected_roundtrip() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../recover-core/tests/fixtures/mini_deleted.img");
        assert!(fixture.exists(), "fixture missing: {}", fixture.display());

        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let out_dir = std::env::temp_dir().join(format!("recover_jni_out_{uniq}"));
        let empty_dir = std::env::temp_dir().join(format!("recover_jni_empty_{uniq}"));
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::create_dir_all(&empty_dir).unwrap();

        let cfg = serde_json::json!({
            "session_key": "jni-rt-test",
            "source": fixture.to_string_lossy(),
            "out_dir": out_dir.to_string_lossy(),
            "types": [],
            "include_allocated": false,
            "bifragment_gap_mb": 16,
            "export_all": false
        });
        let scan_resp: serde_json::Value =
            serde_json::from_str(&run_scan_json(&cfg.to_string())).unwrap();
        assert_eq!(scan_resp["ok"], true, "scan failed: {scan_resp}");
        let items = scan_resp["data"]["items"].as_array().unwrap();
        assert!(!items.is_empty(), "expected recovered items from fixture");
        let first_id = items[0]["id"].as_str().unwrap().to_string();
        let ids_json = serde_json::to_string(&vec![first_id]).unwrap();

        // Passing an empty directory without checkpoint MUST fail.
        let bad_export: serde_json::Value = serde_json::from_str(&export_items_json(
            &fixture.to_string_lossy(),
            &empty_dir.to_string_lossy(),
            &ids_json,
        ))
        .unwrap();
        assert_eq!(bad_export["ok"], false);

        // Passing the scan session's `out_dir` MUST succeed and produce a real file on disk.
        let ok_export: serde_json::Value = serde_json::from_str(&export_items_json(
            &fixture.to_string_lossy(),
            &out_dir.to_string_lossy(),
            &ids_json,
        ))
        .unwrap();
        assert_eq!(ok_export["ok"], true, "export failed: {ok_export}");
        let exported_path = ok_export["data"][0].as_str().unwrap();
        assert!(Path::new(exported_path).exists());

        let _ = std::fs::remove_dir_all(&out_dir);
        let _ = std::fs::remove_dir_all(&empty_dir);
    }
}

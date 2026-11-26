use crate::carve::validators::{validate_by_ref, ValidationResult};
use crate::carve::{carve_chunk, SignatureDatabase};
use crate::companion::sqlite_ro::ReadOnlySqlite;
use crate::error::{RecoverError, Result};
use crate::io::{MemoryReader, SafeChunkReader};
use crate::models::{
    ByteRange, ConfidenceLevel, FileFamily, FsType, RecoveredItem, RecoveryMethod, ScanSession,
    SessionStatus,
};
use crate::report::{create_unique_file, sanitize_filename, write_reports};
use crate::scan::{generate_thumbnail, new_uuid, now_iso_utc};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Output of scanning an unencrypted iOS Finder / iTunes backup directory.
#[derive(Debug, Clone)]
pub struct IosBackupScanResult {
    pub session: ScanSession,
    pub items: Vec<RecoveredItem>,
    pub exported_paths: Vec<PathBuf>,
    pub report_json_path: PathBuf,
    pub report_html_path: PathBuf,
}

/// Scans an unencrypted iOS backup directory (`Manifest.db`, `Photos.sqlite`, `.ithmb` caches,
/// and media files in `CameraRollDomain` / `AppDomainGroup` / `MediaDomain`) strictly read-only.
pub fn scan_ios_backup(
    backup_dir: &Path,
    out_dir: &Path,
    export_all: bool,
) -> Result<IosBackupScanResult> {
    if !backup_dir.is_dir() {
        return Err(RecoverError::InvalidSource(format!(
            "iOS backup directory '{}' does not exist",
            backup_dir.display()
        )));
    }
    std::fs::create_dir_all(out_dir).map_err(|e| RecoverError::Io {
        offset: 0,
        source: e,
    })?;

    let mut warnings = Vec::new();
    let manifest_plist = backup_dir.join("Manifest.plist");
    if manifest_plist.exists() {
        if let Ok(plist_txt) = std::fs::read_to_string(&manifest_plist) {
            if plist_txt.contains("<key>IsEncrypted</key>") && plist_txt.contains("<true/>") {
                return Err(RecoverError::InvalidSource(
                    "iOS backup is encrypted (IsEncrypted = true). Decrypt locally via Finder/iTunes or provide the backup password to idevicebackup2 before scanning."
                        .into(),
                ));
            }
        }
    }

    let manifest_db_path = backup_dir.join("Manifest.db");
    if !manifest_db_path.exists() {
        return Err(RecoverError::InvalidSource(format!(
            "Manifest.db not found inside '{}'. Create an unencrypted backup via Finder or `idevicebackup2 backup --full`.",
            backup_dir.display()
        )));
    }

    let manifest_db = ReadOnlySqlite::open(&manifest_db_path)?;
    let file_rows = manifest_db.read_table("Files");

    // Map relativePath -> actual backup blob path (`<backup>/<prefix2>/<fileID>` or `<backup>/<fileID>`)
    let mut photos_sqlite_path: Option<PathBuf> = None;
    let mut media_candidates: Vec<(String, String, PathBuf)> = Vec::new();
    let mut ithmb_paths: Vec<(String, PathBuf)> = Vec::new();

    for row in file_rows {
        let file_id = row.first().and_then(|v| v.as_str()).unwrap_or("").to_string();
        let domain = row.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let rel_path = row.get(2).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if file_id.is_empty() {
            continue;
        }
        let Some(blob_path) = resolve_backup_blob(backup_dir, &file_id) else {
            continue;
        };

        if rel_path.ends_with("PhotoData/Photos.sqlite") || rel_path == "Photos.sqlite" {
            photos_sqlite_path = Some(blob_path.clone());
        } else if rel_path.to_ascii_lowercase().ends_with(".ithmb") {
            ithmb_paths.push((rel_path, blob_path));
        } else if domain.contains("CameraRollDomain")
            || rel_path.contains("DCIM/")
            || rel_path.contains("Caches/")
            || rel_path.contains("URLCache")
        {
            media_candidates.push((domain, rel_path, blob_path));
        }
    }

    // Parse `Photos.sqlite` (`ZASSET`) if present to detect logically trashed assets (`ZTRASHEDSTATE == 1`)
    let mut trashed_filenames: HashSet<String> = HashSet::new();
    if let Some(ref psql) = photos_sqlite_path {
        if let Ok(pdb) = ReadOnlySqlite::open(psql) {
            let tables = pdb.list_tables();
            if let Some((_, create_sql)) = tables.get("ZASSET") {
                let cols = parse_create_columns(create_sql);
                let fname_idx = cols.iter().position(|c| c.eq_ignore_ascii_case("ZFILENAME"));
                let trash_idx = cols.iter().position(|c| c.eq_ignore_ascii_case("ZTRASHEDSTATE"));
                for row in pdb.read_table("ZASSET") {
                    let is_trashed = trash_idx
                        .and_then(|i| row.get(i))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        == 1;
                    if is_trashed {
                        if let Some(fname) = fname_idx.and_then(|i| row.get(i)).and_then(|v| v.as_str()) {
                            trashed_filenames.insert(fname.to_string());
                        }
                    }
                }
            } else {
                warnings.push("Photos.sqlite found but ZASSET table missing".into());
            }
        }
    }

    let session_id = new_uuid();
    let mut items = Vec::new();
    let mut seen_sha: HashSet<String> = HashSet::new();
    let mut exported_paths = Vec::new();
    let mut pending_blobs: Vec<(RecoveredItem, Vec<u8>)> = Vec::new();

    // 1. Validate direct media & cache blobs from Manifest.db
    for (domain, rel_path, blob_path) in media_candidates {
        let Ok(bytes) = std::fs::read(&blob_path) else {
            continue;
        };
        if bytes.len() < 32 {
            continue;
        }
        let Some(vref) = detect_magic(&bytes) else {
            continue;
        };
        let val: ValidationResult = validate_by_ref(vref, &bytes);
        if !val.valid {
            continue;
        }
        let slice = &bytes[..val.exact_len];
        let sha = hex::encode(Sha256::digest(slice));
        if !seen_sha.insert(sha.clone()) {
            continue;
        }
        let id = new_uuid();
        let leaf = Path::new(&rel_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("asset")
            .to_string();
        let is_trashed = trashed_filenames.contains(&leaf);
        let mut notes = val.notes.clone();
        notes.push(format!("iOS backup domain={domain}"));
        if is_trashed {
            notes.push("Marked ZTRASHEDSTATE=1 in Photos.sqlite (Recently Deleted)".into());
        }
        let preview_path = if val.family == FileFamily::Image {
            generate_thumbnail(&id, slice, out_dir)
        } else {
            None
        };
        let item = RecoveredItem {
            id,
            session_id: session_id.clone(),
            byte_offset: 0,
            length: val.exact_len as u64,
            fragments: vec![ByteRange {
                offset: 0,
                length: val.exact_len as u64,
            }],
            fragment_count: 1,
            family: val.family,
            mime: val.mime,
            ext: val.ext,
            sha256: sha,
            confidence: ConfidenceLevel::High,
            confidence_score: if is_trashed { 0.96 } else { 0.88 },
            preview_path,
            fs_path: Some(format!("{domain}/{rel_path}")),
            original_name: Some(leaf),
            deleted_at: if is_trashed {
                Some("trashed_in_photos_sqlite".into())
            } else {
                None
            },
            recovery_source: RecoveryMethod::CompanionBackup,
            validation_notes: notes,
        };
        pending_blobs.push((item.clone(), slice.to_vec()));
        items.push(item);
    }

    // 2. Carve `.ithmb` thumbnail caches for orphaned JPEG/PNG thumbnails
    let sig_db = SignatureDatabase::load_default()?;
    for (rel_path, ithmb_path) in ithmb_paths {
        let Ok(bytes) = std::fs::read(&ithmb_path) else {
            continue;
        };
        let reader = SafeChunkReader::new(Arc::new(MemoryReader::new(bytes.clone())));
        let cands = carve_chunk(&reader, &sig_db, None, true, 0, 0, &bytes, 0.0);
        for c in cands {
            if !seen_sha.insert(c.sha256.clone()) {
                continue;
            }
            let id = new_uuid();
            let preview_path = c
                .inline_payload
                .as_deref()
                .and_then(|b| generate_thumbnail(&id, b, out_dir));
            let slice = c
                .inline_payload
                .unwrap_or_else(|| bytes[c.byte_offset as usize..(c.byte_offset + c.length) as usize].to_vec());
            let mut notes = c.notes;
            notes.push(format!("Carved from iOS thumbnail cache {rel_path}"));
            let item = RecoveredItem {
                id,
                session_id: session_id.clone(),
                byte_offset: c.byte_offset,
                length: c.length,
                fragments: c.fragments,
                fragment_count: 1,
                family: c.family,
                mime: c.mime,
                ext: c.ext,
                sha256: c.sha256,
                confidence: ConfidenceLevel::Medium,
                confidence_score: 0.72,
                preview_path,
                fs_path: Some(rel_path.clone()),
                original_name: None,
                deleted_at: None,
                recovery_source: RecoveryMethod::CompanionBackup,
                validation_notes: notes,
            };
            pending_blobs.push((item.clone(), slice));
            items.push(item);
        }
    }

    if export_all {
        let base = out_dir.join("recovered");
        for (item, data) in pending_blobs {
            let fam_dir = base.join(item.family.dir_name());
            std::fs::create_dir_all(&fam_dir).map_err(|e| RecoverError::Io {
                offset: 0,
                source: e,
            })?;
            let fname = item
                .original_name
                .as_deref()
                .map(sanitize_filename)
                .unwrap_or_else(|| format!("ios_{}.{}", &item.sha256[..8], item.ext));
            let (dest, mut f) = create_unique_file(&fam_dir, &fname)?;
            f.write_all(&data).map_err(|e| RecoverError::Io {
                offset: 0,
                source: e,
            })?;
            exported_paths.push(dest);
        }
    }

    let session = ScanSession {
        id: session_id,
        source: backup_dir.to_string_lossy().to_string(),
        fs_type: FsType::IosBackup,
        started_at: now_iso_utc(),
        updated_at: now_iso_utc(),
        status: SessionStatus::Completed,
        bytes_scanned: 0,
        total_bytes: 0,
        device_fingerprint: format!("ios_backup:{}", backup_dir.display()),
        bad_sectors: Vec::new(),
        zero_block_ratio: 0.0,
        high_entropy_ratio: 0.0,
        warnings,
    };

    let (report_json_path, report_html_path) = write_reports(&session, &items, out_dir)?;
    Ok(IosBackupScanResult {
        session,
        items,
        exported_paths,
        report_json_path,
        report_html_path,
    })
}

/// Checks if `idevicebackup2` (libimobiledevice) is installed on PATH for USB iOS companion capture.
pub fn probe_libimobiledevice() -> Option<String> {
    let out = std::process::Command::new("idevice_id")
        .arg("-l")
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

fn resolve_backup_blob(backup_dir: &Path, file_id: &str) -> Option<PathBuf> {
    if file_id.len() >= 2 {
        let nested = backup_dir.join(&file_id[..2]).join(file_id);
        if nested.is_file() {
            return Some(nested);
        }
    }
    let flat = backup_dir.join(file_id);
    if flat.is_file() {
        Some(flat)
    } else {
        None
    }
}

fn detect_magic(buf: &[u8]) -> Option<&'static str> {
    if buf.starts_with(b"\xFF\xD8\xFF") {
        Some("jpeg")
    } else if buf.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else if buf.starts_with(b"GIF87a") || buf.starts_with(b"GIF89a") {
        Some("gif")
    } else if buf.len() >= 12 && &buf[4..8] == b"ftyp" {
        Some("bmff")
    } else if buf.starts_with(b"%PDF-") {
        Some("pdf")
    } else {
        None
    }
}

fn parse_create_columns(sql: &str) -> Vec<String> {
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    let Some(close) = sql.rfind(')') else {
        return Vec::new();
    };
    sql[open + 1..close]
        .split(',')
        .filter_map(|col| col.split_whitespace().next())
        .map(|s| s.trim_matches('"').trim_matches('`').to_string())
        .collect()
}

/// Helper map export if external callers correlate backup items by path.
#[allow(dead_code)]
pub type BackupIndex = HashMap<String, PathBuf>;

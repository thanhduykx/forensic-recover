use crate::carve::confidence::{score_candidate, BlockAnomalyTracker, ConfidenceInput};
use crate::carve::rules::SignatureDatabase;
use crate::carve::validators::{validate_by_ref, ValidationResult};
use crate::carve::{carve_chunk, CarvedCandidate};
use crate::error::Result;
use crate::fs::{detect_and_parse_fs, DeletedFsEntry, FsParseOutput};
use crate::io::{
    list_vss_snapshots, open_source_reader, verify_destination_safe, BlockReader, SafeChunkReader,
};
use crate::models::{
    ConfidenceLevel, FileFamily, RecoveredItem, RecoveryMethod, ScanConfig, ScanProgress,
    ScanSession, SessionStatus, SourceInspectInfo,
};
use crate::report::{export_recovered_items, write_reports};
use crate::scan::checkpoint::{CheckpointManager, SavedCheckpoint};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static UUID_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn new_uuid() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = UUID_SEQ.fetch_add(1, Ordering::Relaxed);
    let a = ((nanos >> 64) as u64) ^ 0x9e37_79b9_7f4a_7c15;
    let b = (nanos as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9) ^ seq;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&a.to_le_bytes());
    bytes[8..].copy_from_slice(&b.to_le_bytes());
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

pub fn now_iso_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}

/// Complete result of a scan or resume run.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub session: ScanSession,
    pub items: Vec<RecoveredItem>,
    pub exported_paths: Vec<PathBuf>,
    pub report_json_path: PathBuf,
    pub report_html_path: PathBuf,
}

/// Inspects a source block device or raw image strictly read-only.
pub fn inspect_source(source: &str) -> Result<SourceInspectInfo> {
    let raw_reader: Arc<dyn BlockReader> = Arc::from(open_source_reader(source)?);
    let safe_reader = SafeChunkReader::new(raw_reader);
    let fs_out = detect_and_parse_fs(&safe_reader);

    Ok(SourceInspectInfo {
        source: source.to_string(),
        total_bytes: safe_reader.total_size(),
        sector_size: safe_reader.sector_size(),
        fs_type: fs_out.fs_type,
        device_fingerprint: safe_reader.device_fingerprint(),
        unallocated_bytes_estimate: fs_out
            .bitmap
            .as_ref()
            .map(|b| b.count_unallocated_bytes()),
        deleted_fs_entries: fs_out.deleted_entries.len(),
        is_encrypted_hint: fs_out.is_encrypted_hint,
        vss_snapshots: list_vss_snapshots(),
        warnings: fs_out.warnings,
    })
}

/// Runs a streaming forensic recovery scan (FS metadata + unallocated carving + bifragment + dedupe).
pub fn run_scan(
    config: &ScanConfig,
    cancel_flag: Option<Arc<AtomicBool>>,
    progress_cb: Option<&(dyn Fn(&ScanProgress) + Send + Sync)>,
) -> Result<ScanResult> {
    let raw_reader: Arc<dyn BlockReader> = Arc::from(open_source_reader(&config.source)?);
    run_scan_with_reader(config, raw_reader, 0, None, Vec::new(), cancel_flag, progress_cb)
}

/// Resumes a previously paused/interrupted scan from `<out>/.recover-session`.
pub fn resume_scan(
    out_dir: &Path,
    cancel_flag: Option<Arc<AtomicBool>>,
    progress_cb: Option<&(dyn Fn(&ScanProgress) + Send + Sync)>,
) -> Result<ScanResult> {
    let (ckpt, existing_items) = CheckpointManager::load_checkpoint(out_dir)?;
    let raw_reader: Arc<dyn BlockReader> = Arc::from(open_source_reader(&ckpt.config.source)?);
    let start_offset = ckpt.session.bytes_scanned.min(raw_reader.total_size());
    run_scan_with_reader(
        &ckpt.config,
        raw_reader,
        start_offset,
        Some(ckpt.session),
        existing_items,
        cancel_flag,
        progress_cb,
    )
}

/// Core streaming scan pipeline accepting an arbitrary `BlockReader` (useful for fault injection in tests).
pub fn run_scan_with_reader(
    config: &ScanConfig,
    raw_reader: Arc<dyn BlockReader>,
    start_offset: u64,
    prior_session: Option<ScanSession>,
    prior_items: Vec<RecoveredItem>,
    cancel_flag: Option<Arc<AtomicBool>>,
    progress_cb: Option<&(dyn Fn(&ScanProgress) + Send + Sync)>,
) -> Result<ScanResult> {
    let out_dir = Path::new(&config.out_dir);
    let dest_check = verify_destination_safe(
        &config.source,
        out_dir,
        config.allow_same_volume_image,
    )?;

    let safe_reader = SafeChunkReader::new(raw_reader);
    let total_bytes = safe_reader.total_size();
    let ckpt_mgr = CheckpointManager::new(out_dir)?;
    let sig_db = SignatureDatabase::load_default()?.filtered(&config.types);

    // Parse filesystem read-only
    let fs_out = detect_and_parse_fs(&safe_reader);

    let mut session = prior_session.unwrap_or_else(|| ScanSession {
        id: new_uuid(),
        source: config.source.clone(),
        fs_type: fs_out.fs_type,
        started_at: now_iso_utc(),
        updated_at: now_iso_utc(),
        status: SessionStatus::Running,
        bytes_scanned: start_offset,
        total_bytes,
        device_fingerprint: safe_reader.device_fingerprint(),
        bad_sectors: Vec::new(),
        zero_block_ratio: 0.0,
        high_entropy_ratio: 0.0,
        warnings: Vec::new(),
    });
    session.status = SessionStatus::Running;
    session.warnings.extend(dest_check.warnings);
    session.warnings.extend(fs_out.warnings.clone());

    let mut items_by_sha: HashMap<String, RecoveredItem> = HashMap::new();
    let mut ordered_hashes: Vec<String> = Vec::new();
    for item in prior_items {
        if !items_by_sha.contains_key(&item.sha256) {
            ordered_hashes.push(item.sha256.clone());
            items_by_sha.insert(item.sha256.clone(), item);
        }
    }

    // Phase 1: Validate deleted FS metadata entries (only on fresh scan `start_offset == 0`)
    let mut fs_entry_by_offset: HashMap<u64, &DeletedFsEntry> = HashMap::new();
    for e in &fs_out.deleted_entries {
        if let Some(first_run) = e.data_runs.first() {
            fs_entry_by_offset.insert(first_run.offset, e);
        }
    }

    if start_offset == 0 {
        for entry in &fs_out.deleted_entries {
            if let Some(item) = recover_from_fs_entry(
                &safe_reader,
                &session.id,
                entry,
                &config.types,
                out_dir,
                config.generate_previews,
            ) {
                insert_or_merge_item(&mut items_by_sha, &mut ordered_hashes, item, &ckpt_mgr)?;
            }
        }
    }

    // Phase 2: Streaming chunked unallocated carving
    let chunk_size = config.chunk_size.max(64 * 1024);
    let overlap = 64usize;
    let mut offset = start_offset;
    let mut last_ckpt_bytes = offset;
    let mut tracker = BlockAnomalyTracker::default();
    let started_clock = Instant::now();
    let mut cancelled = false;

    while offset < total_bytes {
        if let Some(ref flag) = cancel_flag {
            if flag.load(Ordering::Relaxed) {
                cancelled = true;
                break;
            }
        }

        let to_read = (chunk_size + overlap).min((total_bytes - offset) as usize);
        let mut buf = vec![0u8; to_read];
        let n = safe_reader.read_resilient(offset, &mut buf);
        if n == 0 {
            break;
        }
        buf.truncate(n);

        let advance = n.min(chunk_size) as u64;
        tracker.observe_chunk(&buf[..advance as usize]);

        // Skip entire chunk if all blocks in chunk are allocated and `include_allocated == false`
        let skip_chunk = if !config.include_allocated {
            if let Some(ref bm) = fs_out.bitmap {
                let step = bm.block_size.max(512);
                let mut any_unalloc = false;
                let mut probe = offset;
                while probe < offset + advance {
                    if !bm.is_offset_allocated(probe) {
                        any_unalloc = true;
                        break;
                    }
                    probe += step;
                }
                !any_unalloc
            } else {
                false
            }
        } else {
            false
        };

        if !skip_chunk && !sig_db.rules.is_empty() {
            let candidates = carve_chunk(
                &safe_reader,
                &sig_db,
                fs_out.bitmap.as_ref(),
                config.include_allocated,
                config.bifragment_gap_bytes,
                offset,
                &buf,
                tracker.zero_ratio(),
            );

            for cand in candidates {
                let mut item = candidate_to_item(
                    &session.id,
                    cand,
                    &fs_entry_by_offset,
                    out_dir,
                    config.generate_previews,
                );
                // Re-score if matched FS metadata
                if item.fs_path.is_some() {
                    item.recovery_source = RecoveryMethod::HybridFsAndCarve;
                    item.confidence_score = (item.confidence_score + 0.08).min(0.99);
                    if item.confidence_score >= 0.75 {
                        item.confidence = ConfidenceLevel::High;
                    }
                }
                insert_or_merge_item(&mut items_by_sha, &mut ordered_hashes, item, &ckpt_mgr)?;
            }
        }

        offset += advance;
        session.bytes_scanned = offset;
        session.updated_at = now_iso_utc();
        session.bad_sectors = safe_reader.bad_sectors();
        session.zero_block_ratio = tracker.zero_ratio();
        session.high_entropy_ratio = tracker.high_entropy_ratio();

        if offset - last_ckpt_bytes >= config.checkpoint_interval_bytes {
            ckpt_mgr.save_session(&SavedCheckpoint {
                session: session.clone(),
                config: config.clone(),
            })?;
            last_ckpt_bytes = offset;
        }

        if let Some(cb) = progress_cb {
            let elapsed = started_clock.elapsed().as_secs_f64().max(0.05);
            let done_delta = offset.saturating_sub(start_offset) as f64;
            let bps = done_delta / elapsed;
            let rem = total_bytes.saturating_sub(offset) as f64;
            let eta = if bps > 1.0 {
                Some((rem / bps) as u64)
            } else {
                None
            };
            cb(&ScanProgress {
                session_id: session.id.clone(),
                bytes_scanned: offset,
                total_bytes,
                percent: if total_bytes == 0 {
                    100.0
                } else {
                    (offset as f64 / total_bytes as f64) * 100.0
                },
                throughput_mbps: bps / (1024.0 * 1024.0),
                eta_seconds: eta,
                items_found: ordered_hashes.len(),
                bad_sector_count: session.bad_sectors.len(),
                phase: "Carving unallocated space".to_string(),
            });
        }
    }

    // Add honest flash/encryption diagnostics
    if session.zero_block_ratio > 0.75 && ordered_hashes.is_empty() {
        session.warnings.push(
            "Over 75% of scanned blocks are zero/0xFF-filled — likely SSD/Flash TRIM/discard has wiped deleted blocks."
                .to_string(),
        );
    }
    if session.high_entropy_ratio > 0.70 {
        session.warnings.push(
            "High uniform entropy (>7.95 bits/byte) across blocks — volume may be encrypted (BitLocker/FileVault/Android FBE)."
                .to_string(),
        );
    }

    session.status = if cancelled {
        SessionStatus::Paused
    } else {
        SessionStatus::Completed
    };
    session.updated_at = now_iso_utc();
    session.bad_sectors = safe_reader.bad_sectors();

    let final_items: Vec<RecoveredItem> = ordered_hashes
        .into_iter()
        .filter_map(|h| items_by_sha.remove(&h))
        .collect();

    ckpt_mgr.rewrite_all_items(&final_items)?;
    ckpt_mgr.save_session(&SavedCheckpoint {
        session: session.clone(),
        config: config.clone(),
    })?;

    let exported_paths = if config.export_all && !cancelled {
        export_recovered_items(&safe_reader, &final_items, out_dir)?
    } else {
        Vec::new()
    };

    let (report_json_path, report_html_path) = write_reports(&session, &final_items, out_dir)?;

    Ok(ScanResult {
        session,
        items: final_items,
        exported_paths,
        report_json_path,
        report_html_path,
    })
}

fn insert_or_merge_item(
    map: &mut HashMap<String, RecoveredItem>,
    order: &mut Vec<String>,
    item: RecoveredItem,
    ckpt: &CheckpointManager,
) -> Result<()> {
    if let Some(existing) = map.get_mut(&item.sha256) {
        if existing.fs_path.is_none() && item.fs_path.is_some() {
            existing.fs_path = item.fs_path;
            existing.original_name = item.original_name;
            existing.deleted_at = item.deleted_at;
            existing.recovery_source = RecoveryMethod::HybridFsAndCarve;
            existing.confidence_score = (existing.confidence_score + 0.10).min(0.99);
            if existing.confidence_score >= 0.75 {
                existing.confidence = ConfidenceLevel::High;
            }
        }
        return Ok(());
    }
    ckpt.append_item(&item)?;
    order.push(item.sha256.clone());
    map.insert(item.sha256.clone(), item);
    Ok(())
}

fn candidate_to_item(
    session_id: &str,
    cand: CarvedCandidate,
    fs_map: &HashMap<u64, &DeletedFsEntry>,
    out_dir: &Path,
    generate_previews: bool,
) -> RecoveredItem {
    let id = new_uuid();
    let preview_path = if generate_previews {
        cand.inline_payload
            .as_deref()
            .and_then(|bytes| generate_thumbnail(&id, bytes, out_dir))
    } else {
        None
    };

    let fs_hit = fs_map.get(&cand.byte_offset).copied();

    RecoveredItem {
        id,
        session_id: session_id.to_string(),
        byte_offset: cand.byte_offset,
        length: cand.length,
        fragment_count: cand.fragments.len(),
        fragments: cand.fragments,
        family: cand.family,
        mime: cand.mime,
        ext: cand.ext,
        sha256: cand.sha256,
        confidence: cand.confidence,
        confidence_score: cand.confidence_score,
        preview_path,
        fs_path: fs_hit.map(|e| e.fs_path.clone()),
        original_name: fs_hit.map(|e| e.name.clone()),
        deleted_at: fs_hit.and_then(|e| e.deleted_at.clone()),
        recovery_source: cand.recovery_method,
        validation_notes: cand.notes,
    }
}

fn recover_from_fs_entry(
    reader: &SafeChunkReader,
    session_id: &str,
    entry: &DeletedFsEntry,
    wanted_types: &[String],
    out_dir: &Path,
    generate_previews: bool,
) -> Option<RecoveredItem> {
    if entry.is_directory || entry.size == 0 || entry.size > 64 * 1024 * 1024 {
        return None;
    }
    let mut payload = Vec::with_capacity(entry.size as usize);
    if let Some(ref res) = entry.resident_data {
        payload.extend_from_slice(res);
    } else {
        for r in &entry.data_runs {
            let need = (entry.size as usize).saturating_sub(payload.len());
            if need == 0 {
                break;
            }
            let take = (r.length as usize).min(need);
            payload.extend_from_slice(&reader.read_vec_resilient(r.offset, take));
        }
    }
    payload.truncate(entry.size as usize);
    if payload.len() < 32 {
        return None;
    }

    // Validate actual content bytes (NEVER classify by filename extension alone!)
    let validator_ref = detect_validator_from_magic(&payload)?;
    let val: ValidationResult = validate_by_ref(validator_ref, &payload);
    if !val.valid {
        return None;
    }
    if !wanted_types.is_empty()
        && !wanted_types
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&val.ext) || (t.eq_ignore_ascii_case("jpeg") && val.ext == "jpg"))
    {
        return None;
    }

    let id = new_uuid();
    let sha = hex::encode(Sha256::digest(&payload[..val.exact_len]));
    let (score, level) = score_candidate(&ConfidenceInput {
        validation: &val,
        fragment_count: entry.data_runs.len().max(1),
        matched_fs_metadata: true,
        recovery_method: RecoveryMethod::FsMetadata,
        bad_sectors_in_range: 0,
        zero_block_ratio: 0.0,
    });
    let preview_path = if generate_previews && val.family == FileFamily::Image {
        generate_thumbnail(&id, &payload[..val.exact_len], out_dir)
    } else {
        None
    };

    Some(RecoveredItem {
        id,
        session_id: session_id.to_string(),
        byte_offset: entry.data_runs.first().map(|r| r.offset).unwrap_or(0),
        length: val.exact_len as u64,
        fragment_count: entry.data_runs.len().max(1),
        fragments: entry.data_runs.clone(),
        family: val.family,
        mime: val.mime,
        ext: val.ext,
        sha256: sha,
        confidence: level,
        confidence_score: score,
        preview_path,
        fs_path: Some(entry.fs_path.clone()),
        original_name: Some(entry.name.clone()),
        deleted_at: entry.deleted_at.clone(),
        recovery_source: RecoveryMethod::FsMetadata,
        validation_notes: val.notes,
    })
}

fn detect_validator_from_magic(buf: &[u8]) -> Option<&'static str> {
    if buf.starts_with(b"\xFF\xD8\xFF") {
        Some("jpeg")
    } else if buf.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else if buf.starts_with(b"GIF87a") || buf.starts_with(b"GIF89a") {
        Some("gif")
    } else if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"WEBP" {
        Some("webp")
    } else if buf.len() >= 12 && &buf[4..8] == b"ftyp" {
        Some("bmff")
    } else if buf.starts_with(b"%PDF-") {
        Some("pdf")
    } else if buf.starts_with(b"PK\x03\x04") {
        Some("zip_ooxml")
    } else {
        None
    }
}

pub fn generate_thumbnail(id: &str, bytes: &[u8], out_dir: &Path) -> Option<String> {
    let img = image::load_from_memory(bytes).ok()?;
    let thumb = img.thumbnail(160, 160);
    let preview_dir = out_dir.join("previews");
    std::fs::create_dir_all(&preview_dir).ok()?;
    let rel = format!("previews/{id}.jpg");
    let full = out_dir.join(&rel);
    thumb.to_rgb8().save_with_format(&full, image::ImageFormat::Jpeg).ok()?;
    Some(rel)
}

pub fn load_session_items(out_dir: &Path) -> Result<(ScanSession, Vec<RecoveredItem>)> {
    let (ckpt, items) = CheckpointManager::load_checkpoint(out_dir)?;
    Ok((ckpt.session, items))
}

/// Filters items and writes them safely without overwriting existing files.
pub fn export_selected_items(
    source: &str,
    out_dir: &Path,
    item_ids: &[String],
) -> Result<Vec<PathBuf>> {
    let (_, items) = CheckpointManager::load_checkpoint(out_dir)?;
    let selected: Vec<RecoveredItem> = if item_ids.is_empty() {
        items
    } else {
        items
            .into_iter()
            .filter(|i| item_ids.iter().any(|id| id == &i.id))
            .collect()
    };
    let raw_reader: Arc<dyn BlockReader> = Arc::from(open_source_reader(source)?);
    let safe_reader = SafeChunkReader::new(raw_reader);
    export_recovered_items(&safe_reader, &selected, out_dir)
}

#[allow(dead_code)]
fn _keep_fs_parse_output(_: &FsParseOutput) {}

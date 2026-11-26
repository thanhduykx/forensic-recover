use crate::error::{RecoverError, Result};
use crate::fs::{read_u16_le, read_u32_le, read_u64_le, AllocationBitmap, DeletedFsEntry, FsParseOutput};
use crate::io::SafeChunkReader;
use crate::models::{ByteRange, FsType};
use std::collections::HashMap;

/// Read-only NTFS parser:
/// - Parses BPB + `$MFT` (with Update Sequence Array fixup on every 1024-byte `FILE` record).
/// - Extracts `$Bitmap` (MFT #6) cluster allocation map.
/// - Extracts deleted MFT records (`flags & 0x01 == 0`) with `$STANDARD_INFORMATION`, `$FILE_NAME`
///   (reconstructing parent directory path), and `$DATA` (resident bytes or non-resident Data Runs).
/// - Enriches deletion timestamps when `$UsnJrnl:$J` (`USN_RECORD_V2`) is present.
pub fn parse_ntfs(reader: &SafeChunkReader, vol_off: u64) -> Result<FsParseOutput> {
    let bpb = reader.read_vec_resilient(vol_off, 512);
    if bpb.len() < 512 || &bpb[3..11] != b"NTFS    " {
        return Err(RecoverError::Parse("Not an NTFS volume".into()));
    }

    let bytes_per_sector = read_u16_le(&bpb, 11) as u64;
    let sectors_per_cluster = bpb[13] as u64;
    let total_sectors = read_u64_le(&bpb, 40);
    let mft_lcn = read_u64_le(&bpb, 48);
    let raw_mft_rec_size = bpb[64] as i8;

    if bytes_per_sector < 512 || sectors_per_cluster == 0 {
        return Err(RecoverError::Parse("Invalid NTFS BPB".into()));
    }

    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let mft_record_size = if raw_mft_rec_size < 0 {
        1usize << ((-raw_mft_rec_size) as u32)
    } else {
        (raw_mft_rec_size as usize) * (cluster_size as usize)
    }
    .clamp(512, 4096);

    let total_clusters = total_sectors / sectors_per_cluster;
    let mft_start_offset = vol_off + mft_lcn * cluster_size;

    // Read MFT record 0 (`$MFT`) to discover all MFT extents (non-resident data runs of `$MFT` itself)
    let mut rec0 = reader.read_vec_resilient(mft_start_offset, mft_record_size);
    let mft_runs = if rec0.len() == mft_record_size && apply_usa_fixup(&mut rec0, bytes_per_sector as usize) {
        extract_mft_data_runs(&rec0, vol_off, cluster_size).unwrap_or_else(|| {
            vec![ByteRange {
                offset: mft_start_offset,
                length: (mft_record_size * 4096) as u64,
            }]
        })
    } else {
        vec![ByteRange {
            offset: mft_start_offset,
            length: (mft_record_size * 1024) as u64,
        }]
    };

    // Bounded MFT scan (up to 65,536 records = 64 MiB of MFT) for responsive read-only forensics
    let mut dir_names: HashMap<u64, (u64, String)> = HashMap::new();
    let mut raw_deleted: Vec<RawNtfsRecord> = Vec::new();
    let mut bitmap: Option<AllocationBitmap> = None;
    let mut usn_deletes: HashMap<u64, String> = HashMap::new();

    let mut rec_index = 0u64;
    let max_records = 65_536u64;

    for run in mft_runs {
        if rec_index >= max_records {
            break;
        }
        let records_in_run = run.length / mft_record_size as u64;
        // Stream MFT run in 1 MiB batches
        let batch_recs = ((1024 * 1024) / mft_record_size).max(1) as u64;
        let mut cursor = 0u64;
        while cursor < records_in_run && rec_index < max_records {
            let count = batch_recs.min(records_in_run - cursor).min(max_records - rec_index);
            let batch_bytes = (count as usize) * mft_record_size;
            let batch_off = run.offset + cursor * (mft_record_size as u64);
            let mut buf = reader.read_vec_resilient(batch_off, batch_bytes);

            for i in 0..count as usize {
                let start = i * mft_record_size;
                let end = start + mft_record_size;
                if end > buf.len() {
                    break;
                }
                let rec = &mut buf[start..end];
                if &rec[0..4] != b"FILE" || !apply_usa_fixup(rec, bytes_per_sector as usize) {
                    rec_index += 1;
                    continue;
                }

                let flags = read_u16_le(rec, 22);
                let in_use = (flags & 0x0001) != 0;
                let is_dir = (flags & 0x0002) != 0;

                let parsed = parse_mft_attributes(rec, vol_off, cluster_size);

                // Record directory parent map for path reconstruction
                if is_dir {
                    if let Some((parent_ref, ref name)) = parsed.file_name {
                        dir_names.insert(rec_index, (parent_ref & 0x0000_FFFF_FFFF_FFFF, name.clone()));
                    }
                }

                // MFT record 6 = `$Bitmap`
                if rec_index == 6 && in_use {
                    let mut bm = AllocationBitmap::new(cluster_size, vol_off, total_clusters);
                    let mut bm_bytes = Vec::new();
                    if let Some(res) = &parsed.resident_data {
                        bm_bytes.extend_from_slice(res);
                    } else {
                        for r in &parsed.data_runs {
                            let take = r.length.min(16 * 1024 * 1024) as usize;
                            bm_bytes.extend_from_slice(&reader.read_vec_resilient(r.offset, take));
                            if bm_bytes.len() >= 16 * 1024 * 1024 {
                                break;
                            }
                        }
                    }
                    for (byte_i, &b) in bm_bytes.iter().enumerate() {
                        for bit in 0..8 {
                            let clus = (byte_i * 8 + bit) as u64;
                            if clus >= total_clusters {
                                break;
                            }
                            if (b & (1 << bit)) != 0 {
                                bm.set_allocated(clus, true);
                            }
                        }
                    }
                    bitmap = Some(bm);
                }

                // `$UsnJrnl` detection by name (`$UsnJrnl`) + `$J` stream
                if parsed
                    .file_name
                    .as_ref()
                    .map(|(_, n)| n == "$UsnJrnl")
                    .unwrap_or(false)
                {
                    if let Some(j_runs) = parsed.usn_j_runs.as_ref() {
                        collect_usn_deletes(reader, j_runs, &mut usn_deletes);
                    }
                }

                if !in_use && !is_dir {
                    if let Some((parent_ref, name)) = parsed.file_name {
                        if !name.starts_with('$')
                            && (parsed.logical_size > 0 || parsed.resident_data.is_some())
                        {
                            raw_deleted.push(RawNtfsRecord {
                                mft_index: rec_index,
                                parent_index: parent_ref & 0x0000_FFFF_FFFF_FFFF,
                                name,
                                logical_size: parsed.logical_size,
                                data_runs: parsed.data_runs,
                                resident_data: parsed.resident_data,
                                created_at: parsed.created_at,
                                modified_at: parsed.modified_at,
                            });
                        }
                    }
                }

                rec_index += 1;
            }
            cursor += count;
        }
    }

    let deleted_entries = raw_deleted
        .into_iter()
        .map(|item| {
            let fs_path = build_ntfs_path(&dir_names, item.parent_index, &item.name);
            let deleted_at = usn_deletes
                .get(&item.mft_index)
                .cloned()
                .or_else(|| item.modified_at.clone());
            DeletedFsEntry {
                fs_path,
                name: item.name,
                size: item.logical_size,
                data_runs: item.data_runs,
                resident_data: item.resident_data,
                created_at: item.created_at,
                modified_at: item.modified_at,
                deleted_at,
                is_directory: false,
            }
        })
        .collect();

    Ok(FsParseOutput {
        fs_type: FsType::Ntfs,
        volume_offset: vol_off,
        deleted_entries,
        bitmap,
        is_encrypted_hint: false,
        warnings: Vec::new(),
    })
}

struct RawNtfsRecord {
    mft_index: u64,
    parent_index: u64,
    name: String,
    logical_size: u64,
    data_runs: Vec<ByteRange>,
    resident_data: Option<Vec<u8>>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

struct ParsedMftAttrs {
    file_name: Option<(u64, String)>,
    logical_size: u64,
    data_runs: Vec<ByteRange>,
    resident_data: Option<Vec<u8>>,
    created_at: Option<String>,
    modified_at: Option<String>,
    usn_j_runs: Option<Vec<ByteRange>>,
}

/// Applies NTFS Update Sequence Array (USA) fixup per 512-byte sector.
fn apply_usa_fixup(rec: &mut [u8], sector_size: usize) -> bool {
    if rec.len() < 48 || sector_size < 512 {
        return false;
    }
    let usa_off = read_u16_le(rec, 4) as usize;
    let usa_count = read_u16_le(rec, 6) as usize;
    if usa_count < 2 || usa_off + usa_count * 2 > rec.len() {
        return false;
    }
    let usn = [rec[usa_off], rec[usa_off + 1]];
    for i in 1..usa_count {
        let sector_end = i * sector_size;
        if sector_end > rec.len() || sector_end < 2 {
            break;
        }
        // Check USN marker at end of sector
        if rec[sector_end - 2..sector_end] != usn {
            return false;
        }
        rec[sector_end - 2] = rec[usa_off + i * 2];
        rec[sector_end - 1] = rec[usa_off + i * 2 + 1];
    }
    true
}

fn extract_mft_data_runs(rec0: &[u8], vol_off: u64, cluster_size: u64) -> Option<Vec<ByteRange>> {
    let parsed = parse_mft_attributes(rec0, vol_off, cluster_size);
    if parsed.data_runs.is_empty() {
        None
    } else {
        Some(parsed.data_runs)
    }
}

fn parse_mft_attributes(rec: &[u8], vol_off: u64, cluster_size: u64) -> ParsedMftAttrs {
    let mut out = ParsedMftAttrs {
        file_name: None,
        logical_size: 0,
        data_runs: Vec::new(),
        resident_data: None,
        created_at: None,
        modified_at: None,
        usn_j_runs: None,
    };

    let mut off = read_u16_le(rec, 20) as usize;
    let mut best_name_ns = 255u8;

    while off + 16 <= rec.len() {
        let attr_type = read_u32_le(rec, off);
        if attr_type == 0xFFFF_FFFF || attr_type == 0 {
            break;
        }
        let attr_len = read_u32_le(rec, off + 4) as usize;
        if attr_len < 16 || off + attr_len > rec.len() {
            break;
        }
        let non_resident = rec[off + 8] != 0;
        let name_len = rec[off + 9] as usize;
        let name_off = read_u16_le(rec, off + 10) as usize;
        let attr_name = if name_len > 0 && off + name_off + name_len * 2 <= off + attr_len {
            let units: Vec<u16> = (0..name_len)
                .map(|k| read_u16_le(rec, off + name_off + k * 2))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::new()
        };

        match attr_type {
            // $STANDARD_INFORMATION
            0x10 if !non_resident => {
                let content_off = read_u16_le(rec, off + 20) as usize;
                let base = off + content_off;
                if base + 24 <= off + attr_len {
                    out.created_at = filetime_to_iso(read_u64_le(rec, base));
                    out.modified_at = filetime_to_iso(read_u64_le(rec, base + 8));
                }
            }
            // $FILE_NAME
            0x30 if !non_resident => {
                let content_off = read_u16_le(rec, off + 20) as usize;
                let base = off + content_off;
                if base + 66 <= off + attr_len {
                    let parent_ref = read_u64_le(rec, base);
                    let fn_len = rec[base + 64] as usize;
                    let fn_ns = rec[base + 65];
                    if base + 66 + fn_len * 2 <= off + attr_len {
                        let units: Vec<u16> = (0..fn_len)
                            .map(|k| read_u16_le(rec, base + 66 + k * 2))
                            .collect();
                        let name = String::from_utf16_lossy(&units);
                        // Prefer Win32 (1) or Win32+DOS (3) over DOS-only (2)
                        let prio = match fn_ns {
                            1 | 3 => 0,
                            0 => 1,
                            _ => 2,
                        };
                        if out.file_name.is_none() || prio < best_name_ns {
                            best_name_ns = prio;
                            out.file_name = Some((parent_ref, name));
                        }
                    }
                }
            }
            // $DATA
            0x80 => {
                if attr_name == "$J" && non_resident {
                    let runs_off = read_u16_le(rec, off + 32) as usize;
                    if off + runs_off < off + attr_len {
                        out.usn_j_runs = Some(decode_data_runs(
                            &rec[off + runs_off..off + attr_len],
                            vol_off,
                            cluster_size,
                        ));
                    }
                } else if attr_name.is_empty() {
                    if !non_resident {
                        let val_len = read_u32_le(rec, off + 16) as usize;
                        let val_off = read_u16_le(rec, off + 20) as usize;
                        if off + val_off + val_len <= off + attr_len {
                            out.logical_size = val_len as u64;
                            out.resident_data = Some(rec[off + val_off..off + val_off + val_len].to_vec());
                        }
                    } else if off + 56 <= off + attr_len {
                        let real_size = read_u64_le(rec, off + 48);
                        let runs_off = read_u16_le(rec, off + 32) as usize;
                        out.logical_size = real_size;
                        if off + runs_off < off + attr_len {
                            out.data_runs = decode_data_runs(
                                &rec[off + runs_off..off + attr_len],
                                vol_off,
                                cluster_size,
                            );
                        }
                    }
                }
            }
            _ => {}
        }

        off += attr_len;
    }

    out
}

/// Decodes variable-length NTFS mapping pairs (Data Runs).
pub fn decode_data_runs(raw: &[u8], vol_off: u64, cluster_size: u64) -> Vec<ByteRange> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut prev_lcn: i64 = 0;

    while pos < raw.len() {
        let header = raw[pos];
        pos += 1;
        if header == 0 {
            break;
        }
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;
        if len_bytes == 0 || len_bytes > 8 || off_bytes > 8 || pos + len_bytes + off_bytes > raw.len() {
            break;
        }

        let mut cluster_len = 0u64;
        for i in 0..len_bytes {
            cluster_len |= (raw[pos + i] as u64) << (i * 8);
        }
        pos += len_bytes;

        if off_bytes == 0 {
            // Sparse run
            pos += off_bytes;
            continue;
        }

        let mut rel_lcn: i64 = 0;
        for i in 0..off_bytes {
            rel_lcn |= (raw[pos + i] as i64) << (i * 8);
        }
        // Sign-extend if top bit of `off_bytes` is set
        let sign_bit = 1i64 << (off_bytes * 8 - 1);
        if (rel_lcn & sign_bit) != 0 {
            rel_lcn |= !((1i64 << (off_bytes * 8)) - 1);
        }
        pos += off_bytes;

        let abs_lcn = prev_lcn.saturating_add(rel_lcn);
        if abs_lcn < 0 {
            break;
        }
        prev_lcn = abs_lcn;
        runs.push(ByteRange {
            offset: vol_off + (abs_lcn as u64).saturating_mul(cluster_size),
            length: cluster_len.saturating_mul(cluster_size),
        });
    }

    runs
}

fn collect_usn_deletes(
    reader: &SafeChunkReader,
    runs: &[ByteRange],
    out: &mut HashMap<u64, String>,
) {
    const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
    for r in runs.iter().take(4) {
        let len = r.length.min(4 * 1024 * 1024) as usize;
        let buf = reader.read_vec_resilient(r.offset, len);
        let mut pos = 0usize;
        while pos + 60 <= buf.len() {
            let rec_len = read_u32_le(&buf, pos) as usize;
            if rec_len == 0 {
                // Skip zero-padded sparse pages in $UsnJrnl
                pos = (pos + 4096) & !4095;
                continue;
            }
            if rec_len < 60 || pos + rec_len > buf.len() {
                break;
            }
            let major = read_u16_le(&buf, pos + 4);
            if major == 2 {
                let file_ref = read_u64_le(&buf, pos + 8) & 0x0000_FFFF_FFFF_FFFF;
                let ts = read_u64_le(&buf, pos + 32);
                let reason = read_u32_le(&buf, pos + 40);
                if (reason & USN_REASON_FILE_DELETE) != 0 {
                    if let Some(iso) = filetime_to_iso(ts) {
                        out.insert(file_ref, iso);
                    }
                }
            }
            pos += rec_len;
        }
    }
}

fn build_ntfs_path(dir_names: &HashMap<u64, (u64, String)>, parent: u64, leaf: &str) -> String {
    let mut parts = vec![leaf.to_string()];
    let mut cur = parent;
    for _ in 0..32 {
        if cur == 5 {
            break;
        }
        if let Some((next_parent, name)) = dir_names.get(&cur) {
            parts.push(name.clone());
            if *next_parent == cur {
                break;
            }
            cur = *next_parent;
        } else {
            break;
        }
    }
    parts.reverse();
    format!("/{}", parts.join("/"))
}

fn filetime_to_iso(ft: u64) -> Option<String> {
    // Windows FILETIME: 100-ns intervals since 1601-01-01
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    if ft == 0 {
        return None;
    }
    let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF_SECS;
    chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

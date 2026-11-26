use crate::carve::validators::{validate_jpeg, validate_png, validate_zip_ooxml, ValidationResult};
use crate::fs::AllocationBitmap;
use crate::io::SafeChunkReader;
use crate::models::ByteRange;

/// Result of a successful 2-fragment gap reassembly.
pub struct BifragmentHit {
    pub fragments: Vec<ByteRange>,
    pub validation: ValidationResult,
    pub payload: Vec<u8>,
}

/// Attempts bounded 2-fragment ("Bifragment Gap Carving") recovery when a contiguous
/// JPEG/PNG/ZIP candidate was interrupted by allocated/unrelated clusters before its footer.
///
/// Strategy:
/// 1. Detect where fragment 1 (`head`) stops being coherent (e.g. non-JPEG marker or non-PNG chunk,
///    aligned down to `sector_size` / `cluster_size` boundary).
/// 2. Scan forward in unallocated space within `max_gap_bytes` for a valid tail fragment ending
///    with the expected footer (`FF D9`, `IEND`+CRC, or `PK\x05\x06` EOCD).
/// 3. Splice `[frag1, frag2]` across candidate cluster boundaries and run the TRUE format validator.
pub fn attempt_bifragment_recovery(
    reader: &SafeChunkReader,
    bitmap: Option<&AllocationBitmap>,
    validator_ref: &str,
    head_offset: u64,
    head_buf: &[u8],
    max_gap_bytes: u64,
) -> Option<BifragmentHit> {
    match validator_ref {
        "jpeg" => recover_bifragment_jpeg(reader, bitmap, head_offset, head_buf, max_gap_bytes),
        "png" => recover_bifragment_png(reader, bitmap, head_offset, head_buf, max_gap_bytes),
        "zip_ooxml" => recover_bifragment_zip(reader, bitmap, head_offset, head_buf, max_gap_bytes),
        _ => None,
    }
}

fn recover_bifragment_jpeg(
    reader: &SafeChunkReader,
    bitmap: Option<&AllocationBitmap>,
    head_offset: u64,
    head_buf: &[u8],
    max_gap_bytes: u64,
) -> Option<BifragmentHit> {
    if head_buf.len() < 512 || &head_buf[..3] != b"\xFF\xD8\xFF" {
        return None;
    }

    // Confirm header actually reaches an SOS (`FF DA`) marker before corruption
    let sos_pos = head_buf.windows(2).position(|w| w == [0xFF, 0xDA])?;
    let unit = bitmap
        .map(|b| b.block_size)
        .unwrap_or(reader.sector_size() as u64)
        .max(512);

    // Determine candidate split boundaries starting after SOS (at least 1 allocation unit)
    let first_split = ((sos_pos + 16) as u64).div_ceil(unit) * unit;
    let max_head = (head_buf.len() as u64).min(1024 * 1024);

    // Collect candidate split offsets (where fragment 1 ends and another file's data begins)
    let mut split_candidates = Vec::new();
    let mut off = first_split;
    while off <= max_head {
        // Prioritize boundary right before a non-JPEG magic header or illegal `FF <xx>` jump
        let slice_idx = off as usize;
        if slice_idx + 8 <= head_buf.len() {
            let block_head = &head_buf[slice_idx..slice_idx + 8];
            let looks_like_foreign = block_head.starts_with(b"\x89PNG")
                || block_head.starts_with(b"\xFF\xD8\xFF")
                || block_head.starts_with(b"%PDF-")
                || block_head.starts_with(b"PK\x03\x04");
            if looks_like_foreign {
                split_candidates.insert(0, off);
            } else {
                split_candidates.push(off);
            }
        }
        off += unit;
        if split_candidates.len() >= 128 {
            break;
        }
    }
    if split_candidates.is_empty() {
        return None;
    }

    // Search forward up to `max_gap_bytes` for EOI (`FF D9`) in unallocated space
    let search_start = head_offset + first_split;
    let search_len = max_gap_bytes.min(reader.total_size().saturating_sub(search_start));
    if search_len < unit {
        return None;
    }
    let window = reader.read_vec_resilient(search_start, search_len as usize);

    // Find all `FF D9` positions in unallocated blocks
    let mut eoi_positions = Vec::new();
    for (idx, pair) in window.windows(2).enumerate() {
        if pair == [0xFF, 0xD9] {
            let abs_eoi_end = search_start + idx as u64 + 2;
            if let Some(bm) = bitmap {
                if bm.is_offset_allocated(abs_eoi_end - 2) {
                    continue;
                }
            }
            eoi_positions.push(idx + 2);
            if eoi_positions.len() >= 16 {
                break;
            }
        }
    }
    if eoi_positions.is_empty() {
        return None;
    }

    // Try pairing each split point in Frag 1 with candidate unallocated Frag 2 starts before EOI
    for &split_rel in &split_candidates {
        let frag1 = &head_buf[..split_rel as usize];
        let frag1_end = head_offset + split_rel;

        for &eoi_rel_end in &eoi_positions {
            let abs_eoi_end = search_start + eoi_rel_end as u64;
            if abs_eoi_end <= frag1_end {
                continue;
            }
            // Walk forward from the first unallocated block after `frag1_end` toward `abs_eoi_end`
            // (bounded to last 4 MiB before EOI) so we capture the FULL second fragment, not a truncated tail.
            let min_frag2_abs = (frag1_end + unit).max(abs_eoi_end.saturating_sub(4 * 1024 * 1024));
            let mut frag2_abs = ((min_frag2_abs - search_start) / unit) * unit + search_start;
            while frag2_abs < abs_eoi_end {
                if let Some(bm) = bitmap {
                    if bm.is_offset_allocated(frag2_abs) {
                        frag2_abs += unit;
                        continue;
                    }
                }
                let frag2_rel = (frag2_abs - search_start) as usize;
                // Skip leading all-zero blocks before frag2 starts
                let blk_end = (frag2_rel + unit as usize).min(eoi_rel_end);
                if window[frag2_rel..blk_end].iter().all(|&b| b == 0) {
                    frag2_abs += unit;
                    continue;
                }
                let frag2 = &window[frag2_rel..eoi_rel_end];
                let mut combined = Vec::with_capacity(frag1.len() + frag2.len());
                combined.extend_from_slice(frag1);
                combined.extend_from_slice(frag2);

                let val = validate_jpeg(&combined);
                if val.valid && val.full_decode_ok {
                    return Some(BifragmentHit {
                        fragments: vec![
                            ByteRange {
                                offset: head_offset,
                                length: split_rel,
                            },
                            ByteRange {
                                offset: frag2_abs,
                                length: (eoi_rel_end as u64) - (frag2_rel as u64),
                            },
                        ],
                        validation: val,
                        payload: combined,
                    });
                }
                frag2_abs += unit;
            }
        }
    }

    None
}

fn recover_bifragment_png(
    reader: &SafeChunkReader,
    bitmap: Option<&AllocationBitmap>,
    head_offset: u64,
    head_buf: &[u8],
    max_gap_bytes: u64,
) -> Option<BifragmentHit> {
    if head_buf.len() < 64 || &head_buf[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    let unit = bitmap
        .map(|b| b.block_size)
        .unwrap_or(reader.sector_size() as u64)
        .max(512);
    let search_start = head_offset + unit;
    let search_len = max_gap_bytes.min(reader.total_size().saturating_sub(search_start));
    let window = reader.read_vec_resilient(search_start, search_len as usize);

    let iend_sig = b"IEND\xAE\x42\x60\x82";
    let iend_idx = window.windows(8).position(|w| w == iend_sig)?;
    let tail_end_rel = iend_idx + 8;

    for split_rel in (unit..(head_buf.len() as u64).min(512 * 1024)).step_by(unit as usize) {
        let frag1 = &head_buf[..split_rel as usize];
        let mut back = 0u64;
        let tail_blk = ((tail_end_rel as u64) / unit) * unit;
        while back <= 256 * 1024 && tail_blk >= back {
            let frag2_rel = (tail_blk - back) as usize;
            let frag2_abs = search_start + frag2_rel as u64;
            if frag2_abs <= head_offset + split_rel {
                break;
            }
            if let Some(bm) = bitmap {
                if bm.is_offset_allocated(frag2_abs) {
                    break;
                }
            }
            let mut combined = Vec::with_capacity(frag1.len() + (tail_end_rel - frag2_rel));
            combined.extend_from_slice(frag1);
            combined.extend_from_slice(&window[frag2_rel..tail_end_rel]);
            let val = validate_png(&combined);
            if val.valid {
                return Some(BifragmentHit {
                    fragments: vec![
                        ByteRange {
                            offset: head_offset,
                            length: split_rel,
                        },
                        ByteRange {
                            offset: frag2_abs,
                            length: (tail_end_rel - frag2_rel) as u64,
                        },
                    ],
                    validation: val,
                    payload: combined,
                });
            }
            back += unit;
        }
    }
    None
}

fn recover_bifragment_zip(
    reader: &SafeChunkReader,
    bitmap: Option<&AllocationBitmap>,
    head_offset: u64,
    head_buf: &[u8],
    max_gap_bytes: u64,
) -> Option<BifragmentHit> {
    if head_buf.len() < 64 || &head_buf[..4] != b"PK\x03\x04" {
        return None;
    }
    let unit = bitmap
        .map(|b| b.block_size)
        .unwrap_or(reader.sector_size() as u64)
        .max(512);
    let search_start = head_offset + unit;
    let search_len = max_gap_bytes.min(reader.total_size().saturating_sub(search_start));
    let window = reader.read_vec_resilient(search_start, search_len as usize);

    let eocd_idx = window.windows(4).position(|w| w == b"PK\x05\x06")?;
    if eocd_idx + 22 > window.len() {
        return None;
    }
    let cmt_len = u16::from_le_bytes([window[eocd_idx + 20], window[eocd_idx + 21]]) as usize;
    let tail_end_rel = (eocd_idx + 22 + cmt_len).min(window.len());

    for split_rel in (unit..(head_buf.len() as u64).min(512 * 1024)).step_by(unit as usize) {
        let frag1 = &head_buf[..split_rel as usize];
        let tail_blk = ((tail_end_rel as u64) / unit) * unit;
        let mut back = 0u64;
        while back <= 256 * 1024 && tail_blk >= back {
            let frag2_rel = (tail_blk - back) as usize;
            let frag2_abs = search_start + frag2_rel as u64;
            if frag2_abs <= head_offset + split_rel {
                break;
            }
            let mut combined = Vec::with_capacity(frag1.len() + (tail_end_rel - frag2_rel));
            combined.extend_from_slice(frag1);
            combined.extend_from_slice(&window[frag2_rel..tail_end_rel]);
            let val = validate_zip_ooxml(&combined);
            if val.valid {
                return Some(BifragmentHit {
                    fragments: vec![
                        ByteRange {
                            offset: head_offset,
                            length: split_rel,
                        },
                        ByteRange {
                            offset: frag2_abs,
                            length: (tail_end_rel - frag2_rel) as u64,
                        },
                    ],
                    validation: val,
                    payload: combined,
                });
            }
            back += unit;
        }
    }
    None
}

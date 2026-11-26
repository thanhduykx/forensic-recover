use crate::carve::bifragment::attempt_bifragment_recovery;
use crate::carve::confidence::score_candidate;
use crate::carve::confidence::ConfidenceInput;
use crate::carve::rules::SignatureDatabase;
use crate::carve::validators::{validate_by_ref, ValidationResult};
use crate::fs::AllocationBitmap;
use crate::io::SafeChunkReader;
use crate::models::{ByteRange, CarveRule, ConfidenceLevel, FileFamily, RecoveryMethod};
use sha2::{Digest, Sha256};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// A validated candidate produced by the carver before deduplication/session wrapping.
#[derive(Debug, Clone)]
pub struct CarvedCandidate {
    pub byte_offset: u64,
    pub length: u64,
    pub fragments: Vec<ByteRange>,
    pub family: FileFamily,
    pub mime: String,
    pub ext: String,
    pub sha256: String,
    pub confidence: ConfidenceLevel,
    pub confidence_score: f32,
    pub recovery_method: RecoveryMethod,
    pub notes: Vec<String>,
    /// Optional small preview bytes (images only, capped) to avoid re-reading for thumbnail generation.
    pub inline_payload: Option<Vec<u8>>,
}

/// Scans a chunk slice `[chunk_offset .. chunk_offset + chunk_len]` for signature hits,
/// reading bounded lookahead from `reader` when a candidate spans past the current chunk.
#[allow(clippy::too_many_arguments)]
pub fn carve_chunk(
    reader: &SafeChunkReader,
    db: &SignatureDatabase,
    bitmap: Option<&AllocationBitmap>,
    include_allocated: bool,
    bifragment_gap_bytes: u64,
    chunk_offset: u64,
    chunk_buf: &[u8],
    zero_block_ratio: f64,
) -> Vec<CarvedCandidate> {
    let mut results = Vec::new();
    let mut pos = 0usize;

    while pos < chunk_buf.len() {
        let b = chunk_buf[pos];
        let rule_indices = db.rules_for_first_byte(b);
        if rule_indices.is_empty() {
            pos += 1;
            continue;
        }

        let mut matched_advance = 0usize;

        for &r_idx in rule_indices {
            let rule = &db.rules[r_idx];
            if pos < rule.header_offset || pos + rule.header.len() > chunk_buf.len() {
                continue;
            }
            if &chunk_buf[pos..pos + rule.header.len()] != rule.header.as_slice() {
                continue;
            }

            let file_rel = pos - rule.header_offset;
            let file_abs = chunk_offset + file_rel as u64;

            if !include_allocated {
                if let Some(bm) = bitmap {
                    if bm.is_offset_allocated(file_abs) {
                        continue;
                    }
                }
            }

            // Isolate each candidate validation with `catch_unwind`
            let attempt = catch_unwind(AssertUnwindSafe(|| {
                evaluate_candidate(
                    reader,
                    rule,
                    bitmap,
                    bifragment_gap_bytes,
                    file_abs,
                    &chunk_buf[file_rel..],
                    zero_block_ratio,
                )
            }));

            if let Ok(Some(cand)) = attempt {
                let skip_len = if cand.fragments.len() == 1 {
                    cand.length.min(chunk_buf.len() as u64 - file_rel as u64) as usize
                } else {
                    cand.fragments[0]
                        .length
                        .min(chunk_buf.len() as u64 - file_rel as u64) as usize
                };
                results.push(cand);
                matched_advance = skip_len.max(1);
                break;
            }
        }

        if matched_advance > 0 {
            pos += matched_advance;
        } else {
            pos += 1;
        }
    }

    results
}

fn evaluate_candidate(
    reader: &SafeChunkReader,
    rule: &CarveRule,
    bitmap: Option<&AllocationBitmap>,
    bifragment_gap_bytes: u64,
    file_abs: u64,
    local_tail: &[u8],
    zero_block_ratio: f64,
) -> Option<CarvedCandidate> {
    // Bounded probe window (up to min(rule.max_len, 16 MiB) first; larger videos walk atoms)
    let probe_cap = rule.max_len.min(16 * 1024 * 1024) as usize;
    let avail_total = reader.total_size().saturating_sub(file_abs) as usize;
    let want = probe_cap.min(avail_total);
    if (want as u64) < rule.min_len {
        return None;
    }

    let owned;
    let buf: &[u8] = if local_tail.len() >= want {
        &local_tail[..want]
    } else {
        owned = reader.read_vec_resilient(file_abs, want);
        &owned
    };

    let val: ValidationResult = validate_by_ref(&rule.validator_ref, buf);
    if val.valid && (val.exact_len as u64) >= rule.min_len {
        let payload = &buf[..val.exact_len];
        let sha = hex::encode(Sha256::digest(payload));
        let bad_count = count_bad_sectors(reader, file_abs, val.exact_len as u64);
        let (score, level) = score_candidate(&ConfidenceInput {
            validation: &val,
            fragment_count: 1,
            matched_fs_metadata: false,
            recovery_method: RecoveryMethod::SignatureCarved,
            bad_sectors_in_range: bad_count,
            zero_block_ratio,
        });
        let inline_payload = if val.family == FileFamily::Image && payload.len() <= 8 * 1024 * 1024 {
            Some(payload.to_vec())
        } else {
            None
        };
        return Some(CarvedCandidate {
            byte_offset: file_abs,
            length: val.exact_len as u64,
            fragments: vec![ByteRange {
                offset: file_abs,
                length: val.exact_len as u64,
            }],
            family: val.family,
            mime: val.mime,
            ext: val.ext,
            sha256: sha,
            confidence: level,
            confidence_score: score,
            recovery_method: RecoveryMethod::SignatureCarved,
            notes: val.notes,
            inline_payload,
        });
    }

    // Contiguous validation failed -> attempt bounded Bifragment Gap Recovery if enabled
    if bifragment_gap_bytes > 0 {
        if let Some(bf) = attempt_bifragment_recovery(
            reader,
            bitmap,
            &rule.validator_ref,
            file_abs,
            buf,
            bifragment_gap_bytes,
        ) {
            let sha = hex::encode(Sha256::digest(&bf.payload));
            let (score, level) = score_candidate(&ConfidenceInput {
                validation: &bf.validation,
                fragment_count: bf.fragments.len(),
                matched_fs_metadata: false,
                recovery_method: RecoveryMethod::BifragmentCarved,
                bad_sectors_in_range: 0,
                zero_block_ratio,
            });
            let mut notes = bf.validation.notes;
            notes.push(format!(
                "Reassembled {} non-contiguous fragments across gap",
                bf.fragments.len()
            ));
            let inline_payload =
                if bf.validation.family == FileFamily::Image && bf.payload.len() <= 8 * 1024 * 1024 {
                    Some(bf.payload)
                } else {
                    None
                };
            return Some(CarvedCandidate {
                byte_offset: file_abs,
                length: bf.validation.exact_len as u64,
                fragments: bf.fragments,
                family: bf.validation.family,
                mime: bf.validation.mime,
                ext: bf.validation.ext,
                sha256: sha,
                confidence: level,
                confidence_score: score,
                recovery_method: RecoveryMethod::BifragmentCarved,
                notes,
                inline_payload,
            });
        }
    }

    None
}

fn count_bad_sectors(reader: &SafeChunkReader, start: u64, len: u64) -> usize {
    let end = start.saturating_add(len);
    reader
        .bad_sectors()
        .iter()
        .filter(|b| b.offset < end && b.offset + b.length > start)
        .count()
}

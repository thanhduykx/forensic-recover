use crate::carve::validators::ValidationResult;
use crate::models::{ConfidenceLevel, RecoveryMethod};

/// Inputs used to score recovery confidence honestly (reflecting flash/TRIM reality).
pub struct ConfidenceInput<'a> {
    pub validation: &'a ValidationResult,
    pub fragment_count: usize,
    pub matched_fs_metadata: bool,
    pub recovery_method: RecoveryMethod,
    pub bad_sectors_in_range: usize,
    pub zero_block_ratio: f64,
}

/// Computes `confidence_score` (`0.0..=1.0`) and discrete `ConfidenceLevel` (`High`/`Medium`/`Low`).
pub fn score_candidate(input: &ConfidenceInput<'_>) -> (f32, ConfidenceLevel) {
    let mut score: f32 = 0.40;

    if input.validation.full_decode_ok {
        score += 0.35;
    } else if input.validation.valid {
        score += 0.18;
    }

    if input.fragment_count <= 1 {
        score += 0.15;
    } else if input.fragment_count == 2 {
        score += 0.03;
    } else {
        score -= 0.10;
    }

    if input.matched_fs_metadata
        || matches!(
            input.recovery_method,
            RecoveryMethod::HybridFsAndCarve | RecoveryMethod::FsMetadata
        )
    {
        score += 0.10;
    }

    if input.bad_sectors_in_range > 0 {
        score -= 0.25;
    }

    // Flash TRIM pressure reduces trust when large portions of the volume are zero-filled
    if input.zero_block_ratio > 0.70 {
        score -= 0.08;
    }

    let clamped = score.clamp(0.05, 0.99);
    let level = if clamped >= 0.75 {
        ConfidenceLevel::High
    } else if clamped >= 0.45 {
        ConfidenceLevel::Medium
    } else {
        ConfidenceLevel::Low
    };
    (clamped, level)
}

/// Tracks block-level TRIM (zero/0xFF-filled) and FBE/BitLocker high-entropy anomalies
/// across the scanned source so the session report warns honestly.
#[derive(Debug, Default, Clone)]
pub struct BlockAnomalyTracker {
    pub total_blocks: u64,
    pub zero_or_ff_blocks: u64,
    pub high_entropy_blocks: u64,
}

impl BlockAnomalyTracker {
    pub fn observe_chunk(&mut self, buf: &[u8]) {
        for blk in buf.chunks(4096) {
            self.total_blocks += 1;
            if blk.iter().all(|&b| b == 0x00) || blk.iter().all(|&b| b == 0xFF) {
                self.zero_or_ff_blocks += 1;
                continue;
            }
            // Fast 256-bin byte histogram on 4 KiB block
            let mut counts = [0u16; 256];
            for &b in blk {
                counts[b as usize] += 1;
            }
            let n = blk.len() as f64;
            let mut ent = 0.0;
            for &c in &counts {
                if c > 0 {
                    let p = (c as f64) / n;
                    ent -= p * p.log2();
                }
            }
            if ent > 7.95 {
                self.high_entropy_blocks += 1;
            }
        }
    }

    pub fn zero_ratio(&self) -> f64 {
        if self.total_blocks == 0 {
            0.0
        } else {
            self.zero_or_ff_blocks as f64 / self.total_blocks as f64
        }
    }

    pub fn high_entropy_ratio(&self) -> f64 {
        if self.total_blocks == 0 {
            0.0
        } else {
            self.high_entropy_blocks as f64 / self.total_blocks as f64
        }
    }
}

pub mod apfs;
pub mod exfat;
pub mod ext4;
pub mod fat;
pub mod hfsplus;
pub mod ntfs;

use crate::io::SafeChunkReader;
use crate::models::{ByteRange, FsType};
use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Metadata extracted for a logically deleted file from filesystem structures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFsEntry {
    pub fs_path: String,
    pub name: String,
    pub size: u64,
    pub data_runs: Vec<ByteRange>,
    pub resident_data: Option<Vec<u8>>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub deleted_at: Option<String>,
    pub is_directory: bool,
}

/// Compact block/cluster allocation bitmap used to skip active allocated blocks
/// during unallocated signature carving.
#[derive(Debug, Clone)]
pub struct AllocationBitmap {
    pub block_size: u64,
    pub data_start_offset: u64,
    /// Bit `i == 1` means block/cluster `i` is ALLOCATED (in use). `0` means UNALLOCATED.
    allocated_bits: Vec<u8>,
    pub total_blocks: u64,
}

impl AllocationBitmap {
    pub fn new(block_size: u64, data_start_offset: u64, total_blocks: u64) -> Self {
        let byte_len = ((total_blocks as usize).saturating_add(7)) / 8;
        Self {
            block_size: block_size.max(512),
            data_start_offset,
            allocated_bits: vec![0u8; byte_len],
            total_blocks,
        }
    }

    pub fn set_allocated(&mut self, block_idx: u64, allocated: bool) {
        if block_idx >= self.total_blocks {
            return;
        }
        let byte_i = (block_idx / 8) as usize;
        let bit_i = (block_idx % 8) as u8;
        if let Some(slot) = self.allocated_bits.get_mut(byte_i) {
            if allocated {
                *slot |= 1 << bit_i;
            } else {
                *slot &= !(1 << bit_i);
            }
        }
    }

    pub fn is_block_allocated(&self, block_idx: u64) -> bool {
        if block_idx >= self.total_blocks {
            return false;
        }
        let byte_i = (block_idx / 8) as usize;
        let bit_i = (block_idx % 8) as u8;
        self.allocated_bits
            .get(byte_i)
            .map(|b| (b & (1 << bit_i)) != 0)
            .unwrap_or(false)
    }

    /// Returns `true` if the byte offset falls inside an allocated block.
    pub fn is_offset_allocated(&self, abs_offset: u64) -> bool {
        if abs_offset < self.data_start_offset {
            return false;
        }
        let rel = abs_offset - self.data_start_offset;
        let blk = rel / self.block_size;
        self.is_block_allocated(blk)
    }

    pub fn count_unallocated_bytes(&self) -> u64 {
        let mut alloc = 0u64;
        for blk in 0..self.total_blocks {
            if self.is_block_allocated(blk) {
                alloc += 1;
            }
        }
        self.total_blocks
            .saturating_sub(alloc)
            .saturating_mul(self.block_size)
    }
}

/// Combined output of read-only filesystem discovery and parsing.
#[derive(Debug, Clone)]
pub struct FsParseOutput {
    pub fs_type: FsType,
    pub volume_offset: u64,
    pub deleted_entries: Vec<DeletedFsEntry>,
    pub bitmap: Option<AllocationBitmap>,
    pub is_encrypted_hint: bool,
    pub warnings: Vec<String>,
}

impl Default for FsParseOutput {
    fn default() -> Self {
        Self {
            fs_type: FsType::RawUnknown,
            volume_offset: 0,
            deleted_entries: Vec::new(),
            bitmap: None,
            is_encrypted_hint: false,
            warnings: Vec::new(),
        }
    }
}

/// Detects partition layout (bare volume vs MBR/GPT) and runs the matching read-only FS parser.
/// Every parser is isolated via `catch_unwind` so a malformed FS structure cannot crash a scan.
pub fn detect_and_parse_fs(reader: &SafeChunkReader) -> FsParseOutput {
    let candidate_offsets = discover_volume_offsets(reader);
    let mut warnings = Vec::new();

    for vol_off in candidate_offsets {
        if let Some(parsed) = try_parse_at_offset(reader, vol_off, &mut warnings) {
            return parsed;
        }
    }

    FsParseOutput {
        fs_type: FsType::RawUnknown,
        volume_offset: 0,
        deleted_entries: Vec::new(),
        bitmap: None,
        is_encrypted_hint: false,
        warnings,
    }
}

fn discover_volume_offsets(reader: &SafeChunkReader) -> Vec<u64> {
    let mut offsets = vec![0u64];
    let sector0 = reader.read_vec_resilient(0, 1024);
    if sector0.len() >= 512 && sector0[510] == 0x55 && sector0[511] == 0xAA {
        // Check if sector 0 is already a volume boot record (NTFS/FAT/exFAT)
        let is_ntfs = &sector0[3..11] == b"NTFS    ";
        let is_exfat = &sector0[3..11] == b"EXFAT   ";
        let is_fat32 = sector0.len() >= 90 && &sector0[82..87] == b"FAT32";
        if !is_ntfs && !is_exfat && !is_fat32 {
            // Check GPT at LBA 1 (`EFI PART`)
            if sector0.len() >= 520 && &sector0[512..520] == b"EFI PART" {
                let gpt_entries = reader.read_vec_resilient(1024, 128 * 128);
                for idx in 0..128 {
                    let base = idx * 128;
                    if base + 48 > gpt_entries.len() {
                        break;
                    }
                    let type_guid = &gpt_entries[base..base + 16];
                    if type_guid.iter().all(|&b| b == 0) {
                        continue;
                    }
                    let first_lba = u64::from_le_bytes(
                        gpt_entries[base + 32..base + 40].try_into().unwrap_or([0; 8]),
                    );
                    let off = first_lba.saturating_mul(512);
                    if off > 0 && off < reader.total_size() && !offsets.contains(&off) {
                        offsets.push(off);
                    }
                }
            } else {
                // Parse MBR partition entries (4 x 16 bytes at 0x1BE)
                for p in 0..4 {
                    let base = 446 + p * 16;
                    let ptype = sector0[base + 4];
                    if ptype == 0 || ptype == 0xEE {
                        continue;
                    }
                    let lba_start = u32::from_le_bytes(
                        sector0[base + 8..base + 12].try_into().unwrap_or([0; 4]),
                    );
                    let off = (lba_start as u64).saturating_mul(512);
                    if off > 0 && off < reader.total_size() && !offsets.contains(&off) {
                        offsets.push(off);
                    }
                }
            }
        }
    }
    offsets
}

fn try_parse_at_offset(
    reader: &SafeChunkReader,
    vol_off: u64,
    warnings: &mut Vec<String>,
) -> Option<FsParseOutput> {
    let head = reader.read_vec_resilient(vol_off, 2048);
    if head.len() < 512 {
        return None;
    }

    // 1. NTFS
    if &head[3..11] == b"NTFS    " {
        return match catch_unwind(AssertUnwindSafe(|| ntfs::parse_ntfs(reader, vol_off))) {
            Ok(Ok(out)) => Some(out),
            Ok(Err(e)) => {
                warnings.push(format!("NTFS parser fallback at {vol_off:#x}: {e}"));
                None
            }
            Err(_) => {
                warnings.push(format!("NTFS parser panicked safely at {vol_off:#x}"));
                None
            }
        };
    }

    // 2. exFAT
    if &head[3..11] == b"EXFAT   " {
        return match catch_unwind(AssertUnwindSafe(|| exfat::parse_exfat(reader, vol_off))) {
            Ok(Ok(out)) => Some(out),
            Ok(Err(e)) => {
                warnings.push(format!("exFAT parser fallback at {vol_off:#x}: {e}"));
                None
            }
            Err(_) => {
                warnings.push(format!("exFAT parser panicked safely at {vol_off:#x}"));
                None
            }
        };
    }

    // 3. FAT32
    if (&head[82..87] == b"FAT32" || &head[54..57] == b"FAT") && head[510] == 0x55 && head[511] == 0xAA
    {
        return match catch_unwind(AssertUnwindSafe(|| fat::parse_fat32(reader, vol_off))) {
            Ok(Ok(out)) => Some(out),
            Ok(Err(e)) => {
                warnings.push(format!("FAT parser fallback at {vol_off:#x}: {e}"));
                None
            }
            Err(_) => {
                warnings.push(format!("FAT parser panicked safely at {vol_off:#x}"));
                None
            }
        };
    }

    // 4. ext4 (superblock at vol_off + 1024, magic 0xEF53 at +0x38)
    if head.len() >= 1024 + 60 && u16::from_le_bytes([head[1024 + 0x38], head[1024 + 0x39]]) == 0xEF53
    {
        return match catch_unwind(AssertUnwindSafe(|| ext4::parse_ext4(reader, vol_off))) {
            Ok(Ok(out)) => Some(out),
            Ok(Err(e)) => {
                warnings.push(format!("ext4 parser fallback at {vol_off:#x}: {e}"));
                None
            }
            Err(_) => {
                warnings.push(format!("ext4 parser panicked safely at {vol_off:#x}"));
                None
            }
        };
    }

    // 5. APFS (`NXSB` at +32)
    if &head[32..36] == b"NXSB" {
        return match catch_unwind(AssertUnwindSafe(|| apfs::parse_apfs(reader, vol_off))) {
            Ok(Ok(out)) => Some(out),
            Ok(Err(e)) => {
                warnings.push(format!("APFS parser fallback at {vol_off:#x}: {e}"));
                None
            }
            Err(_) => {
                warnings.push(format!("APFS parser panicked safely at {vol_off:#x}"));
                None
            }
        };
    }

    // 6. HFS+ (`H+` / `HX` at vol_off + 1024)
    if head.len() >= 1026 && (&head[1024..1026] == b"H+" || &head[1024..1026] == b"HX") {
        return match catch_unwind(AssertUnwindSafe(|| hfsplus::parse_hfsplus(reader, vol_off))) {
            Ok(Ok(out)) => Some(out),
            Ok(Err(e)) => {
                warnings.push(format!("HFS+ parser fallback at {vol_off:#x}: {e}"));
                None
            }
            Err(_) => {
                warnings.push(format!("HFS+ parser panicked safely at {vol_off:#x}"));
                None
            }
        };
    }

    None
}

#[inline]
pub(crate) fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    buf.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_le_bytes)
        .unwrap_or(0)
}

#[inline]
pub(crate) fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    buf.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

#[inline]
pub(crate) fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    buf.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

#[allow(dead_code)]
#[inline]
pub(crate) fn read_u16_be(buf: &[u8], off: usize) -> u16 {
    buf.get(off..off + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_be_bytes)
        .unwrap_or(0)
}

#[inline]
pub(crate) fn read_u32_be(buf: &[u8], off: usize) -> u32 {
    buf.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0)
}

#[allow(dead_code)]
#[inline]
pub(crate) fn read_u64_be(buf: &[u8], off: usize) -> u64 {
    buf.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0)
}

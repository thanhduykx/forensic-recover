use crate::error::{RecoverError, Result};
use crate::fs::{read_u32_be, AllocationBitmap, FsParseOutput};
use crate::io::SafeChunkReader;
use crate::models::FsType;

/// Read-only HFS+ (`H+` / `HX`) volume header + allocation bitmap parser.
pub fn parse_hfsplus(reader: &SafeChunkReader, vol_off: u64) -> Result<FsParseOutput> {
    let vh = reader.read_vec_resilient(vol_off + 1024, 512);
    if vh.len() < 512 || (&vh[0..2] != b"H+" && &vh[0..2] != b"HX") {
        return Err(RecoverError::Parse("Not a valid HFS+ Volume Header".into()));
    }

    let block_size = read_u32_be(&vh, 40) as u64;
    let total_blocks = read_u32_be(&vh, 44) as u64;
    if block_size < 512 || total_blocks == 0 {
        return Err(RecoverError::Parse("Invalid HFS+ geometry".into()));
    }

    // `allocationFile` fork data starts at offset 112; first extent descriptor at +128 (startBlock, blockCount)
    let alloc_start_blk = read_u32_be(&vh, 128) as u64;
    let alloc_blk_count = read_u32_be(&vh, 132) as u64;

    let mut bitmap = AllocationBitmap::new(block_size, vol_off, total_blocks);
    if alloc_blk_count > 0 && alloc_start_blk < total_blocks {
        let read_bytes = (alloc_blk_count * block_size).min(8 * 1024 * 1024) as usize;
        let bm_raw = reader.read_vec_resilient(vol_off + alloc_start_blk * block_size, read_bytes);
        for (byte_i, &b) in bm_raw.iter().enumerate() {
            // HFS+ allocation bitmap is big-endian bit order (MSB = lowest block)
            for bit in 0..8 {
                let blk = (byte_i * 8 + bit) as u64;
                if blk >= total_blocks {
                    break;
                }
                if (b & (0x80 >> bit)) != 0 {
                    bitmap.set_allocated(blk, true);
                }
            }
        }
    }

    Ok(FsParseOutput {
        fs_type: FsType::HfsPlus,
        volume_offset: vol_off,
        deleted_entries: Vec::new(),
        bitmap: Some(bitmap),
        is_encrypted_hint: false,
        warnings: vec![
            "HFS+ Volume Header & allocation bitmap parsed; unallocated space will be carved by signature validators."
                .to_string(),
        ],
    })
}

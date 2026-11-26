use crate::error::{RecoverError, Result};
use crate::fs::{read_u16_le, read_u32_le, AllocationBitmap, DeletedFsEntry, FsParseOutput};
use crate::io::SafeChunkReader;
use crate::models::{ByteRange, FsType};

/// Read-only ext4 parser:
/// - Parses superblock at `vol_off + 1024` (`0xEF53`).
/// - Reads Block Group Descriptor Table (32 or 64 byte descriptors).
/// - Builds block allocation bitmap across groups.
/// - Scans inode tables for deleted inodes (`i_dtime != 0` with `i_size > 0`) and resolves
///   EXT4 extents (`0xF30A` magic) or direct block pointers.
pub fn parse_ext4(reader: &SafeChunkReader, vol_off: u64) -> Result<FsParseOutput> {
    let sb = reader.read_vec_resilient(vol_off + 1024, 1024);
    if sb.len() < 256 || read_u16_le(&sb, 0x38) != 0xEF53 {
        return Err(RecoverError::Parse("Not a valid ext4 superblock".into()));
    }

    let inodes_count = read_u32_le(&sb, 0x00) as u64;
    let blocks_count_lo = read_u32_le(&sb, 0x04) as u64;
    let first_data_block = read_u32_le(&sb, 0x14) as u64;
    let log_block_size = read_u32_le(&sb, 0x18).min(6);
    let blocks_per_group = read_u32_le(&sb, 0x20) as u64;
    let inodes_per_group = read_u32_le(&sb, 0x28) as u64;
    let inode_size = read_u16_le(&sb, 0x58).max(128) as usize;
    let desc_size = read_u16_le(&sb, 0xFE).max(32) as usize;
    let feature_incompat = read_u32_le(&sb, 0x60);
    let is_64bit = (feature_incompat & 0x0080) != 0;
    let blocks_count_hi = if is_64bit {
        read_u32_le(&sb, 0x150) as u64
    } else {
        0
    };

    let block_size = 1024u64 << log_block_size;
    let total_blocks = (blocks_count_hi << 32) | blocks_count_lo;
    if blocks_per_group == 0 || inodes_per_group == 0 || total_blocks == 0 {
        return Err(RecoverError::Parse("Invalid ext4 block/inode group geometry".into()));
    }

    let num_groups = (total_blocks - first_data_block)
        .div_ceil(blocks_per_group)
        .min(4096) as usize;
    let bgdt_block = if block_size == 1024 { 2 } else { 1 };
    let bgdt_off = vol_off + bgdt_block * block_size;
    let actual_desc_size = if is_64bit && desc_size >= 64 { desc_size } else { 32 };
    let bgdt_raw = reader.read_vec_resilient(bgdt_off, num_groups * actual_desc_size);

    let mut bitmap = AllocationBitmap::new(block_size, vol_off, total_blocks);
    let mut deleted_entries = Vec::new();

    for g in 0..num_groups {
        let base = g * actual_desc_size;
        if base + 32 > bgdt_raw.len() {
            break;
        }
        let blk_bm_lo = read_u32_le(&bgdt_raw, base) as u64;
        let ino_tbl_lo = read_u32_le(&bgdt_raw, base + 8) as u64;
        let (blk_bm_hi, ino_tbl_hi) = if actual_desc_size >= 64 {
            (
                read_u32_le(&bgdt_raw, base + 32) as u64,
                read_u32_le(&bgdt_raw, base + 40) as u64,
            )
        } else {
            (0, 0)
        };
        let blk_bitmap_blk = (blk_bm_hi << 32) | blk_bm_lo;
        let inode_table_blk = (ino_tbl_hi << 32) | ino_tbl_lo;

        // Read block bitmap for group `g`
        if blk_bitmap_blk > 0 && blk_bitmap_blk < total_blocks {
            let bm_bytes = blocks_per_group.div_ceil(8).min(block_size) as usize;
            let bm_raw = reader.read_vec_resilient(vol_off + blk_bitmap_blk * block_size, bm_bytes);
            let group_start_blk = first_data_block + (g as u64) * blocks_per_group;
            for (byte_i, &b) in bm_raw.iter().enumerate() {
                for bit in 0..8 {
                    let local_blk = (byte_i * 8 + bit) as u64;
                    if local_blk >= blocks_per_group {
                        break;
                    }
                    if (b & (1 << bit)) != 0 {
                        bitmap.set_allocated(group_start_blk + local_blk, true);
                    }
                }
            }
        }

        // Scan deleted inodes in group `g` (bounded to 16,384 inodes per group)
        if inode_table_blk > 0 && inode_table_blk < total_blocks {
            let scan_inodes = (inodes_per_group as usize).min(16_384);
            let table_bytes = scan_inodes * inode_size;
            let table_raw = reader.read_vec_resilient(
                vol_off + inode_table_blk * block_size,
                table_bytes.min(8 * 1024 * 1024),
            );
            for idx in 0..scan_inodes {
                let off = idx * inode_size;
                if off + 128 > table_raw.len() {
                    break;
                }
                let inode = &table_raw[off..off + inode_size.min(table_raw.len() - off)];
                let i_mode = read_u16_le(inode, 0x00);
                let i_size_lo = read_u32_le(inode, 0x04) as u64;
                let i_dtime = read_u32_le(inode, 0x14);
                let i_flags = read_u32_le(inode, 0x20);
                let i_size_hi = read_u32_le(inode, 0x6C) as u64;
                let size = (i_size_hi << 32) | i_size_lo;
                let is_reg = (i_mode & 0xF000) == 0x8000;
                let ino_num = (g as u64) * inodes_per_group + (idx as u64) + 1;

                if ino_num <= inodes_count && i_dtime != 0 && size > 0 && (is_reg || i_mode == 0) {
                    let uses_extents = (i_flags & 0x0008_0000) != 0;
                    let i_block = &inode[0x28..0x64];
                    let runs = if uses_extents {
                        parse_ext4_extents(i_block, vol_off, block_size)
                    } else {
                        parse_ext4_direct_blocks(i_block, vol_off, block_size)
                    };
                    if !runs.is_empty() {
                        let deleted_at = chrono::DateTime::from_timestamp(i_dtime as i64, 0)
                            .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                        let name = format!("inode_{ino_num}");
                        deleted_entries.push(DeletedFsEntry {
                            fs_path: format!("/__ext4_deleted/{name}"),
                            name,
                            size,
                            data_runs: runs,
                            resident_data: None,
                            created_at: None,
                            modified_at: deleted_at.clone(),
                            deleted_at,
                            is_directory: false,
                        });
                    }
                }
            }
        }
    }

    Ok(FsParseOutput {
        fs_type: FsType::Ext4,
        volume_offset: vol_off,
        deleted_entries,
        bitmap: Some(bitmap),
        is_encrypted_hint: false,
        warnings: Vec::new(),
    })
}

fn parse_ext4_extents(i_block: &[u8], vol_off: u64, block_size: u64) -> Vec<ByteRange> {
    if i_block.len() < 12 || read_u16_le(i_block, 0) != 0xF30A {
        return Vec::new();
    }
    let entries = read_u16_le(i_block, 2) as usize;
    let depth = read_u16_le(i_block, 6);
    if depth != 0 {
        return Vec::new();
    }
    let mut runs = Vec::new();
    for i in 0..entries.min(4) {
        let base = 12 + i * 12;
        if base + 12 > i_block.len() {
            break;
        }
        let ee_len = (read_u16_le(i_block, base + 4) & 0x7FFF) as u64;
        let ee_start_hi = read_u16_le(i_block, base + 6) as u64;
        let ee_start_lo = read_u32_le(i_block, base + 8) as u64;
        let start_blk = (ee_start_hi << 32) | ee_start_lo;
        if ee_len > 0 && start_blk > 0 {
            runs.push(ByteRange {
                offset: vol_off + start_blk * block_size,
                length: ee_len * block_size,
            });
        }
    }
    runs
}

fn parse_ext4_direct_blocks(i_block: &[u8], vol_off: u64, block_size: u64) -> Vec<ByteRange> {
    let mut runs = Vec::new();
    for i in 0..12 {
        let blk = read_u32_le(i_block, i * 4) as u64;
        if blk == 0 {
            break;
        }
        runs.push(ByteRange {
            offset: vol_off + blk * block_size,
            length: block_size,
        });
    }
    runs
}

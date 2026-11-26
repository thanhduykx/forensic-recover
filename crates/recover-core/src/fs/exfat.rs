use crate::error::{RecoverError, Result};
use crate::fs::{read_u16_le, read_u32_le, read_u64_le, AllocationBitmap, DeletedFsEntry, FsParseOutput};
use crate::io::SafeChunkReader;
use crate::models::{ByteRange, FsType};

/// Read-only exFAT parser:
/// - Reads VBR (`ClusterHeapOffset`, `ClusterCount`, `SectorsPerClusterShift`).
/// - Extracts Allocation Bitmap (`0x81`) and scans root/subdirectories for deleted File (`0x05`)
///   + Stream Extension (`0x40`) + File Name (`0x41`) triplets.
pub fn parse_exfat(reader: &SafeChunkReader, vol_off: u64) -> Result<FsParseOutput> {
    let vbr = reader.read_vec_resilient(vol_off, 512);
    if vbr.len() < 512 || &vbr[3..11] != b"EXFAT   " {
        return Err(RecoverError::Parse("Not a valid exFAT VBR".into()));
    }

    let sector_shift = vbr[108].min(16);
    let spc_shift = vbr[109].min(24);
    let bytes_per_sector = 1u64 << sector_shift;
    let cluster_size = bytes_per_sector << spc_shift;
    let cluster_heap_sector = read_u32_le(&vbr, 88) as u64;
    let cluster_count = read_u32_le(&vbr, 92) as u64;
    let root_cluster = read_u32_le(&vbr, 96);

    if cluster_count == 0 || root_cluster < 2 {
        return Err(RecoverError::Parse("Invalid exFAT geometry".into()));
    }

    let data_start_offset = vol_off + cluster_heap_sector * bytes_per_sector;
    let mut bitmap = AllocationBitmap::new(cluster_size, data_start_offset, cluster_count);

    let root_off = data_start_offset + (root_cluster as u64 - 2) * cluster_size;
    let root_buf = reader.read_vec_resilient(root_off, cluster_size.min(4 * 1024 * 1024) as usize);

    // First locate Allocation Bitmap (`0x81`) in root directory
    for chunk in root_buf.as_chunks::<32>().0 {
        if chunk[0] == 0x81 {
            let bm_clus = read_u32_le(chunk, 20);
            let bm_len = read_u64_le(chunk, 24).min(16 * 1024 * 1024) as usize;
            if bm_clus >= 2 {
                let bm_off = data_start_offset + (bm_clus as u64 - 2) * cluster_size;
                let bm_raw = reader.read_vec_resilient(bm_off, bm_len);
                for (byte_i, &b) in bm_raw.iter().enumerate() {
                    for bit in 0..8 {
                        let clus_idx = (byte_i * 8 + bit) as u64;
                        if clus_idx < cluster_count && (b & (1 << bit)) != 0 {
                            bitmap.set_allocated(clus_idx, true);
                        }
                    }
                }
            }
            break;
        }
    }

    // Parse deleted directory entries (0x05 File, followed by 0x40 Stream, 0x41+ FileName)
    let mut deleted_entries = Vec::new();
    let entries: Vec<&[u8; 32]> = root_buf.as_chunks::<32>().0.iter().collect();
    let mut i = 0usize;
    while i < entries.len() {
        let e = entries[i];
        if e[0] == 0x00 {
            break;
        }
        if e[0] == 0x05 {
            let sec_count = e[1] as usize;
            let file_attr = read_u16_le(e, 4);
            let is_dir = (file_attr & 0x10) != 0;
            if !is_dir && i + sec_count < entries.len() && sec_count >= 2 {
                let stream = entries[i + 1];
                if stream[0] == 0x40 {
                    let name_len = stream[3] as usize;
                    let data_len = read_u64_le(stream, 24);
                    let first_clus = read_u32_le(stream, 20);
                    let mut utf16 = Vec::new();
                    for k in 2..=sec_count {
                        let ne = entries[i + k];
                        if ne[0] != 0x41 {
                            break;
                        }
                        for p in (2..32).step_by(2) {
                            let u = read_u16_le(ne, p);
                            if u != 0 && utf16.len() < name_len {
                                utf16.push(u);
                            }
                        }
                    }
                    let name = String::from_utf16_lossy(&utf16);
                    if !name.is_empty() && data_len > 0 && first_clus >= 2 {
                        let off = data_start_offset + (first_clus as u64 - 2) * cluster_size;
                        deleted_entries.push(DeletedFsEntry {
                            fs_path: format!("/{name}"),
                            name,
                            size: data_len,
                            data_runs: vec![ByteRange {
                                offset: off,
                                length: data_len,
                            }],
                            resident_data: None,
                            created_at: None,
                            modified_at: None,
                            deleted_at: None,
                            is_directory: false,
                        });
                    }
                }
            }
            i += 1 + sec_count;
            continue;
        }
        i += 1;
    }

    Ok(FsParseOutput {
        fs_type: FsType::ExFat,
        volume_offset: vol_off,
        deleted_entries,
        bitmap: Some(bitmap),
        is_encrypted_hint: false,
        warnings: Vec::new(),
    })
}

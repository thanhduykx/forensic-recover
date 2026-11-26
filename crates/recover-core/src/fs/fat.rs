use crate::error::{RecoverError, Result};
use crate::fs::{read_u16_le, read_u32_le, AllocationBitmap, DeletedFsEntry, FsParseOutput};
use crate::io::SafeChunkReader;
use crate::models::{ByteRange, FsType};
use std::collections::{HashSet, VecDeque};

/// Read-only FAT32 parser:
/// - Parses BPB & FAT table to build unallocated cluster bitmap.
/// - Walks root & active subdirectories, reconstructing VFAT LFNs and extracting
///   deleted directory entries (`0xE5`) with starting cluster and file size.
pub fn parse_fat32(reader: &SafeChunkReader, vol_off: u64) -> Result<FsParseOutput> {
    let bpb = reader.read_vec_resilient(vol_off, 512);
    if bpb.len() < 512 {
        return Err(RecoverError::Parse("FAT32 BPB truncated".into()));
    }

    let bytes_per_sector = read_u16_le(&bpb, 11) as u64;
    let sectors_per_cluster = bpb[13] as u64;
    let reserved_sectors = read_u16_le(&bpb, 14) as u64;
    let num_fats = bpb[16] as u64;
    let total_sectors_16 = read_u16_le(&bpb, 19) as u64;
    let total_sectors_32 = read_u32_le(&bpb, 32) as u64;
    let fat_size_16 = read_u16_le(&bpb, 22) as u64;
    let fat_size_32 = read_u32_le(&bpb, 36) as u64;
    let root_cluster = read_u32_le(&bpb, 44);

    if bytes_per_sector < 512 || sectors_per_cluster == 0 || num_fats == 0 {
        return Err(RecoverError::Parse("Invalid FAT BPB geometry".into()));
    }

    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16
    } else {
        total_sectors_32
    };
    let fat_sectors = if fat_size_16 != 0 {
        fat_size_16
    } else {
        fat_size_32
    };
    if fat_sectors == 0 || root_cluster < 2 {
        return Err(RecoverError::Parse("Unsupported FAT12/16 or invalid FAT32 root".into()));
    }

    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let fat_offset = vol_off + reserved_sectors * bytes_per_sector;
    let data_start_sector = reserved_sectors + num_fats * fat_sectors;
    let data_start_offset = vol_off + data_start_sector * bytes_per_sector;
    let data_sectors = total_sectors.saturating_sub(data_start_sector);
    let total_clusters = data_sectors / sectors_per_cluster;

    // Cap FAT read at 64 MiB to stay memory-bounded
    let fat_bytes = (fat_sectors * bytes_per_sector).min(64 * 1024 * 1024) as usize;
    let fat_raw = reader.read_vec_resilient(fat_offset, fat_bytes);

    let mut bitmap = AllocationBitmap::new(cluster_size, data_start_offset, total_clusters);
    let max_entries = (fat_raw.len() / 4).min((total_clusters as usize) + 2);
    for clus in 2..max_entries {
        let val = read_u32_le(&fat_raw, clus * 4) & 0x0FFF_FFFF;
        if val != 0 {
            bitmap.set_allocated((clus - 2) as u64, true);
        }
    }

    let mut deleted_entries = Vec::new();
    let mut visited_dirs: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<(u32, String)> = VecDeque::new();
    queue.push_back((root_cluster, String::new()));

    while let Some((dir_clus, dir_path)) = queue.pop_front() {
        if dir_clus < 2 || !visited_dirs.insert(dir_clus) || visited_dirs.len() > 8192 {
            continue;
        }
        let dir_clusters = collect_fat_chain(&fat_raw, dir_clus, 256);
        let mut lfn_parts: Vec<(u8, String)> = Vec::new();

        for clus in dir_clusters {
            if (clus as u64) < 2 || (clus as u64 - 2) >= total_clusters {
                continue;
            }
            let off = data_start_offset + (clus as u64 - 2) * cluster_size;
            let buf = reader.read_vec_resilient(off, cluster_size as usize);
            for chunk in buf.as_chunks::<32>().0 {
                let first = chunk[0];
                if first == 0x00 {
                    break;
                }
                let attr = chunk[11];
                if attr == 0x0F {
                    // VFAT Long File Name entry (deleted LFN starts with 0xE5 too)
                    let seq = first & 0x1F;
                    if let Some(frag) = decode_lfn_chunk(chunk) {
                        lfn_parts.push((seq, frag));
                    }
                    continue;
                }
                // Skip volume label
                if (attr & 0x08) != 0 {
                    lfn_parts.clear();
                    continue;
                }

                let is_deleted = first == 0xE5;
                let is_dir = (attr & 0x10) != 0;
                let short_name = decode_83_name(chunk);
                let name = if !lfn_parts.is_empty() {
                    lfn_parts.sort_by_key(|(seq, _)| *seq);
                    let joined: String = lfn_parts.iter().map(|(_, s)| s.as_str()).collect();
                    lfn_parts.clear();
                    if joined.trim().is_empty() {
                        short_name
                    } else {
                        joined
                    }
                } else {
                    short_name
                };

                if name == "." || name == ".." {
                    continue;
                }

                let clus_hi = read_u16_le(chunk, 20) as u32;
                let clus_lo = read_u16_le(chunk, 26) as u32;
                let start_clus = (clus_hi << 16) | clus_lo;
                let file_size = read_u32_le(chunk, 28) as u64;
                let full_path = if dir_path.is_empty() {
                    format!("/{name}")
                } else {
                    format!("{dir_path}/{name}")
                };

                if is_dir && !is_deleted && start_clus >= 2 {
                    queue.push_back((start_clus, full_path));
                } else if is_deleted && !is_dir && file_size > 0 && start_clus >= 2 {
                    let needed_clusters = file_size.div_ceil(cluster_size).max(1);
                    let run_off = data_start_offset + (start_clus as u64 - 2) * cluster_size;
                    // On FAT32, deletion zeroes the FAT chain, so we hypothesize contiguous runs
                    // from `start_clus` while validators/bifragment confirm actual payload.
                    let runs = if needed_clusters == 1 || !fat_has_chain(&fat_raw, start_clus) {
                        vec![ByteRange {
                            offset: run_off,
                            length: file_size,
                        }]
                    } else {
                        collect_fat_chain(&fat_raw, start_clus, needed_clusters as usize)
                            .into_iter()
                            .map(|c| ByteRange {
                                offset: data_start_offset + (c as u64 - 2) * cluster_size,
                                length: cluster_size,
                            })
                            .collect()
                    };

                    let mod_date = read_u16_le(chunk, 24);
                    let mod_time = read_u16_le(chunk, 22);
                    let modified_at = decode_dos_datetime(mod_date, mod_time);
                    deleted_entries.push(DeletedFsEntry {
                        fs_path: full_path,
                        name,
                        size: file_size,
                        data_runs: runs,
                        resident_data: None,
                        created_at: None,
                        modified_at: modified_at.clone(),
                        deleted_at: modified_at,
                        is_directory: false,
                    });
                }
            }
        }
    }

    Ok(FsParseOutput {
        fs_type: FsType::Fat32,
        volume_offset: vol_off,
        deleted_entries,
        bitmap: Some(bitmap),
        is_encrypted_hint: false,
        warnings: Vec::new(),
    })
}

fn fat_has_chain(fat_raw: &[u8], start: u32) -> bool {
    let idx = (start as usize) * 4;
    if idx + 4 > fat_raw.len() {
        return false;
    }
    (read_u32_le(fat_raw, idx) & 0x0FFF_FFFF) != 0
}

fn collect_fat_chain(fat_raw: &[u8], start: u32, max_clusters: usize) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut cur = start;
    let mut seen = HashSet::new();
    while cur >= 2 && chain.len() < max_clusters && seen.insert(cur) {
        chain.push(cur);
        let idx = (cur as usize) * 4;
        if idx + 4 > fat_raw.len() {
            break;
        }
        let next = read_u32_le(fat_raw, idx) & 0x0FFF_FFFF;
        if !(2..0x0FFF_FFF7).contains(&next) {
            break;
        }
        cur = next;
    }
    chain
}

fn decode_83_name(entry: &[u8]) -> String {
    let mut base_bytes = entry[0..8].to_vec();
    if base_bytes[0] == 0xE5 {
        base_bytes[0] = b'_';
    }
    let base = String::from_utf8_lossy(&base_bytes).trim_end().to_string();
    let ext = String::from_utf8_lossy(&entry[8..11]).trim_end().to_string();
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

fn decode_lfn_chunk(entry: &[u8]) -> Option<String> {
    let mut units = Vec::with_capacity(13);
    for &(start, count) in &[(1usize, 5usize), (14, 6), (28, 2)] {
        for i in 0..count {
            let u = read_u16_le(entry, start + i * 2);
            if u == 0x0000 || u == 0xFFFF {
                return Some(String::from_utf16_lossy(&units));
            }
            units.push(u);
        }
    }
    Some(String::from_utf16_lossy(&units))
}

fn decode_dos_datetime(date: u16, time: u16) -> Option<String> {
    if date == 0 {
        return None;
    }
    let day = (date & 0x1F) as u32;
    let month = ((date >> 5) & 0x0F) as u32;
    let year = 1980 + ((date >> 9) & 0x7F) as i32;
    let sec = ((time & 0x1F) * 2) as u32;
    let min = ((time >> 5) & 0x3F) as u32;
    let hour = ((time >> 11) & 0x1F) as u32;
    Some(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z"))
}

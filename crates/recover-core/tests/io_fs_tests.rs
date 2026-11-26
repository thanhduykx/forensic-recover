use recover_core::fs::apfs::apfs_fletcher64;
use recover_core::fs::detect_and_parse_fs;
use recover_core::io::{
    verify_destination_safe, AlignedBuffer, FaultInjectingReader, MemoryReader, SafeChunkReader,
};
use recover_core::models::FsType;
use std::sync::Arc;

#[test]
fn test_aligned_buffer_and_bad_sector_isolation() {
    let aligned = AlignedBuffer::new(4097);
    assert_eq!(aligned.as_ptr() as usize % 4096, 0);
    assert_eq!(aligned.capacity(), 8192);

    // 16 KiB image filled with 0xAB, bad sector at [4096, 4608)
    let raw = vec![0xABu8; 16 * 1024];
    let mem = Arc::new(MemoryReader::new(raw));
    let faulty = Arc::new(FaultInjectingReader::new(mem, vec![(4096, 4608)]));
    let safe = SafeChunkReader::new(faulty);

    let mut out = vec![0u8; 16 * 1024];
    let n = safe.read_resilient(0, &mut out);
    assert_eq!(n, 16 * 1024);
    assert!(out[0..4096].iter().all(|&b| b == 0xAB));
    assert!(out[4096..4608].iter().all(|&b| b == 0x00));
    assert!(out[4608..16384].iter().all(|&b| b == 0xAB));

    let bad = safe.bad_sectors();
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].offset, 4096);
    assert_eq!(bad[0].length, 512);
}

#[test]
fn test_same_disk_guard_blocks_overlap() {
    let tmp = std::env::temp_dir().join("forensic_guard_test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let img = tmp.join("disk.img");
    std::fs::write(&img, vec![0u8; 4096]).unwrap();

    // Same file path as out_dir must fail
    let res = verify_destination_safe(&img.to_string_lossy(), &img, true);
    assert!(res.is_err());

    // Disallowing same-volume image must reject if both on same drive
    let out = tmp.join("out");
    let res2 = verify_destination_safe(&img.to_string_lossy(), &out, false);
    assert!(res2.is_err());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_fat32_deleted_entry_parser() {
    // Construct a minimal valid 2 MiB FAT32 volume with 512B sectors, 8 sectors/cluster (4 KiB cluster)
    let mut img = vec![0u8; 2 * 1024 * 1024];
    let bps = 512usize;
    let spc = 8usize;
    let reserved = 32usize;
    let num_fats = 2usize;
    let fat_secs = 32usize;
    let total_secs = (img.len() / bps) as u32;

    img[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
    img[13] = spc as u8;
    img[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    img[16] = num_fats as u8;
    img[32..36].copy_from_slice(&total_secs.to_le_bytes());
    img[36..40].copy_from_slice(&(fat_secs as u32).to_le_bytes());
    img[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster = 2
    img[82..87].copy_from_slice(b"FAT32");
    img[510] = 0x55;
    img[511] = 0xAA;

    let fat_off = reserved * bps;
    // Cluster 2 = root dir EOC
    img[fat_off + 8..fat_off + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    // Cluster 3 = allocated file
    img[fat_off + 12..fat_off + 16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    // Cluster 5 = unallocated (0x00000000), previously held deleted PHOTO1.JPG

    let data_start = (reserved + num_fats * fat_secs) * bps;
    let root_off = data_start; // cluster 2

    // Entry 0: deleted `PHOTO1.JPG` (0xE5 + "HOTO1  JPG") pointing to cluster 5, size 1234
    let mut e0 = [0u8; 32];
    e0[0] = 0xE5;
    e0[1..8].copy_from_slice(b"HOTO1  ");
    e0[8..11].copy_from_slice(b"JPG");
    e0[11] = 0x20;
    e0[26..28].copy_from_slice(&5u16.to_le_bytes());
    e0[28..32].copy_from_slice(&1234u32.to_le_bytes());
    img[root_off..root_off + 32].copy_from_slice(&e0);

    let reader = SafeChunkReader::new(Arc::new(MemoryReader::new(img)));
    let parsed = detect_and_parse_fs(&reader);
    assert_eq!(parsed.fs_type, FsType::Fat32);
    assert_eq!(parsed.deleted_entries.len(), 1);
    assert_eq!(parsed.deleted_entries[0].name, "_HOTO1.JPG");
    assert_eq!(parsed.deleted_entries[0].size, 1234);
    assert_eq!(
        parsed.deleted_entries[0].data_runs[0].offset,
        (data_start + 3 * spc * bps) as u64
    );

    let bm = parsed.bitmap.unwrap();
    assert!(bm.is_block_allocated(0)); // cluster 2
    assert!(bm.is_block_allocated(1)); // cluster 3
    assert!(!bm.is_block_allocated(3)); // cluster 5 unallocated
}

#[test]
fn test_ntfs_mft_usa_and_data_runs_parser() {
    // Build a 1 MiB NTFS image: 512B sector, 8 sectors/cluster (4 KiB cluster)
    let mut img = vec![0u8; 1024 * 1024];
    let bps = 512usize;
    let cluster_size = 4096usize;
    img[3..11].copy_from_slice(b"NTFS    ");
    img[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
    img[13] = 8;
    let total_secs = (img.len() / bps) as u64;
    img[40..48].copy_from_slice(&total_secs.to_le_bytes());
    img[48..56].copy_from_slice(&4u64.to_le_bytes()); // $MFT at cluster 4
    img[64] = (-10i8) as u8; // 1024-byte MFT records
    img[510] = 0x55;
    img[511] = 0xAA;

    let mft_off = 4 * cluster_size;

    // Record 0 ($MFT): in_use=1, $DATA non-resident covering clusters 4..8 (4 clusters = 4096*4 = 16 records)
    let mut rec0 = [0u8; 1024];
    make_mft_header(&mut rec0, 0x0001, 56);
    // $DATA attribute (0x80), non-resident=1, total_len=72, runs at +64
    let mut a = 56usize;
    rec0[a..a + 4].copy_from_slice(&0x80u32.to_le_bytes());
    rec0[a + 4..a + 8].copy_from_slice(&72u32.to_le_bytes());
    rec0[a + 8] = 1; // non-resident
    rec0[a + 32..a + 34].copy_from_slice(&64u16.to_le_bytes());
    rec0[a + 48..a + 56].copy_from_slice(&4096u64.to_le_bytes());
    rec0[a + 64..a + 68].copy_from_slice(&[0x11, 0x04, 0x04, 0x00]); // len=4, lcn=4
    a += 72;
    rec0[a..a + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    apply_test_usa(&mut rec0, 1);
    img[mft_off..mft_off + 1024].copy_from_slice(&rec0);

    // Record 6 ($Bitmap): in_use=1, resident 32-byte bitmap marking clusters 0..8 allocated
    let mut rec6 = [0u8; 1024];
    make_mft_header(&mut rec6, 0x0001, 56);
    let mut off6 = 56usize;
    rec6[off6..off6 + 4].copy_from_slice(&0x80u32.to_le_bytes());
    rec6[off6 + 4..off6 + 8].copy_from_slice(&32u32.to_le_bytes());
    rec6[off6 + 16..off6 + 20].copy_from_slice(&8u32.to_le_bytes());
    rec6[off6 + 20..off6 + 22].copy_from_slice(&24u16.to_le_bytes());
    rec6[off6 + 24] = 0xFF; // clusters 0..7 allocated, cluster 8.. unallocated
    off6 += 32;
    rec6[off6..off6 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    apply_test_usa(&mut rec6, 2);
    img[mft_off + 6 * 1024..mft_off + 7 * 1024].copy_from_slice(&rec6);

    // Record 10: Deleted file `vacation.jpg` (flags=0x0000), $DATA at cluster 20, len 6000
    let mut rec10 = [0u8; 1024];
    make_mft_header(&mut rec10, 0x0000, 56);
    let mut off10 = 56usize;
    // $FILE_NAME (0x30)
    let name_utf16: Vec<u16> = "vacation.jpg".encode_utf16().collect();
    let fn_attr_len = ((24 + 66 + name_utf16.len() * 2) + 7) & !7;
    rec10[off10..off10 + 4].copy_from_slice(&0x30u32.to_le_bytes());
    rec10[off10 + 4..off10 + 8].copy_from_slice(&(fn_attr_len as u32).to_le_bytes());
    rec10[off10 + 20..off10 + 22].copy_from_slice(&24u16.to_le_bytes());
    let fn_base = off10 + 24;
    rec10[fn_base..fn_base + 8].copy_from_slice(&5u64.to_le_bytes()); // parent = root (5)
    rec10[fn_base + 64] = name_utf16.len() as u8;
    rec10[fn_base + 65] = 1; // Win32
    for (i, u) in name_utf16.iter().enumerate() {
        rec10[fn_base + 66 + i * 2..fn_base + 68 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    off10 += fn_attr_len;

    // $DATA (0x80) non-resident, real_size=6000, run: len=2 clusters, lcn=20 (0x14)
    rec10[off10..off10 + 4].copy_from_slice(&0x80u32.to_le_bytes());
    rec10[off10 + 4..off10 + 8].copy_from_slice(&72u32.to_le_bytes());
    rec10[off10 + 8] = 1;
    rec10[off10 + 32..off10 + 34].copy_from_slice(&64u16.to_le_bytes());
    rec10[off10 + 48..off10 + 56].copy_from_slice(&6000u64.to_le_bytes());
    rec10[off10 + 64..off10 + 68].copy_from_slice(&[0x11, 0x02, 20, 0x00]);
    off10 += 72;
    rec10[off10..off10 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    apply_test_usa(&mut rec10, 3);
    img[mft_off + 10 * 1024..mft_off + 11 * 1024].copy_from_slice(&rec10);

    let reader = SafeChunkReader::new(Arc::new(MemoryReader::new(img)));
    let parsed = detect_and_parse_fs(&reader);
    assert_eq!(parsed.fs_type, FsType::Ntfs);
    assert_eq!(parsed.deleted_entries.len(), 1);
    let e = &parsed.deleted_entries[0];
    assert_eq!(e.name, "vacation.jpg");
    assert_eq!(e.fs_path, "/vacation.jpg");
    assert_eq!(e.size, 6000);
    assert_eq!(e.data_runs[0].offset, (20 * cluster_size) as u64);
    assert_eq!(e.data_runs[0].length, (2 * cluster_size) as u64);
}

#[test]
fn test_ext4_deleted_inode_extent_and_apfs_fletcher() {
    // Test APFS NXSB superblock checksum & detection
    let mut apfs_img = vec![0u8; 64 * 1024];
    apfs_img[32..36].copy_from_slice(b"NXSB");
    apfs_img[36..40].copy_from_slice(&4096u32.to_le_bytes());
    apfs_img[40..48].copy_from_slice(&16u64.to_le_bytes());
    let cksum = apfs_fletcher64(&apfs_img[8..4096]);
    apfs_img[0..8].copy_from_slice(&cksum.to_le_bytes());
    let apfs_reader = SafeChunkReader::new(Arc::new(MemoryReader::new(apfs_img)));
    let apfs_parsed = detect_and_parse_fs(&apfs_reader);
    assert_eq!(apfs_parsed.fs_type, FsType::Apfs);

    // Test ext4 deleted inode with extent header
    let mut ext_img = vec![0u8; 1024 * 1024];
    let blk_size = 4096usize;
    let sb = &mut ext_img[1024..2048];
    sb[0x00..0x04].copy_from_slice(&128u32.to_le_bytes()); // inodes_count
    sb[0x04..0x08].copy_from_slice(&256u32.to_le_bytes()); // blocks_count
    sb[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes()); // log_block_size = 2 => 4096
    sb[0x20..0x24].copy_from_slice(&256u32.to_le_bytes()); // blocks_per_group
    sb[0x28..0x2C].copy_from_slice(&128u32.to_le_bytes()); // inodes_per_group
    sb[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    sb[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes()); // inode_size

    // BGDT at block 1: blk_bitmap at block 3, inode_table at block 5
    let bgdt = blk_size;
    ext_img[bgdt..bgdt + 4].copy_from_slice(&3u32.to_le_bytes());
    ext_img[bgdt + 8..bgdt + 12].copy_from_slice(&5u32.to_le_bytes());

    // Inode 11 (index 10) at block 5 + 10*256
    let ino_off = 5 * blk_size + 10 * 256;
    ext_img[ino_off..ino_off + 2].copy_from_slice(&0x81A4u16.to_le_bytes()); // regular file
    ext_img[ino_off + 4..ino_off + 8].copy_from_slice(&5000u32.to_le_bytes()); // i_size
    ext_img[ino_off + 0x14..ino_off + 0x18].copy_from_slice(&1_700_000_000u32.to_le_bytes()); // i_dtime
    ext_img[ino_off + 0x20..ino_off + 0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXT4_EXTENTS_FL
    let eb = ino_off + 0x28;
    ext_img[eb..eb + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
    ext_img[eb + 2..eb + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 extent
    ext_img[eb + 12 + 4..eb + 12 + 6].copy_from_slice(&2u16.to_le_bytes()); // 2 blocks
    ext_img[eb + 12 + 8..eb + 12 + 12].copy_from_slice(&42u32.to_le_bytes()); // start block 42

    let ext_reader = SafeChunkReader::new(Arc::new(MemoryReader::new(ext_img)));
    let ext_parsed = detect_and_parse_fs(&ext_reader);
    assert_eq!(ext_parsed.fs_type, FsType::Ext4);
    assert_eq!(ext_parsed.deleted_entries.len(), 1);
    assert_eq!(ext_parsed.deleted_entries[0].size, 5000);
    assert_eq!(ext_parsed.deleted_entries[0].data_runs[0].offset, (42 * blk_size) as u64);
}

fn make_mft_header(rec: &mut [u8], flags: u16, first_attr: u16) {
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&48u16.to_le_bytes()); // USA offset
    rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // USA count (USN + 2 sectors)
    rec[20..22].copy_from_slice(&first_attr.to_le_bytes());
    rec[22..24].copy_from_slice(&flags.to_le_bytes());
}

fn apply_test_usa(rec: &mut [u8], usn: u16) {
    let usn_bytes = usn.to_le_bytes();
    rec[48..50].copy_from_slice(&usn_bytes);
    let s1 = [rec[510], rec[511]];
    let s2 = [rec[1022], rec[1023]];
    rec[50..52].copy_from_slice(&s1);
    rec[52..54].copy_from_slice(&s2);
    rec[510..512].copy_from_slice(&usn_bytes);
    rec[1022..1024].copy_from_slice(&usn_bytes);
}

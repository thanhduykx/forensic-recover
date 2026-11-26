use crc32fast::Hasher as Crc32;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use image::{ImageEncoder, RgbaImage};
use recover_core::companion::scan_ios_backup;
use recover_core::io::{FaultInjectingReader, FileImageReader, SafeChunkReader};
use recover_core::models::ScanConfig;
use recover_core::scan::{resume_scan, run_scan_with_reader};
use recover_core::ScanFacade;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn make_jpeg(w: u32, h: u32, seed: u8) -> Vec<u8> {
    let mut img = RgbaImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgba([
            ((x * 13 + y * 7 + seed as u32) & 0xFF) as u8,
            (((x * 5) ^ (y * 19) ^ seed as u32) & 0xFF) as u8,
            ((x + y * 3 + seed as u32 * 5) & 0xFF) as u8,
            255,
        ]);
    }
    let mut out = Vec::new();
    let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 85);
    let rgb = image::DynamicImage::ImageRgba8(img).to_rgb8();
    enc.write_image(rgb.as_raw(), w, h, image::ExtendedColorType::Rgb8)
        .unwrap();
    out
}

fn make_png(w: u32, h: u32) -> Vec<u8> {
    let mut img = RgbaImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgba([(x % 250) as u8, (y % 250) as u8, ((x ^ y) % 250) as u8, 255]);
    }
    let mut out = Vec::new();
    let enc = image::codecs::png::PngEncoder::new(&mut out);
    enc.write_image(img.as_raw(), w, h, image::ExtendedColorType::Rgba8)
        .unwrap();
    out
}

fn make_docx() -> Vec<u8> {
    let entries: [(&str, &[u8]); 2] = [
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document><w:p>Forensic Test</w:p></w:document>"),
    ];
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data) in entries {
        let local_off = out.len() as u32;
        let mut crc = Crc32::new();
        crc.update(data);
        let crc_val = crc.finalize();
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        let comp = enc.finish().unwrap();

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&crc_val.to_le_bytes());
        out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&comp);

        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&8u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&crc_val.to_le_bytes());
        cd.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&local_off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let cd_sz = cd.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00\x02\x00\x02\x00");
    out.extend_from_slice(&cd_sz.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Builds a formatted 4 MiB FAT32 volume image containing 12 deleted JPEGs, 1 deleted PNG,
/// and 1 deleted DOCX (plus directory entries marked `0xE5` and zeroed FAT entries), returning
/// `(image_bytes, expected_jpeg_shas)`.
fn build_formatted_fat32_corpus() -> (Vec<u8>, Vec<String>) {
    let mut img = vec![0u8; 4 * 1024 * 1024];
    let bps = 512usize;
    let spc = 8usize; // 4096-byte clusters
    let cluster_size = bps * spc;
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
    img[fat_off + 8..fat_off + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // root cluster

    let data_start = (reserved + num_fats * fat_secs) * bps;
    let mut next_clus = 4usize;
    let mut jpeg_shas = Vec::new();

    for (dir_idx, i) in (0..12u8).enumerate() {
        let jpg = make_jpeg(64 + (i as u32) * 4, 64, i + 1);
        let sha = hex::encode(Sha256::digest(&jpg));
        jpeg_shas.push(sha);

        let clus_needed = jpg.len().div_ceil(cluster_size);
        let off = data_start + (next_clus - 2) * cluster_size;
        img[off..off + jpg.len()].copy_from_slice(&jpg);

        // Deleted FAT32 directory entry (`0xE5`)
        let mut entry = [0u8; 32];
        entry[0] = 0xE5;
        let name8 = format!("IMG{:04} ", i);
        entry[1..8].copy_from_slice(&name8.as_bytes()[..7]);
        entry[8..11].copy_from_slice(b"JPG");
        entry[11] = 0x20;
        entry[20..22].copy_from_slice(&((next_clus >> 16) as u16).to_le_bytes());
        entry[26..28].copy_from_slice(&((next_clus & 0xFFFF) as u16).to_le_bytes());
        entry[28..32].copy_from_slice(&(jpg.len() as u32).to_le_bytes());
        let d_off = data_start + dir_idx * 32;
        img[d_off..d_off + 32].copy_from_slice(&entry);

        next_clus += clus_needed + 1;
    }

    // Add deleted PNG and DOCX
    let png = make_png(48, 48);
    let png_off = data_start + (next_clus - 2) * cluster_size;
    img[png_off..png_off + png.len()].copy_from_slice(&png);
    next_clus += png.len().div_ceil(cluster_size) + 1;

    let docx = make_docx();
    let docx_off = data_start + (next_clus - 2) * cluster_size;
    img[docx_off..docx_off + docx.len()].copy_from_slice(&docx);

    (img, jpeg_shas)
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    hex::encode(Sha256::digest(&bytes))
}

#[test]
fn test_fat32_corpus_recovery_rate_and_source_hash_immutability() {
    let tmp = std::env::temp_dir().join("forensic_corpus_fat32");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let img_path = tmp.join("fat32_deleted.img");
    let out_dir = tmp.join("out");
    let (img, expected_jpeg_shas) = build_formatted_fat32_corpus();
    std::fs::write(&img_path, &img).unwrap();

    let hash_before = sha256_file(&img_path);

    let cfg = ScanConfig {
        source: img_path.to_string_lossy().to_string(),
        out_dir: out_dir.to_string_lossy().to_string(),
        types: vec!["jpg".into(), "png".into(), "docx".into()],
        export_all: true,
        ..Default::default()
    };

    let res = ScanFacade::scan(&cfg, None, None).unwrap();
    let hash_after = sha256_file(&img_path);
    assert_eq!(hash_before, hash_after, "Source image hash MUST NOT change!");

    let recovered_jpg_shas: Vec<String> = res
        .items
        .iter()
        .filter(|i| i.ext == "jpg")
        .map(|i| i.sha256.clone())
        .collect();
    let matched = expected_jpeg_shas
        .iter()
        .filter(|s| recovered_jpg_shas.contains(s))
        .count();
    let rate = (matched as f64) / (expected_jpeg_shas.len() as f64);
    assert!(
        rate > 0.90,
        "Contiguous deleted JPEG recovery rate must be > 90%, got {:.1}% ({}/{})",
        rate * 100.0,
        matched,
        expected_jpeg_shas.len()
    );

    assert!(res.items.iter().any(|i| i.ext == "png"));
    assert!(res.items.iter().any(|i| i.ext == "docx"));
    assert!(res.report_json_path.is_file());
    assert!(res.report_html_path.is_file());
    assert!(!res.exported_paths.is_empty());

    // Verify collision-safe export never overwrites existing files
    let before_count = std::fs::read_dir(out_dir.join("recovered/images"))
        .unwrap()
        .count();
    let second_export =
        ScanFacade::export_selected(&cfg.source, &out_dir, &[]).unwrap();
    let after_count = std::fs::read_dir(out_dir.join("recovered/images"))
        .unwrap()
        .count();
    assert!(!second_export.is_empty());
    assert!(after_count > before_count);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_bad_sector_resilience_and_checkpoint_resume() {
    let tmp = std::env::temp_dir().join("forensic_resume_bad_sector");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let img_path = tmp.join("source.img");
    let out_dir = tmp.join("out");
    let (img, expected_shas) = build_formatted_fat32_corpus();
    std::fs::write(&img_path, &img).unwrap();

    // 1. Bad sector fault injection in an unallocated middle region (`0x180000..0x181000`)
    let file_reader = Arc::new(FileImageReader::open(&img_path).unwrap());
    let faulty = Arc::new(FaultInjectingReader::new(
        file_reader,
        vec![(0x18_0000, 0x18_1000)],
    ));
    let cfg = ScanConfig {
        source: img_path.to_string_lossy().to_string(),
        out_dir: out_dir.to_string_lossy().to_string(),
        types: vec!["jpg".into()],
        chunk_size: 256 * 1024,
        checkpoint_interval_bytes: 256 * 1024,
        generate_previews: false,
        ..Default::default()
    };
    let bad_res = run_scan_with_reader(&cfg, faulty, 0, None, Vec::new(), None, None).unwrap();
    assert!(!bad_res.session.bad_sectors.is_empty());
    assert!(bad_res.items.len() >= expected_shas.len());

    // 2. Checkpoint + Resume test
    let out_resume = tmp.join("out_resume");
    let cfg_resume = ScanConfig {
        source: img_path.to_string_lossy().to_string(),
        out_dir: out_resume.to_string_lossy().to_string(),
        types: vec!["jpg".into(), "png".into()],
        chunk_size: 256 * 1024,
        checkpoint_interval_bytes: 256 * 1024,
        generate_previews: false,
        ..Default::default()
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_cb = Arc::clone(&cancel);
    let paused = ScanFacade::scan(
        &cfg_resume,
        Some(cancel),
        Some(&move |p| {
            if p.bytes_scanned >= 1024 * 1024 {
                cancel_cb.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }),
    )
    .unwrap();
    assert_eq!(paused.session.status, recover_core::models::SessionStatus::Paused);

    let resumed = resume_scan(&out_resume, None, None).unwrap();
    assert_eq!(
        resumed.session.status,
        recover_core::models::SessionStatus::Completed
    );
    assert!(resumed.items.len() >= expected_shas.len());

    // Sanity check SafeChunkReader compiles & reads cleanly
    let _ = SafeChunkReader::new(Arc::new(FileImageReader::open(&img_path).unwrap()));
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_ios_backup_readonly_sqlite_recovery() {
    let tmp = std::env::temp_dir().join("forensic_ios_backup_test");
    let _ = std::fs::remove_dir_all(&tmp);
    let backup = tmp.join("backup");
    let out = tmp.join("out");
    std::fs::create_dir_all(backup.join("aa")).unwrap();
    std::fs::create_dir_all(backup.join("bb")).unwrap();

    // Write a real JPEG blob (`aa/aabbcc`) and a Photos.sqlite blob (`bb/bbccdd`)
    let jpg = make_jpeg(48, 48, 9);
    let expected_sha = hex::encode(Sha256::digest(&jpg));
    std::fs::write(backup.join("aa/aabbcc"), &jpg).unwrap();

    // Build minimal single-page SQLite 3 files for `Photos.sqlite` and `Manifest.db`
    let photos_sql = build_minimal_sqlite_table(
        "ZASSET",
        "CREATE TABLE ZASSET (ZFILENAME TEXT, ZTRASHEDSTATE INTEGER)",
        &[("IMG_9999.JPG", 1)],
    );
    std::fs::write(backup.join("bb/bbccdd"), &photos_sql).unwrap();

    let manifest_sql = build_minimal_sqlite_table(
        "Files",
        "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)",
        &[],
    );
    // Rebuild Manifest.db with two rows (3 text columns)
    let manifest_db = build_minimal_sqlite_files_table(&[
        ("aabbcc", "CameraRollDomain", "Media/DCIM/100APPLE/IMG_9999.JPG"),
        ("bbccdd", "CameraRollDomain", "Media/PhotoData/Photos.sqlite"),
    ]);
    let _ = manifest_sql;
    std::fs::write(backup.join("Manifest.db"), &manifest_db).unwrap();

    let res = scan_ios_backup(&backup, &out, true).unwrap();
    assert_eq!(res.items.len(), 1);
    assert_eq!(res.items[0].sha256, expected_sha);
    assert_eq!(res.items[0].original_name.as_deref(), Some("IMG_9999.JPG"));
    assert_eq!(
        res.items[0].deleted_at.as_deref(),
        Some("trashed_in_photos_sqlite")
    );
    assert_eq!(res.exported_paths.len(), 1);

    let _ = std::fs::remove_dir_all(&tmp);
}

fn encode_sqlite_record(cols: &[(&str, Option<i64>)]) -> Vec<u8> {
    let mut header = Vec::new();
    let mut body = Vec::new();
    for &(txt, int_opt) in cols {
        if let Some(v) = int_opt {
            if v == 1 {
                header.push(9u8);
            } else if v == 0 {
                header.push(8u8);
            } else {
                header.push(1u8);
                body.push(v as u8);
            }
        } else {
            let st = (txt.len() * 2 + 13) as u64;
            push_varint(&mut header, st);
            body.extend_from_slice(txt.as_bytes());
        }
    }
    let hdr_len = (header.len() + 1) as u8;
    let mut rec = vec![hdr_len];
    rec.extend_from_slice(&header);
    rec.extend_from_slice(&body);
    rec
}

fn push_varint(buf: &mut Vec<u8>, mut v: u64) {
    if v < 128 {
        buf.push(v as u8);
        return;
    }
    let mut tmp = Vec::new();
    tmp.push((v & 0x7F) as u8);
    v >>= 7;
    while v > 0 {
        tmp.push(((v & 0x7F) | 0x80) as u8);
        v >>= 7;
    }
    tmp.reverse();
    buf.extend_from_slice(&tmp);
}

fn build_minimal_sqlite_table(
    tbl_name: &str,
    create_sql: &str,
    rows: &[(&str, i64)],
) -> Vec<u8> {
    let ps = 4096usize;
    let mut db = vec![0u8; ps * 2];
    db[..16].copy_from_slice(b"SQLite format 3\0");
    db[16..18].copy_from_slice(&(ps as u16).to_be_bytes());
    db[18] = 1;
    db[19] = 1;

    // Page 1: sqlite_schema pointing `tbl_name` -> root page 2
    let schema_rec = encode_sqlite_record(&[
        ("table", None),
        (tbl_name, None),
        (tbl_name, None),
        ("", Some(2)),
        (create_sql, None),
    ]);
    write_leaf_page(&mut db[..ps], 100, &[schema_rec]);

    let row_recs: Vec<Vec<u8>> = rows
        .iter()
        .map(|&(a, b)| encode_sqlite_record(&[(a, None), ("", Some(b))]))
        .collect();
    write_leaf_page(&mut db[ps..ps * 2], 0, &row_recs);
    db
}

fn build_minimal_sqlite_files_table(rows: &[(&str, &str, &str)]) -> Vec<u8> {
    let ps = 4096usize;
    let mut db = vec![0u8; ps * 2];
    db[..16].copy_from_slice(b"SQLite format 3\0");
    db[16..18].copy_from_slice(&(ps as u16).to_be_bytes());
    db[18] = 1;
    db[19] = 1;

    let schema_rec = encode_sqlite_record(&[
        ("table", None),
        ("Files", None),
        ("Files", None),
        ("", Some(2)),
        ("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT)", None),
    ]);
    write_leaf_page(&mut db[..ps], 100, &[schema_rec]);

    let row_recs: Vec<Vec<u8>> = rows
        .iter()
        .map(|&(id, dom, rel)| encode_sqlite_record(&[(id, None), (dom, None), (rel, None)]))
        .collect();
    write_leaf_page(&mut db[ps..ps * 2], 0, &row_recs);
    db
}

fn write_leaf_page(page: &mut [u8], hdr_off: usize, recs: &[Vec<u8>]) {
    page[hdr_off] = 0x0D; // leaf table B-tree
    page[hdr_off + 3..hdr_off + 5].copy_from_slice(&(recs.len() as u16).to_be_bytes());
    let mut cursor = page.len();
    for (idx, rec) in recs.iter().enumerate() {
        let mut cell = Vec::new();
        push_varint(&mut cell, rec.len() as u64);
        push_varint(&mut cell, (idx + 1) as u64);
        cell.extend_from_slice(rec);
        cursor -= cell.len();
        page[cursor..cursor + cell.len()].copy_from_slice(&cell);
        let ptr_pos = hdr_off + 8 + idx * 2;
        page[ptr_pos..ptr_pos + 2].copy_from_slice(&(cursor as u16).to_be_bytes());
    }
}

#[test]
fn test_committed_mini_deleted_fixture_immutability() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("mini_deleted.img");
    assert!(fixture.is_file(), "Committed fixture mini_deleted.img must exist");

    let tmp = std::env::temp_dir().join("forensic_fixture_scan_out");
    let _ = std::fs::remove_dir_all(&tmp);
    let hash_before = sha256_file(&fixture);

    let cfg = ScanConfig {
        source: fixture.to_string_lossy().to_string(),
        out_dir: tmp.to_string_lossy().to_string(),
        types: vec!["jpg".into(), "png".into()],
        export_all: true,
        ..Default::default()
    };
    let res = ScanFacade::scan(&cfg, None, None).unwrap();
    let hash_after = sha256_file(&fixture);

    assert_eq!(hash_before, hash_after);
    assert!(res.items.iter().any(|i| i.ext == "jpg"));
    assert!(res.items.iter().any(|i| i.ext == "png"));
    assert!(res.report_html_path.is_file());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[allow(dead_code)]
fn _unused(_: PathBuf) {}

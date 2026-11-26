use crc32fast::Hasher as Crc32;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use image::{ImageEncoder, RgbaImage};
use recover_core::carve::validators::{
    validate_bmff, validate_gif, validate_jpeg, validate_pdf, validate_png, validate_webp,
    validate_zip_ooxml,
};
use recover_core::carve::{carve_chunk, SignatureDatabase};
use recover_core::fs::AllocationBitmap;
use recover_core::io::{MemoryReader, SafeChunkReader};
use std::io::Write;
use std::sync::Arc;

fn make_real_jpeg(w: u32, h: u32, seed: u8) -> Vec<u8> {
    let mut img = RgbaImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        let r = ((x.wrapping_mul(17) ^ y.wrapping_mul(31) ^ (seed as u32)) & 0xFF) as u8;
        let g = ((x.wrapping_mul(7) + y.wrapping_mul(13) + (seed as u32)) & 0xFF) as u8;
        let b = ((x ^ y).wrapping_mul(11) & 0xFF) as u8;
        *p = image::Rgba([r, g, b, 255]);
    }
    let mut out = Vec::new();
    let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 85);
    let rgb = image::DynamicImage::ImageRgba8(img).to_rgb8();
    enc.write_image(rgb.as_raw(), w, h, image::ExtendedColorType::Rgb8)
        .unwrap();
    out
}

fn make_real_png(w: u32, h: u32) -> Vec<u8> {
    let mut img = RgbaImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgba([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8, 255]);
    }
    let mut out = Vec::new();
    let enc = image::codecs::png::PngEncoder::new(&mut out);
    enc.write_image(img.as_raw(), w, h, image::ExtendedColorType::Rgba8)
        .unwrap();
    out
}

fn make_real_gif(w: u32, h: u32) -> Vec<u8> {
    let img = RgbaImage::new(w, h);
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(&mut out);
        enc.encode(img.as_raw(), w, h, image::ExtendedColorType::Rgba8)
            .unwrap();
    }
    out
}

fn make_real_webp(w: u32, h: u32) -> Vec<u8> {
    let img = RgbaImage::new(w, h);
    let mut out = Vec::new();
    let enc = image::codecs::webp::WebPEncoder::new_lossless(&mut out);
    enc.write_image(img.as_raw(), w, h, image::ExtendedColorType::Rgba8)
        .unwrap();
    out
}

fn make_minimal_bmff(brand: &[u8; 4], is_heif: bool) -> Vec<u8> {
    let mut out = Vec::new();
    // ftyp box (24 bytes)
    out.extend_from_slice(&24u32.to_be_bytes());
    out.extend_from_slice(b"ftyp");
    out.extend_from_slice(brand);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(brand);
    out.extend_from_slice(b"iso2");
    if is_heif {
        // meta box (16 bytes)
        out.extend_from_slice(&16u32.to_be_bytes());
        out.extend_from_slice(b"meta");
        out.extend_from_slice(&[0u8; 8]);
    } else {
        // moov box containing mvhd (24 bytes)
        out.extend_from_slice(&24u32.to_be_bytes());
        out.extend_from_slice(b"moov");
        out.extend_from_slice(&16u32.to_be_bytes());
        out.extend_from_slice(b"mvhd");
        out.extend_from_slice(&[0u8; 8]);
    }
    // mdat box (32 bytes)
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(b"mdat");
    out.extend_from_slice(&[0x55u8; 24]);
    out
}

fn make_real_pdf() -> Vec<u8> {
    b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \ntrailer\n<< /Size 2 >>\nstartxref\n45\n%%EOF\n".to_vec()
}

fn make_real_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for &(name, data) in entries {
        let local_off = out.len() as u32;
        let mut crc = Crc32::new();
        crc.update(data);
        let crc_val = crc.finalize();

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        let comp = enc.finish().unwrap();

        // Local file header
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes()); // deflate
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&crc_val.to_le_bytes());
        out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&comp);

        // Central Directory header
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

    // EOCD
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_sz.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn test_all_format_validators() {
    let jpg = make_real_jpeg(64, 64, 1);
    let r = validate_jpeg(&jpg);
    assert!(r.valid && r.full_decode_ok && r.ext == "jpg" && r.exact_len == jpg.len());

    let png = make_real_png(48, 48);
    let r = validate_png(&png);
    assert!(r.valid && r.ext == "png" && r.exact_len == png.len());

    let gif = make_real_gif(32, 32);
    let r = validate_gif(&gif);
    assert!(r.valid && r.ext == "gif" && r.exact_len == gif.len());

    let webp = make_real_webp(32, 32);
    let r = validate_webp(&webp);
    assert!(r.valid && r.ext == "webp" && r.exact_len == webp.len());

    let mp4 = make_minimal_bmff(b"isom", false);
    let r = validate_bmff(&mp4);
    assert!(r.valid && r.ext == "mp4" && r.exact_len == mp4.len());

    let mov = make_minimal_bmff(b"qt  ", false);
    let r = validate_bmff(&mov);
    assert!(r.valid && r.ext == "mov" && r.exact_len == mov.len());

    let heic = make_minimal_bmff(b"heic", true);
    let r = validate_bmff(&heic);
    assert!(r.valid && r.ext == "heic" && r.exact_len == heic.len());

    let pdf = make_real_pdf();
    let r = validate_pdf(&pdf);
    assert!(r.valid && r.ext == "pdf" && r.exact_len == pdf.len());

    let docx = make_real_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document>hello</w:document>"),
    ]);
    let r = validate_zip_ooxml(&docx);
    assert!(r.valid && r.full_decode_ok && r.ext == "docx" && r.exact_len == docx.len());

    let xlsx = make_real_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("xl/workbook.xml", b"<workbook/>"),
    ]);
    let r = validate_zip_ooxml(&xlsx);
    assert!(r.valid && r.ext == "xlsx" && r.exact_len == xlsx.len());
}

#[test]
fn test_corrupt_exif_jpeg_is_still_recovered() {
    let jpg = make_real_jpeg(96, 96, 7);
    // Inject a corrupted APP1 (`FF E1`) segment immediately after SOI (`FF D8`)
    let mut corrupted = Vec::new();
    corrupted.extend_from_slice(&jpg[..2]);
    let bad_exif_payload = b"BROKEN_EXIF_GARBAGE_\x00\xFF\xFE\x12\x34";
    let seg_len = (bad_exif_payload.len() + 2) as u16;
    corrupted.extend_from_slice(&[0xFF, 0xE1]);
    corrupted.extend_from_slice(&seg_len.to_be_bytes());
    corrupted.extend_from_slice(bad_exif_payload);
    corrupted.extend_from_slice(&jpg[2..]);

    let res = validate_jpeg(&corrupted);
    assert!(res.valid);
    assert!(res.full_decode_ok);
    assert!(res.notes.iter().any(|n| n.contains("APP1/EXIF")));
}

#[test]
fn test_bifragment_jpeg_reassembly() {
    let jpg = make_real_jpeg(160, 120, 42);
    assert!(jpg.len() > 4096, "JPEG should span > 1 cluster for split test");

    let cluster = 4096usize;
    let split = cluster; // First 4096 bytes in cluster 0, rest in cluster 4
    let mut disk = vec![0u8; 16 * cluster];
    disk[..split].copy_from_slice(&jpg[..split]);

    // Put an allocated PNG barrier in clusters 1..3
    let barrier_png = make_real_png(32, 32);
    disk[cluster..cluster + barrier_png.len()].copy_from_slice(&barrier_png);
    let mut bm = AllocationBitmap::new(cluster as u64, 0, 16);
    bm.set_allocated(1, true);
    bm.set_allocated(2, true);

    // Put fragment 2 of JPEG in cluster 4
    let frag2 = &jpg[split..];
    disk[4 * cluster..4 * cluster + frag2.len()].copy_from_slice(frag2);

    let reader = SafeChunkReader::new(Arc::new(MemoryReader::new(disk.clone())));
    let db = SignatureDatabase::load_default().unwrap();
    let hits = carve_chunk(&reader, &db, Some(&bm), false, 1024 * 1024, 0, &disk, 0.2);

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].ext, "jpg");
    assert_eq!(hits[0].fragments.len(), 2);
    assert_eq!(hits[0].fragments[0].offset, 0);
    assert_eq!(hits[0].fragments[1].offset, (4 * cluster) as u64);
    assert_eq!(hits[0].length, jpg.len() as u64);
}

#[test]
fn test_spoofed_headers_false_positive_rate_under_2_percent() {
    // 120 spoofed headers with garbage payloads in 512 KiB image
    let mut disk = vec![0u8; 512 * 1024];
    let headers: [&[u8]; 6] = [
        b"\xFF\xD8\xFF\xE0",
        b"\x89PNG\r\n\x1A\n",
        b"%PDF-1.7",
        b"PK\x03\x04",
        b"GIF89a",
        b"RIFF\x20\x00\x00\x00WEBP",
    ];
    for i in 0..120 {
        let off = i * 4096;
        let h = headers[i % headers.len()];
        disk[off..off + h.len()].copy_from_slice(h);
        // Deterministic pseudo-random garbage following header
        for j in h.len()..2048 {
            disk[off + j] = ((i * 131 + j * 17) ^ (j >> 2)) as u8;
        }
    }

    let reader = SafeChunkReader::new(Arc::new(MemoryReader::new(disk.clone())));
    let db = SignatureDatabase::load_default().unwrap();
    let hits = carve_chunk(&reader, &db, None, true, 0, 0, &disk, 0.1);
    let fp_rate = (hits.len() as f64) / 120.0;
    assert!(
        fp_rate < 0.02,
        "False positive rate too high: {:.2}% ({} hits / 120 spoofed)",
        fp_rate * 100.0,
        hits.len()
    );
}

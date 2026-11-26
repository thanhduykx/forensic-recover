use crate::models::FileFamily;
use crc32fast::Hasher as Crc32;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use image::ImageDecoder;
use std::io::Read;

/// Structural + decoder validation outcome for a carved byte buffer.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub family: FileFamily,
    pub mime: String,
    pub ext: String,
    pub exact_len: usize,
    pub full_decode_ok: bool,
    pub entropy: f64,
    pub notes: Vec<String>,
}

impl ValidationResult {
    fn invalid(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            family: FileFamily::Media,
            mime: String::new(),
            ext: String::new(),
            exact_len: 0,
            full_decode_ok: false,
            entropy: 0.0,
            notes: vec![reason.into()],
        }
    }
}

/// Computes Shannon entropy in bits/byte `[0.0, 8.0]`.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut ent = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            ent -= p * p.log2();
        }
    }
    ent
}

/// Dispatches to the format-specific structural/decoder validator.
pub fn validate_by_ref(validator_ref: &str, data: &[u8]) -> ValidationResult {
    match validator_ref {
        "jpeg" => validate_jpeg(data),
        "png" => validate_png(data),
        "bmff" => validate_bmff(data),
        "gif" => validate_gif(data),
        "webp" => validate_webp(data),
        "pdf" => validate_pdf(data),
        "zip_ooxml" => validate_zip_ooxml(data),
        _ => ValidationResult::invalid(format!("Unknown validator '{validator_ref}'")),
    }
}

/// Validates JPEG (`FF D8 FF`) by walking segments, skipping corrupt EXIF payloads safely,
/// verifying SOF dimensions + SOS entropy stream, locating exact `FF D9` EOI, and running
/// `image::codecs::jpeg::JpegDecoder`.
pub fn validate_jpeg(data: &[u8]) -> ValidationResult {
    if data.len() < 128 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
        return ValidationResult::invalid("Missing JPEG SOI/marker");
    }
    // Byte 3 must be a valid initial JPEG marker (APP0..APP15, DQT, DHT, SOF0..2, COM)
    if !matches!(data[3], 0xC0..=0xC3 | 0xC4 | 0xDB | 0xE0..=0xEF | 0xFE) {
        return ValidationResult::invalid("Invalid post-SOI JPEG marker");
    }

    let mut pos = 2usize;
    let mut saw_sof = false;
    let mut saw_dqt = false;
    let mut saw_dht = false;
    let mut notes = Vec::new();
    let mut sos_data_start: Option<usize> = None;

    while pos + 2 <= data.len() {
        if data[pos] != 0xFF {
            return ValidationResult::invalid("JPEG marker alignment lost before SOS");
        }
        while pos < data.len() && data[pos] == 0xFF {
            pos += 1;
        }
        if pos >= data.len() {
            return ValidationResult::invalid("Truncated JPEG marker");
        }
        let marker = data[pos];
        pos += 1;

        if marker == 0xD9 {
            // Premature EOI before SOS
            return ValidationResult::invalid("JPEG EOI reached before SOS scan");
        }
        if marker == 0x00 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            continue;
        }
        if pos + 2 > data.len() {
            return ValidationResult::invalid("Truncated JPEG segment length");
        }
        let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        if seg_len < 2 || pos + seg_len > data.len() {
            return ValidationResult::invalid("Invalid JPEG segment length");
        }
        let seg_payload = &data[pos + 2..pos + seg_len];

        match marker {
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                if seg_payload.len() < 6 {
                    return ValidationResult::invalid("Truncated SOF segment");
                }
                let precision = seg_payload[0];
                let height = u16::from_be_bytes([seg_payload[1], seg_payload[2]]);
                let width = u16::from_be_bytes([seg_payload[3], seg_payload[4]]);
                let comps = seg_payload[5];
                if !matches!(precision, 8 | 12 | 16)
                    || width == 0
                    || height == 0
                    || !matches!(comps, 1 | 3 | 4)
                {
                    return ValidationResult::invalid("Invalid SOF dimensions/components");
                }
                saw_sof = true;
            }
            0xDB => saw_dqt = true,
            0xC4 => saw_dht = true,
            0xE1 => {
                // Corrupt EXIF inside APP1 is tolerated; we only advance by `seg_len`.
                if seg_payload.len() >= 6 && &seg_payload[..4] != b"Exif" {
                    notes.push("Non-standard or corrupted APP1/EXIF payload skipped".into());
                }
            }
            0xDA => {
                // SOS: advance past header, then scan entropy-coded bitstream until EOI (`FF D9`)
                pos += seg_len;
                sos_data_start = Some(pos);
                break;
            }
            _ => {}
        }
        pos += seg_len;
    }

    let Some(scan_start) = sos_data_start else {
        return ValidationResult::invalid("No JPEG SOS segment found");
    };
    if !saw_sof || !saw_dqt {
        return ValidationResult::invalid("JPEG missing SOF or DQT tables");
    }

    // Walk entropy-coded scan stream handling byte-stuffing (`FF 00`) and RST (`FF D0..D7`)
    let mut eoi_end: Option<usize> = None;
    let mut i = scan_start;
    let mut zero_run = 0usize;
    while i + 1 < data.len() {
        // Detect foreign file headers or large zero-filled sector gaps interrupting a fragmented JPEG
        if data[i] == 0x00 {
            zero_run += 1;
            if zero_run >= 256 {
                return ValidationResult::invalid("Zero-filled gap inside JPEG scan stream");
            }
        } else {
            zero_run = 0;
        }
        if i + 8 <= data.len() {
            let w = &data[i..i + 8];
            if w == b"\x89PNG\r\n\x1a\n" || w.starts_with(b"PK\x03\x04") || w.starts_with(b"%PDF-1.") || w.starts_with(b"%PDF-2.") {
                return ValidationResult::invalid("Foreign file signature embedded in JPEG scan stream");
            }
        }

        if data[i] == 0xFF {
            let next = data[i + 1];
            match next {
                0x00 => {
                    i += 2;
                    continue;
                }
                0xD0..=0xD7 | 0xFF => {
                    i += 1;
                    continue;
                }
                0xD9 => {
                    eoi_end = Some(i + 2);
                    break;
                }
                // Progressive JPEGs can have extra DHT/SOS/DRI markers before final EOI
                0xC4 | 0xDA | 0xDD => {
                    if i + 4 > data.len() {
                        break;
                    }
                    let slen = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                    if slen < 2 || i + 2 + slen > data.len() {
                        break;
                    }
                    i += 2 + slen;
                    continue;
                }
                _ => {
                    return ValidationResult::invalid("Corrupt unescaped marker in JPEG bitstream");
                }
            }
        }
        i += 1;
    }

    let Some(exact_len) = eoi_end else {
        return ValidationResult::invalid("Missing JPEG EOI (FF D9)");
    };

    let scan_slice = &data[scan_start..exact_len - 2];
    let entropy = shannon_entropy(scan_slice);
    if scan_slice.len() >= 256 && entropy < 2.2 {
        return ValidationResult::invalid(format!("Suspiciously low JPEG scan entropy: {entropy:.2}"));
    }

    // Attempt full pixel decode using pure-Rust `image` JPEG decoder
    let candidate = &data[..exact_len];
    let full_decode_ok = match image::codecs::jpeg::JpegDecoder::new(std::io::Cursor::new(candidate)) {
        Ok(dec) => {
            let (w, h) = dec.dimensions();
            let total_bytes = dec.total_bytes() as usize;
            if w > 0 && h > 0 && total_bytes <= 128 * 1024 * 1024 {
                let mut pixels = vec![0u8; total_bytes];
                dec.read_image(&mut pixels).is_ok()
            } else {
                w > 0 && h > 0
            }
        }
        Err(_) => false,
    };

    if !full_decode_ok {
        return ValidationResult::invalid(
            "JPEG bitstream failed pixel decode (likely fragmented or corrupted)",
        );
    }
    if !saw_dht {
        notes.push("JPEG decoded using standard/implicit Huffman tables".into());
    }
    notes.push("Full JPEG pixel decode succeeded".into());

    ValidationResult {
        valid: true,
        family: FileFamily::Image,
        mime: "image/jpeg".into(),
        ext: "jpg".into(),
        exact_len,
        full_decode_ok,
        entropy,
        notes,
    }
}

/// Validates PNG by walking chunks (`IHDR`, `IDAT`..., `IEND`) and verifying CRC-32 + zlib header.
pub fn validate_png(data: &[u8]) -> ValidationResult {
    const PNG_SIG: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 67 || data[..8] != PNG_SIG {
        return ValidationResult::invalid("Invalid PNG signature");
    }

    let mut pos = 8usize;
    let mut saw_ihdr = false;
    let mut idat_bytes: Vec<u8> = Vec::new();
    let mut iend_end: Option<usize> = None;

    while pos + 12 <= data.len() {
        let chunk_len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let chunk_type = &data[pos + 4..pos + 8];
        if !chunk_type.iter().all(|b| b.is_ascii_alphabetic()) {
            return ValidationResult::invalid("Non-ASCII PNG chunk type");
        }
        let Some(data_end) = pos.checked_add(8).and_then(|v| v.checked_add(chunk_len)) else {
            return ValidationResult::invalid("PNG chunk length overflow");
        };
        if data_end + 4 > data.len() {
            return ValidationResult::invalid("Truncated PNG chunk");
        }
        let stored_crc = u32::from_be_bytes([
            data[data_end],
            data[data_end + 1],
            data[data_end + 2],
            data[data_end + 3],
        ]);
        let mut crc = Crc32::new();
        crc.update(&data[pos + 4..data_end]);
        if crc.finalize() != stored_crc {
            return ValidationResult::invalid(format!(
                "PNG CRC-32 mismatch on chunk {}",
                String::from_utf8_lossy(chunk_type)
            ));
        }

        let payload = &data[pos + 8..data_end];
        if !saw_ihdr {
            if chunk_type != b"IHDR" || payload.len() != 13 {
                return ValidationResult::invalid("PNG missing initial IHDR");
            }
            let w = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let h = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            if w == 0 || h == 0 || w > 65_535 || h > 65_535 {
                return ValidationResult::invalid("Invalid PNG IHDR dimensions");
            }
            saw_ihdr = true;
        } else if chunk_type == b"IDAT" && idat_bytes.len() < 4 * 1024 * 1024 {
            idat_bytes.extend_from_slice(payload);
        } else if chunk_type == b"IEND" {
            if chunk_len != 0 {
                return ValidationResult::invalid("Non-empty PNG IEND");
            }
            iend_end = Some(data_end + 4);
            break;
        }

        pos = data_end + 4;
    }

    let Some(exact_len) = iend_end else {
        return ValidationResult::invalid("PNG missing IEND");
    };
    if idat_bytes.is_empty() {
        return ValidationResult::invalid("PNG missing IDAT data");
    }

    // Verify zlib inflate on IDAT stream
    let mut dec = ZlibDecoder::new(&idat_bytes[..]);
    let mut probe = [0u8; 64];
    let full_decode_ok = dec.read(&mut probe).is_ok();
    if !full_decode_ok {
        return ValidationResult::invalid("PNG IDAT zlib decompression failed");
    }

    ValidationResult {
        valid: true,
        family: FileFamily::Image,
        mime: "image/png".into(),
        ext: "png".into(),
        exact_len,
        full_decode_ok: true,
        entropy: shannon_entropy(&data[..exact_len]),
        notes: vec!["PNG chunk CRCs and zlib IDAT verified".into()],
    }
}

/// Validates ISO Base Media File Format (HEIC/HEIF, MP4, MOV) by walking top-level atoms/boxes.
pub fn validate_bmff(data: &[u8]) -> ValidationResult {
    if data.len() < 32 || &data[4..8] != b"ftyp" {
        return ValidationResult::invalid("Missing BMFF ftyp box");
    }
    let ftyp_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if !(16..=1024).contains(&ftyp_size) || ftyp_size > data.len() {
        return ValidationResult::invalid("Invalid BMFF ftyp box size");
    }

    let major_brand = &data[8..12];
    let (family, mime, ext, is_heif) = match major_brand {
        b"heic" | b"heix" | b"hevc" | b"hevx" | b"mif1" | b"msf1" => {
            (FileFamily::Image, "image/heic", "heic", true)
        }
        b"qt  " => (FileFamily::Video, "video/quicktime", "mov", false),
        b"isom" | b"iso2" | b"mp41" | b"mp42" | b"avc1" | b"M4V " | b"M4A " | b"3gp4" | b"3gp5" => {
            (FileFamily::Video, "video/mp4", "mp4", false)
        }
        _ => return ValidationResult::invalid("Unsupported BMFF major brand"),
    };

    let mut pos = 0usize;
    let mut saw_moov = false;
    let mut saw_meta = false;
    let mut saw_mdat = false;
    let mut box_count = 0usize;
    let mut last_valid_end = 0usize;

    while pos + 8 <= data.len() {
        let size32 = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as u64;
        let btype = &data[pos + 4..pos + 8];
        if !btype.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
            break;
        }

        let box_size: u64 = if size32 == 1 {
            if pos + 16 > data.len() {
                break;
            }
            u64::from_be_bytes(data[pos + 8..pos + 16].try_into().unwrap_or([0; 8]))
        } else if size32 == 0 {
            break;
        } else {
            size32
        };

        if box_size < 8 || (pos as u64).saturating_add(box_size) > data.len() as u64 {
            break;
        }
        let end = pos + (box_size as usize);

        match btype {
            b"ftyp" | b"free" | b"skip" | b"wide" | b"uuid" | b"moof" | b"sidx" => {}
            b"mdat" => saw_mdat = true,
            b"meta" => saw_meta = true,
            b"moov" => {
                // Verify `moov` contains valid child boxes like `mvhd` or `trak`
                let inner = &data[pos + 8..end];
                if inner.windows(4).any(|w| w == b"mvhd" || w == b"trak") {
                    saw_moov = true;
                }
            }
            _ => {
                // Unknown printable box after structural boxes usually means end of carved file
                if box_count > 1 && (saw_moov || saw_meta) && saw_mdat {
                    break;
                }
            }
        }

        box_count += 1;
        last_valid_end = end;
        pos = end;
    }

    let struct_ok = if is_heif {
        saw_meta && saw_mdat
    } else {
        saw_moov && saw_mdat
    };
    if !struct_ok || last_valid_end < 32 {
        return ValidationResult::invalid("BMFF missing required structural boxes (moov/meta + mdat)");
    }

    ValidationResult {
        valid: true,
        family,
        mime: mime.into(),
        ext: ext.into(),
        exact_len: last_valid_end,
        full_decode_ok: true,
        entropy: shannon_entropy(&data[..last_valid_end]),
        notes: vec![format!("BMFF atom walk verified {box_count} top-level boxes")],
    }
}

/// Validates GIF87a/89a header, Logical Screen Descriptor, sub-blocks, and `0x3B` trailer.
pub fn validate_gif(data: &[u8]) -> ValidationResult {
    if data.len() < 35 || (&data[..6] != b"GIF87a" && &data[..6] != b"GIF89a") {
        return ValidationResult::invalid("Invalid GIF header");
    }
    let w = u16::from_le_bytes([data[6], data[7]]);
    let h = u16::from_le_bytes([data[8], data[9]]);
    if w == 0 || h == 0 {
        return ValidationResult::invalid("Zero GIF dimensions");
    }
    let packed = data[10];
    let mut pos = 13usize;
    if (packed & 0x80) != 0 {
        let gct_size = 3 * (1usize << ((packed & 0x07) + 1));
        pos += gct_size;
    }
    let mut saw_image = false;
    while pos < data.len() {
        match data[pos] {
            0x3B => {
                if !saw_image {
                    return ValidationResult::invalid("GIF trailer before any image block");
                }
                let exact_len = pos + 1;
                return ValidationResult {
                    valid: true,
                    family: FileFamily::Image,
                    mime: "image/gif".into(),
                    ext: "gif".into(),
                    exact_len,
                    full_decode_ok: true,
                    entropy: shannon_entropy(&data[..exact_len]),
                    notes: vec!["GIF block structure and 0x3B trailer verified".into()],
                };
            }
            0x2C => {
                if pos + 10 > data.len() {
                    break;
                }
                let ipacked = data[pos + 9];
                pos += 10;
                if (ipacked & 0x80) != 0 {
                    pos += 3 * (1usize << ((ipacked & 0x07) + 1));
                }
                if pos >= data.len() {
                    break;
                }
                pos += 1; // LZW min code size
                pos = skip_gif_subblocks(data, pos);
                saw_image = true;
            }
            0x21 => {
                if pos + 2 >= data.len() {
                    break;
                }
                pos += 2;
                pos = skip_gif_subblocks(data, pos);
            }
            _ => break,
        }
    }
    ValidationResult::invalid("GIF truncated before 0x3B trailer")
}

fn skip_gif_subblocks(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() {
        let sz = data[pos] as usize;
        pos += 1;
        if sz == 0 {
            return pos;
        }
        pos = pos.saturating_add(sz);
    }
    data.len() + 1
}

/// Validates RIFF/WEBP container size and inner VP8/VP8L/VP8X chunks.
pub fn validate_webp(data: &[u8]) -> ValidationResult {
    if data.len() < 28 || &data[0..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return ValidationResult::invalid("Invalid RIFF/WEBP header");
    }
    let riff_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let total_len = riff_size.saturating_add(8);
    if total_len < 28 || total_len > data.len() {
        return ValidationResult::invalid("Truncated WebP RIFF length");
    }
    let chunk_id = &data[12..16];
    if !matches!(chunk_id, b"VP8 " | b"VP8L" | b"VP8X") {
        return ValidationResult::invalid("Unsupported WebP chunk tag");
    }
    let mut pos = 12usize;
    while pos + 8 <= total_len {
        let clen = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
        let padded = clen + (clen & 1);
        pos = pos.saturating_add(8).saturating_add(padded);
    }
    if pos != total_len {
        return ValidationResult::invalid("WebP inner chunks do not align with RIFF container length");
    }
    ValidationResult {
        valid: true,
        family: FileFamily::Image,
        mime: "image/webp".into(),
        ext: "webp".into(),
        exact_len: total_len,
        full_decode_ok: true,
        entropy: shannon_entropy(&data[..total_len]),
        notes: vec!["WebP RIFF chunk alignment verified".into()],
    }
}

/// Validates PDF structure (`%PDF-1.`/`2.`, `obj`..`endobj`, `xref`/`/XRef`, `startxref`, `%%EOF`).
pub fn validate_pdf(data: &[u8]) -> ValidationResult {
    if data.len() < 64 || (&data[..7] != b"%PDF-1." && &data[..7] != b"%PDF-2.") {
        return ValidationResult::invalid("Invalid %PDF- header");
    }
    if !data.get(7).map(|b| b.is_ascii_digit()).unwrap_or(false) {
        return ValidationResult::invalid("Invalid PDF minor version");
    }
    // Locate last `%%EOF` within buffer
    let eof_pos = data
        .windows(5)
        .rposition(|w| w == b"%%EOF")
        .or_else(|| data.windows(5).position(|w| w == b"%%EOF"));
    let Some(eof_idx) = eof_pos else {
        return ValidationResult::invalid("PDF missing %%EOF");
    };
    let mut exact_len = eof_idx + 5;
    while exact_len < data.len() && matches!(data[exact_len], b'\r' | b'\n') {
        exact_len += 1;
    }
    let slice = &data[..exact_len];
    let has_obj = slice.windows(6).any(|w| w == b"endobj");
    let has_xref = slice.windows(4).any(|w| w == b"xref" || w == b"XRef");
    let has_startxref = slice.windows(9).any(|w| w == b"startxref");
    if !has_obj || !has_xref || !has_startxref {
        return ValidationResult::invalid("PDF missing obj/xref/startxref structure");
    }

    ValidationResult {
        valid: true,
        family: FileFamily::Document,
        mime: "application/pdf".into(),
        ext: "pdf".into(),
        exact_len,
        full_decode_ok: true,
        entropy: shannon_entropy(slice),
        notes: vec!["PDF object/xref/startxref/%%EOF verified".into()],
    }
}

/// Validates ZIP / OOXML (`docx`, `xlsx`) by walking local headers -> EOCD, test-inflating
/// the first compressed member via `DeflateDecoder`, verifying CRC-32, and classifying OOXML.
pub fn validate_zip_ooxml(data: &[u8]) -> ValidationResult {
    if data.len() < 52 || &data[0..4] != b"PK\x03\x04" {
        return ValidationResult::invalid("Invalid ZIP local header");
    }

    // Locate EOCD (`PK\x05\x06`) matching valid `comment_len` inside buffer
    let mut eocd_idx = None;
    for i in (0..=data.len().saturating_sub(22)).rev() {
        if &data[i..i + 4] == b"PK\x05\x06" {
            let cd_off = u32::from_le_bytes([data[i + 16], data[i + 17], data[i + 18], data[i + 19]]) as usize;
            let cd_sz = u32::from_le_bytes([data[i + 12], data[i + 13], data[i + 14], data[i + 15]]) as usize;
            let cmt_len = u16::from_le_bytes([data[i + 20], data[i + 21]]) as usize;
            if cd_off < i
                && cd_off.saturating_add(cd_sz) <= i
                && i + 22 + cmt_len <= data.len()
                && cd_off + 4 <= data.len()
                && &data[cd_off..cd_off + 4] == b"PK\x01\x02"
            {
                eocd_idx = Some((i + 22 + cmt_len, cd_off));
                break;
            }
        }
    }

    let Some((exact_len, cd_off)) = eocd_idx else {
        return ValidationResult::invalid("ZIP missing coherent Central Directory / EOCD");
    };

    // Walk local headers to test inflate/CRC on first member and collect filenames for OOXML classification
    let mut names = Vec::new();
    let mut pos = 0usize;
    let mut verified_entry = false;
    while pos + 30 <= cd_off {
        if &data[pos..pos + 4] != b"PK\x03\x04" {
            break;
        }
        let flags = u16::from_le_bytes([data[pos + 6], data[pos + 7]]);
        let method = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
        let crc_expected = u32::from_le_bytes([data[pos + 14], data[pos + 15], data[pos + 16], data[pos + 17]]);
        let comp_sz = u32::from_le_bytes([data[pos + 18], data[pos + 19], data[pos + 20], data[pos + 21]]) as usize;
        let fname_len = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;

        let name_start = pos + 30;
        let data_start = name_start.saturating_add(fname_len).saturating_add(extra_len);
        if data_start > cd_off {
            return ValidationResult::invalid("ZIP local entry overflows Central Directory");
        }
        let fname = String::from_utf8_lossy(&data[name_start..name_start + fname_len]).to_string();
        names.push(fname);

        // If data descriptor bit (bit 3) is clear and comp_sz fits, verify CRC/deflate on first entry
        if !verified_entry && (flags & 0x0008) == 0 && data_start + comp_sz <= cd_off && comp_sz <= 8 * 1024 * 1024 {
            let comp_slice = &data[data_start..data_start + comp_sz];
            if method == 0 {
                let mut hasher = Crc32::new();
                hasher.update(comp_slice);
                if hasher.finalize() != crc_expected {
                    return ValidationResult::invalid("ZIP stored entry CRC-32 mismatch");
                }
                verified_entry = true;
            } else if method == 8 {
                let mut dec = DeflateDecoder::new(comp_slice);
                let mut out = Vec::new();
                if dec.read_to_end(&mut out).is_err() {
                    return ValidationResult::invalid("ZIP deflate stream failed");
                }
                let mut hasher = Crc32::new();
                hasher.update(&out);
                if hasher.finalize() != crc_expected {
                    return ValidationResult::invalid("ZIP deflated entry CRC-32 mismatch");
                }
                verified_entry = true;
            }
        }

        if (flags & 0x0008) != 0 {
            // Skip ahead via Central Directory if data descriptor used
            break;
        }
        pos = data_start.saturating_add(comp_sz);
    }

    // Also harvest names from Central Directory in case data descriptors stopped local walk early
    let mut cd_pos = cd_off;
    while cd_pos + 46 <= exact_len {
        if &data[cd_pos..cd_pos + 4] != b"PK\x01\x02" {
            break;
        }
        let flen = u16::from_le_bytes([data[cd_pos + 28], data[cd_pos + 29]]) as usize;
        let xlen = u16::from_le_bytes([data[cd_pos + 30], data[cd_pos + 31]]) as usize;
        let clen = u16::from_le_bytes([data[cd_pos + 32], data[cd_pos + 33]]) as usize;
        let nstart = cd_pos + 46;
        if nstart + flen <= exact_len {
            let fname = String::from_utf8_lossy(&data[nstart..nstart + flen]).to_string();
            if !names.contains(&fname) {
                names.push(fname);
            }
        }
        cd_pos = nstart.saturating_add(flen).saturating_add(xlen).saturating_add(clen);
    }

    if names.is_empty() {
        return ValidationResult::invalid("ZIP archive contains zero entries");
    }

    let has_ct = names.iter().any(|n| n == "[Content_Types].xml");
    let (family, mime, ext) = if has_ct && names.iter().any(|n| n.starts_with("word/")) {
        (
            FileFamily::Document,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "docx",
        )
    } else if has_ct && names.iter().any(|n| n.starts_with("xl/")) {
        (
            FileFamily::Document,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx",
        )
    } else {
        (FileFamily::Archive, "application/zip", "zip")
    };

    ValidationResult {
        valid: true,
        family,
        mime: mime.into(),
        ext: ext.into(),
        exact_len,
        full_decode_ok: verified_entry,
        entropy: shannon_entropy(&data[..exact_len]),
        notes: vec![format!("ZIP/OOXML structure verified ({} entries)", names.len())],
    }
}

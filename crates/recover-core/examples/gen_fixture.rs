use image::{ImageEncoder, RgbaImage};
use std::path::Path;

fn main() {
    let out_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("mini_deleted.img");
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    let mut img = vec![0u8; 256 * 1024];
    let bps = 512usize;
    let spc = 4usize; // 2048B cluster
    let cluster_size = bps * spc;
    let reserved = 8usize;
    let num_fats = 2usize;
    let fat_secs = 8usize;
    let total_secs = (img.len() / bps) as u32;

    img[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
    img[13] = spc as u8;
    img[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    img[16] = num_fats as u8;
    img[32..36].copy_from_slice(&total_secs.to_le_bytes());
    img[36..40].copy_from_slice(&(fat_secs as u32).to_le_bytes());
    img[44..48].copy_from_slice(&2u32.to_le_bytes());
    img[82..87].copy_from_slice(b"FAT32");
    img[510] = 0x55;
    img[511] = 0xAA;

    let fat_off = reserved * bps;
    img[fat_off + 8..fat_off + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());

    let data_start = (reserved + num_fats * fat_secs) * bps;

    // Generate real JPEG (48x48)
    let mut rgb = RgbaImage::new(48, 48);
    for (x, y, p) in rgb.enumerate_pixels_mut() {
        *p = image::Rgba([(x * 5) as u8, (y * 5) as u8, ((x ^ y) * 3) as u8, 255]);
    }
    let mut jpg = Vec::new();
    let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpg, 80);
    enc.write_image(
        image::DynamicImage::ImageRgba8(rgb.clone()).to_rgb8().as_raw(),
        48,
        48,
        image::ExtendedColorType::Rgb8,
    )
    .unwrap();

    // Generate real PNG (32x32)
    let mut png = Vec::new();
    let png_enc = image::codecs::png::PngEncoder::new(&mut png);
    png_enc
        .write_image(
            RgbaImage::new(32, 32).as_raw(),
            32,
            32,
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();

    // Place deleted JPEG at cluster 4 (`0xE5` dir entry)
    let jpg_off = data_start + 2 * cluster_size;
    img[jpg_off..jpg_off + jpg.len()].copy_from_slice(&jpg);
    let mut d0 = [0u8; 32];
    d0[0] = 0xE5;
    d0[1..8].copy_from_slice(b"ELETED1");
    d0[8..11].copy_from_slice(b"JPG");
    d0[11] = 0x20;
    d0[26..28].copy_from_slice(&4u16.to_le_bytes());
    d0[28..32].copy_from_slice(&(jpg.len() as u32).to_le_bytes());
    img[data_start..data_start + 32].copy_from_slice(&d0);

    // Place deleted PNG at cluster 10
    let png_off = data_start + 8 * cluster_size;
    img[png_off..png_off + png.len()].copy_from_slice(&png);
    let mut d1 = [0u8; 32];
    d1[0] = 0xE5;
    d1[1..8].copy_from_slice(b"ELETED2");
    d1[8..11].copy_from_slice(b"PNG");
    d1[11] = 0x20;
    d1[26..28].copy_from_slice(&10u16.to_le_bytes());
    d1[28..32].copy_from_slice(&(png.len() as u32).to_le_bytes());
    img[data_start + 32..data_start + 64].copy_from_slice(&d1);

    // Place a spoofed JPEG header followed by garbage at cluster 16
    let spoof_off = data_start + 14 * cluster_size;
    img[spoof_off..spoof_off + 4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    for i in 4..512 {
        img[spoof_off + i] = (i * 29) as u8;
    }

    std::fs::write(&out_path, &img).unwrap();
    println!("Generated fixture at {} ({} bytes)", out_path.display(), img.len());
}

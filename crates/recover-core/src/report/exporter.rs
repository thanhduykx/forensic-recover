use crate::error::{RecoverError, Result};
use crate::io::SafeChunkReader;
use crate::models::RecoveredItem;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Exports recovered items from the read-only source into `<out_dir>/recovered/<family>/`.
/// NEVER overwrites existing files: auto-suffixes `_recovered_001`, `_recovered_002`, etc.
pub fn export_recovered_items(
    reader: &SafeChunkReader,
    items: &[RecoveredItem],
    out_dir: &Path,
) -> Result<Vec<PathBuf>> {
    let base_out = out_dir.join("recovered");
    std::fs::create_dir_all(&base_out).map_err(|e| RecoverError::Io {
        offset: 0,
        source: e,
    })?;

    let mut written = Vec::with_capacity(items.len());
    for item in items {
        let fam_dir = base_out.join(item.family.dir_name());
        std::fs::create_dir_all(&fam_dir).map_err(|e| RecoverError::Io {
            offset: 0,
            source: e,
        })?;

        let raw_name = item
            .original_name
            .as_deref()
            .filter(|n| !n.trim().is_empty())
            .map(sanitize_filename)
            .unwrap_or_else(|| {
                let short_sha = &item.sha256[..8.min(item.sha256.len())];
                format!("offset_{:#x}_{}.{}", item.byte_offset, short_sha, item.ext)
            });

        // Ensure extension matches validated format rather than possibly stripped FS name
        let final_name = ensure_ext(&raw_name, &item.ext);
        let (dest_path, mut file) = create_unique_file(&fam_dir, &final_name)?;

        let mut remaining = item.length as usize;
        for frag in &item.fragments {
            if remaining == 0 {
                break;
            }
            let take = (frag.length as usize).min(remaining);
            let mut offset = frag.offset;
            let mut left = take;
            while left > 0 {
                let step = left.min(1024 * 1024);
                let chunk = reader.read_vec_resilient(offset, step);
                file.write_all(&chunk).map_err(|e| RecoverError::Io {
                    offset,
                    source: e,
                })?;
                offset += chunk.len() as u64;
                left -= chunk.len();
                remaining -= chunk.len();
                if chunk.is_empty() {
                    break;
                }
            }
        }
        file.flush().map_err(|e| RecoverError::Io {
            offset: 0,
            source: e,
        })?;
        written.push(dest_path);
    }

    Ok(written)
}

/// Atomically creates a brand-new file using `create_new(true)` so existing files are NEVER overwritten.
pub fn create_unique_file(dir: &Path, filename: &str) -> Result<(PathBuf, File)> {
    let path_obj = Path::new(filename);
    let stem = path_obj
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("recovered");
    let ext = path_obj.extension().and_then(|s| s.to_str()).unwrap_or("");

    let candidate = dir.join(filename);
    if let Ok(f) = OpenOptions::new().write(true).create_new(true).open(&candidate) {
        return Ok((candidate, f));
    }

    for idx in 1..10_000 {
        let next_name = if ext.is_empty() {
            format!("{stem}_recovered_{idx:03}")
        } else {
            format!("{stem}_recovered_{idx:03}.{ext}")
        };
        let next_path = dir.join(next_name);
        if let Ok(f) = OpenOptions::new().write(true).create_new(true).open(&next_path) {
            return Ok((next_path, f));
        }
    }

    Err(RecoverError::Io {
        offset: 0,
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "Exceeded unique filename collision attempts",
        ),
    })
}

pub fn sanitize_filename(raw: &str) -> String {
    let leaf = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = leaf
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('.');
    if trimmed.is_empty() {
        "recovered_file".to_string()
    } else {
        trimmed.to_string()
    }
}

fn ensure_ext(name: &str, validated_ext: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let target = format!(".{}", validated_ext.to_ascii_lowercase());
    if lower.ends_with(&target) {
        name.to_string()
    } else {
        format!("{name}.{validated_ext}")
    }
}

use crate::error::{RecoverError, Result};
use crate::fs::{read_u32_le, read_u64_le, FsParseOutput};
use crate::io::SafeChunkReader;
use crate::models::FsType;

/// Read-only APFS container superblock (`NXSB`) parser + Fletcher-64 checksum + encryption check.
/// Combines with raw signature carving over unallocated container space.
pub fn parse_apfs(reader: &SafeChunkReader, vol_off: u64) -> Result<FsParseOutput> {
    let nx = reader.read_vec_resilient(vol_off, 4096);
    if nx.len() < 256 || &nx[32..36] != b"NXSB" {
        return Err(RecoverError::Parse("Not a valid APFS NXSB superblock".into()));
    }

    let stored_cksum = read_u64_le(&nx, 0);
    let block_size = read_u32_le(&nx, 36) as u64;
    let block_count = read_u64_le(&nx, 40);
    if block_size < 4096 || block_count == 0 {
        return Err(RecoverError::Parse("Invalid APFS container geometry".into()));
    }

    let mut warnings = Vec::new();
    if nx.len() >= block_size as usize {
        let computed = apfs_fletcher64(&nx[8..block_size as usize]);
        if computed != stored_cksum {
            warnings.push(format!(
                "APFS NXSB Fletcher-64 checksum mismatch (stored={stored_cksum:#x}, computed={computed:#x}); continuing with carver."
            ));
        }
    }

    // Probe early blocks for `APSB` volume superblock crypto flags
    let mut is_encrypted_hint = false;
    for blk in 1..64u64 {
        let probe = reader.read_vec_resilient(vol_off + blk * block_size, 512);
        if probe.len() >= 128 && &probe[32..36] == b"APSB" {
            let fs_flags = read_u64_le(&probe, 48);
            // Bit 0 (`APFS_FS_UNENCRYPTED`) == 0 typically implies FileVault / Data Protection crypto
            if (fs_flags & 0x01) == 0 {
                is_encrypted_hint = true;
                warnings.push(
                    "APFS volume appears encrypted (SEP/FileVault). Deleted per-file keys cannot be carved from raw unallocated blocks."
                        .to_string(),
                );
            }
            break;
        }
    }

    warnings.push(
        "APFS parsed at container superblock level; unallocated media recovery proceeds via signature carving + validator."
            .to_string(),
    );

    Ok(FsParseOutput {
        fs_type: FsType::Apfs,
        volume_offset: vol_off,
        deleted_entries: Vec::new(),
        bitmap: None,
        is_encrypted_hint,
        warnings,
    })
}

/// Computes APFS 64-bit Fletcher checksum over a block excluding the first 8-byte checksum field.
pub fn apfs_fletcher64(data: &[u8]) -> u64 {
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    for chunk in data.as_chunks::<4>().0 {
        let word = u32::from_le_bytes(*chunk) as u64;
        sum1 = (sum1 + word) % 0xFFFF_FFFF;
        sum2 = (sum2 + sum1) % 0xFFFF_FFFF;
    }
    let check1 = 0xFFFF_FFFF - ((sum1 + sum2) % 0xFFFF_FFFF);
    let check2 = 0xFFFF_FFFF - ((sum1 + check1) % 0xFFFF_FFFF);
    (check2 << 32) | check1
}

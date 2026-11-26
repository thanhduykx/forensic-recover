pub mod aligned;
pub mod guard;
pub mod platform;

use crate::models::BadSectorRange;
use std::io;
use std::sync::{Arc, Mutex};

pub use aligned::AlignedBuffer;
pub use guard::{verify_destination_safe, DestinationCheck};
pub use platform::{is_raw_device_path, list_vss_snapshots, open_source_reader, FileImageReader};

/// Read-only random-access block/image reader abstraction.
pub trait BlockReader: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
    fn total_size(&self) -> u64;
    fn sector_size(&self) -> u32;
    fn device_fingerprint(&self) -> String;
    fn is_read_only(&self) -> bool;
}

/// Fault-tolerant chunk reader that isolates bad sectors:
/// When a multi-sector read fails, it steps down to single-sector granularity,
/// zero-pads unreadable sectors so global byte offsets never drift, and records
/// each failure in `bad_sectors`.
pub struct SafeChunkReader {
    inner: Arc<dyn BlockReader>,
    bad_sectors: Mutex<Vec<BadSectorRange>>,
}

impl SafeChunkReader {
    pub fn new(inner: Arc<dyn BlockReader>) -> Self {
        Self {
            inner,
            bad_sectors: Mutex::new(Vec::new()),
        }
    }

    pub fn total_size(&self) -> u64 {
        self.inner.total_size()
    }

    pub fn sector_size(&self) -> u32 {
        self.inner.sector_size().max(512)
    }

    pub fn device_fingerprint(&self) -> String {
        self.inner.device_fingerprint()
    }

    pub fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }

    pub fn bad_sectors(&self) -> Vec<BadSectorRange> {
        self.bad_sectors.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Reads up to `buf.len()` bytes at `offset`. Never fails on bad sectors;
    /// bad sectors are zero-padded and logged instead.
    pub fn read_resilient(&self, offset: u64, buf: &mut [u8]) -> usize {
        if offset >= self.inner.total_size() || buf.is_empty() {
            return 0;
        }
        let max_len = ((self.inner.total_size() - offset) as usize).min(buf.len());
        let slice = &mut buf[..max_len];

        if let Ok(n) = self.inner.read_at(offset, slice) {
            return n;
        }

        // Step down to sector-level recovery so healthy neighbor sectors are preserved.
        let sec = self.sector_size() as usize;
        let mut cursor = 0usize;
        while cursor < max_len {
            let step = sec.min(max_len - cursor);
            let sec_off = offset + cursor as u64;
            match self.inner.read_at(sec_off, &mut slice[cursor..cursor + step]) {
                Ok(n) if n == step => {}
                Ok(n) => {
                    slice[cursor + n..cursor + step].fill(0);
                }
                Err(err) => {
                    slice[cursor..cursor + step].fill(0);
                    if let Ok(mut log) = self.bad_sectors.lock() {
                        if let Some(last) = log.last_mut() {
                            if last.offset + last.length == sec_off {
                                last.length += step as u64;
                            } else {
                                log.push(BadSectorRange {
                                    offset: sec_off,
                                    length: step as u64,
                                    error: err.to_string(),
                                });
                            }
                        } else {
                            log.push(BadSectorRange {
                                offset: sec_off,
                                length: step as u64,
                                error: err.to_string(),
                            });
                        }
                    }
                }
            }
            cursor += step;
        }
        max_len
    }

    /// Convenience helper returning an owned Vec<u8> up to `len` bytes.
    pub fn read_vec_resilient(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let n = self.read_resilient(offset, &mut buf);
        buf.truncate(n);
        buf
    }
}

/// In-memory / wrapped reader that injects I/O errors for specific byte ranges (used in tests).
pub struct FaultInjectingReader {
    inner: Arc<dyn BlockReader>,
    fault_ranges: Vec<(u64, u64)>,
}

impl FaultInjectingReader {
    pub fn new(inner: Arc<dyn BlockReader>, fault_ranges: Vec<(u64, u64)>) -> Self {
        Self {
            inner,
            fault_ranges,
        }
    }
}

impl BlockReader for FaultInjectingReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let req_end = offset.saturating_add(buf.len() as u64);
        for &(f_start, f_end) in &self.fault_ranges {
            if offset < f_end && req_end > f_start {
                return Err(io::Error::other(
                    "Simulated hardware CRC bad sector",
                ));
            }
        }
        self.inner.read_at(offset, buf)
    }

    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }

    fn device_fingerprint(&self) -> String {
        self.inner.device_fingerprint()
    }

    fn is_read_only(&self) -> bool {
        self.inner.is_read_only()
    }
}

/// Simple memory-backed reader for unit tests.
pub struct MemoryReader {
    data: Vec<u8>,
    sector_size: u32,
}

impl MemoryReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            sector_size: 512,
        }
    }
}

impl BlockReader for MemoryReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.data.len() as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let avail = self.data.len() - start;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }

    fn total_size(&self) -> u64 {
        self.data.len() as u64
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn device_fingerprint(&self) -> String {
        format!("mem:{}", self.data.len())
    }

    fn is_read_only(&self) -> bool {
        true
    }
}

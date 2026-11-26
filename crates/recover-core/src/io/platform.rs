use crate::error::{RecoverError, Result};
use crate::io::aligned::AlignedBuffer;
use crate::io::BlockReader;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::Path;

/// Standard read-only file-backed reader for `.img`, `.dd`, `.raw` disk images.
pub struct FileImageReader {
    file: File,
    total_size: u64,
    sector_size: u32,
    fingerprint: String,
}

impl FileImageReader {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|e| RecoverError::InvalidSource(format!("{}: {e}", path.display())))?;
        let meta = file.metadata().map_err(|e| RecoverError::Io {
            offset: 0,
            source: e,
        })?;
        let total_size = meta.len();
        let fingerprint = compute_quick_fingerprint(&file, total_size, &path.to_string_lossy());
        Ok(Self {
            file,
            total_size,
            sector_size: 512,
            fingerprint,
        })
    }
}

impl BlockReader for FileImageReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.total_size || buf.is_empty() {
            return Ok(0);
        }
        let max_read = ((self.total_size - offset) as usize).min(buf.len());
        read_exact_pos(&self.file, offset, &mut buf[..max_read])
    }

    fn total_size(&self) -> u64 {
        self.total_size
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn device_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    fn is_read_only(&self) -> bool {
        true
    }
}

#[cfg(windows)]
fn read_exact_pos(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    let mut total = 0;
    while total < buf.len() {
        let n = file.seek_read(&mut buf[total..], offset + total as u64)?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

#[cfg(unix)]
fn read_exact_pos(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    let mut total = 0;
    while total < buf.len() {
        let n = file.read_at(&mut buf[total..], offset + total as u64)?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

fn compute_quick_fingerprint(file: &File, total_size: u64, label: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(total_size.to_le_bytes());
    let mut head = [0u8; 4096];
    if let Ok(n) = read_exact_pos(file, 0, &mut head) {
        hasher.update(&head[..n]);
    }
    hex::encode(&hasher.finalize()[..16])
}

/// Platform raw block device reader.
/// - Windows: `GENERIC_READ` + `FILE_FLAG_NO_BUFFERING` on `\\.\PhysicalDriveN`, `\\.\X:`, or VSS snapshots.
/// - Linux: `O_RDONLY | O_DIRECT` on `/dev/sdX`, `/dev/nvmeXnY`.
/// - macOS: `O_RDONLY` + `F_NOCACHE` on `/dev/rdisk*`.
pub fn open_source_reader(source: &str) -> Result<Box<dyn BlockReader>> {
    let trimmed = source.trim();
    if is_raw_device_path(trimmed) {
        return open_raw_device(trimmed);
    }
    let path = Path::new(trimmed);
    if !path.exists() {
        return Err(RecoverError::InvalidSource(format!(
            "Source '{}' does not exist",
            trimmed
        )));
    }
    if path.is_dir() {
        return Err(RecoverError::InvalidSource(format!(
            "Source '{}' is a directory (use ios-backup or companion mode for backup directories)",
            trimmed
        )));
    }
    Ok(Box::new(FileImageReader::open(path)?))
}

pub fn is_raw_device_path(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    lower.starts_with(r"\\.\")
        || lower.starts_with(r"\\?\")
        || lower.starts_with("/dev/")
}

#[cfg(windows)]
pub fn list_vss_snapshots() -> Vec<String> {
    let Ok(out) = std::process::Command::new("vssadmin")
        .args(["list", "shadows"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.contains("HarddiskVolumeShadowCopy") {
                trimmed
                    .split(':')
                    .next_back()
                    .map(|p| format!(r"\\.\GLOBALROOT{}", p.trim()))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(not(windows))]
pub fn list_vss_snapshots() -> Vec<String> {
    Vec::new()
}

#[cfg(windows)]
fn open_raw_device(source: &str) -> Result<Box<dyn BlockReader>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_NO_BUFFERING, FILE_FLAG_RANDOM_ACCESS, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{
        DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY, IOCTL_DISK_GET_LENGTH_INFO,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let wide: Vec<u16> = std::ffi::OsStr::new(source)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: Strictly `GENERIC_READ` only; no write access requested.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS,
            0 as _,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(RecoverError::InvalidSource(format!(
            "Failed to open raw device '{}' read-only (Administrator privileges required for raw disks): {}",
            source,
            std::io::Error::last_os_error()
        )));
    }

    let mut length: i64 = 0;
    let mut returned: u32 = 0;
    let ok_len = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null(),
            0,
            &mut length as *mut i64 as *mut _,
            std::mem::size_of::<i64>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok_len == 0 || length <= 0 {
        unsafe { CloseHandle(handle) };
        return Err(RecoverError::InvalidSource(format!(
            "Could not query length of raw device '{}': {}",
            source,
            std::io::Error::last_os_error()
        )));
    }

    let mut geom: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
    let mut geom_ret: u32 = 0;
    let ok_geom = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            std::ptr::null(),
            0,
            &mut geom as *mut DISK_GEOMETRY as *mut _,
            std::mem::size_of::<DISK_GEOMETRY>() as u32,
            &mut geom_ret,
            std::ptr::null_mut(),
        )
    };
    let sector_size = if ok_geom != 0 && geom.BytesPerSector >= 512 {
        geom.BytesPerSector
    } else {
        512
    };

    let reader = WindowsRawReader {
        handle: handle as isize,
        total_size: length as u64,
        sector_size,
        fingerprint: format!("winraw:{}:{}", source, length),
    };
    Ok(Box::new(reader))
}

#[cfg(windows)]
struct WindowsRawReader {
    handle: isize,
    total_size: u64,
    sector_size: u32,
    fingerprint: String,
}

#[cfg(windows)]
unsafe impl Send for WindowsRawReader {}
#[cfg(windows)]
unsafe impl Sync for WindowsRawReader {}

#[cfg(windows)]
impl Drop for WindowsRawReader {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle as _);
        }
    }
}

#[cfg(windows)]
impl BlockReader for WindowsRawReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use windows_sys::Win32::Storage::FileSystem::ReadFile;
        use windows_sys::Win32::System::IO::OVERLAPPED;

        if offset >= self.total_size || buf.is_empty() {
            return Ok(0);
        }
        let align = self.sector_size.max(4096) as u64;
        let aligned_start = (offset / align) * align;
        let head_skip = (offset - aligned_start) as usize;
        let avail = (self.total_size - offset) as usize;
        let want = buf.len().min(avail);
        let raw_need = ((head_skip + want) as u64).div_ceil(align) * align;

        let mut aligned = AlignedBuffer::new(raw_need as usize);
        let mut total_read = 0usize;
        while total_read < raw_need as usize && (aligned_start + total_read as u64) < self.total_size
        {
            let cur_off = aligned_start + total_read as u64;
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            overlapped.Anonymous.Anonymous.Offset = (cur_off & 0xFFFF_FFFF) as u32;
            overlapped.Anonymous.Anonymous.OffsetHigh = (cur_off >> 32) as u32;

            let to_read = (raw_need as usize - total_read).min(1024 * 1024);
            let mut got: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle as _,
                    aligned.as_mut_ptr().add(total_read) as *mut _,
                    to_read as u32,
                    &mut got,
                    &mut overlapped,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if got == 0 {
                break;
            }
            total_read += got as usize;
        }
        let copy_len = want.min(total_read.saturating_sub(head_skip));
        buf[..copy_len].copy_from_slice(&aligned[head_skip..head_skip + copy_len]);
        Ok(copy_len)
    }

    fn total_size(&self) -> u64 {
        self.total_size
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn device_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    fn is_read_only(&self) -> bool {
        true
    }
}

#[cfg(unix)]
fn open_raw_device(source: &str) -> Result<Box<dyn BlockReader>> {
    use std::ffi::CString;
    use std::os::unix::io::FromRawFd;

    let c_path = CString::new(source).map_err(|e| RecoverError::InvalidSource(e.to_string()))?;

    #[cfg(target_os = "linux")]
    let flags = libc::O_RDONLY | libc::O_DIRECT | libc::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::O_RDONLY | libc::O_CLOEXEC;

    let mut fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        // Fallback without O_DIRECT if filesystem/device (e.g., loop or tmpfs) rejects O_DIRECT
        fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(RecoverError::InvalidSource(format!(
                "Failed to open '{}' read-only: {}",
                source,
                io::Error::last_os_error()
            )));
        }
    }

    #[cfg(target_os = "macos")]
    unsafe {
        libc::fcntl(fd, libc::F_NOCACHE, 1);
    }

    let file = unsafe { File::from_raw_fd(fd) };
    let (total_size, sector_size) = query_unix_block_size(&file, fd)?;
    Ok(Box::new(UnixRawReader {
        file,
        total_size,
        sector_size,
        fingerprint: format!("unixraw:{}:{}", source, total_size),
    }))
}

#[cfg(unix)]
fn query_unix_block_size(file: &File, fd: libc::c_int) -> Result<(u64, u32)> {
    #[cfg(target_os = "linux")]
    {
        const BLKGETSIZE64: libc::c_ulong = 0x80081272;
        let mut bytes: u64 = 0;
        let rc = unsafe { libc::ioctl(fd, BLKGETSIZE64 as _, &mut bytes) };
        if rc == 0 && bytes > 0 {
            return Ok((bytes, 512));
        }
    }
    #[cfg(target_os = "macos")]
    {
        const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x40046418;
        const DKIOCGETBLOCKCOUNT: libc::c_ulong = 0x40086419;
        let mut blk_size: u32 = 512;
        let mut blk_count: u64 = 0;
        unsafe {
            libc::ioctl(fd, DKIOCGETBLOCKSIZE, &mut blk_size);
            if libc::ioctl(fd, DKIOCGETBLOCKCOUNT, &mut blk_count) == 0 && blk_count > 0 {
                return Ok((blk_count.saturating_mul(blk_size as u64), blk_size.max(512)));
            }
        }
    }
    let meta = file.metadata().map_err(|e| RecoverError::Io {
        offset: 0,
        source: e,
    })?;
    Ok((meta.len(), 512))
}

#[cfg(unix)]
struct UnixRawReader {
    file: File,
    total_size: u64,
    sector_size: u32,
    fingerprint: String,
}

#[cfg(unix)]
impl BlockReader for UnixRawReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.total_size || buf.is_empty() {
            return Ok(0);
        }
        let align = 4096u64;
        let aligned_start = (offset / align) * align;
        let head_skip = (offset - aligned_start) as usize;
        let avail = (self.total_size - offset) as usize;
        let want = buf.len().min(avail);
        let raw_need = ((head_skip + want) as u64).div_ceil(align) * align;

        let mut aligned = AlignedBuffer::new(raw_need as usize);
        let got = read_exact_pos(&self.file, aligned_start, &mut aligned[..raw_need as usize])?;
        let copy_len = want.min(got.saturating_sub(head_skip));
        buf[..copy_len].copy_from_slice(&aligned[head_skip..head_skip + copy_len]);
        Ok(copy_len)
    }

    fn total_size(&self) -> u64 {
        self.total_size
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn device_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    fn is_read_only(&self) -> bool {
        true
    }
}

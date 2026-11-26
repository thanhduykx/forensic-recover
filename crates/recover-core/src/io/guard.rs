use crate::error::{RecoverError, Result};
use std::path::Path;

/// Result of checking whether `out_dir` is safe relative to `source`.
#[derive(Debug, Clone)]
pub struct DestinationCheck {
    pub safe: bool,
    pub warnings: Vec<String>,
    pub destination_free_bytes: u64,
}

/// Validates that `out_dir` will NEVER overwrite the source device/image
/// and checks available free space on the destination volume.
pub fn verify_destination_safe(
    source: &str,
    out_dir: &Path,
    allow_same_volume_image: bool,
) -> Result<DestinationCheck> {
    let mut warnings = Vec::new();
    let src_lower = source.trim().to_ascii_lowercase();

    // Ensure destination exists (or find nearest existing ancestor) for volume checks.
    std::fs::create_dir_all(out_dir).map_err(|e| RecoverError::Io {
        offset: 0,
        source: e,
    })?;

    let out_canon = std::fs::canonicalize(out_dir).unwrap_or_else(|_| out_dir.to_path_buf());
    let src_path = Path::new(source);

    if src_path.exists() {
        if let Ok(src_canon) = std::fs::canonicalize(src_path) {
            if src_canon == out_canon || out_canon.starts_with(&src_canon) {
                return Err(RecoverError::UnsafeDestination(format!(
                    "Destination '{}' overlaps with source '{}'",
                    out_canon.display(),
                    src_canon.display()
                )));
            }
            if src_path.is_file() && src_canon.parent() == Some(out_canon.as_path()) {
                warnings.push(
                    "Image file resides in the parent of destination; source file remains strictly read-only."
                        .to_string(),
                );
            }
        }
    }

    check_platform_disk_overlap(&src_lower, source, &out_canon, allow_same_volume_image, &mut warnings)?;

    let free_bytes = query_free_space(&out_canon).unwrap_or(0);
    if free_bytes > 0 && free_bytes < 64 * 1024 * 1024 {
        warnings.push(format!(
            "Low free space on destination ({} MiB available). Recovery of large media may fail.",
            free_bytes / (1024 * 1024)
        ));
    }

    Ok(DestinationCheck {
        safe: true,
        warnings,
        destination_free_bytes: free_bytes,
    })
}

#[cfg(windows)]
fn check_platform_disk_overlap(
    src_lower: &str,
    source: &str,
    out_canon: &Path,
    allow_same_volume_image: bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let out_str = out_canon.to_string_lossy().to_string();
    let out_drive = extract_windows_drive(&out_str);

    // Case 1: Source is a Windows drive volume like `\\.\E:` or `E:` or `E:\` (NOT a regular `.img` file)
    let is_regular_file = Path::new(source).is_file();
    if !is_regular_file {
        if let Some(src_drive) = extract_windows_drive(source) {
            if let Some(ref dst_drive) = out_drive {
                if src_drive.eq_ignore_ascii_case(dst_drive) {
                    return Err(RecoverError::UnsafeDestination(format!(
                        "Destination drive ({dst_drive}) is the SAME volume as source ({src_drive}). Writing recovered data to the scanned drive risks overwriting deleted sectors!"
                    )));
                }
            }
        }
    }

    // Case 2: Source is `\\.\PhysicalDriveN` -> compare physical disk numbers with out_drive extents
    if src_lower.starts_with(r"\\.\physicaldrive") {
        if let Ok(src_disk_num) = src_lower
            .trim_start_matches(r"\\.\physicaldrive")
            .parse::<u32>()
        {
            if let Some(ref dst_drive) = out_drive {
                if let Ok(dst_disks) = windows_volume_disk_numbers(dst_drive) {
                    if dst_disks.contains(&src_disk_num) {
                        return Err(RecoverError::UnsafeDestination(format!(
                            "Destination '{}' resides on PhysicalDrive{} which is the scanned source device! Choose a different physical drive.",
                            out_canon.display(),
                            src_disk_num
                        )));
                    }
                }
            }
        }
    }

    // Case 3: Regular image file on the same drive letter -> warn loudly (or reject if disallowed)
    let src_path = Path::new(source);
    if src_path.is_file() {
        if let (Some(sd), Some(dd)) = (
            std::fs::canonicalize(src_path)
                .ok()
                .and_then(|p| extract_windows_drive(&p.to_string_lossy())),
            out_drive,
        ) {
            if sd.eq_ignore_ascii_case(&dd) {
                let msg = format!(
                    "Source image file and destination folder are both on volume {dd}. Ensure this image was not dumped from {dd} itself."
                );
                if !allow_same_volume_image {
                    return Err(RecoverError::UnsafeDestination(msg));
                }
                warnings.push(msg);
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn extract_windows_drive(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim()
        .trim_start_matches(r"\\?\")
        .trim_start_matches(r"\\.\");
    let bytes = cleaned.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(format!("{}:", (bytes[0] as char).to_ascii_uppercase()))
    } else {
        None
    }
}

#[cfg(windows)]
fn windows_volume_disk_numbers(drive: &str) -> std::io::Result<Vec<u32>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::VOLUME_DISK_EXTENTS;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;

    let vol_path = format!(r"\\.\{}", drive.trim_end_matches('\\'));
    let wide: Vec<u16> = std::ffi::OsStr::new(&vol_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: Read-only metadata query handle (`dwDesiredAccess = 0`).
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            0 as _,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = [0u8; 1024];
    let mut returned: u32 = 0;
    // SAFETY: `buf` is large enough for VOLUME_DISK_EXTENTS + multiple DISK_EXTENT entries.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: `buf` starts with `VOLUME_DISK_EXTENTS`.
    let extents = unsafe { &*(buf.as_ptr() as *const VOLUME_DISK_EXTENTS) };
    let count = extents.NumberOfDiskExtents as usize;
    let mut disks = Vec::with_capacity(count);
    for i in 0..count.min(32) {
        let ptr = unsafe { extents.Extents.as_ptr().add(i) };
        let disk_num = unsafe { (*ptr).DiskNumber };
        disks.push(disk_num);
    }
    Ok(disks)
}

#[cfg(unix)]
fn check_platform_disk_overlap(
    _src_lower: &str,
    source: &str,
    out_canon: &Path,
    allow_same_volume_image: bool,
    warnings: &mut Vec<String>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let src_path = Path::new(source);
    if let (Ok(src_meta), Ok(out_meta)) = (std::fs::metadata(src_path), std::fs::metadata(out_canon)) {
        if src_path.is_file() && src_meta.dev() == out_meta.dev() {
            let msg = "Source image file and destination directory share the same filesystem device."
                .to_string();
            if !allow_same_volume_image {
                return Err(RecoverError::UnsafeDestination(msg));
            }
            warnings.push(msg);
        }
    }

    // Check `/proc/mounts` on Linux when scanning a block device like `/dev/sda` or `/dev/sdb1`
    if source.starts_with("/dev/") {
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            let dev_name = Path::new(source)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            for line in mounts.lines() {
                let mut parts = line.split_whitespace();
                if let (Some(dev), Some(mnt)) = (parts.next(), parts.next()) {
                    if !dev_name.is_empty() && (dev == source || dev.contains(&dev_name)) {
                        let mnt_path = PathBuf::from(mnt);
                        if out_canon.starts_with(&mnt_path) && mnt != "/" {
                            return Err(RecoverError::UnsafeDestination(format!(
                                "Destination '{}' is mounted on source block device '{}'",
                                out_canon.display(),
                                dev
                            )));
                        }
                        if mnt == "/" && out_canon.starts_with("/") && source.starts_with(dev.trim_end_matches(char::is_numeric)) {
                            // Best-effort check for root partition overlap
                            if let (Ok(m1), Ok(m2)) = (std::fs::metadata(mnt), std::fs::metadata(out_canon)) {
                                if m1.dev() == m2.dev() {
                                    return Err(RecoverError::UnsafeDestination(format!(
                                        "Destination '{}' is on the root filesystem backed by '{}'",
                                        out_canon.display(),
                                        dev
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
pub fn query_free_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut avail: u64 = 0;
    let mut total: u64 = 0;
    let mut free: u64 = 0;
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) };
    if ok != 0 {
        Some(avail)
    } else {
        None
    }
}

#[cfg(unix)]
pub fn query_free_space(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc == 0 {
        Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
    } else {
        None
    }
}

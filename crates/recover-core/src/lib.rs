pub mod carve;
pub mod companion;
pub mod error;
pub mod fs;
pub mod io;
pub mod models;
pub mod report;
pub mod scan;

use crate::models::{RecoveredItem, ScanConfig, ScanProgress, ScanSession, SourceInspectInfo};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// High-level facade for Desktop UI, CLI, and JNI consumers.
/// UI layers MUST call only `ScanFacade` methods and never perform raw block I/O directly.
pub struct ScanFacade;

impl ScanFacade {
    pub fn inspect(source: &str) -> error::Result<SourceInspectInfo> {
        scan::inspect_source(source)
    }

    pub fn check_destination(
        source: &str,
        out_dir: &Path,
        allow_same_volume_image: bool,
    ) -> error::Result<io::DestinationCheck> {
        io::verify_destination_safe(source, out_dir, allow_same_volume_image)
    }

    pub fn scan(
        config: &ScanConfig,
        cancel_flag: Option<Arc<AtomicBool>>,
        progress_cb: Option<&(dyn Fn(&ScanProgress) + Send + Sync)>,
    ) -> error::Result<scan::ScanResult> {
        scan::run_scan(config, cancel_flag, progress_cb)
    }

    pub fn resume(
        out_dir: &Path,
        cancel_flag: Option<Arc<AtomicBool>>,
        progress_cb: Option<&(dyn Fn(&ScanProgress) + Send + Sync)>,
    ) -> error::Result<scan::ScanResult> {
        scan::resume_scan(out_dir, cancel_flag, progress_cb)
    }

    pub fn load_session(out_dir: &Path) -> error::Result<(ScanSession, Vec<RecoveredItem>)> {
        scan::load_session_items(out_dir)
    }

    pub fn export_selected(
        source: &str,
        out_dir: &Path,
        item_ids: &[String],
    ) -> error::Result<Vec<PathBuf>> {
        scan::export_selected_items(source, out_dir, item_ids)
    }

    pub fn scan_ios_backup(
        backup_dir: &Path,
        out_dir: &Path,
        export_all: bool,
    ) -> error::Result<companion::IosBackupScanResult> {
        companion::scan_ios_backup(backup_dir, out_dir, export_all)
    }
}

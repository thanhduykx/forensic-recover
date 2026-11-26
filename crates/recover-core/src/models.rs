use serde::{Deserialize, Serialize};

/// Contiguous byte range on the source block device or image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

impl ByteRange {
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.length)
    }
}

/// Logical file system classification detected on the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsType {
    Ntfs,
    Fat32,
    ExFat,
    Ext4,
    Apfs,
    HfsPlus,
    IosBackup,
    RawUnknown,
}

impl FsType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FsType::Ntfs => "ntfs",
            FsType::Fat32 => "fat32",
            FsType::ExFat => "exfat",
            FsType::Ext4 => "ext4",
            FsType::Apfs => "apfs",
            FsType::HfsPlus => "hfsplus",
            FsType::IosBackup => "ios_backup",
            FsType::RawUnknown => "raw_unknown",
        }
    }
}

/// Current lifecycle status of a scan session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Paused,
    Completed,
    Failed,
}

/// Confidence tier derived from validation depth, contiguity, metadata match, and flash heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

/// Origin of a recovered candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMethod {
    FsMetadata,
    SignatureCarved,
    BifragmentCarved,
    HybridFsAndCarve,
    CompanionBackup,
}

/// High-level media/document grouping for UI filtering and export subdirectories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileFamily {
    Image,
    Video,
    Document,
    Archive,
    Media,
}

impl FileFamily {
    pub fn dir_name(&self) -> &'static str {
        match self {
            FileFamily::Image => "images",
            FileFamily::Video => "videos",
            FileFamily::Document => "documents",
            FileFamily::Archive => "archives",
            FileFamily::Media => "media",
        }
    }
}

/// Sector range that failed hardware/OS read and was zero-padded to keep offsets exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadSectorRange {
    pub offset: u64,
    pub length: u64,
    pub error: String,
}

/// Minimum required ScanSession model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub id: String,
    pub source: String,
    pub fs_type: FsType,
    pub started_at: String,
    pub updated_at: String,
    pub status: SessionStatus,
    pub bytes_scanned: u64,
    pub total_bytes: u64,
    pub device_fingerprint: String,
    pub bad_sectors: Vec<BadSectorRange>,
    pub zero_block_ratio: f64,
    pub high_entropy_ratio: f64,
    pub warnings: Vec<String>,
}

/// Minimum required RecoveredItem model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredItem {
    pub id: String,
    pub session_id: String,
    pub byte_offset: u64,
    pub length: u64,
    pub fragments: Vec<ByteRange>,
    pub fragment_count: usize,
    pub family: FileFamily,
    pub mime: String,
    pub ext: String,
    pub sha256: String,
    pub confidence: ConfidenceLevel,
    pub confidence_score: f32,
    pub preview_path: Option<String>,
    pub fs_path: Option<String>,
    pub original_name: Option<String>,
    pub deleted_at: Option<String>,
    pub recovery_source: RecoveryMethod,
    pub validation_notes: Vec<String>,
}

/// Minimum required CarveRule model (with runtime byte representation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarveRule {
    pub sig_id: String,
    pub family: FileFamily,
    pub header: Vec<u8>,
    pub header_offset: usize,
    pub footer: Option<Vec<u8>>,
    pub min_len: u64,
    pub max_len: u64,
    pub validator_ref: String,
    pub mime: String,
    pub ext: String,
}

/// Progress snapshot emitted during streaming scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub session_id: String,
    pub bytes_scanned: u64,
    pub total_bytes: u64,
    pub percent: f64,
    pub throughput_mbps: f64,
    pub eta_seconds: Option<u64>,
    pub items_found: usize,
    pub bad_sector_count: usize,
    pub phase: String,
}

/// Configuration for a scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub source: String,
    pub out_dir: String,
    pub types: Vec<String>,
    pub include_allocated: bool,
    pub bifragment_gap_bytes: u64,
    pub chunk_size: usize,
    pub checkpoint_interval_bytes: u64,
    pub generate_previews: bool,
    pub export_all: bool,
    pub allow_same_volume_image: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            source: String::new(),
            out_dir: String::new(),
            types: Vec::new(),
            include_allocated: false,
            bifragment_gap_bytes: 16 * 1024 * 1024,
            chunk_size: 1024 * 1024,
            checkpoint_interval_bytes: 16 * 1024 * 1024,
            generate_previews: true,
            export_all: false,
            allow_same_volume_image: true,
        }
    }
}

/// Summary returned by `recover inspect` and UI source inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInspectInfo {
    pub source: String,
    pub total_bytes: u64,
    pub sector_size: u32,
    pub fs_type: FsType,
    pub device_fingerprint: String,
    pub unallocated_bytes_estimate: Option<u64>,
    pub deleted_fs_entries: usize,
    pub is_encrypted_hint: bool,
    pub vss_snapshots: Vec<String>,
    pub warnings: Vec<String>,
}

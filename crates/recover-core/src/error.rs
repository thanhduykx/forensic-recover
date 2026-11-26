use thiserror::Error;

/// Core error type for forensic recovery operations.
#[derive(Debug, Error)]
pub enum RecoverError {
    #[error("I/O error at offset {offset:#x}: {source}")]
    Io {
        offset: u64,
        #[source]
        source: std::io::Error,
    },

    #[error("Destination safety violation: {0}")]
    UnsafeDestination(String),

    #[error("Invalid source path or device: {0}")]
    InvalidSource(String),

    #[error("Unsupported or invalid signature rule: {0}")]
    InvalidSignature(String),

    #[error("Checkpoint error: {0}")]
    Checkpoint(String),

    #[error("Scan cancelled by user")]
    Cancelled,

    #[error("Parser error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, RecoverError>;

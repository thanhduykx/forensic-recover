use crate::error::{RecoverError, Result};
use crate::models::{RecoveredItem, ScanConfig, ScanSession};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Persisted session state for crash-safe pause/resume without re-scanning earlier offsets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedCheckpoint {
    pub session: ScanSession,
    pub config: ScanConfig,
}

pub struct CheckpointManager {
    dir: PathBuf,
}

impl CheckpointManager {
    pub fn new(out_dir: &Path) -> Result<Self> {
        let dir = out_dir.join(".recover-session");
        std::fs::create_dir_all(&dir).map_err(|e| RecoverError::Io {
            offset: 0,
            source: e,
        })?;
        Ok(Self { dir })
    }

    pub fn session_path(&self) -> PathBuf {
        self.dir.join("session.json")
    }

    pub fn wal_path(&self) -> PathBuf {
        self.dir.join("wal.jsonl")
    }

    /// Atomically saves session checkpoint (`session.json.tmp` -> `session.json`).
    pub fn save_session(&self, ckpt: &SavedCheckpoint) -> Result<()> {
        let tmp = self.dir.join("session.json.tmp");
        let target = self.session_path();
        let data = serde_json::to_vec_pretty(ckpt)
            .map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
        std::fs::write(&tmp, data).map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
        std::fs::rename(&tmp, &target).map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
        Ok(())
    }

    pub fn append_item(&self, item: &RecoveredItem) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.wal_path())
            .map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
        let line = serde_json::to_string(item)
            .map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
        writeln!(f, "{line}").map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
        Ok(())
    }

    pub fn rewrite_all_items(&self, items: &[RecoveredItem]) -> Result<()> {
        let tmp = self.dir.join("wal.jsonl.tmp");
        {
            let mut f = File::create(&tmp).map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
            for item in items {
                let line = serde_json::to_string(item)
                    .map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
                writeln!(f, "{line}").map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
            }
        }
        std::fs::rename(&tmp, self.wal_path())
            .map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
        Ok(())
    }

    pub fn load_checkpoint(out_dir: &Path) -> Result<(SavedCheckpoint, Vec<RecoveredItem>)> {
        let mgr = Self::new(out_dir)?;
        let raw = std::fs::read_to_string(mgr.session_path())
            .map_err(|e| RecoverError::Checkpoint(format!("No saved checkpoint: {e}")))?;
        let ckpt: SavedCheckpoint =
            serde_json::from_str(&raw).map_err(|e| RecoverError::Checkpoint(e.to_string()))?;

        let mut items = Vec::new();
        if mgr.wal_path().exists() {
            let f = File::open(mgr.wal_path())
                .map_err(|e| RecoverError::Checkpoint(e.to_string()))?;
            let reader = BufReader::new(f);
            for line in reader.lines().map_while(|l| l.ok()) {
                let t = line.trim();
                if t.is_empty() {
                    continue;
                }
                if let Ok(item) = serde_json::from_str::<RecoveredItem>(t) {
                    items.push(item);
                }
            }
        }
        Ok((ckpt, items))
    }
}

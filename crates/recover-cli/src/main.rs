mod ui_server;

use clap::{Parser, Subcommand};
use recover_core::models::{ConfidenceLevel, ScanConfig};
use recover_core::ScanFacade;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "recover",
    version,
    about = "Read-only digital forensics & unallocated media/document recovery CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a raw device, partition, or disk image read-only and recover deleted files
    Scan {
        /// Source block device (\\.\PhysicalDriveN, /dev/sdb, /dev/rdisk2) or raw .img/.dd file
        #[arg(long)]
        source: String,

        /// Destination directory on a DIFFERENT physical drive (never writes to source)
        #[arg(long)]
        out: PathBuf,

        /// Comma-separated file extensions to recover (e.g. jpg,png,mp4,pdf,docx)
        #[arg(long, default_value = "")]
        types: String,

        /// Also scan allocated clusters in addition to unallocated space
        #[arg(long, default_value_t = false)]
        include_allocated: bool,

        /// Max gap in MiB when searching for a 2nd fragment of fragmented files (0 disables)
        #[arg(long, default_value_t = 16)]
        bifragment_gap_mb: u64,

        /// Only index/report + preview without exporting recovered files immediately
        #[arg(long, default_value_t = false)]
        no_export: bool,
    },

    /// Resume a previously paused or interrupted scan from its WAL checkpoint
    Resume {
        /// Destination output folder containing `.recover-session`
        #[arg(long)]
        out: PathBuf,
    },

    /// Inspect source geometry, filesystem type, deleted entries, and VSS snapshots (read-only)
    Inspect {
        #[arg(long)]
        source: String,
    },

    /// Scan an unencrypted iOS Finder/iTunes backup (Manifest.db, Photos.sqlite, .ithmb)
    IosBackup {
        #[arg(long)]
        backup_dir: PathBuf,

        #[arg(long)]
        out: PathBuf,

        #[arg(long, default_value_t = false)]
        no_export: bool,
    },

    /// Export specific item IDs from a completed session without overwriting existing files
    Export {
        #[arg(long)]
        source: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "")]
        ids: String,
    },

    /// Start the local offline 3-step Desktop UI & Companion IPC server
    Ui {
        #[arg(long, default_value_t = 1420)]
        port: u16,
        #[arg(long)]
        dist: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            source,
            out,
            types,
            include_allocated,
            bifragment_gap_mb,
            no_export,
        } => {
            let parsed_types: Vec<String> = types
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let cfg = ScanConfig {
                source,
                out_dir: out.to_string_lossy().to_string(),
                types: parsed_types,
                include_allocated,
                bifragment_gap_bytes: bifragment_gap_mb * 1024 * 1024,
                export_all: !no_export,
                ..Default::default()
            };

            let res = ScanFacade::scan(
                &cfg,
                None,
                Some(&|p| {
                    eprint!(
                        "\r[{:.1}%] {:.2} MB/s | items={} | bad_sectors={} ",
                        p.percent, p.throughput_mbps, p.items_found, p.bad_sector_count
                    );
                }),
            )?;
            eprintln!();

            println!("Session ID    : {}", res.session.id);
            println!("Filesystem    : {}", res.session.fs_type.as_str());
            println!("Bytes scanned : {} / {}", res.session.bytes_scanned, res.session.total_bytes);
            println!("Bad sectors   : {}", res.session.bad_sectors.len());
            println!("Recovered     : {} validated files", res.items.len());
            let high = res
                .items
                .iter()
                .filter(|i| i.confidence == ConfidenceLevel::High)
                .count();
            println!("High conf.    : {}", high);
            println!("Exported      : {} files", res.exported_paths.len());
            println!("JSON report   : {}", res.report_json_path.display());
            println!("HTML report   : {}", res.report_html_path.display());
            for w in &res.session.warnings {
                println!("WARNING       : {w}");
            }
        }
        Commands::Resume { out } => {
            let res = ScanFacade::resume(&out, None, None)?;
            println!(
                "Resumed session {}: {} items, report at {}",
                res.session.id,
                res.items.len(),
                res.report_html_path.display()
            );
        }
        Commands::Inspect { source } => {
            let info = ScanFacade::inspect(&source)?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Commands::IosBackup {
            backup_dir,
            out,
            no_export,
        } => {
            let res = ScanFacade::scan_ios_backup(&backup_dir, &out, !no_export)?;
            println!(
                "iOS backup scanned: {} items, exported {} files, report: {}",
                res.items.len(),
                res.exported_paths.len(),
                res.report_html_path.display()
            );
        }
        Commands::Export { source, out, ids } => {
            let item_ids: Vec<String> = ids
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let paths = ScanFacade::export_selected(&source, &out, &item_ids)?;
            println!("Exported {} file(s) safely.", paths.len());
        }
        Commands::Ui { port, dist } => {
            ui_server::serve_ui(port, dist)?;
        }
    }

    Ok(())
}

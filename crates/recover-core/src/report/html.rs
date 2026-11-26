use crate::error::{RecoverError, Result};
use crate::models::{ConfidenceLevel, RecoveredItem, ScanSession};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct JsonReport<'a> {
    pub session: &'a ScanSession,
    pub total_items: usize,
    pub items: &'a [RecoveredItem],
}

/// Writes `report.json` and self-contained offline `report.html` into `out_dir`.
pub fn write_reports(
    session: &ScanSession,
    items: &[RecoveredItem],
    out_dir: &Path,
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(out_dir).map_err(|e| RecoverError::Io {
        offset: 0,
        source: e,
    })?;

    let json_path = out_dir.join("report.json");
    let json_payload = serde_json::to_string_pretty(&JsonReport {
        session,
        total_items: items.len(),
        items,
    })
    .map_err(|e| RecoverError::Parse(e.to_string()))?;
    std::fs::write(&json_path, json_payload).map_err(|e| RecoverError::Io {
        offset: 0,
        source: e,
    })?;

    let html_path = out_dir.join("report.html");
    let html = render_html(session, items);
    std::fs::write(&html_path, html).map_err(|e| RecoverError::Io {
        offset: 0,
        source: e,
    })?;

    Ok((json_path, html_path))
}

fn render_html(session: &ScanSession, items: &[RecoveredItem]) -> String {
    let high = items
        .iter()
        .filter(|i| i.confidence == ConfidenceLevel::High)
        .count();
    let med = items
        .iter()
        .filter(|i| i.confidence == ConfidenceLevel::Medium)
        .count();
    let low = items
        .iter()
        .filter(|i| i.confidence == ConfidenceLevel::Low)
        .count();

    let warnings_html: String = if session.warnings.is_empty() {
        String::new()
    } else {
        let lis: String = session
            .warnings
            .iter()
            .map(|w| format!("<li>{}</li>", escape_html(w)))
            .collect();
        format!("<div class='warn'><strong>Forensic Diagnostics:</strong><ul>{lis}</ul></div>")
    };

    let rows_html: String = items
        .iter()
        .map(|it| {
            let badge_cls = match it.confidence {
                ConfidenceLevel::High => "badge high",
                ConfidenceLevel::Medium => "badge med",
                ConfidenceLevel::Low => "badge low",
            };
            let thumb_html = match &it.preview_path {
                Some(p) => format!("<img src='{}' alt='preview' loading='lazy'/>", escape_html(p)),
                None => "<span class='nothumb'>NO PREVIEW</span>".to_string(),
            };
            let fs_name = it
                .fs_path
                .as_deref()
                .or(it.original_name.as_deref())
                .unwrap_or("(unallocated orphan)");
            format!(
                "<tr>
                  <td>{thumb_html}</td>
                  <td><code>{:#x}</code></td>
                  <td>{} B</td>
                  <td><strong>{}</strong><br><small>{}</small></td>
                  <td><span class='{badge_cls}'>{:?} ({:.0}%)</span></td>
                  <td>{}</td>
                  <td>{}</td>
                  <td><code>{}</code></td>
                </tr>",
                it.byte_offset,
                it.length,
                escape_html(&it.ext.to_uppercase()),
                escape_html(&it.mime),
                it.confidence,
                it.confidence_score * 100.0,
                it.fragment_count,
                escape_html(fs_name),
                escape_html(&it.sha256[..16.min(it.sha256.len())])
            )
        })
        .collect();

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Forensic Recovery Report - {}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 24px; background: #0f172a; color: #e2e8f0; }}
  h1 {{ margin: 0 0 8px 0; font-size: 22px; }}
  .meta {{ color: #94a3b8; font-size: 13px; margin-bottom: 16px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; min-width: 140px; }}
  .warn {{ background: #451a03; border: 1px solid #f59e0b; color: #fde68a; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 10px; border-bottom: 1px solid #334155; text-align: left; font-size: 13px; vertical-align: middle; }}
  th {{ background: #0b1324; color: #94a3b8; text-transform: uppercase; font-size: 11px; }}
  img {{ width: 64px; height: 64px; object-fit: cover; border-radius: 4px; background: #0f172a; }}
  .nothumb {{ display: inline-block; padding: 6px 8px; font-size: 10px; background: #334155; border-radius: 4px; color: #94a3b8; }}
  .badge {{ padding: 3px 8px; border-radius: 999px; font-weight: 600; font-size: 11px; }}
  .badge.high {{ background: #064e3b; color: #6ee7b7; }}
  .badge.med {{ background: #78350f; color: #fcd34d; }}
  .badge.low {{ background: #7f1d1d; color: #fca5a5; }}
</style>
</head>
<body>
  <h1>Forensic Recovery Audit Report (Offline)</h1>
  <div class="meta">
    Session: <code>{}</code> &bull; Source: <code>{}</code> &bull; FS: <strong>{}</strong> &bull; Bad Sectors: <strong>{}</strong>
  </div>
  <div class="cards">
    <div class="card">Total Recovered<br><strong>{}</strong></div>
    <div class="card">High Confidence<br><strong>{}</strong></div>
    <div class="card">Medium Confidence<br><strong>{}</strong></div>
    <div class="card">Low Confidence<br><strong>{}</strong></div>
    <div class="card">Zero/TRIM Ratio<br><strong>{:.1}%</strong></div>
  </div>
  {warnings_html}
  <table>
    <thead>
      <tr><th>Preview</th><th>Offset</th><th>Length</th><th>Format</th><th>Confidence</th><th>Fragments</th><th>Original Path</th><th>SHA-256 (prefix)</th></tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>"#,
        escape_html(&session.id),
        escape_html(&session.id),
        escape_html(&session.source),
        escape_html(session.fs_type.as_str()),
        session.bad_sectors.len(),
        items.len(),
        high,
        med,
        low,
        session.zero_block_ratio * 100.0
    )
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

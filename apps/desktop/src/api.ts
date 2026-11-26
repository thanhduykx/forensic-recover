export type ConfidenceLevel = "high" | "medium" | "low";
export type FileFamily = "image" | "video" | "document" | "archive" | "media";

export interface ByteRange {
  offset: number;
  length: number;
}

export interface BadSectorRange {
  offset: number;
  length: number;
  error: string;
}

export interface ScanSession {
  id: string;
  source: string;
  fs_type: string;
  started_at: string;
  updated_at: string;
  status: "running" | "paused" | "completed" | "failed";
  bytes_scanned: number;
  total_bytes: number;
  device_fingerprint: string;
  bad_sectors: BadSectorRange[];
  zero_block_ratio: number;
  high_entropy_ratio: number;
  warnings: string[];
}

export interface RecoveredItem {
  id: string;
  session_id: string;
  byte_offset: number;
  length: number;
  fragments: ByteRange[];
  fragment_count: number;
  family: FileFamily;
  mime: string;
  ext: string;
  sha256: string;
  confidence: ConfidenceLevel;
  confidence_score: number;
  preview_path: string | null;
  fs_path: string | null;
  original_name: string | null;
  deleted_at: string | null;
  recovery_source: string;
  validation_notes: string[];
}

export interface ScanProgress {
  session_id: string;
  bytes_scanned: number;
  total_bytes: number;
  percent: number;
  throughput_mbps: number;
  eta_seconds: number | null;
  items_found: number;
  bad_sector_count: number;
  phase: string;
}

export interface SourceListResponse {
  sources: string[];
  vss_snapshots: string[];
  adb_devices: Array<{ serial: string; state: string; rooted: boolean; fbe_encrypted: boolean }>;
  ios_udids: string | null;
}

export interface DestinationCheckResponse {
  safe: boolean;
  warnings?: string[];
  destination_free_bytes?: number;
  error?: string;
}

export interface SourceInspectInfo {
  source: string;
  total_bytes: number;
  sector_size: number;
  fs_type: string;
  device_fingerprint: string;
  unallocated_bytes_estimate: number | null;
  deleted_fs_entries: number;
  is_encrypted_hint: boolean;
  vss_snapshots: string[];
  warnings: string[];
}

export interface ScanStatusResponse {
  running: boolean;
  progress: ScanProgress | null;
  last_error: string | null;
  session: ScanSession | null;
  items_count: number;
}

interface TauriInternals {
  invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: TauriInternals;
  }
}

const isTauri = (): boolean => typeof window !== "undefined" && Boolean(window.__TAURI_INTERNALS__?.invoke);

async function tauriInvoke<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!window.__TAURI_INTERNALS__?.invoke) {
    throw new Error("Tauri internals unavailable");
  }
  return window.__TAURI_INTERNALS__.invoke<T>(cmd, args);
}

async function httpJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...init
  });
  const data = (await res.json()) as T & { error?: string };
  if (!res.ok) {
    throw new Error(data.error ?? `HTTP ${res.status}`);
  }
  return data;
}

export const Api = {
  async listSources(): Promise<SourceListResponse> {
    if (isTauri()) return tauriInvoke("list_sources");
    return httpJson("/api/sources");
  },

  async inspectSource(source: string): Promise<SourceInspectInfo> {
    if (isTauri()) return tauriInvoke("inspect_source_cmd", { source });
    return httpJson("/api/inspect", {
      method: "POST",
      body: JSON.stringify({ source })
    });
  },

  async checkDestination(source: string, outDir: string): Promise<DestinationCheckResponse> {
    if (isTauri()) return tauriInvoke("check_destination_cmd", { source, outDir });
    const res = await fetch("/api/check-destination", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, out_dir: outDir, allow_same_volume_image: true })
    });
    return (await res.json()) as DestinationCheckResponse;
  },

  async startScan(params: {
    source: string;
    outDir: string;
    types: string[];
    includeAllocated: boolean;
    bifragmentGapMb: number;
  }): Promise<{ started: boolean }> {
    if (isTauri()) return tauriInvoke("start_scan_cmd", params);
    return httpJson("/api/scan", {
      method: "POST",
      body: JSON.stringify({
        source: params.source,
        out_dir: params.outDir,
        types: params.types,
        include_allocated: params.includeAllocated,
        bifragment_gap_mb: params.bifragmentGapMb,
        export_all: false
      })
    });
  },

  async scanIosBackup(backupDir: string, outDir: string): Promise<{ session: ScanSession; items_count: number }> {
    if (isTauri()) return tauriInvoke("scan_ios_backup_cmd", { backupDir, outDir });
    return httpJson("/api/ios-backup", {
      method: "POST",
      body: JSON.stringify({ backup_dir: backupDir, out_dir: outDir, export_all: false })
    });
  },

  async cancelScan(): Promise<void> {
    if (isTauri()) {
      await tauriInvoke("cancel_scan_cmd");
      return;
    }
    await httpJson("/api/cancel", { method: "POST" });
  },

  async getStatus(): Promise<ScanStatusResponse> {
    if (isTauri()) return tauriInvoke("get_scan_status_cmd");
    return httpJson("/api/status");
  },

  async listItems(): Promise<RecoveredItem[]> {
    if (isTauri()) return tauriInvoke("list_recovered_items_cmd");
    return httpJson("/api/items");
  },

  async exportSelected(source: string, outDir: string, itemIds: string[]): Promise<{ exported: string[] }> {
    if (isTauri()) return tauriInvoke("recover_items_cmd", { source, outDir, itemIds });
    return httpJson("/api/export", {
      method: "POST",
      body: JSON.stringify({ source, out_dir: outDir, item_ids: itemIds })
    });
  }
};

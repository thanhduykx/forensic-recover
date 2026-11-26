import "./styles.css";
import {
  Api,
  ConfidenceLevel,
  DestinationCheckResponse,
  RecoveredItem,
  ScanStatusResponse,
  SourceInspectInfo,
  SourceListResponse
} from "./api";

type Step = 1 | 2 | 3;

const ALL_TYPES = ["jpg", "png", "heic", "gif", "webp", "mp4", "mov", "pdf", "docx", "xlsx", "zip"];

interface AppState {
  step: Step;
  mode: "disk" | "ios_backup";
  source: string;
  outDir: string;
  selectedTypes: Set<string>;
  includeAllocated: boolean;
  bifragmentGapMb: number;
  sourcesData: SourceListResponse | null;
  inspectInfo: SourceInspectInfo | null;
  destCheck: DestinationCheckResponse | null;
  status: ScanStatusResponse | null;
  items: RecoveredItem[];
  selectedIds: Set<string>;
  filterFamily: string;
  filterConfidence: string;
  filterSearch: string;
  previewItem: RecoveredItem | null;
  errorMsg: string | null;
  exportMsg: string | null;
}

const state: AppState = {
  step: 1,
  mode: "disk",
  source: "",
  outDir: "",
  selectedTypes: new Set(["jpg", "png", "mp4", "pdf", "docx"]),
  includeAllocated: false,
  bifragmentGapMb: 16,
  sourcesData: null,
  inspectInfo: null,
  destCheck: null,
  status: null,
  items: [],
  selectedIds: new Set(),
  filterFamily: "all",
  filterConfidence: "all",
  filterSearch: "",
  previewItem: null,
  errorMsg: null,
  exportMsg: null
};

let pollTimer: number | null = null;

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function init() {
  render();
  try {
    state.sourcesData = await Api.listSources();
    if (!state.source && state.sourcesData.sources.length > 0) {
      state.source = state.sourcesData.sources[0];
    }
  } catch {
    // Allow manual image path entry even if source listing fails
  }
  render();
}

function startPolling() {
  if (pollTimer !== null) window.clearInterval(pollTimer);
  pollTimer = window.setInterval(async () => {
    try {
      const st = await Api.getStatus();
      state.status = st;
      if (!st.running) {
        if (pollTimer !== null) {
          window.clearInterval(pollTimer);
          pollTimer = null;
        }
        if (st.last_error) {
          state.errorMsg = st.last_error;
        } else {
          state.items = await Api.listItems();
          state.step = 3;
        }
      }
      render();
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
      render();
    }
  }, 500);
}

function filteredItems(): RecoveredItem[] {
  const q = state.filterSearch.trim().toLowerCase();
  return state.items.filter((it) => {
    if (state.filterFamily !== "all" && it.family !== state.filterFamily) return false;
    if (state.filterConfidence !== "all" && it.confidence !== state.filterConfidence) return false;
    if (q) {
      const hay = `${it.original_name ?? ""} ${it.fs_path ?? ""} ${it.ext} ${it.sha256}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function render() {
  const app = document.getElementById("app");
  if (!app) return;

  const hasLowConfidence =
    state.items.some((i) => i.confidence === "low") ||
    (state.status?.session?.zero_block_ratio ?? 0) > 0.5 ||
    (state.status?.session?.high_entropy_ratio ?? 0) > 0.5;

  app.innerHTML = `
    <header class="topbar">
      <div class="brand">
        <h1>Forensic Recover Engine</h1>
      </div>
      <div class="pill-row">
        <span class="pill safe">READ-ONLY SOURCE LOCK</span>
        <span class="pill safe">100% OFFLINE / NO CLOUD</span>
      </div>
    </header>
    <main class="container">
      <div class="stepper">
        <div class="step-tab ${state.step === 1 ? "active" : ""}">1. Chọn nguồn &amp; Đích an toàn</div>
        <div class="step-tab ${state.step === 2 ? "active" : ""}">2. Quét Unallocated &amp; Metadata</div>
        <div class="step-tab ${state.step === 3 ? "active" : ""}">3. Xem trước &amp; Khôi phục</div>
      </div>

      <div class="banner warn">
        <strong>Cảnh báo Flash / TRIM:</strong> Điện thoại dùng flash + TRIM nên tỷ lệ phục hồi thấp. Hãy ngừng dùng máy ngay và tuyệt đối không ghi dữ liệu mới lên ổ nguồn.
      </div>

      ${state.errorMsg ? `<div class="banner danger">${esc(state.errorMsg)}</div>` : ""}
      ${state.exportMsg ? `<div class="banner good">${esc(state.exportMsg)}</div>` : ""}

      ${state.step === 1 ? renderStep1() : state.step === 2 ? renderStep2() : renderStep3(hasLowConfidence)}
      ${state.previewItem ? renderModal(state.previewItem) : ""}
    </main>
  `;

  bindEvents();
}

function renderStep1(): string {
  const sources = state.sourcesData?.sources ?? [];
  const adbCount = state.sourcesData?.adb_devices.length ?? 0;
  const iosOk = Boolean(state.sourcesData?.ios_udids);
  const destSafe = state.destCheck ? state.destCheck.safe : true;

  return `
    <section class="card">
      <h2>Chế độ nguồn dữ liệu</h2>
      <div class="row" style="margin-bottom:14px;">
        <button class="btn ${state.mode === "disk" ? "primary" : ""}" id="mode-disk">Ổ đĩa / Phân vùng / Raw Image (.img/.dd)</button>
        <button class="btn ${state.mode === "ios_backup" ? "primary" : ""}" id="mode-ios">iOS Backup Companion (Finder/iTunes)</button>
        <span class="pill">USB ADB: ${adbCount} thiết bị</span>
        <span class="pill">iOS USB: ${iosOk ? "Đã kết nối" : "Chưa phát hiện"}</span>
      </div>

      <div class="grid-2">
        <div>
          <label>${state.mode === "disk" ? "Đường dẫn thiết bị nguồn hoặc file .img (Read-Only)" : "Thư mục iOS Backup (chứa Manifest.db)"}</label>
          <input type="text" id="inp-source" value="${esc(state.source)}" placeholder="${state.mode === "disk" ? "\\\\.\\PhysicalDrive1 hoặc C:\\forensics\\usb.img" : "C:\\Users\\...\\MobileSync\\Backup\\<UDID>"}" />
          ${
            sources.length > 0 && state.mode === "disk"
              ? `<div style="margin-top:8px;"><select id="sel-source"><option value="">-- Chọn nhanh thiết bị phát hiện --</option>${sources
                  .map((s) => `<option value="${esc(s)}">${esc(s)}</option>`)
                  .join("")}</select></div>`
              : ""
          }
        </div>
        <div>
          <label>Thư mục đích lưu kết quả (PHẢI nằm trên ổ khác nguồn)</label>
          <input type="text" id="inp-out" value="${esc(state.outDir)}" placeholder="D:\\recovered_output" />
          <div class="row" style="margin-top:8px;">
            <button class="btn" id="btn-inspect">Kiểm tra nguồn (Read-Only)</button>
            <button class="btn" id="btn-check-dest">Kiểm tra an toàn đích &amp; Free Space</button>
          </div>
        </div>
      </div>

      ${
        state.inspectInfo
          ? `<div class="stats-grid" style="margin-top:14px;">
              <div class="stat"><small>Filesystem</small><strong>${esc(state.inspectInfo.fs_type.toUpperCase())}</strong></div>
              <div class="stat"><small>Dung lượng</small><strong>${fmtBytes(state.inspectInfo.total_bytes)}</strong></div>
              <div class="stat"><small>Mục đã xóa (FS)</small><strong>${state.inspectInfo.deleted_fs_entries}</strong></div>
              <div class="stat"><small>Mã hóa</small><strong>${state.inspectInfo.is_encrypted_hint ? "Cảnh báo Encrypted" : "Không phát hiện"}</strong></div>
            </div>`
          : ""
      }

      ${
        state.destCheck
          ? `<div class="banner ${state.destCheck.safe ? "good" : "danger"}" style="margin-top:12px;">
              ${
                state.destCheck.safe
                  ? `Đích hợp lệ. Dung lượng trống: <strong>${fmtBytes(state.destCheck.destination_free_bytes ?? 0)}</strong>. ${(state.destCheck.warnings ?? []).map(esc).join(" ")}`
                  : `KHÔNG AN TOÀN: ${esc(state.destCheck.error ?? "Trùng ổ nguồn")}`
              }
            </div>`
          : ""
      }
    </section>

    ${
      state.mode === "disk"
        ? `<section class="card">
            <h2>Định dạng cần carving &amp; Phân mảnh</h2>
            <div class="chip-grid" style="margin-bottom:12px;">
              ${ALL_TYPES.map(
                (t) => `<label class="chip"><input type="checkbox" class="chk-type" value="${t}" ${state.selectedTypes.has(t) ? "checked" : ""}/> ${t.toUpperCase()}</label>`
              ).join("")}
            </div>
            <div class="grid-2">
              <div>
                <label>Cửa sổ ghép phân mảnh (Bifragment Gap - MiB)</label>
                <input type="number" id="inp-gap" min="0" max="64" value="${state.bifragmentGapMb}" />
              </div>
              <div style="display:flex;align-items:end;">
                <label class="chip"><input type="checkbox" id="chk-alloc" ${state.includeAllocated ? "checked" : ""}/> Quét cả vùng đang cấp phát (chậm hơn)</label>
              </div>
            </div>
          </section>`
        : ""
    }

    <div class="row">
      <button class="btn primary" id="btn-start" ${!state.source || !state.outDir || !destSafe ? "disabled" : ""}>
        Bắt đầu quét Read-Only &rarr;
      </button>
    </div>
  `;
}

function renderStep2(): string {
  const p = state.status?.progress;
  const pct = p ? p.percent.toFixed(1) : "0.0";
  return `
    <section class="card">
      <h2>Đang quét streaming theo chunk 4 KiB-aligned</h2>
      <p style="color:var(--muted);font-size:13px;">${esc(p?.phase ?? "Đang khởi tạo pipeline và đọc metadata...")}</p>
      <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
      <div class="stats-grid">
        <div class="stat"><small>Tiến độ</small><strong>${pct}%</strong></div>
        <div class="stat"><small>Tốc độ</small><strong>${p ? p.throughput_mbps.toFixed(2) : "0.00"} MB/s</strong></div>
        <div class="stat"><small>Đã tìm thấy</small><strong>${p?.items_found ?? state.status?.items_count ?? 0}</strong></div>
        <div class="stat"><small>Bad Sectors đã skip</small><strong>${p?.bad_sector_count ?? 0}</strong></div>
      </div>
      <div class="row">
        <button class="btn danger" id="btn-cancel">Tạm dừng / Lưu Checkpoint</button>
      </div>
    </section>
  `;
}

function renderStep3(showLowWarning: boolean): string {
  const items = filteredItems();
  const sess = state.status?.session;
  return `
    ${
      showLowWarning
        ? `<div class="banner warn">
            <strong>Kết quả có thể không đầy đủ:</strong> Phát hiện mục độ tin cậy thấp hoặc tỷ lệ block trống/TRIM cao (${((sess?.zero_block_ratio ?? 0) * 100).toFixed(1)}%). Dữ liệu trên thiết bị Flash có thể đã bị TRIM/GC ghi xóa một phần.
          </div>`
        : ""
    }

    <section class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:12px;">
        <div class="row">
          <select id="flt-family" style="width:auto;">
            <option value="all" ${state.filterFamily === "all" ? "selected" : ""}>Tất cả loại</option>
            <option value="image" ${state.filterFamily === "image" ? "selected" : ""}>Ảnh (Image)</option>
            <option value="video" ${state.filterFamily === "video" ? "selected" : ""}>Video</option>
            <option value="document" ${state.filterFamily === "document" ? "selected" : ""}>Tài liệu (PDF/Office)</option>
            <option value="archive" ${state.filterFamily === "archive" ? "selected" : ""}>Lưu trữ (ZIP)</option>
          </select>
          <select id="flt-conf" style="width:auto;">
            <option value="all" ${state.filterConfidence === "all" ? "selected" : ""}>Mọi độ tin cậy</option>
            <option value="high" ${state.filterConfidence === "high" ? "selected" : ""}>High</option>
            <option value="medium" ${state.filterConfidence === "medium" ? "selected" : ""}>Medium</option>
            <option value="low" ${state.filterConfidence === "low" ? "selected" : ""}>Low</option>
          </select>
          <input type="text" id="flt-search" style="width:220px;" value="${esc(state.filterSearch)}" placeholder="Tìm theo tên / path / sha256..." />
        </div>
        <div class="row">
          <button class="btn" id="btn-sel-high">Chọn mức High</button>
          <button class="btn" id="btn-sel-all">Chọn tất cả (${items.length})</button>
          <button class="btn" id="btn-sel-clear">Bỏ chọn</button>
          <button class="btn primary" id="btn-export" ${state.selectedIds.size === 0 ? "disabled" : ""}>
            Khôi phục ${state.selectedIds.size} file đã chọn
          </button>
          <button class="btn" id="btn-back">Quét nguồn khác</button>
        </div>
      </div>

      ${
        items.length === 0
          ? `<p style="color:var(--muted);">Không có kết quả khớp bộ lọc hiện tại.</p>`
          : `<div class="thumb-grid">
              ${items
                .map((it) => {
                  const checked = state.selectedIds.has(it.id);
                  const previewUrl = it.preview_path ? `/${it.preview_path.replace(/^\/+/, "")}` : null;
                  return `
                    <div class="item-card ${checked ? "selected" : ""}">
                      <div class="thumb-box" data-preview="${esc(it.id)}">
                        ${
                          previewUrl
                            ? `<img src="${esc(previewUrl)}" alt="${esc(it.ext)}" />`
                            : `<span class="pill">${esc(it.ext.toUpperCase())}</span>`
                        }
                      </div>
                      <div class="item-body">
                        <div class="row" style="justify-content:space-between;margin-bottom:6px;">
                          <label style="margin:0;display:flex;align-items:center;gap:6px;color:var(--text);">
                            <input type="checkbox" class="chk-item" data-id="${esc(it.id)}" ${checked ? "checked" : ""}/>
                            <strong>${esc(it.original_name ?? `${it.ext.toUpperCase()} @ 0x${it.byte_offset.toString(16)}`)}</strong>
                          </label>
                          <span class="badge ${it.confidence}">${it.confidence}</span>
                        </div>
                        <div style="color:var(--muted);">
                          ${fmtBytes(it.length)} &bull; ${it.fragment_count} mảnh &bull; ${(it.confidence_score * 100).toFixed(0)}%
                        </div>
                      </div>
                    </div>
                  `;
                })
                .join("")}
            </div>`
      }
    </section>
  `;
}

function renderModal(it: RecoveredItem): string {
  const previewUrl = it.preview_path ? `/${it.preview_path.replace(/^\/+/, "")}` : null;
  return `
    <div class="modal-backdrop" id="modal-bg">
      <div class="modal">
        <div class="row" style="justify-content:space-between;margin-bottom:10px;">
          <h2 style="margin:0;">Xem trước trước khi ghi ra đĩa</h2>
          <button class="btn" id="btn-close-modal">Đóng</button>
        </div>
        ${
          previewUrl
            ? `<div style="text-align:center;margin-bottom:12px;"><img src="${esc(previewUrl)}" style="max-height:260px;border-radius:8px;" /></div>`
            : ""
        }
        <p><strong>Định dạng:</strong> ${esc(it.mime)} (${esc(it.ext)})</p>
        <p><strong>Độ tin cậy:</strong> <span class="badge ${it.confidence}">${it.confidence} (${(it.confidence_score * 100).toFixed(0)}%)</span></p>
        <p><strong>Offset &amp; Kích thước:</strong> <code>0x${it.byte_offset.toString(16)}</code> &bull; ${fmtBytes(it.length)} (${it.fragment_count} fragments)</p>
        <p><strong>Đường dẫn FS gốc:</strong> <code>${esc(it.fs_path ?? "(Unallocated orphan)")}</code></p>
        <p><strong>SHA-256:</strong> <code style="word-break:break-all;">${esc(it.sha256)}</code></p>
        <p><strong>Ghi chú validator:</strong> ${it.validation_notes.map(esc).join(" | ")}</p>
      </div>
    </div>
  `;
}

function bindEvents() {
  document.getElementById("mode-disk")?.addEventListener("click", () => {
    state.mode = "disk";
    render();
  });
  document.getElementById("mode-ios")?.addEventListener("click", () => {
    state.mode = "ios_backup";
    render();
  });

  document.getElementById("inp-source")?.addEventListener("input", (e) => {
    state.source = (e.target as HTMLInputElement).value;
    const btn = document.getElementById("btn-start") as HTMLButtonElement | null;
    if (btn) btn.disabled = !state.source || !state.outDir;
  });

  document.getElementById("sel-source")?.addEventListener("change", (e) => {
    const val = (e.target as HTMLSelectElement).value;
    if (val) {
      state.source = val;
      render();
    }
  });

  document.getElementById("inp-out")?.addEventListener("input", (e) => {
    state.outDir = (e.target as HTMLInputElement).value;
    const btn = document.getElementById("btn-start") as HTMLButtonElement | null;
    if (btn) btn.disabled = !state.source || !state.outDir;
  });

  document.getElementById("inp-gap")?.addEventListener("input", (e) => {
    state.bifragmentGapMb = Number((e.target as HTMLInputElement).value) || 0;
  });

  document.getElementById("chk-alloc")?.addEventListener("change", (e) => {
    state.includeAllocated = (e.target as HTMLInputElement).checked;
  });

  document.querySelectorAll<HTMLInputElement>(".chk-type").forEach((el) => {
    el.addEventListener("change", () => {
      if (el.checked) state.selectedTypes.add(el.value);
      else state.selectedTypes.delete(el.value);
    });
  });

  document.getElementById("btn-inspect")?.addEventListener("click", async () => {
    state.errorMsg = null;
    try {
      state.inspectInfo = await Api.inspectSource(state.source);
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
    }
    render();
  });

  document.getElementById("btn-check-dest")?.addEventListener("click", async () => {
    state.errorMsg = null;
    try {
      state.destCheck = await Api.checkDestination(state.source, state.outDir);
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
    }
    render();
  });

  document.getElementById("btn-start")?.addEventListener("click", async () => {
    state.errorMsg = null;
    state.exportMsg = null;
    try {
      const dest = await Api.checkDestination(state.source, state.outDir);
      state.destCheck = dest;
      if (!dest.safe) {
        state.errorMsg = dest.error ?? "Đích không an toàn.";
        render();
        return;
      }
      if (state.mode === "ios_backup") {
        state.step = 2;
        render();
        await Api.scanIosBackup(state.source, state.outDir);
        state.status = await Api.getStatus();
        state.items = await Api.listItems();
        state.step = 3;
        render();
      } else {
        await Api.startScan({
          source: state.source,
          outDir: state.outDir,
          types: Array.from(state.selectedTypes),
          includeAllocated: state.includeAllocated,
          bifragmentGapMb: state.bifragmentGapMb
        });
        state.step = 2;
        render();
        startPolling();
      }
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
      state.step = 1;
      render();
    }
  });

  document.getElementById("btn-cancel")?.addEventListener("click", async () => {
    await Api.cancelScan();
  });

  document.getElementById("flt-family")?.addEventListener("change", (e) => {
    state.filterFamily = (e.target as HTMLSelectElement).value;
    render();
  });
  document.getElementById("flt-conf")?.addEventListener("change", (e) => {
    state.filterConfidence = (e.target as HTMLSelectElement).value as ConfidenceLevel | "all";
    render();
  });
  document.getElementById("flt-search")?.addEventListener("input", (e) => {
    state.filterSearch = (e.target as HTMLInputElement).value;
    render();
  });

  document.querySelectorAll<HTMLInputElement>(".chk-item").forEach((el) => {
    el.addEventListener("change", () => {
      const id = el.dataset.id ?? "";
      if (el.checked) state.selectedIds.add(id);
      else state.selectedIds.delete(id);
      render();
    });
  });

  document.querySelectorAll<HTMLElement>(".thumb-box").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.dataset.preview;
      state.previewItem = state.items.find((i) => i.id === id) ?? null;
      render();
    });
  });

  document.getElementById("btn-sel-high")?.addEventListener("click", () => {
    state.selectedIds = new Set(
      filteredItems()
        .filter((i) => i.confidence === "high")
        .map((i) => i.id)
    );
    render();
  });
  document.getElementById("btn-sel-all")?.addEventListener("click", () => {
    state.selectedIds = new Set(filteredItems().map((i) => i.id));
    render();
  });
  document.getElementById("btn-sel-clear")?.addEventListener("click", () => {
    state.selectedIds.clear();
    render();
  });

  document.getElementById("btn-export")?.addEventListener("click", async () => {
    state.errorMsg = null;
    try {
      const res = await Api.exportSelected(state.source, state.outDir, Array.from(state.selectedIds));
      state.exportMsg = `Đã khôi phục an toàn ${res.exported.length} file (không ghi đè) vào ${state.outDir}`;
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
    }
    render();
  });

  document.getElementById("btn-back")?.addEventListener("click", () => {
    state.step = 1;
    render();
  });

  document.getElementById("btn-close-modal")?.addEventListener("click", () => {
    state.previewItem = null;
    render();
  });
  document.getElementById("modal-bg")?.addEventListener("click", (e) => {
    if ((e.target as HTMLElement).id === "modal-bg") {
      state.previewItem = null;
      render();
    }
  });
}

init();

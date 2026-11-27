import "./styles.css";
import {
  Api,
  ConfidenceLevel,
  DestinationCheckResponse,
  DriveInfo,
  RecoveredItem,
  ScanStatusResponse,
  SourceInspectInfo,
  SourceListResponse
} from "./api";

type Step = 1 | 2 | 3;
type PresetKey = "all" | "photos" | "videos" | "docs" | "archives" | "custom";

const ALL_TYPES = ["jpg", "png", "heic", "gif", "webp", "mp4", "mov", "pdf", "docx", "xlsx", "zip"];

const PRESETS: Record<Exclude<PresetKey, "custom">, { label: string; types: string[] }> = {
  all: { label: "Tất cả file phổ biến", types: [...ALL_TYPES] },
  photos: { label: "Ảnh (JPG, PNG, HEIC...)", types: ["jpg", "png", "heic", "gif", "webp"] },
  videos: { label: "Video (MP4, MOV)", types: ["mp4", "mov"] },
  docs: { label: "Tài liệu (PDF, Word, Excel)", types: ["pdf", "docx", "xlsx"] },
  archives: { label: "File nén (ZIP)", types: ["zip"] }
};

interface AppState {
  step: Step;
  mode: "disk" | "ios_backup";
  source: string;
  sourceLabel: string;
  outDir: string;
  outWarning: string | null;
  preset: PresetKey;
  selectedTypes: Set<string>;
  includeAllocated: boolean;
  bifragmentGapMb: number;
  loadingSources: boolean;
  pickingBusy: boolean;
  cancelling: boolean;
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
  exportedCount: number;
  reportHtmlPath: string | null;
}

const state: AppState = {
  step: 1,
  mode: "disk",
  source: "",
  sourceLabel: "",
  outDir: "",
  outWarning: null,
  preset: "all",
  selectedTypes: new Set(ALL_TYPES),
  includeAllocated: false,
  bifragmentGapMb: 16,
  loadingSources: true,
  pickingBusy: false,
  cancelling: false,
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
  exportMsg: null,
  exportedCount: 0,
  reportHtmlPath: null
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
  if (n <= 0) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function confLabel(c: ConfidenceLevel): string {
  if (c === "high") return "Rất tốt";
  if (c === "medium") return "Khá";
  return "Thấp";
}

function isRawDevicePath(src: string): boolean {
  const s = src.trim();
  return s.startsWith("\\\\.\\") || s.startsWith("/dev/");
}

async function selectSource(source: string, label: string, mode: "disk" | "ios_backup" = "disk") {
  state.mode = mode;
  state.source = source;
  state.sourceLabel = label;
  state.errorMsg = null;
  state.inspectInfo = null;
  state.destCheck = null;
  state.outWarning = null;
  render();

  if (source) {
    try {
      const sug = await Api.suggestOutDir(source);
      if (sug.needs_external_drive) {
        state.outDir = "";
        state.outWarning = sug.message ?? "Cần chọn thư mục lưu trên ổ đĩa khác.";
      } else {
        state.outDir = sug.out_dir;
        state.outWarning = null;
      }
    } catch {
      // Fallback: user can still pick folder manually
    }
    render();
  }
}

async function refreshSources(autoSelect = false) {
  state.loadingSources = true;
  render();
  try {
    state.sourcesData = await Api.listSources();
    const drives = state.sourcesData.drives ?? [];
    if (autoSelect && !state.source) {
      // Prefer auto-selecting a non-system / removable drive if available
      const preferred =
        drives.find((d) => d.drive_type === "removable") ?? drives.find((d) => !d.is_system) ?? drives[0];
      if (preferred) {
        await selectSource(preferred.id, `Ổ ${preferred.letter} (${preferred.label})`, "disk");
      }
    } else if (state.source && state.outWarning) {
      // Re-check suggested destination in case user just plugged in an external USB drive
      await selectSource(state.source, state.sourceLabel, state.mode);
    }
  } catch {
    // Allow manual or picker selection
  } finally {
    state.loadingSources = false;
    render();
  }
}

async function init() {
  await refreshSources(true);
}

function stopPolling() {
  if (pollTimer !== null) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }
}

function startPolling() {
  stopPolling();
  const pollOnce = async () => {
    try {
      const st = await Api.getStatus();
      state.status = st;
      if (!st.running) {
        stopPolling();
        state.cancelling = false;
        if (st.last_error) {
          state.errorMsg = st.last_error;
          state.step = 1;
        } else {
          state.items = await Api.listItems();
          state.reportHtmlPath = st.report_html_path ?? null;
          // Auto-select all high-confidence files so user can recover in 1 click!
          state.selectedIds = new Set(
            state.items.filter((i) => i.confidence === "high").map((i) => i.id)
          );
          if (state.selectedIds.size === 0 && state.items.length > 0) {
            state.selectedIds = new Set(state.items.map((i) => i.id));
          }
          state.step = 3;
        }
        render();
        return;
      }
      render();
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
      render();
    }
    pollTimer = window.setTimeout(() => {
      void pollOnce();
    }, 450);
  };
  pollTimer = window.setTimeout(() => {
    void pollOnce();
  }, 350);
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

  // Preserve search focus if user is actively typing in Step 3 search box
  const activeEl = document.activeElement as HTMLInputElement | null;
  const activeId = activeEl?.id ?? null;
  const selStart = activeEl?.selectionStart ?? null;
  const selEnd = activeEl?.selectionEnd ?? null;

  const isAdmin = state.sourcesData?.is_admin ?? false;
  const hasLowConfidence =
    state.items.some((i) => i.confidence === "low") ||
    (state.status?.session?.zero_block_ratio ?? 0) > 0.5;

  app.innerHTML = `
    <header class="topbar">
      <div class="brand">
        <div>
          <h1>Forensic Recover</h1>
          <div class="brand-sub">Khôi phục dữ liệu đã xóa — An toàn, chỉ đọc, không gửi lên mạng</div>
        </div>
      </div>
      <div class="pill-row">
        <span class="pill safe">CHỈ ĐỌC (AN TOÀN)</span>
        <span class="pill safe">100% OFFLINE</span>
        ${
          isAdmin
            ? `<span class="pill safe">Quyền Quản trị (Admin)</span>`
            : `<span class="pill warn" title="Để quét trực tiếp ổ đĩa/USB, hãy chạy file MO-UNG-DUNG-ADMIN.bat">Chế độ thường (Không phải Admin)</span>`
        }
      </div>
    </header>
    <main class="container">
      <div class="stepper">
        <div class="step-tab ${state.step === 1 ? "active" : "done"}">
          <span class="step-num">1</span> Chọn nơi cần khôi phục
        </div>
        <div class="step-tab ${state.step === 2 ? "active" : state.step > 2 ? "done" : ""}">
          <span class="step-num">2</span> Đang tìm file đã xóa
        </div>
        <div class="step-tab ${state.step === 3 ? "active" : ""}">
          <span class="step-num">3</span> Xem trước &amp; Lưu về máy
        </div>
      </div>

      ${state.errorMsg ? `<div class="banner danger"><strong>Lỗi:</strong> ${esc(state.errorMsg)}</div>` : ""}

      ${state.step === 1 ? renderStep1() : state.step === 2 ? renderStep2() : renderStep3(hasLowConfidence)}
      ${state.previewItem ? renderModal(state.previewItem) : ""}
    </main>
  `;

  bindEvents();

  if (activeId) {
    const next = document.getElementById(activeId) as HTMLInputElement | null;
    if (next) {
      next.focus();
      if (selStart !== null && selEnd !== null && typeof next.setSelectionRange === "function") {
        next.setSelectionRange(selStart, selEnd);
      }
    }
  }
}

function renderDriveCard(d: DriveInfo): string {
  const selected = state.mode === "disk" && state.source === d.id;
  const used = d.total_bytes > 0 ? Math.max(0, d.total_bytes - d.free_bytes) : 0;
  const pct = d.total_bytes > 0 ? Math.min(100, Math.round((used / d.total_bytes) * 100)) : 0;
  const icon = d.drive_type === "removable" ? "🔌" : "💾";
  const tag =
    d.drive_type === "removable"
      ? `<span class="pill safe">USB / Thẻ nhớ</span>`
      : d.is_system
        ? `<span class="pill">Ổ hệ thống</span>`
        : `<span class="pill">Ổ cứng</span>`;

  return `
    <button type="button" class="drive-card ${selected ? "selected" : ""}" data-drive-id="${esc(d.id)}" data-drive-label="${esc(`Ổ ${d.letter} (${d.label})`)}">
      <div class="drive-head">
        <span class="drive-title">${icon} Ổ ${esc(d.letter)} — ${esc(d.label)}</span>
        ${tag}
      </div>
      ${
        d.total_bytes > 0
          ? `<div class="usage-bar"><div class="usage-fill" style="width:${pct}%"></div></div>
             <div class="drive-meta">Trống ${fmtBytes(d.free_bytes)} / Tổng ${fmtBytes(d.total_bytes)}</div>`
          : `<div class="drive-meta">Nhấn để chọn quét ổ ${esc(d.letter)}</div>`
      }
    </button>
  `;
}

function renderStep1(): string {
  const drives = state.sourcesData?.drives ?? [];
  const iosBackups = state.sourcesData?.ios_backups ?? [];
  const isAdmin = state.sourcesData?.is_admin ?? false;
  const demoAvailable = state.sourcesData?.demo_available ?? false;
  const needsAdminTip = !isAdmin && state.mode === "disk" && isRawDevicePath(state.source);
  const canStart = Boolean(state.source && state.outDir && !state.outWarning);

  return `
    <section class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:4px;">
        <h2 style="margin:0;">1. Bạn muốn tìm file đã xóa ở đâu?</h2>
        <button type="button" class="btn" id="btn-refresh-drives" ${state.loadingSources ? "disabled" : ""}>
          ${state.loadingSources ? "⏳ Đang quét ổ..." : "🔄 Làm mới ổ đĩa"}
        </button>
      </div>
      <p class="card-hint">Chỉ cần nhấn chọn một ổ đĩa/USB bên dưới, hoặc mở file ảnh đĩa (.img) / chạy thử mẫu.</p>

      ${
        state.loadingSources
          ? `<p class="card-hint">Đang phát hiện các ổ đĩa trên máy...</p>`
          : drives.length > 0
            ? `<div class="drive-grid">${drives.map(renderDriveCard).join("")}</div>`
            : `<p class="card-hint">Không tự phát hiện được danh sách ổ đĩa — hãy chọn file ảnh đĩa hoặc nhập thủ công ở mục Nâng cao.</p>`
      }

      <div class="alt-grid">
        <button type="button" class="action-card ${state.mode === "disk" && state.source && !isRawDevicePath(state.source) ? "selected" : ""}" id="btn-pick-file" ${state.pickingBusy ? "disabled" : ""}>
          <strong>📁 Mở file ảnh đĩa (.img / .dd)</strong>
          <span>Chọn file ảnh ổ đĩa có sẵn trên máy tính</span>
        </button>

        <button type="button" class="action-card ${state.mode === "ios_backup" ? "selected" : ""}" id="btn-mode-ios">
          <strong>📱 Bản sao lưu iPhone / iPad</strong>
          <span>${iosBackups.length > 0 ? `Tìm thấy ${iosBackups.length} bản sao lưu iTunes/Finder` : "Chọn thư mục sao lưu chứa Manifest.db"}</span>
        </button>

        ${
          demoAvailable
            ? `<button type="button" class="action-card" id="btn-run-demo">
                <strong>🧪 Chạy thử ngay (Ảnh mẫu)</strong>
                <span>Thử quét &amp; khôi phục ảnh đã xóa trong 2 giây</span>
              </button>`
            : ""
        }
      </div>

      ${
        state.mode === "ios_backup"
          ? `<div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">
              <div class="row" style="justify-content:space-between;margin-bottom:8px;">
                <strong>Chọn thư mục bản sao lưu iPhone / iPad:</strong>
                <button type="button" class="btn" id="btn-pick-ios-folder" ${state.pickingBusy ? "disabled" : ""}>📂 Chọn thư mục sao lưu...</button>
              </div>
              ${
                iosBackups.length > 0
                  ? `<div class="alt-grid">${iosBackups
                      .map(
                        (b) => `
                        <button type="button" class="action-card ${state.source === b.path ? "selected" : ""}" data-ios-path="${esc(b.path)}" data-ios-name="${esc(b.name)}">
                          <strong>📱 ${esc(b.name)}</strong>
                          <span>${esc(b.path)}</span>
                        </button>`
                      )
                      .join("")}</div>`
                  : `<p class="card-hint" style="margin:0;">Chưa thấy bản sao lưu mặc định. Nhấn <strong>"Chọn thư mục sao lưu..."</strong> để trỏ tới thư mục chứa <code>Manifest.db</code>.</p>`
              }
            </div>`
          : ""
      }

      ${
        needsAdminTip
          ? `<div class="banner warn" style="margin-top:14px;margin-bottom:0;">
              <strong>Lưu ý quyền Quản trị (Admin):</strong> Để đọc trực tiếp ổ đĩa/USB (<code>${esc(state.source)}</code>), Windows yêu cầu quyền Administrator. Nếu bị báo lỗi quyền, hãy đóng cửa sổ và mở lại bằng file <strong>MO-UNG-DUNG-ADMIN.bat</strong>.
            </div>`
          : ""
      }
    </section>

    ${
      state.mode === "disk"
        ? `<section class="card">
            <h2>2. Loại file muốn tìm</h2>
            <p class="card-hint">Mặc định tìm tất cả ảnh, video, tài liệu và file nén phổ biến.</p>
            <div class="preset-row">
              ${(Object.keys(PRESETS) as Array<Exclude<PresetKey, "custom">>)
                .map(
                  (k) =>
                    `<button type="button" class="preset-btn ${state.preset === k ? "active" : ""}" data-preset="${k}">${esc(PRESETS[k].label)}</button>`
                )
                .join("")}
            </div>

            <details class="advanced">
              <summary>⚙️ Cài đặt nâng cao (dành cho chuyên gia — không bắt buộc)</summary>
              <div class="chip-grid" style="margin-bottom:12px;">
                ${ALL_TYPES.map(
                  (t) =>
                    `<label class="chip"><input type="checkbox" class="chk-type" value="${t}" ${state.selectedTypes.has(t) ? "checked" : ""}/> ${t.toUpperCase()}</label>`
                ).join("")}
              </div>
              <div class="grid-2" style="margin-bottom:12px;">
                <div>
                  <label>Đường dẫn nguồn thủ công</label>
                  <input type="text" id="inp-source" value="${esc(state.source)}" placeholder="\\\\.\\E: hoặc C:\\path\\usb.img" />
                </div>
                <div>
                  <label>Cửa sổ ghép file phân mảnh (MiB)</label>
                  <input type="number" id="inp-gap" min="0" max="64" value="${state.bifragmentGapMb}" />
                </div>
              </div>
              <div class="row">
                <label class="chip"><input type="checkbox" id="chk-alloc" ${state.includeAllocated ? "checked" : ""}/> Quét cả file chưa bị xóa (chậm hơn)</label>
                <button type="button" class="btn" id="btn-inspect" ${!state.source ? "disabled" : ""}>Kiểm tra thông số nguồn</button>
              </div>
              ${
                state.inspectInfo
                  ? `<div class="stats-grid" style="margin-top:12px;">
                      <div class="stat"><small>Hệ thống tệp</small><strong>${esc(state.inspectInfo.fs_type.toUpperCase())}</strong></div>
                      <div class="stat"><small>Dung lượng</small><strong>${fmtBytes(state.inspectInfo.total_bytes)}</strong></div>
                      <div class="stat"><small>Mục đã xóa (FS)</small><strong>${state.inspectInfo.deleted_fs_entries}</strong></div>
                      <div class="stat"><small>Mã hóa</small><strong>${state.inspectInfo.is_encrypted_hint ? "Có dấu hiệu mã hóa" : "Không"}</strong></div>
                    </div>`
                  : ""
              }
            </details>
          </section>`
        : ""
    }

    <section class="card">
      <h2>${state.mode === "disk" ? "3" : "2"}. Nơi lưu file khôi phục (Tự động chọn an toàn)</h2>
      <p class="card-hint">Ứng dụng luôn lưu sang một ổ đĩa khác để <strong>không bao giờ ghi đè</strong> dữ liệu đã xóa trên ổ nguồn.</p>
      <div class="dest-box">
        <div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:2px;">Thư mục đích:</div>
          <div class="dest-path">${state.outDir ? esc(state.outDir) : "(Chưa chọn — hãy nhấn nút Đổi thư mục lưu)"}</div>
        </div>
        <button type="button" class="btn" id="btn-pick-out" ${state.pickingBusy ? "disabled" : ""}>📂 Đổi thư mục lưu...</button>
      </div>
      ${state.outWarning ? `<div class="banner warn" style="margin-top:10px;margin-bottom:0;">${esc(state.outWarning)}</div>` : ""}
    </section>

    <div class="cta-bar">
      <div style="font-size:13px;color:var(--muted);">
        ${state.source ? `Đang chọn: <strong style="color:var(--text);">${esc(state.sourceLabel || state.source)}</strong>` : "Hãy chọn 1 ổ đĩa hoặc file ảnh đĩa ở Bước 1."}
      </div>
      <button type="button" class="btn primary lg" id="btn-start" ${!canStart ? "disabled" : ""}>
        🔍 Bắt đầu tìm file đã xóa
      </button>
    </div>
  `;
}

function renderStep2(): string {
  const p = state.status?.progress;
  const pct = p ? Math.min(100, p.percent).toFixed(1) : "0.0";
  return `
    <section class="card">
      <h2>Đang quét tìm file đã xóa...</h2>
      <p class="card-hint">${esc(p?.phase ?? "Đang khởi tạo và đọc dữ liệu (chế độ Chỉ đọc an toàn)...")}</p>
      <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
      <div class="stats-grid">
        <div class="stat"><small>Tiến độ</small><strong>${pct}%</strong></div>
        <div class="stat"><small>Tốc độ đọc</small><strong>${p ? p.throughput_mbps.toFixed(1) : "0.0"} MB/s</strong></div>
        <div class="stat"><small>File đã tìm thấy</small><strong>${p?.items_found ?? state.status?.items_count ?? 0}</strong></div>
        <div class="stat"><small>Vùng lỗi đã bỏ qua</small><strong>${p?.bad_sector_count ?? 0}</strong></div>
      </div>
      <div class="row">
        <button type="button" class="btn danger" id="btn-cancel" ${state.cancelling ? "disabled" : ""}>
          ${state.cancelling ? "⏳ Đang dừng quét..." : "⏹ Dừng quét"}
        </button>
      </div>
    </section>
  `;
}

function renderStep3(showLowWarning: boolean): string {
  const items = filteredItems();
  const sess = state.status?.session;
  const highCount = state.items.filter((i) => i.confidence === "high").length;

  return `
    ${
      state.exportMsg
        ? `<div class="banner good">
            <div style="margin-bottom:10px;"><strong>Thành công!</strong> ${esc(state.exportMsg)}</div>
            <div class="row">
              <button type="button" class="btn good" id="btn-open-out">📂 Mở thư mục chứa file đã khôi phục</button>
              ${
                state.reportHtmlPath
                  ? `<button type="button" class="btn" id="btn-open-report">📄 Xem báo cáo chi tiết (HTML)</button>`
                  : ""
              }
            </div>
          </div>`
        : ""
    }

    ${
      showLowWarning
        ? `<div class="banner warn">
            <strong>Lưu ý về thiết bị Flash / SSD:</strong> Một số vùng dữ liệu đã trống (TRIM ${((sess?.zero_block_ratio ?? 0) * 100).toFixed(0)}%) nên có thể không khôi phục được 100% file cũ.
          </div>`
        : ""
    }

    <section class="card">
      <div class="row" style="justify-content:space-between;margin-bottom:14px;">
        <div>
          <h2 style="margin:0;">Tìm thấy ${state.items.length} file có thể khôi phục</h2>
          <div class="card-hint" style="margin:2px 0 0;">Đã tự động đánh dấu sẵn ${highCount} file chất lượng Rất tốt. Nhấn vào ảnh để xem phóng to trước khi lưu.</div>
        </div>
        <div class="row">
          ${
            state.mode === "ios_backup"
              ? `<button type="button" class="btn good lg" id="btn-open-out-header">
                  📂 Mở thư mục file đã trích xuất
                </button>`
              : `<button type="button" class="btn primary lg" id="btn-export" ${state.selectedIds.size === 0 ? "disabled" : ""}>
                  💾 Khôi phục ${state.selectedIds.size} file đã chọn
                </button>`
          }
          <button type="button" class="btn" id="btn-back">← Quét nguồn khác</button>
        </div>
      </div>

      <div class="row" style="justify-content:space-between;margin-bottom:14px;">
        <div class="row">
          <select id="flt-family" style="width:auto;">
            <option value="all" ${state.filterFamily === "all" ? "selected" : ""}>Tất cả loại file</option>
            <option value="image" ${state.filterFamily === "image" ? "selected" : ""}>🖼️ Ảnh</option>
            <option value="video" ${state.filterFamily === "video" ? "selected" : ""}>🎬 Video</option>
            <option value="document" ${state.filterFamily === "document" ? "selected" : ""}>📄 Tài liệu</option>
            <option value="archive" ${state.filterFamily === "archive" ? "selected" : ""}>📦 File nén</option>
          </select>
          <select id="flt-conf" style="width:auto;">
            <option value="all" ${state.filterConfidence === "all" ? "selected" : ""}>Mọi mức độ</option>
            <option value="high" ${state.filterConfidence === "high" ? "selected" : ""}>Rất tốt</option>
            <option value="medium" ${state.filterConfidence === "medium" ? "selected" : ""}>Khá</option>
            <option value="low" ${state.filterConfidence === "low" ? "selected" : ""}>Thấp</option>
          </select>
          <input type="text" id="flt-search" style="width:210px;" value="${esc(state.filterSearch)}" placeholder="Tìm theo tên hoặc định dạng..." />
        </div>
        <div class="row">
          <button type="button" class="btn" id="btn-sel-high">Chọn mức Rất tốt</button>
          <button type="button" class="btn" id="btn-sel-all">Chọn tất cả (${items.length})</button>
          <button type="button" class="btn" id="btn-sel-clear">Bỏ chọn</button>
        </div>
      </div>

      ${
        items.length === 0
          ? `<div class="banner info" style="margin:0;">Không tìm thấy file nào khớp với bộ lọc hiện tại. Hãy thử đổi bộ lọc hoặc quay lại chọn nguồn khác.</div>`
          : `<div class="thumb-grid">
              ${items
                .map((it) => {
                  const checked = state.selectedIds.has(it.id);
                  const previewUrl = it.preview_path ? `/${it.preview_path.replace(/^\/+/, "")}` : null;
                  return `
                    <div class="item-card ${checked ? "selected" : ""}">
                      <div class="thumb-box" data-preview="${esc(it.id)}" title="Nhấn để xem trước">
                        ${
                          previewUrl
                            ? `<img src="${esc(previewUrl)}" alt="${esc(it.ext)}" />`
                            : `<span class="pill">${esc(it.ext.toUpperCase())}</span>`
                        }
                      </div>
                      <div class="item-body">
                        <div class="row" style="justify-content:space-between;margin-bottom:6px;flex-wrap:nowrap;">
                          <label style="margin:0;display:flex;align-items:center;gap:6px;color:var(--text);overflow:hidden;">
                            <input type="checkbox" class="chk-item" data-id="${esc(it.id)}" ${checked ? "checked" : ""}/>
                            <strong style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(it.original_name ?? `File_${it.ext.toUpperCase()}_${it.id.slice(0, 6)}`)}</strong>
                          </label>
                          <span class="badge ${it.confidence}">${confLabel(it.confidence)}</span>
                        </div>
                        <div style="color:var(--muted);">
                          ${fmtBytes(it.length)} &bull; ${it.ext.toUpperCase()} &bull; ${(it.confidence_score * 100).toFixed(0)}%
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
        <div class="row" style="justify-content:space-between;margin-bottom:12px;">
          <h2 style="margin:0;">Xem trước file</h2>
          <button type="button" class="btn" id="btn-close-modal">Đóng</button>
        </div>
        ${
          previewUrl
            ? `<div style="text-align:center;margin-bottom:14px;"><img src="${esc(previewUrl)}" style="max-height:300px;max-width:100%;border-radius:8px;" /></div>`
            : ""
        }
        <p><strong>Tên file:</strong> ${esc(it.original_name ?? `File_${it.ext.toUpperCase()}`)}</p>
        <p><strong>Định dạng:</strong> ${esc(it.ext.toUpperCase())} (${esc(it.mime)})</p>
        <p><strong>Dung lượng:</strong> ${fmtBytes(it.length)}</p>
        <p><strong>Khả năng khôi phục:</strong> <span class="badge ${it.confidence}">${confLabel(it.confidence)} (${(it.confidence_score * 100).toFixed(0)}%)</span></p>
        <details class="advanced">
          <summary>Thông tin kỹ thuật (Forensic)</summary>
          <p><strong>Offset:</strong> <code>0x${it.byte_offset.toString(16)}</code> (${it.fragment_count} mảnh)</p>
          <p><strong>Đường dẫn gốc:</strong> <code>${esc(it.fs_path ?? "(Không có tên gốc)")}</code></p>
          <p><strong>SHA-256:</strong> <code style="word-break:break-all;">${esc(it.sha256)}</code></p>
          <p><strong>Ghi chú:</strong> ${it.validation_notes.map(esc).join(" | ")}</p>
        </details>
      </div>
    </div>
  `;
}

async function runScanNow() {
  state.errorMsg = null;
  state.exportMsg = null;
  state.exportedCount = 0;
  try {
    const dest = await Api.checkDestination(state.source, state.outDir);
    state.destCheck = dest;
    if (!dest.safe) {
      state.errorMsg = dest.error ?? "Thư mục lưu không an toàn (trùng ổ nguồn).";
      render();
      return;
    }
    if (state.mode === "ios_backup") {
      state.step = 2;
      render();
      const res = await Api.scanIosBackup(state.source, state.outDir);
      state.status = await Api.getStatus();
      state.items = await Api.listItems();
      state.reportHtmlPath = res.report_html_path ?? state.status?.report_html_path ?? null;
      state.selectedIds = new Set(state.items.map((i) => i.id));
      state.exportedCount = res.exported_count ?? state.items.length;
      if (state.exportedCount > 0) {
        state.exportMsg = `Đã trích xuất an toàn ${state.exportedCount} file từ bản sao lưu iPhone/iPad vào ${state.outDir}`;
      }
      state.step = 3;
      render();
    } else {
      state.cancelling = false;
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
}

function bindEvents() {
  // Refresh drive list (e.g. after user plugs in a USB flash drive)
  document.getElementById("btn-refresh-drives")?.addEventListener("click", () => {
    void refreshSources(false);
  });

  // Drive cards
  document.querySelectorAll<HTMLElement>("[data-drive-id]").forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.dataset.driveId ?? "";
      const label = el.dataset.driveLabel ?? id;
      void selectSource(id, label, "disk");
    });
  });

  // Pick image file (.img/.dd)
  document.getElementById("btn-pick-file")?.addEventListener("click", async () => {
    state.pickingBusy = true;
    state.errorMsg = null;
    render();
    try {
      const res = await Api.pickFile();
      if (!res.cancelled && res.path) {
        const name = res.path.split(/[\\/]/).pop() ?? res.path;
        await selectSource(res.path, `File ảnh: ${name}`, "disk");
      }
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
    } finally {
      state.pickingBusy = false;
      render();
    }
  });

  // Switch to iOS backup mode
  document.getElementById("btn-mode-ios")?.addEventListener("click", () => {
    state.mode = "ios_backup";
    state.errorMsg = null;
    const firstBackup = state.sourcesData?.ios_backups?.[0];
    if (firstBackup) {
      void selectSource(firstBackup.path, `iPhone Backup: ${firstBackup.name}`, "ios_backup");
    } else {
      state.source = "";
      state.sourceLabel = "";
      render();
    }
  });

  // Auto-detected iOS backup cards
  document.querySelectorAll<HTMLElement>("[data-ios-path]").forEach((el) => {
    el.addEventListener("click", () => {
      const p = el.dataset.iosPath ?? "";
      const name = el.dataset.iosName ?? p;
      void selectSource(p, `iPhone Backup: ${name}`, "ios_backup");
    });
  });

  // Pick iOS backup folder
  document.getElementById("btn-pick-ios-folder")?.addEventListener("click", async () => {
    state.pickingBusy = true;
    state.errorMsg = null;
    render();
    try {
      const res = await Api.pickFolder();
      if (!res.cancelled && res.path) {
        const name = res.path.split(/[\\/]/).pop() ?? res.path;
        await selectSource(res.path, `iPhone Backup: ${name}`, "ios_backup");
      }
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
    } finally {
      state.pickingBusy = false;
      render();
    }
  });

  // 1-click Demo scan
  document.getElementById("btn-run-demo")?.addEventListener("click", async () => {
    state.errorMsg = null;
    try {
      const demo = await Api.getDemoSource();
      state.mode = "disk";
      state.source = demo.source;
      state.sourceLabel = "Ảnh mẫu Demo (mini_deleted.img)";
      state.outDir = demo.suggested_out_dir;
      state.outWarning = null;
      state.preset = "all";
      state.selectedTypes = new Set(ALL_TYPES);
      await runScanNow();
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
      render();
    }
  });

  // Pick output folder
  document.getElementById("btn-pick-out")?.addEventListener("click", async () => {
    state.pickingBusy = true;
    state.errorMsg = null;
    render();
    try {
      const res = await Api.pickFolder();
      if (!res.cancelled && res.path) {
        state.outDir = res.path;
        state.outWarning = null;
        if (state.source) {
          const chk = await Api.checkDestination(state.source, res.path);
          state.destCheck = chk;
          if (!chk.safe) {
            state.outWarning = chk.error ?? "Thư mục lưu đang nằm trên cùng ổ với ổ nguồn. Hãy chọn ổ đĩa khác.";
          }
        }
      }
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
    } finally {
      state.pickingBusy = false;
      render();
    }
  });

  // Preset buttons
  document.querySelectorAll<HTMLElement>("[data-preset]").forEach((el) => {
    el.addEventListener("click", () => {
      const k = el.dataset.preset as Exclude<PresetKey, "custom">;
      if (PRESETS[k]) {
        state.preset = k;
        state.selectedTypes = new Set(PRESETS[k].types);
        render();
      }
    });
  });

  // Advanced controls
  document.getElementById("inp-source")?.addEventListener("input", (e) => {
    state.source = (e.target as HTMLInputElement).value;
    state.sourceLabel = state.source;
    const btnStart = document.getElementById("btn-start") as HTMLButtonElement | null;
    if (btnStart) btnStart.disabled = !state.source || !state.outDir || Boolean(state.outWarning);
    const btnInspect = document.getElementById("btn-inspect") as HTMLButtonElement | null;
    if (btnInspect) btnInspect.disabled = !state.source;
  });

  document.getElementById("inp-source")?.addEventListener("change", () => {
    if (state.source.trim()) {
      void selectSource(state.source.trim(), state.source.trim(), state.mode);
    }
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
      state.preset = "custom";
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

  // Primary Start Scan button
  document.getElementById("btn-start")?.addEventListener("click", () => {
    void runScanNow();
  });

  // Cancel Scan
  document.getElementById("btn-cancel")?.addEventListener("click", async () => {
    state.cancelling = true;
    render();
    try {
      await Api.cancelScan();
    } catch (e) {
      state.cancelling = false;
      state.errorMsg = e instanceof Error ? e.message : String(e);
      render();
    }
  });

  // Step 3 filters & selection
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
      state.exportedCount = res.exported.length;
      state.exportMsg = `Đã khôi phục an toàn ${res.exported.length} file vào thư mục ${state.outDir}`;
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
    }
    render();
  });

  const openOutHandler = async () => {
    try {
      await Api.openFolder(state.outDir);
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
      render();
    }
  };
  document.getElementById("btn-open-out")?.addEventListener("click", openOutHandler);
  document.getElementById("btn-open-out-header")?.addEventListener("click", openOutHandler);

  document.getElementById("btn-open-report")?.addEventListener("click", async () => {
    if (!state.reportHtmlPath) return;
    try {
      await Api.openFolder(state.reportHtmlPath);
    } catch (e) {
      state.errorMsg = e instanceof Error ? e.message : String(e);
      render();
    }
  });

  document.getElementById("btn-back")?.addEventListener("click", () => {
    state.step = 1;
    state.exportMsg = null;
    state.errorMsg = null;
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

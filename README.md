# Forensic Recover — Hệ sinh thái phục hồi dữ liệu Read-Only (Desktop / Android / iOS)

Hệ thống phục hồi dữ liệu cấp độ **Digital Forensics** (100% offline, không gửi dữ liệu lên cloud, tuyệt đối **read-only** với thiết bị nguồn) dành cho bài toán **tập tin ảnh, video, tài liệu đã bị xóa logic nhưng dữ liệu vật lý vẫn còn trên vùng chưa cấp phát (unallocated space)**.

> **CẢNH BÁO PHẦN CỨNG QUAN TRỌNG:**
> Điện thoại và ổ SSD đời mới dùng bộ nhớ Flash có **TRIM/discard**, **Wear-Leveling** và mã hóa theo từng file (**Android FBE** / **Apple SEP**). **Hãy ngừng sử dụng thiết bị nguồn ngay lập tức** và **không bao giờ lưu file khôi phục, log hay temp lên cùng ổ nguồn**. Không một phần mềm nào có thể cam kết phục hồi 100% sau khi TRIM hoặc FBE key eviction đã diễn ra.

---

## 1. Kiến trúc & Đánh đổi Công nghệ (Architecture & Trade-offs)

```text
[Raw Disk / VSS / .img / iOS Backup]
        │  (GENERIC_READ + NO_BUFFERING | O_DIRECT | F_NOCACHE)
        ▼
[Same-Disk Guard + SafeChunkReader (4 KiB aligned + bad-sector bisect)]
        │
        ├──► core::fs (NTFS $MFT/$Bitmap/$UsnJrnl, FAT32, exFAT, ext4, APFS, HFS+)
        ├──► core::carve (JSON Signature DB + Real Format Validators + Bifragment Gap)
        └──► core::companion (Pure-Rust Read-Only SQLite B-Tree: Manifest.db, Photos.sqlite)
        │
        ▼
[Confidence Scorer (High/Med/Low) + SHA-256 Dedupe + WAL Checkpoint]
        │
        ├──► recover CLI (`recover scan`, `resume`, `inspect`, `ios-backup`, `ui`)
        ├──► Desktop UI (Tauri v2 + Local Loopback IPC — 3-step flow)
        ├──► Android APK (Kotlin minSdk 26 + ForegroundService + recover-jni)
        └──► iOS IPA (Swift iOS 15+ + PhotoKit/Cache + Companion + Jailbreak O_RDONLY)
```

### So sánh Trade-off
- **Core Engine: Rust vs C++**: Chọn **Rust** vì an toàn bộ nhớ ở compile-time khi parse sector/MFT/EXIF bị ghi đè một nửa (không buffer over-read/UAF), cô lập từng candidate bằng `Result` + `catch_unwind`, đa luồng an toàn khi hash/validate, và biên dịch chung cho Desktop CLI/Tauri + Android JNI (`cdylib`).
- **Desktop UI: Tauri v2 vs Electron**: Chọn **Tauri v2** (kèm chế độ fallback local loopback server `recover ui`) để bộ cài nhỏ gọn (~8–15 MB thay vì ~200 MB Chromium), ít chiếm RAM trên máy cứu hộ, khóa CSP offline và gọi thẳng `ScanFacade` trong Rust mà không qua `N-API`.

---

## 2. Giới hạn thực tế & Capability Matrix

### Giới hạn vật lý không thể vượt qua
1. **SSD / UFS / eMMC TRIM & Garbage Collection**: Khi hệ điều hành phát lệnh `TRIM`/`UNMAP` sau xóa, controller flash có thể trả về toàn `0x00` hoặc `0xFF` (DZAT/DRAT). Engine phát hiện `zero_block_ratio` và cảnh báo trung thực thay vì đoán mò.
2. **Android 10+ FBE & iOS 15+ Apple SEP**: Ngay cả khi có quyền root/jailbreak đọc raw block (`/dev/block/by-name/userdata`, `/dev/rdisk0s1s2`), mỗi file được mã hóa bằng key riêng; khi key bị Keystore/SEP hủy lúc xóa, các block unallocated chỉ còn ciphertext (entropy ~7.98–8.0 bits/byte).
3. **BitLocker / FileVault (ngoài phạm vi)**: Nếu toàn phân vùng được mã hóa ở lớp volume và chưa giải mã qua OS/key, cần gắn volume đã mở khóa hoặc image đã decrypt trước khi quét.

### Capability Matrix theo nền tảng

| Nền tảng / Chế độ | Đọc Raw Block Device | Parse FS Metadata | Unallocated Carving | Nguồn dữ liệu thực tế | Mức độ phục hồi kỳ vọng |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **Desktop — HDD / USB / Thẻ SD** | Có (Admin/root) | NTFS, FAT32, exFAT, ext4, APFS/HFS+ | Đầy đủ + Bifragment | `\\.\PhysicalDriveN`, VSS, `/dev/sdX`, `/dev/rdiskN`, `.img` | **Cao** nếu chưa ghi đè |
| **Desktop — SSD bật TRIM** | Có (Admin/root) | Có (`$MFT`, `$UsnJrnl` thường còn) | Giới hạn bởi TRIM | VSS Snapshot / Raw volume | **Trung bình – Thấp** (ưu tiên VSS) |
| **Android — Không Root (APK thường)** | Không (SELinux) | Không | Chỉ trên file rời | `MediaStore` (`IS_TRASHED`), `.trashed-*`, cache, `LOST.DIR` | **Giới hạn sandbox** |
| **Android — Có Root (`su`/Magisk)** | Có (`/dev/block/...`) | ext4 / FAT32 / exFAT | Đầy đủ qua `recover-jni` | `dd` read-only ra thẻ/USB ngoài rồi carve | **Cao** trên SD; **Thấp** trên `/userdata` FBE |
| **iOS — Không Jailbreak + USB Companion** | Không | SQLite B-Tree (`Manifest.db`, `Photos.sqlite`) | Carve `.ithmb` & cache | Finder/iTunes Backup (`idevicebackup2`) | **Khả thi nhất cho iPhone phổ thông** |
| **iOS — Sideload IPA độc lập** | Không | Không | Container cache cục bộ | PhotoKit (Recently Deleted), App Group, `URLCache` | **Hẹp** trong sandbox |
| **iOS — Jailbreak (`/dev/rdisk0s1s2`)** | Có (`O_RDONLY`) | APFS superblock | Có (nếu còn key) | Stream read-only ra USB-C ngoài | **Thấp** với file SEP đã hủy key |

---

## 3. Cấu trúc Repository & Ranh giới Module

- `signatures/signatures.v1.json`: Signature DB có version (JPEG, PNG, HEIC/HEIF, GIF, WebP, MP4/MOV, PDF, DOCX/XLSX/ZIP).
- `crates/recover-core`: Engine thuần Rust độc lập UI:
  - `core::io`: `BlockReader`, `AlignedBuffer` (4 KiB), Windows raw + VSS, Linux `O_DIRECT`, macOS `F_NOCACHE`, `SafeChunkReader` (bisect bad sector + zero-pad), `SameDiskGuard`.
  - `core::fs`: Read-only parsers cho NTFS (`$MFT`, USA fixup, Data Runs, `$Bitmap`, `$UsnJrnl`), FAT32, exFAT, ext4, APFS (`NXSB` + Fletcher-64), HFS+.
  - `core::carve`: Sliding-window carver, validator cấu trúc/decode thật (chống false-positive < 2%), Bifragment Gap Carving (2 mảnh), Confidence Scorer, SHA-256 dedupe.
  - `core::companion`: Pure-Rust read-only SQLite3 B-Tree reader cho iOS Backup (`Manifest.db`, `Photos.sqlite`) & ADB helper.
  - `core::scan` & `core::report`: Streaming orchestrator, WAL checkpoint/resume, tạo thumbnail & báo cáo HTML/JSON, xuất file không bao giờ ghi đè.
- `crates/recover-cli`: Binary `recover` (`scan`, `resume`, `inspect`, `ios-backup`, `export`, `ui`).
- `crates/recover-jni`: Thư viện `cdylib` (`librecover_jni.so`) cho Android Root.
- `apps/desktop`: Giao diện 3 bước (Vite + TypeScript + Tauri v2 `src-tauri`).
- `apps/android`: Ứng dụng Kotlin (`minSdk 26`, ForegroundService chịu Doze, MediaStore + Root JNI).
- `apps/ios`: Ứng dụng Swift (`iOS 15+`, PhotoKit/cache, Companion, Jailbreak raw mode).

---

## 4. Hướng dẫn Build & Chạy trên 3 Nền tảng

### A. Core & CLI (Windows / macOS / Linux)
```bash
# Chạy toàn bộ unit test & forensic corpus tests
cargo test --workspace

# Build CLI bản release
cargo build --release -p recover-cli

# Quét ổ / disk image read-only end-to-end
./target/release/recover scan --source /dev/sdb --out D:\out --types jpg,png

# Kiểm tra thiết bị / phân vùng trước khi quét
./target/release/recover inspect --source \\.\PhysicalDrive1

# Quét bản sao lưu iOS không mã hóa (từ idevicebackup2 / Finder)
./target/release/recover ios-backup --backup-dir ./ios_backup --out ./out_ios
```

### B. Desktop UI (3 bước)
```bash
# 1. Build frontend offline
cd apps/desktop
npm install
npm run build

# 2A. Chạy ngay qua local IPC server tích hợp (Windows/macOS/Linux)
cd ../..
./target/release/recover ui --port 1420 --dist apps/desktop/dist

# 2B. Hoặc chạy gói Tauri v2 native window (yêu cầu MSVC/WebView2 trên Windows hoặc WebKitGTK trên Linux)
cd apps/desktop/src-tauri
cargo tauri build
```

### C. Android APK (Kotlin + JNI)
```bash
# Biên dịch Rust core sang librecover_jni.so
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t x86_64 -o apps/android/app/src/main/jniLibs build --release -p recover-jni

# Build APK Debug
cd apps/android
./gradlew assembleDebug
# Cài qua ADB: adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### D. iOS IPA (Swift + XcodeGen + Sideload)
```bash
# Trên macOS (đã cài Xcode & xcodegen)
cd apps/ios
swift build
xcodegen generate
xcodebuild -project ForensicRecoverIOS.xcodeproj \
  -scheme ForensicRecoverIOS \
  -sdk iphoneos \
  -configuration Release \
  CODE_SIGNING_ALLOWED=NO \
  archive -archivePath build/ForensicRecover.xcarchive

# Đóng gói Payload/ForensicRecoverIOS.app -> ForensicRecoverIOS-unsigned.ipa
# Sideload bằng AltStore, SideStore, Sideloadly (Non-Jailbreak) hoặc TrollStore (Jailbreak/CoreTrust).
```

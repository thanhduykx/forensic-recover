package com.forensic.recover.root

import com.forensic.recover.bridge.NativeRecoveryBridge
import com.forensic.recover.scanner.AndroidCandidate
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicReference

data class RootCapabilities(
    val hasRoot: Boolean,
    val magiskDetected: Boolean,
    val cryptoType: String,
    val userdataBlockPath: String?,
    val externalSdBlocks: List<String>
)

data class RootScanResult(
    val ok: Boolean,
    val items: List<AndroidCandidate> = emptyList(),
    val error: String? = null
)

/**
 * Detects root/Magisk safely, inspects Android FBE status (`ro.crypto.type`),
 * and streams block devices strictly READ-ONLY to a separate external destination image
 * before invoking the shared Rust `recover-core` carver via JNI.
 */
object RootBlockScanner {
    const val ROOT_SESSION_KEY = "android-root"
    private val activeDdProcess = AtomicReference<Process?>(null)

    fun probe(): RootCapabilities {
        val suResult = runSu("id")
        val hasRoot = suResult?.contains("uid=0") == true
        val magisk = File("/sbin/.magisk").exists() ||
            File("/data/adb/magisk").exists() ||
            (runShell("which magisk")?.isNotBlank() == true)
        val crypto = runShell("getprop ro.crypto.type")?.trim().orEmpty().ifEmpty { "unknown" }

        val userdata = if (hasRoot) {
            runSu("readlink -f /dev/block/by-name/userdata")?.trim()?.takeIf { it.startsWith("/dev/") }
                ?: "/dev/block/by-name/userdata"
        } else {
            null
        }

        val sdBlocks = if (hasRoot) {
            runSu("ls /dev/block/mmcblk1* 2>/dev/null")
                ?.lines()
                ?.map { it.trim() }
                ?.filter { it.startsWith("/dev/block/") }
                .orEmpty()
        } else {
            emptyList()
        }

        return RootCapabilities(
            hasRoot = hasRoot,
            magiskDetected = magisk,
            cryptoType = crypto,
            userdataBlockPath = userdata,
            externalSdBlocks = sdBlocks
        )
    }

    fun cancelActive() {
        activeDdProcess.getAndSet(null)?.let { proc ->
            try {
                proc.destroyForcibly()
            } catch (_: Exception) {
            }
        }
        if (NativeRecoveryBridge.isNativeLoaded) {
            try {
                NativeRecoveryBridge.nativeCancelScan(ROOT_SESSION_KEY)
            } catch (_: Exception) {
            }
        }
    }

    internal fun isUnsafeSameVolumeDest(blockDevice: String, destPath: String): Boolean {
        if (!blockDevice.contains("userdata", ignoreCase = true)) return false
        val norm = destPath.replace('\\', '/')
        return norm.startsWith("/data/") ||
            norm == "/data" ||
            norm.startsWith("/storage/emulated/") ||
            norm.startsWith("/sdcard/")
    }

    /**
     * Dumps unallocated/block device strictly read-only into `destImageFile` on external storage
     * (never `/data/...` or `/storage/emulated/...` when scanning `userdata`!),
     * then runs Rust JNI carving.
     */
    fun dumpReadOnlyAndCarve(
        blockDevice: String,
        destImageFile: File,
        outDir: File,
        types: List<String> = emptyList(),
        isCancelled: () -> Boolean = { false },
        onProgressText: (Int, String) -> Unit
    ): RootScanResult {
        if (isUnsafeSameVolumeDest(blockDevice, destImageFile.absolutePath)) {
            return RootScanResult(
                ok = false,
                error = "Từ chối ghi ảnh phân vùng /userdata vào bộ nhớ trong (/data hoặc /storage/emulated). Hãy chọn thẻ nhớ ngoài SD hoặc USB-OTG."
            )
        }
        if (blockDevice.contains('\'') || blockDevice.contains('\n') ||
            destImageFile.absolutePath.contains('\'') || destImageFile.absolutePath.contains('\n')
        ) {
            return RootScanResult(ok = false, error = "Đường dẫn thiết bị hoặc thư mục đích không hợp lệ.")
        }
        if (!NativeRecoveryBridge.isNativeLoaded) {
            return RootScanResult(ok = false, error = "Thư viện librecover_jni.so chưa được nạp trong bản APK này.")
        }

        outDir.mkdirs()
        destImageFile.parentFile?.mkdirs()

        if (isCancelled()) return RootScanResult(ok = false, error = "Đã hủy quét.")

        onProgressText(15, "Đang sao lưu chỉ-đọc $blockDevice sang ${destImageFile.name}...")
        // `dd` opens `if=` O_RDONLY; `conv=noerror,sync` preserves offsets across bad blocks.
        val cmd = "dd if='$blockDevice' of='${destImageFile.absolutePath}' bs=1048576 conv=noerror,sync"
        val proc = try {
            ProcessBuilder("su", "-c", cmd)
                .redirectErrorStream(true)
                .start()
        } catch (e: Exception) {
            return RootScanResult(ok = false, error = "Không thể chạy lệnh su/dd: ${e.message}")
        }
        activeDdProcess.set(proc)
        val ddOutput = StringBuilder()
        try {
            proc.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    if (ddOutput.length < 2048) ddOutput.appendLine(line)
                }
            }
            val exit = proc.waitFor()
            if (isCancelled()) {
                return RootScanResult(ok = false, error = "Đã hủy trong quá trình sao lưu phân vùng.")
            }
            if (exit != 0 || !destImageFile.exists() || destImageFile.length() == 0L) {
                return RootScanResult(
                    ok = false,
                    error = "Sao lưu dd thất bại (exit=$exit): ${ddOutput.toString().trim().take(240)}"
                )
            }
        } finally {
            activeDdProcess.compareAndSet(proc, null)
        }

        if (isCancelled()) return RootScanResult(ok = false, error = "Đã hủy quét.")

        onProgressText(65, "Đang chạy bộ giải mã Rust forensic carver (JNI)...")
        val cfg = JSONObject().apply {
            put("session_key", ROOT_SESSION_KEY)
            put("source", destImageFile.absolutePath)
            put("out_dir", outDir.absolutePath)
            put("types", JSONArray(types))
            put("include_allocated", false)
            put("bifragment_gap_mb", 16)
            put("export_all", false)
        }
        val rawJson = NativeRecoveryBridge.nativeRunScan(cfg.toString())
        val parsed = parseJniScanResponse(rawJson, destImageFile.absolutePath, outDir.absolutePath)
        if (parsed.ok) {
            onProgressText(100, "Hoàn tất quét sâu Root/JNI (${parsed.items.size} tệp đã xác thực)")
        }
        return parsed
    }

    internal fun parseJniScanResponse(
        rawJson: String,
        sourceImagePath: String,
        outDirPath: String
    ): RootScanResult {
        return try {
            val root = JSONObject(rawJson)
            if (!root.optBoolean("ok", false)) {
                return RootScanResult(
                    ok = false,
                    error = root.optString("error").ifBlank { "Lỗi không xác định từ Rust JNI." }
                )
            }
            val data = root.optJSONObject("data")
                ?: return RootScanResult(ok = true, items = emptyList())
            val itemsArr = data.optJSONArray("items") ?: JSONArray()
            val out = mutableListOf<AndroidCandidate>()
            for (i in 0 until itemsArr.length()) {
                val obj = itemsArr.optJSONObject(i) ?: continue
                val id = obj.optString("id").ifBlank { "jni_$i" }
                val ext = obj.optString("ext").ifBlank { "bin" }
                val origName = obj.optString("original_name").takeIf { it.isNotBlank() && it != "null" }
                    ?: "carved_${id.take(8)}.$ext"
                val length = obj.optLong("length", 0L)
                val confidence = obj.optString("confidence", "medium").lowercase()
                val sha = obj.optString("sha256", "").take(12).ifBlank { "jni" }
                val source = obj.optString("recovery_source", "signature_carved")
                out += AndroidCandidate(
                    id = "jni_$id",
                    title = origName,
                    origin = "Root/JNI ($source)",
                    detectedExt = ext,
                    sizeBytes = length,
                    confidence = confidence,
                    sha256Prefix = sha,
                    jniItemId = id,
                    jniSourcePath = sourceImagePath,
                    jniOutDir = outDirPath
                )
            }
            RootScanResult(ok = true, items = out)
        } catch (e: Exception) {
            RootScanResult(ok = false, error = "Không thể đọc kết quả JSON từ Rust JNI: ${e.message}")
        }
    }

    private fun runSu(cmd: String): String? = try {
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
        p.inputStream.bufferedReader().readText().also { p.waitFor() }
    } catch (_: Exception) {
        null
    }

    private fun runShell(cmd: String): String? = try {
        val p = ProcessBuilder("sh", "-c", cmd).redirectErrorStream(true).start()
        p.inputStream.bufferedReader().readText().also { p.waitFor() }
    } catch (_: Exception) {
        null
    }
}

package com.forensic.recover.root

import com.forensic.recover.bridge.NativeRecoveryBridge
import java.io.File

data class RootCapabilities(
    val hasRoot: Boolean,
    val magiskDetected: Boolean,
    val cryptoType: String,
    val userdataBlockPath: String?,
    val externalSdBlocks: List<String>
)

/**
 * Detects root/Magisk safely, inspects Android FBE status (`ro.crypto.type`),
 * and streams block devices strictly READ-ONLY to a separate external destination image
 * before invoking the shared Rust `recover-core` carver via JNI.
 */
object RootBlockScanner {
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

    /**
     * Dumps unallocated/block device strictly read-only into `destImageFile` on external storage
     * (never `/data/...` when scanning `userdata`!), then runs Rust JNI carving.
     */
    fun dumpReadOnlyAndCarve(
        blockDevice: String,
        destImageFile: File,
        outDir: File,
        types: List<String>,
        onProgressText: (String) -> Unit
    ): String {
        require(!destImageFile.absolutePath.startsWith("/data/") || !blockDevice.contains("userdata")) {
            "Refusing to write image onto /data while imaging userdata! Use external SD or USB-OTG."
        }
        outDir.mkdirs()
        destImageFile.parentFile?.mkdirs()

        onProgressText("Imaging $blockDevice read-only to ${destImageFile.absolutePath}...")
        // Note: `dd` opens `if=` O_RDONLY; `conv=noerror,sync` preserves offsets across bad blocks.
        val cmd = "dd if='$blockDevice' of='${destImageFile.absolutePath}' bs=1048576 conv=noerror,sync"
        val proc = ProcessBuilder("su", "-c", cmd)
            .redirectErrorStream(true)
            .start()
        val exit = proc.waitFor()
        if (exit != 0 || !destImageFile.exists()) {
            return """{"ok":false,"error":"Root dd imaging failed with exit=$exit"}"""
        }

        if (!NativeRecoveryBridge.isNativeLoaded) {
            return """{"ok":false,"error":"librecover_jni.so not bundled in this APK build"}"""
        }

        onProgressText("Running Rust forensic carver on offline image...")
        val escapedTypes = types.joinToString(",") { "\"$it\"" }
        val cfgJson = """
            {
              "session_key": "android-root",
              "source": "${destImageFile.absolutePath}",
              "out_dir": "${outDir.absolutePath}",
              "types": [$escapedTypes],
              "include_allocated": false,
              "bifragment_gap_mb": 16,
              "export_all": false
            }
        """.trimIndent()
        return NativeRecoveryBridge.nativeRunScan(cfgJson)
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

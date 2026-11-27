package com.forensic.recover.export

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import androidx.documentfile.provider.DocumentFile
import com.forensic.recover.bridge.NativeRecoveryBridge
import com.forensic.recover.scanner.AndroidCandidate
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.util.Locale

data class ExportSummary(
    val totalRequested: Int,
    val savedCount: Int,
    val failedCount: Int,
    val destinationLabel: String,
    val savedIds: Set<String> = emptySet(),
    val savedNames: List<String> = emptyList(),
    val errors: List<String> = emptyList()
)

/**
 * Collision-safe exporter for recovered Android candidates.
 * Default target: `Downloads/ForensicRecover/` (MediaStore.Downloads on API 29+,
 * direct public Downloads directory on API 26-28), or a user-selected SAF directory tree.
 * Existing files are NEVER overwritten — numeric suffixes `_1`, `_2`, ... are appended.
 */
object RecoveryExporter {
    const val SUBFOLDER_NAME = "ForensicRecover"
    private val TRASHED_PREFIX_REGEX = Regex("^\\.trashed-\\d+-", RegexOption.IGNORE_CASE)
    private val UNSAFE_CHARS_REGEX = Regex("[\\\\/:*?\"<>|\\p{Cntrl}]+")

    internal fun sanitizeExportName(rawTitle: String, detectedExt: String): String {
        var name = rawTitle.trim()
        name = TRASHED_PREFIX_REGEX.replace(name, "")
        name = name.trimStart('.')
        name = UNSAFE_CHARS_REGEX.replace(name, "_").trim()
        if (name.isEmpty()) {
            name = "recovered_file"
        }
        val cleanExt = detectedExt.trim().trimStart('.').lowercase(Locale.ROOT)
        if (cleanExt.isNotEmpty() && !name.lowercase(Locale.ROOT).endsWith(".$cleanExt")) {
            name = "$name.$cleanExt"
        }
        return name
    }

    internal fun buildUniqueFileName(desiredName: String, existingNames: Set<String>): String {
        val lowerExisting = existingNames.map { it.lowercase(Locale.ROOT) }.toHashSet()
        if (desiredName.lowercase(Locale.ROOT) !in lowerExisting) {
            return desiredName
        }
        val dotIdx = desiredName.lastIndexOf('.')
        val stem = if (dotIdx > 0) desiredName.substring(0, dotIdx) else desiredName
        val ext = if (dotIdx > 0) desiredName.substring(dotIdx) else ""
        var counter = 1
        while (true) {
            val candidate = "${stem}_${counter}${ext}"
            if (candidate.lowercase(Locale.ROOT) !in lowerExisting) {
                return candidate
            }
            counter++
        }
    }

    internal fun resolveUniqueFile(dir: File, desiredName: String): File {
        val existing = dir.list()?.toSet().orEmpty()
        val unique = buildUniqueFileName(desiredName, existing)
        return File(dir, unique)
    }

    internal fun mimeForExt(ext: String): String = when (ext.trim().trimStart('.').lowercase(Locale.ROOT)) {
        "jpg", "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "gif" -> "image/gif"
        "webp" -> "image/webp"
        "mp4", "m4v" -> "video/mp4"
        "mov" -> "video/quicktime"
        "pdf" -> "application/pdf"
        "zip" -> "application/zip"
        else -> "application/octet-stream"
    }

    fun exportCandidates(
        context: Context,
        items: List<AndroidCandidate>,
        targetTreeUri: Uri? = null,
        onProgress: (Int, Int, String) -> Unit = { _, _, _ -> }
    ): ExportSummary {
        if (items.isEmpty()) {
            return ExportSummary(
                totalRequested = 0,
                savedCount = 0,
                failedCount = 0,
                destinationLabel = targetDestinationLabel(context, targetTreeUri)
            )
        }

        val destLabel = targetDestinationLabel(context, targetTreeUri)
        val savedIds = LinkedHashSet<String>()
        val savedNames = mutableListOf<String>()
        val errors = mutableListOf<String>()

        val safTree: DocumentFile? = targetTreeUri?.let { DocumentFile.fromTreeUri(context, it) }
        if (targetTreeUri != null && (safTree == null || !safTree.canWrite())) {
            return ExportSummary(
                totalRequested = items.size,
                savedCount = 0,
                failedCount = items.size,
                destinationLabel = destLabel,
                errors = listOf("Không có quyền ghi vào thư mục đã chọn. Hãy chọn lại thư mục khác.")
            )
        }

        val knownNames = HashSet<String>()
        if (safTree != null) {
            safTree.listFiles().mapNotNull { it.name }.forEach { knownNames.add(it) }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            knownNames.addAll(queryExistingDownloadNames(context))
        } else {
            val legacyDir = legacyDownloadDir()
            legacyDir.mkdirs()
            legacyDir.list()?.forEach { knownNames.add(it) }
        }

        items.forEachIndexed { idx, item ->
            val desiredName = sanitizeExportName(item.title, item.detectedExt)
            val uniqueName = buildUniqueFileName(desiredName, knownNames)
            onProgress(idx + 1, items.size, "Đang lưu $uniqueName (${idx + 1}/${items.size})...")

            try {
                val writtenName = openCandidateStreamAndWrite(
                    context = context,
                    item = item,
                    uniqueName = uniqueName,
                    safTree = safTree
                )
                knownNames.add(writtenName)
                savedIds.add(item.id)
                savedNames.add(writtenName)
            } catch (e: Exception) {
                errors.add("${item.title}: ${e.message ?: "Lỗi ghi tệp"}")
            }
        }

        return ExportSummary(
            totalRequested = items.size,
            savedCount = savedIds.size,
            failedCount = items.size - savedIds.size,
            destinationLabel = destLabel,
            savedIds = savedIds,
            savedNames = savedNames,
            errors = errors
        )
    }

    fun targetDestinationLabel(context: Context, targetTreeUri: Uri?): String {
        if (targetTreeUri == null) {
            return "Downloads/$SUBFOLDER_NAME/"
        }
        val doc = DocumentFile.fromTreeUri(context, targetTreeUri)
        val name = doc?.name
        return if (!name.isNullOrBlank()) "Thư mục đã chọn ($name)" else "Thư mục đã chọn"
    }

    internal fun resolveJniExportOutDir(item: AndroidCandidate): String {
        val outDir = item.jniOutDir?.trim()
        if (outDir.isNullOrEmpty()) {
            throw IllegalStateException("Thiếu thư mục phiên Rust JNI (jniOutDir) để nạp checkpoint.")
        }
        return outDir
    }

    internal fun parseJniExportedFilePath(rawResp: String): String {
        val parsed = JSONObject(rawResp)
        if (!parsed.optBoolean("ok", false)) {
            throw IllegalStateException(parsed.optString("error").ifBlank { "Rust JNI xuất tệp thất bại" })
        }
        val paths = parsed.optJSONArray("data")
        return paths?.optString(0)?.takeIf { it.isNotBlank() }
            ?: throw IllegalStateException("Rust JNI không trả về đường dẫn tệp xuất")
    }

    private fun openCandidateStreamAndWrite(
        context: Context,
        item: AndroidCandidate,
        uniqueName: String,
        safTree: DocumentFile?
    ): String {
        // Case 1: Root/JNI item — Rust `export_selected` loads checkpoint from `item.jniOutDir`,
        // carves into `<jniOutDir>/recovered/<family>/`, then we copy safely to Downloads/SAF.
        if (item.jniItemId != null && item.jniSourcePath != null) {
            if (!NativeRecoveryBridge.isNativeLoaded) {
                throw IllegalStateException("Thư viện librecover_jni.so chưa sẵn sàng")
            }
            val jniOutDir = resolveJniExportOutDir(item)
            val idsJson = JSONArray().put(item.jniItemId).toString()
            val rawResp = NativeRecoveryBridge.nativeExportItems(
                item.jniSourcePath,
                jniOutDir,
                idsJson
            )
            val exportedPath = parseJniExportedFilePath(rawResp)
            val exportedFile = File(exportedPath)
            if (!exportedFile.exists()) {
                throw IllegalStateException("Không tìm thấy tệp sau khi giải mã từ ảnh nguồn")
            }
            return try {
                exportedFile.inputStream().use { input ->
                    writeStreamToDestination(context, input, uniqueName, item.detectedExt, safTree)
                }
            } finally {
                // Remove intermediate carved copy to avoid doubling SD usage while preserving checkpoint files.
                try {
                    exportedFile.delete()
                } catch (_: Exception) {
                }
            }
        }

        // Case 2: MediaStore ContentUri
        if (item.contentUri != null) {
            val stream = context.contentResolver.openInputStream(item.contentUri)
                ?: throw IllegalStateException("Không thể đọc nội dung từ MediaStore URI")
            return stream.use { input ->
                writeStreamToDestination(context, input, uniqueName, item.detectedExt, safTree)
            }
        }

        // Case 3: Direct file path
        if (item.filePath != null) {
            val src = File(item.filePath)
            if (!src.exists() || !src.canRead()) {
                throw IllegalStateException("Không thể đọc tệp nguồn")
            }
            return src.inputStream().use { input ->
                writeStreamToDestination(context, input, uniqueName, item.detectedExt, safTree)
            }
        }

        throw IllegalStateException("Thiếu nguồn dữ liệu để lưu tệp")
    }

    private fun writeStreamToDestination(
        context: Context,
        input: InputStream,
        uniqueName: String,
        detectedExt: String,
        safTree: DocumentFile?
    ): String {
        val mime = mimeForExt(detectedExt)

        if (safTree != null) {
            val created = safTree.createFile(mime, uniqueName)
                ?: throw IllegalStateException("Không thể tạo tệp trong thư mục đã chọn")
            val out = context.contentResolver.openOutputStream(created.uri)
                ?: throw IllegalStateException("Không thể mở luồng ghi SAF")
            out.use { input.copyTo(it) }
            return created.name ?: uniqueName
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val resolver = context.contentResolver
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, uniqueName)
                put(MediaStore.Downloads.MIME_TYPE, mime)
                put(
                    MediaStore.Downloads.RELATIVE_PATH,
                    "${Environment.DIRECTORY_DOWNLOADS}/$SUBFOLDER_NAME"
                )
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("Không thể tạo tệp trong Downloads/$SUBFOLDER_NAME")
            try {
                val out = resolver.openOutputStream(uri)
                    ?: throw IllegalStateException("Không thể mở luồng ghi MediaStore.Downloads")
                out.use { input.copyTo(it) }
                val done = ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }
                resolver.update(uri, done, null, null)
                val actualName = try {
                    resolver.query(uri, arrayOf(MediaStore.Downloads.DISPLAY_NAME), null, null, null)?.use { c ->
                        if (c.moveToFirst()) c.getString(0) else null
                    }
                } catch (_: Exception) {
                    null
                }
                return actualName?.takeIf { it.isNotBlank() } ?: uniqueName
            } catch (e: Exception) {
                try {
                    resolver.delete(uri, null, null)
                } catch (_: Exception) {
                }
                throw e
            }
        } else {
            val dir = legacyDownloadDir().apply { mkdirs() }
            val dest = resolveUniqueFile(dir, uniqueName)
            dest.outputStream().use { input.copyTo(it) }
            return dest.name
        }
    }

    private fun legacyDownloadDir(): File {
        @Suppress("DEPRECATION")
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        return File(downloads, SUBFOLDER_NAME)
    }

    private fun queryExistingDownloadNames(context: Context): Set<String> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return emptySet()
        val names = HashSet<String>()
        val projection = arrayOf(MediaStore.Downloads.DISPLAY_NAME)
        val selection = "${MediaStore.Downloads.RELATIVE_PATH} LIKE ?"
        val args = arrayOf("%$SUBFOLDER_NAME%")
        try {
            context.contentResolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                projection,
                selection,
                args,
                null
            )?.use { c ->
                val idx = c.getColumnIndex(MediaStore.Downloads.DISPLAY_NAME)
                if (idx >= 0) {
                    while (c.moveToNext()) {
                        c.getString(idx)?.let { names.add(it) }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return names
    }
}

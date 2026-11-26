package com.forensic.recover.scanner

import android.content.ContentUris
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest

data class AndroidCandidate(
    val id: String,
    val title: String,
    val origin: String,
    val detectedExt: String,
    val sizeBytes: Long,
    val confidence: String,
    val sha256Prefix: String,
    val contentUri: Uri? = null,
    val filePath: String? = null
)

/**
 * Non-root forensic scanner for Android (minSdk 26+):
 * - Queries MediaStore including IS_TRASHED / IS_PENDING (API 29+)
 * - Scans `.trashed-*` files, accessible `Android/data/<pkg>/cache`, and `LOST.DIR`
 * - Validates actual magic headers rather than trusting missing/renamed file extensions.
 */
object NonRootScanner {
    fun scanAll(context: Context, onProgress: (Int, String) -> Unit): List<AndroidCandidate> {
        val out = mutableListOf<AndroidCandidate>()
        onProgress(15, "Querying MediaStore (incl. trashed & pending)...")
        out += scanMediaStore(context)

        onProgress(45, "Scanning .trashed & LOST.DIR directories...")
        val extRoot = Environment.getExternalStorageDirectory()
        out += scanDirectoryMagic(File(extRoot, "LOST.DIR"), "LOST.DIR", "medium")
        out += scanTrashedFolders(extRoot)

        onProgress(80, "Scanning accessible app caches...")
        val androidData = File(extRoot, "Android/data")
        if (androidData.exists() && androidData.canRead()) {
            androidData.listFiles()?.forEach { pkgDir ->
                val cache = File(pkgDir, "cache")
                if (cache.exists() && cache.canRead()) {
                    out += scanDirectoryMagic(cache, "AppCache:${pkgDir.name}", "low")
                }
            }
        }
        onProgress(100, "Completed non-root scan (${out.size} validated items)")
        return out
    }

    private fun scanMediaStore(context: Context): List<AndroidCandidate> {
        val list = mutableListOf<AndroidCandidate>()
        val uri = MediaStore.Files.getContentUri("external")
        val projection = mutableListOf(
            MediaStore.Files.FileColumns._ID,
            MediaStore.Files.FileColumns.DISPLAY_NAME,
            MediaStore.Files.FileColumns.SIZE,
            MediaStore.Files.FileColumns.MIME_TYPE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            projection += MediaStore.MediaColumns.IS_PENDING
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            projection += MediaStore.MediaColumns.IS_TRASHED
        }

        val cursor = context.contentResolver.query(uri, projection.toTypedArray(), null, null, null)
            ?: return list

        cursor.use { c ->
            val idIdx = c.getColumnIndexOrThrow(MediaStore.Files.FileColumns._ID)
            val nameIdx = c.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DISPLAY_NAME)
            val sizeIdx = c.getColumnIndexOrThrow(MediaStore.Files.FileColumns.SIZE)
            val trashedIdx = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                c.getColumnIndex(MediaStore.MediaColumns.IS_TRASHED)
            } else -1

            while (c.moveToNext()) {
                val id = c.getLong(idIdx)
                val name = c.getString(nameIdx) ?: "media_$id"
                val size = c.getLong(sizeIdx)
                val isTrashed = trashedIdx >= 0 && c.getInt(trashedIdx) == 1
                if (!isTrashed && !name.startsWith(".trashed")) continue

                val itemUri = ContentUris.withAppendedId(uri, id)
                val ext = sniffUriMagic(context, itemUri) ?: continue
                list += AndroidCandidate(
                    id = "ms_$id",
                    title = name,
                    origin = if (isTrashed) "MediaStore.IS_TRASHED" else ".trashed",
                    detectedExt = ext,
                    sizeBytes = size,
                    confidence = "high",
                    sha256Prefix = "uri:$id",
                    contentUri = itemUri
                )
            }
        }
        return list
    }

    private fun scanTrashedFolders(root: File): List<AndroidCandidate> {
        val out = mutableListOf<AndroidCandidate>()
        val dirs = listOf(File(root, "DCIM"), File(root, "Pictures"), File(root, "Download"))
        for (dir in dirs) {
            if (!dir.exists() || !dir.canRead()) continue
            dir.walkTopDown().maxDepth(3).forEach { f ->
                if (f.isFile && f.name.startsWith(".trashed")) {
                    val ext = sniffFileMagic(f) ?: return@forEach
                    out += AndroidCandidate(
                        id = "file_${f.absolutePath.hashCode()}",
                        title = f.name,
                        origin = ".trashed",
                        detectedExt = ext,
                        sizeBytes = f.length(),
                        confidence = "high",
                        sha256Prefix = quickSha256Prefix(f),
                        filePath = f.absolutePath
                    )
                }
            }
        }
        return out
    }

    private fun scanDirectoryMagic(dir: File, origin: String, conf: String): List<AndroidCandidate> {
        if (!dir.exists() || !dir.canRead()) return emptyList()
        val out = mutableListOf<AndroidCandidate>()
        dir.walkTopDown().maxDepth(3).forEach { f ->
            if (f.isFile && f.length() >= 64) {
                val ext = sniffFileMagic(f) ?: return@forEach
                out += AndroidCandidate(
                    id = "f_${f.absolutePath.hashCode()}",
                    title = f.name,
                    origin = origin,
                    detectedExt = ext,
                    sizeBytes = f.length(),
                    confidence = conf,
                    sha256Prefix = quickSha256Prefix(f),
                    filePath = f.absolutePath
                )
            }
        }
        return out
    }

    private fun sniffUriMagic(context: Context, uri: Uri): String? = try {
        context.contentResolver.openInputStream(uri)?.use { ins ->
            val buf = ByteArray(16)
            val n = ins.read(buf)
            if (n >= 8) classifyMagic(buf.copyOf(n)) else null
        }
    } catch (_: Exception) {
        null
    }

    private fun sniffFileMagic(file: File): String? = try {
        RandomAccessFile(file, "r").use { raf ->
            val buf = ByteArray(16)
            val n = raf.read(buf)
            if (n >= 8) classifyMagic(buf.copyOf(n)) else null
        }
    } catch (_: Exception) {
        null
    }

    private fun classifyMagic(h: ByteArray): String? {
        if (h.size >= 3 && h[0] == 0xFF.toByte() && h[1] == 0xD8.toByte() && h[2] == 0xFF.toByte()) return "jpg"
        if (h.size >= 8 && h[0] == 0x89.toByte() && h[1] == 0x50.toByte() && h[2] == 0x4E.toByte() && h[3] == 0x47.toByte()) return "png"
        if (h.size >= 6 && String(h, 0, 6) in listOf("GIF87a", "GIF89a")) return "gif"
        if (h.size >= 12 && String(h, 4, 4) == "ftyp") return "mp4"
        if (h.size >= 5 && String(h, 0, 5) == "%PDF-") return "pdf"
        if (h.size >= 4 && h[0] == 0x50.toByte() && h[1] == 0x4B.toByte() && h[2] == 0x03.toByte() && h[3] == 0x04.toByte()) return "zip"
        return null
    }

    private fun quickSha256Prefix(file: File): String = try {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { ins ->
            val buf = ByteArray(8192)
            val n = ins.read(buf)
            if (n > 0) md.update(buf, 0, n)
        }
        md.digest().take(6).joinToString("") { "%02x".format(it) }
    } catch (_: Exception) {
        "000000"
    }
}

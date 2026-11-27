package com.forensic.recover

import com.forensic.recover.export.RecoveryExporter
import com.forensic.recover.root.RootBlockScanner
import com.forensic.recover.scanner.AndroidCandidate
import com.forensic.recover.scanner.NonRootScanner
import com.forensic.recover.service.RecoveryForegroundService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RecoveryLogicTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun sanitizeExportName_stripsTrashedPrefixAndUnsafeChars() {
        assertEquals(
            "IMG_20260101.jpg",
            RecoveryExporter.sanitizeExportName(".trashed-1710000000-IMG_20260101.jpg", "jpg")
        )
        assertEquals(
            "hidden_photo.png",
            RecoveryExporter.sanitizeExportName("...hidden:photo", "png")
        )
        assertEquals(
            "recovered_file.mp4",
            RecoveryExporter.sanitizeExportName("   ...  ", "mp4")
        )
        assertEquals(
            "doc_1.pdf",
            RecoveryExporter.sanitizeExportName("doc/1.pdf", "pdf")
        )
    }

    @Test
    fun buildUniqueFileName_neverOverwritesExistingCaseInsensitive() {
        val existing = setOf("photo.jpg", "PHOTO_1.JPG", "photo_2.jpg")
        assertEquals("photo_3.jpg", RecoveryExporter.buildUniqueFileName("photo.jpg", existing))
        assertEquals("fresh.jpg", RecoveryExporter.buildUniqueFileName("fresh.jpg", existing))
        assertEquals("readme_1", RecoveryExporter.buildUniqueFileName("readme", setOf("README")))
    }

    @Test
    fun resolveUniqueFile_onDiskPreservesExistingFile() {
        val dir = tempFolder.newFolder("downloads")
        val existing = dir.resolve("vacation.jpg")
        existing.writeText("original")

        val next = RecoveryExporter.resolveUniqueFile(dir, "vacation.jpg")
        assertEquals("vacation_1.jpg", next.name)
        assertFalse(next.exists())
        assertEquals("original", existing.readText())
    }

    @Test
    fun parseJniScanResponse_handlesValidAndErrorPayloads() {
        val validJson = """
            {
              "ok": true,
              "data": {
                "items": [
                  {
                    "id": "item-001",
                    "ext": "jpg",
                    "original_name": null,
                    "length": 4096,
                    "confidence": "high",
                    "sha256": "abcdef1234567890",
                    "recovery_source": "signature_carved"
                  }
                ]
              },
              "error": null
            }
        """.trimIndent()
        val parsed = RootBlockScanner.parseJniScanResponse(validJson, "/mnt/sd/img.raw", "/mnt/sd/out")
        assertTrue(parsed.ok)
        assertEquals(1, parsed.items.size)
        val item = parsed.items.first()
        assertEquals("jni_item-001", item.id)
        assertEquals("item-001", item.jniItemId)
        assertEquals("jpg", item.detectedExt)
        assertEquals(4096L, item.sizeBytes)
        assertEquals("high", item.confidence)
        assertEquals("abcdef123456", item.sha256Prefix)

        val errJson = """{"ok":false,"data":null,"error":"Permission denied"}"""
        val parsedErr = RootBlockScanner.parseJniScanResponse(errJson, "/mnt/sd/img.raw", "/mnt/sd/out")
        assertFalse(parsedErr.ok)
        assertEquals("Permission denied", parsedErr.error)

        val malformed = RootBlockScanner.parseJniScanResponse("{not-json", "/mnt/sd/img.raw", "/mnt/sd/out")
        assertFalse(malformed.ok)
        assertTrue(malformed.error!!.isNotBlank())
    }

    @Test
    fun isUnsafeSameVolumeDest_blocksInternalStorageForUserdataAndResolvedSymlink() {
        assertTrue(RootBlockScanner.isUnsafeSameVolumeDest("/dev/block/by-name/userdata", "/data/local/tmp/a.img"))
        assertTrue(RootBlockScanner.isUnsafeSameVolumeDest("/dev/block/by-name/userdata", "/storage/emulated/0/a.img"))
        assertTrue(RootBlockScanner.isUnsafeSameVolumeDest("/dev/block/by-name/userdata", "/sdcard/a.img"))
        assertTrue(RootBlockScanner.isUnsafeSameVolumeDest("/dev/block/by-name/userdata", "/sdcard"))
        assertFalse(RootBlockScanner.isUnsafeSameVolumeDest("/dev/block/by-name/userdata", "/storage/1234-ABCD/a.img"))
        assertFalse(RootBlockScanner.isUnsafeSameVolumeDest("/dev/block/mmcblk1p1", "/storage/emulated/0/a.img"))

        // Resolved symlink from `readlink -f /dev/block/by-name/userdata` (e.g. /dev/block/sda42)
        // must STILL be blocked from writing to internal storage!
        assertTrue(
            RootBlockScanner.isUnsafeSameVolumeDest(
                blockDevice = "/dev/block/sda42",
                destPath = "/storage/emulated/0/Android/data/com.forensic.recover/files/forensic_ro_1.img",
                knownUserdataPath = "/dev/block/sda42"
            )
        )
        assertFalse(
            RootBlockScanner.isUnsafeSameVolumeDest(
                blockDevice = "/dev/block/sda42",
                destPath = "/storage/1234-ABCD/forensic_ro_1.img",
                knownUserdataPath = "/dev/block/sda42"
            )
        )
    }

    @Test
    fun jniExportContract_requiresSessionOutDirAndParsesExportedPath() {
        val goodCandidate = AndroidCandidate(
            id = "jni_item-1",
            title = "photo.jpg",
            origin = "Root/JNI",
            detectedExt = "jpg",
            sizeBytes = 1024L,
            confidence = "high",
            sha256Prefix = "abcdef",
            jniItemId = "item-1",
            jniSourcePath = "/storage/1234-ABCD/forensic_ro_1.img",
            jniOutDir = "/storage/1234-ABCD/forensic_out_1"
        )
        assertEquals("/storage/1234-ABCD/forensic_out_1", RecoveryExporter.resolveJniExportOutDir(goodCandidate))

        val missingOutDir = goodCandidate.copy(jniOutDir = null)
        try {
            RecoveryExporter.resolveJniExportOutDir(missingOutDir)
            fail("Expected IllegalStateException when jniOutDir is missing")
        } catch (_: IllegalStateException) {
            // expected
        }

        assertEquals(
            "/storage/1234-ABCD/forensic_out_1/recovered/images/photo.jpg",
            RecoveryExporter.parseJniExportedFilePath(
                """{"ok":true,"data":["/storage/1234-ABCD/forensic_out_1/recovered/images/photo.jpg"],"error":null}"""
            )
        )
        try {
            RecoveryExporter.parseJniExportedFilePath("""{"ok":false,"data":null,"error":"Checkpoint missing"}""")
            fail("Expected IllegalStateException on ok=false")
        } catch (e: IllegalStateException) {
            assertEquals("Checkpoint missing", e.message)
        }
    }

    @Test
    fun foregroundServiceCancelAndScanId_monotonicAndResettable() {
        val id1 = RecoveryForegroundService.nextScanId()
        val id2 = RecoveryForegroundService.nextScanId()
        assertTrue(id2 > id1)

        RecoveryForegroundService.requestCancelFlag()
        assertTrue(RecoveryForegroundService.isCancelRequested())

        RecoveryForegroundService.clearCancelFlag()
        assertFalse(RecoveryForegroundService.isCancelRequested())
    }

    @Test
    fun classifyMagic_detectsKnownSignaturesAndRejectsUnknown() {
        assertEquals("jpg", NonRootScanner.classifyMagic(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte())))
        assertEquals("png", NonRootScanner.classifyMagic(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)))
        assertEquals("pdf", NonRootScanner.classifyMagic("%PDF-1.7".toByteArray()))
        assertEquals("zip", NonRootScanner.classifyMagic(byteArrayOf(0x50, 0x4B, 0x03, 0x04, 0x14, 0x00)))
        assertNull(NonRootScanner.classifyMagic(byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)))
    }
}

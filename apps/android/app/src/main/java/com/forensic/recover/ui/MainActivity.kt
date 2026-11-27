package com.forensic.recover.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.forensic.recover.bridge.NativeRecoveryBridge
import com.forensic.recover.export.ExportSummary
import com.forensic.recover.export.RecoveryExporter
import com.forensic.recover.root.RootBlockScanner
import com.forensic.recover.root.RootCapabilities
import com.forensic.recover.scanner.AndroidCandidate
import com.forensic.recover.scanner.NonRootScanner
import com.forensic.recover.service.RecoveryForegroundService
import com.forensic.recover.service.ScanPhase
import com.forensic.recover.service.ScanServiceState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    RecoveryThreeStepScreen()
                }
            }
        }
    }
}

private fun requiredRuntimePermissions(): List<String> = when {
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> listOf(
        Manifest.permission.READ_MEDIA_IMAGES,
        Manifest.permission.READ_MEDIA_VIDEO,
        Manifest.permission.POST_NOTIFICATIONS
    )
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> listOf(
        Manifest.permission.READ_EXTERNAL_STORAGE
    )
    else -> listOf(
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.WRITE_EXTERNAL_STORAGE
    )
}

private fun missingPermissions(context: Context): List<String> =
    requiredRuntimePermissions().filter { perm ->
        ContextCompat.checkSelfPermission(context, perm) != PackageManager.PERMISSION_GRANTED
    }

private fun permissionDisplayName(permission: String): String = when (permission) {
    Manifest.permission.READ_MEDIA_IMAGES -> "Ảnh (READ_MEDIA_IMAGES)"
    Manifest.permission.READ_MEDIA_VIDEO -> "Video (READ_MEDIA_VIDEO)"
    Manifest.permission.READ_EXTERNAL_STORAGE -> "Bộ nhớ ngoài (READ_EXTERNAL_STORAGE)"
    Manifest.permission.WRITE_EXTERNAL_STORAGE -> "Lưu tệp vào Downloads (WRITE_EXTERNAL_STORAGE)"
    Manifest.permission.POST_NOTIFICATIONS -> "Thông báo tiến độ quét nền (POST_NOTIFICATIONS)"
    else -> permission.substringAfterLast('.')
}

private fun formatFileSize(bytes: Long): String {
    if (bytes < 1024L) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024.0) return String.format(Locale.US, "%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024.0) return String.format(Locale.US, "%.2f MB", mb)
    val gb = mb / 1024.0
    return String.format(Locale.US, "%.2f GB", gb)
}

private fun defaultRootWorkDir(context: Context): String {
    val extDirs = context.getExternalFilesDirs(null).filterNotNull()
    // Prefer removable external SD/USB-OTG storage (index >= 1) if mounted.
    val removable = extDirs.drop(1).firstOrNull()
    return (removable ?: extDirs.firstOrNull() ?: context.filesDir).absolutePath
}

@Composable
fun RecoveryThreeStepScreen() {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()

    val serviceState by RecoveryForegroundService.state.collectAsState()
    var step by remember { mutableIntStateOf(1) }
    var rootCaps by remember { mutableStateOf<RootCapabilities?>(null) }
    var probingRoot by remember { mutableStateOf(true) }
    var filterConf by remember { mutableStateOf("all") }

    // Permissions state
    var missingPerms by remember { mutableStateOf(missingPermissions(context)) }
    var requestedPermsOnce by remember { mutableStateOf(false) }

    // Root scan UI state
    var selectedBlockDevice by remember { mutableStateOf("") }
    var rootDestDirPath by remember { mutableStateOf(defaultRootWorkDir(context)) }
    var bannerMessage by remember { mutableStateOf<String?>(null) }
    var fallbackScanJob by remember { mutableStateOf<Job?>(null) }

    // Export state in Step 3
    var customTreeUri by remember { mutableStateOf<Uri?>(null) }
    var isExporting by remember { mutableStateOf(false) }
    var exportProgressText by remember { mutableStateOf("") }
    var savedItemIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var lastExportSummary by remember { mutableStateOf<ExportSummary?>(null) }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) {
        requestedPermsOnce = true
        missingPerms = missingPermissions(context)
    }

    val folderPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            try {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            } catch (_: SecurityException) {
            }
            customTreeUri = uri
        }
    }

    // Refresh permissions whenever user returns from App Settings.
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                missingPerms = missingPermissions(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // Probe root/Magisk/FBE off the main thread.
    LaunchedEffect(Unit) {
        probingRoot = true
        val caps = withContext(Dispatchers.IO) { RootBlockScanner.probe() }
        rootCaps = caps
        if (caps.hasRoot) {
            selectedBlockDevice = caps.externalSdBlocks.firstOrNull()
                ?: caps.userdataBlockPath.orEmpty()
        }
        probingRoot = false
    }

    // Sync UI step with ForegroundService scan lifecycle.
    LaunchedEffect(serviceState.phase, serviceState.scanId) {
        when (serviceState.phase) {
            ScanPhase.RUNNING -> step = 2
            ScanPhase.COMPLETED -> {
                savedItemIds = emptySet()
                lastExportSummary = null
                step = 3
            }
            ScanPhase.CANCELLED -> {
                bannerMessage = serviceState.statusText
                step = 1
            }
            ScanPhase.ERROR -> {
                bannerMessage = serviceState.errorMessage ?: serviceState.statusText
                step = 1
            }
            ScanPhase.IDLE -> Unit
        }
    }

    fun startNonRootScan() {
        bannerMessage = null
        step = 2
        val intent = Intent(context, RecoveryForegroundService::class.java).apply {
            action = RecoveryForegroundService.ACTION_START
        }
        val startedService = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            true
        } catch (_: Exception) {
            false
        }

        if (!startedService) {
            fallbackScanJob?.cancel()
            RecoveryForegroundService.clearCancelFlag()
            val scanId = RecoveryForegroundService.nextScanId()
            fallbackScanJob = scope.launch(Dispatchers.IO) {
                RecoveryForegroundService.updateState(
                    ScanServiceState(
                        scanId = scanId,
                        phase = ScanPhase.RUNNING,
                        progressPercent = 10,
                        statusText = "Đang quét nền (chế độ dự phòng)..."
                    )
                )
                try {
                    val found = NonRootScanner.scanAll(
                        context = context.applicationContext,
                        isCancelled = { RecoveryForegroundService.isCancelRequested() }
                    ) { pct, msg ->
                        if (!RecoveryForegroundService.isCancelRequested()) {
                            RecoveryForegroundService.updateState(
                                ScanServiceState(
                                    scanId = scanId,
                                    phase = ScanPhase.RUNNING,
                                    progressPercent = pct,
                                    statusText = msg
                                )
                            )
                        }
                    }
                    if (RecoveryForegroundService.isCancelRequested()) {
                        RecoveryForegroundService.updateState(
                            ScanServiceState(
                                scanId = scanId,
                                phase = ScanPhase.CANCELLED,
                                statusText = "Đã hủy quét."
                            )
                        )
                    } else {
                        RecoveryForegroundService.updateState(
                            ScanServiceState(
                                scanId = scanId,
                                phase = ScanPhase.COMPLETED,
                                progressPercent = 100,
                                statusText = "Hoàn tất: tìm thấy ${found.size} tệp đã xác thực",
                                results = found
                            )
                        )
                    }
                } catch (e: Exception) {
                    RecoveryForegroundService.updateState(
                        ScanServiceState(
                            scanId = scanId,
                            phase = ScanPhase.ERROR,
                            statusText = "Lỗi quét: ${e.message}",
                            errorMessage = e.message
                        )
                    )
                }
            }
        }
    }

    fun startRootScan() {
        val blockDev = selectedBlockDevice.trim()
        val destRoot = rootDestDirPath.trim()
        val knownUserdata = rootCaps?.userdataBlockPath
        if (blockDev.isBlank()) {
            bannerMessage = "Vui lòng chọn thiết bị khối (block device) để quét."
            return
        }
        if (destRoot.isBlank()) {
            bannerMessage = "Vui lòng nhập thư mục ngoài để lưu ảnh tạm và kết quả."
            return
        }
        val ts = System.currentTimeMillis()
        val destImg = File(destRoot, "forensic_ro_$ts.img")
        val outDir = File(destRoot, "forensic_out_$ts")
        if (RootBlockScanner.isUnsafeSameVolumeDest(blockDev, destImg.absolutePath, knownUserdata) ||
            RootBlockScanner.isUnsafeSameVolumeDest(blockDev, outDir.absolutePath, knownUserdata)
        ) {
            bannerMessage = "An toàn dữ liệu: Không thể ghi ảnh /userdata vào bộ nhớ trong (/data hoặc /storage/emulated). Hãy dùng thẻ nhớ ngoài SD hoặc USB-OTG."
            return
        }

        bannerMessage = null
        step = 2
        val intent = Intent(context, RecoveryForegroundService::class.java).apply {
            action = RecoveryForegroundService.ACTION_START_ROOT
            putExtra(RecoveryForegroundService.EXTRA_BLOCK_DEVICE, blockDev)
            putExtra(RecoveryForegroundService.EXTRA_DEST_IMAGE, destImg.absolutePath)
            putExtra(RecoveryForegroundService.EXTRA_OUT_DIR, outDir.absolutePath)
            putExtra(RecoveryForegroundService.EXTRA_KNOWN_USERDATA, knownUserdata)
        }
        val startedService = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            true
        } catch (_: Exception) {
            false
        }

        if (!startedService) {
            fallbackScanJob?.cancel()
            RecoveryForegroundService.clearCancelFlag()
            val scanId = RecoveryForegroundService.nextScanId()
            fallbackScanJob = scope.launch(Dispatchers.IO) {
                RecoveryForegroundService.updateState(
                    ScanServiceState(
                        scanId = scanId,
                        phase = ScanPhase.RUNNING,
                        progressPercent = 10,
                        statusText = "Đang khởi tạo quét sâu Root + Rust JNI...",
                        isRootMode = true
                    )
                )
                val res = RootBlockScanner.dumpReadOnlyAndCarve(
                    blockDevice = blockDev,
                    destImageFile = destImg,
                    outDir = outDir,
                    knownUserdataPath = knownUserdata,
                    isCancelled = { RecoveryForegroundService.isCancelRequested() },
                    onProgressText = { pct, msg ->
                        if (!RecoveryForegroundService.isCancelRequested()) {
                            RecoveryForegroundService.updateState(
                                ScanServiceState(
                                    scanId = scanId,
                                    phase = ScanPhase.RUNNING,
                                    progressPercent = pct,
                                    statusText = msg,
                                    isRootMode = true
                                )
                            )
                        }
                    }
                )
                if (RecoveryForegroundService.isCancelRequested()) {
                    RecoveryForegroundService.updateState(
                        ScanServiceState(
                            scanId = scanId,
                            phase = ScanPhase.CANCELLED,
                            statusText = "Đã hủy quét Root/JNI.",
                            isRootMode = true
                        )
                    )
                } else if (res.ok) {
                    RecoveryForegroundService.updateState(
                        ScanServiceState(
                            scanId = scanId,
                            phase = ScanPhase.COMPLETED,
                            progressPercent = 100,
                            statusText = "Hoàn tất quét Root/JNI: ${res.items.size} tệp",
                            results = res.items,
                            isRootMode = true
                        )
                    )
                } else {
                    RecoveryForegroundService.updateState(
                        ScanServiceState(
                            scanId = scanId,
                            phase = ScanPhase.ERROR,
                            statusText = res.error ?: "Quét Root/JNI thất bại.",
                            errorMessage = res.error,
                            isRootMode = true
                        )
                    )
                }
            }
        }
    }

    fun cancelActiveScan() {
        RecoveryForegroundService.requestCancelFlag()
        fallbackScanJob?.cancel()
        fallbackScanJob = null
        try {
            val cancelIntent = Intent(context, RecoveryForegroundService::class.java).apply {
                action = RecoveryForegroundService.ACTION_CANCEL
            }
            context.startService(cancelIntent)
        } catch (_: Exception) {
            RecoveryForegroundService.updateState(
                ScanServiceState(
                    scanId = RecoveryForegroundService.nextScanId(),
                    phase = ScanPhase.CANCELLED,
                    statusText = "Đã hủy quét."
                )
            )
        }
    }

    fun runExport(itemsToSave: List<AndroidCandidate>) {
        if (isExporting || itemsToSave.isEmpty()) return
        scope.launch {
            isExporting = true
            exportProgressText = "Đang chuẩn bị lưu ${itemsToSave.size} tệp..."
            val summary = withContext(Dispatchers.IO) {
                RecoveryExporter.exportCandidates(
                    context = context.applicationContext,
                    items = itemsToSave,
                    targetTreeUri = customTreeUri
                ) { done, total, msg ->
                    scope.launch(Dispatchers.Main) {
                        exportProgressText = "[$done/$total] $msg"
                    }
                }
            }
            savedItemIds = savedItemIds + summary.savedIds
            lastExportSummary = summary
            isExporting = false
            exportProgressText = ""
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text(
            "Forensic Recover Android (Offline)",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(8.dp))
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Text(
                "Cảnh báo Flash + TRIM/FBE: Điện thoại dùng bộ nhớ flash + TRIM nên tỷ lệ phục hồi thấp. Hãy ngừng ghi dữ liệu mới và lưu tệp khôi phục sang thẻ nhớ/USB hoặc thư mục Downloads/ForensicRecover/.",
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodySmall
            )
        }
        Spacer(Modifier.height(10.dp))

        bannerMessage?.let { msg ->
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
                modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(msg, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                    TextButton(onClick = { bannerMessage = null }) { Text("Đóng") }
                }
            }
        }

        when (step) {
            1 -> {
                Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                    Text(
                        "Bước 1: Cấp quyền & Chọn chế độ quét",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.height(8.dp))

                    // Runtime permissions card
                    if (missingPerms.isNotEmpty()) {
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.tertiaryContainer
                            ),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    "Cần cấp quyền truy cập để quét đầy đủ",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    "Ứng dụng chỉ đọc (read-only) để tìm ảnh/video trong thùng rác (.trashed), LOST.DIR và hiển thị thông báo tiến độ quét nền. Các quyền còn thiếu:",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                Spacer(Modifier.height(4.dp))
                                missingPerms.forEach { perm ->
                                    Text(
                                        "• ${permissionDisplayName(perm)}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                }
                                Spacer(Modifier.height(8.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Button(onClick = {
                                        permissionLauncher.launch(missingPerms.toTypedArray())
                                    }) {
                                        Text("Cấp quyền ngay (1 chạm)")
                                    }
                                    if (requestedPermsOnce) {
                                        OutlinedButton(onClick = {
                                            val settingsIntent = Intent(
                                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                                Uri.fromParts("package", context.packageName, null)
                                            )
                                            context.startActivity(settingsIntent)
                                        }) {
                                            Text("Mở Cài đặt")
                                        }
                                    }
                                }
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                    } else {
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer
                            ),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                "✓ Đã có đầy đủ quyền truy cập ảnh, video và thông báo quét nền.",
                                modifier = Modifier.padding(10.dp),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                    }

                    // Device capabilities summary
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text("Trạng thái thiết bị", style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(4.dp))
                            if (probingRoot) {
                                Text("Đang kiểm tra Root / Magisk / FBE...", style = MaterialTheme.typography.bodySmall)
                            } else {
                                rootCaps?.let { caps ->
                                    Text(
                                        "Root/Magisk: ${if (caps.hasRoot) "Có (uid=0)" else "Không (Dùng chế độ Non-Root)"}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Text(
                                        "Mã hóa FBE: ${caps.cryptoType}",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    val jniLabel = if (NativeRecoveryBridge.isNativeLoaded) {
                                        "Đã nạp (ABI v${NativeRecoveryBridge.nativeAbiVersion()})"
                                    } else {
                                        "Chưa nạp"
                                    }
                                    Text(
                                        "Rust JNI Engine: $jniLabel",
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    if (caps.cryptoType == "file") {
                                        Spacer(Modifier.height(4.dp))
                                        Text(
                                            "Lưu ý: Phân vùng /userdata dùng File-Based Encryption — key của tệp đã xóa có thể đã bị Keystore hủy.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.error
                                        )
                                    }
                                }
                            }
                        }
                    }

                    Spacer(Modifier.height(12.dp))

                    // Primary Non-Root scan button
                    Button(
                        onClick = { startNonRootScan() },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Quét nhanh (MediaStore / .trashed / LOST.DIR)")
                    }

                    // Root + Rust JNI scan section (shown when root is detected)
                    val caps = rootCaps
                    if (caps != null && caps.hasRoot) {
                        Spacer(Modifier.height(14.dp))
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant
                            ),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    "Chế độ nâng cao: Quét sâu Root + Rust JNI",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    "Sao lưu chỉ-đọc thiết bị khối (block device) sang tệp ảnh rồi giải mã chữ ký bằng lõi Rust JNI.",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                Spacer(Modifier.height(8.dp))

                                val devices = buildList {
                                    addAll(caps.externalSdBlocks)
                                    caps.userdataBlockPath?.let { add(it) }
                                }.distinct()

                                if (devices.isNotEmpty()) {
                                    Text("Chọn phân vùng / thẻ nhớ khối:", style = MaterialTheme.typography.labelMedium)
                                    Spacer(Modifier.height(4.dp))
                                    devices.forEach { dev ->
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            RadioButton(
                                                selected = selectedBlockDevice == dev,
                                                onClick = { selectedBlockDevice = dev }
                                            )
                                            Text(dev, style = MaterialTheme.typography.bodySmall)
                                        }
                                    }
                                }

                                Spacer(Modifier.height(6.dp))
                                OutlinedTextField(
                                    value = rootDestDirPath,
                                    onValueChange = { rootDestDirPath = it },
                                    label = { Text("Thư mục lưu ảnh tạm & kết quả (SD / USB-OTG)") },
                                    singleLine = true,
                                    modifier = Modifier.fillMaxWidth()
                                )
                                if (RootBlockScanner.isUserdataBlock(selectedBlockDevice, caps.userdataBlockPath)) {
                                    Spacer(Modifier.height(4.dp))
                                    Text(
                                        "Bắt buộc dùng đường dẫn trên thẻ nhớ ngoài SD hoặc USB-OTG khi quét /userdata.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.error
                                    )
                                }
                                Spacer(Modifier.height(10.dp))
                                Button(
                                    onClick = { startRootScan() },
                                    enabled = NativeRecoveryBridge.isNativeLoaded && selectedBlockDevice.isNotBlank(),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Quét sâu Root + Rust JNI")
                                }
                            }
                        }
                    }
                }
            }

            2 -> {
                Text(
                    if (serviceState.isRootMode) {
                        "Bước 2: Đang quét sâu Root + Rust JNI"
                    } else {
                        "Bước 2: Đang quét nền (Foreground Service)"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(16.dp))
                val progressFraction = (serviceState.progressPercent / 100f).coerceIn(0f, 1f)
                LinearProgressIndicator(
                    progress = { progressFraction },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "${serviceState.progressPercent}% — ${serviceState.statusText}",
                    style = MaterialTheme.typography.bodyMedium
                )
                Spacer(Modifier.height(16.dp))
                OutlinedButton(onClick = { cancelActiveScan() }) {
                    Text("Hủy quét")
                }
            }

            3 -> {
                val results = serviceState.results
                val shown = results.filter { filterConf == "all" || it.confidence == filterConf }

                Text(
                    "Bước 3: Kết quả đã xác thực (${results.size} tệp)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                if (results.any { it.confidence == "low" } || results.isEmpty()) {
                    Text(
                        "Kết quả có thể không đầy đủ do giới hạn sandbox Android hoặc TRIM.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Spacer(Modifier.height(8.dp))

                // Export controls card
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            "Nơi lưu: ${RecoveryExporter.targetDestinationLabel(context, customTreeUri)}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium
                        )
                        Spacer(Modifier.height(6.dp))
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Button(
                                onClick = { runExport(shown) },
                                enabled = !isExporting && shown.isNotEmpty(),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text(
                                    if (isExporting) "Đang lưu..." else "Lưu tất cả (${shown.size})"
                                )
                            }
                            OutlinedButton(
                                onClick = { folderPickerLauncher.launch(null) },
                                enabled = !isExporting
                            ) {
                                Text("Chọn thư mục")
                            }
                        }
                        if (isExporting && exportProgressText.isNotBlank()) {
                            Spacer(Modifier.height(6.dp))
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                            Text(exportProgressText, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }

                // Export feedback banner
                lastExportSummary?.let { summary ->
                    Spacer(Modifier.height(8.dp))
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (summary.failedCount == 0) {
                                MaterialTheme.colorScheme.primaryContainer
                            } else {
                                MaterialTheme.colorScheme.errorContainer
                            }
                        ),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(
                                "Đã lưu ${summary.savedCount}/${summary.totalRequested} tệp vào ${summary.destinationLabel} (không ghi đè tệp cũ).",
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Medium
                            )
                            if (summary.savedNames.isNotEmpty()) {
                                val preview = summary.savedNames.take(3).joinToString(", ")
                                val more = if (summary.savedNames.size > 3) " (+${summary.savedNames.size - 3} tệp)" else ""
                                Text(
                                    "Tệp đã lưu: $preview$more",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                            if (summary.errors.isNotEmpty()) {
                                Text(
                                    "Lỗi: ${summary.errors.first()}",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                    }
                }

                // Filter chips + Rescan
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(vertical = 8.dp)
                ) {
                    val chipLabels = listOf(
                        "all" to "Tất cả",
                        "high" to "Cao",
                        "medium" to "TB",
                        "low" to "Thấp"
                    )
                    chipLabels.forEach { (key, label) ->
                        FilterChip(
                            selected = filterConf == key,
                            onClick = { filterConf = key },
                            label = { Text(label) }
                        )
                    }
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = {
                        RecoveryForegroundService.resetToIdle()
                        step = 1
                    }) {
                        Text("Quét lại")
                    }
                }

                if (shown.isEmpty()) {
                    Text(
                        "Không có tệp nào khớp bộ lọc hiện tại.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(top = 12.dp)
                    )
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        items(shown, key = { it.id }) { item ->
                            val isSaved = item.id in savedItemIds
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(10.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f).padding(end = 8.dp)) {
                                        Text(
                                            "${item.title} [${item.detectedExt.uppercase(Locale.ROOT)}]",
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.Medium
                                        )
                                        Text(
                                            "${item.origin} • ${formatFileSize(item.sizeBytes)} • Tin cậy: ${item.confidence} • ${item.sha256Prefix}",
                                            style = MaterialTheme.typography.bodySmall
                                        )
                                    }
                                    FilledTonalButton(
                                        onClick = { runExport(listOf(item)) },
                                        enabled = !isExporting
                                    ) {
                                        Text(if (isSaved) "Đã lưu ✓" else "Lưu")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

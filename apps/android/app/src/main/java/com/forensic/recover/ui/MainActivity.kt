package com.forensic.recover.ui

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.forensic.recover.root.RootBlockScanner
import com.forensic.recover.root.RootCapabilities
import com.forensic.recover.scanner.AndroidCandidate
import com.forensic.recover.scanner.NonRootScanner
import com.forensic.recover.service.RecoveryForegroundService

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

@Composable
fun RecoveryThreeStepScreen() {
    val context = LocalContext.current
    var step by remember { mutableIntStateOf(1) }
    var rootCaps by remember { mutableStateOf<RootCapabilities?>(null) }
    var results by remember { mutableStateOf<List<AndroidCandidate>>(emptyList()) }
    var progressMsg by remember { mutableStateOf("Sẵn sàng") }
    var filterConf by remember { mutableStateOf("all") }

    LaunchedEffect(Unit) {
        rootCaps = RootBlockScanner.probe()
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("Forensic Recover Android (Offline)", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Text(
                "Cảnh báo Flash + TRIM/FBE: Điện thoại dùng bộ nhớ flash + TRIM nên tỷ lệ phục hồi thấp. Hãy ngừng dùng máy ngay và lưu file khôi phục sang thẻ nhớ/USB khác.",
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodySmall
            )
        }
        Spacer(Modifier.height(12.dp))

        when (step) {
            1 -> {
                Text("Bước 1: Chọn nguồn & kiểm tra Root", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                rootCaps?.let { caps ->
                    Text("Root/Magisk: ${if (caps.hasRoot) "Có (uid=0)" else "Không (Fallback Non-Root)"}")
                    Text("Android FBE Crypto: ${caps.cryptoType}")
                    if (caps.cryptoType == "file") {
                        Text(
                            "Lưu ý: Phân vùng /userdata dùng File-Based Encryption — key của file đã xóa có thể đã bị Keystore hủy.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                Spacer(Modifier.height(12.dp))
                Button(onClick = {
                    step = 2
                    val svc = Intent(context, RecoveryForegroundService::class.java).apply {
                        action = RecoveryForegroundService.ACTION_START
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        context.startForegroundService(svc)
                    } else {
                        context.startService(svc)
                    }
                    results = NonRootScanner.scanAll(context) { pct, msg ->
                        progressMsg = "[$pct%] $msg"
                    }
                    step = 3
                }) {
                    Text("Quét MediaStore / .trashed / LOST.DIR")
                }
            }

            2 -> {
                Text("Bước 2: Đang quét nền (Foreground Service)", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(12.dp))
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Text(progressMsg)
            }

            3 -> {
                Text("Bước 3: Kết quả đã xác thực (${results.size})", style = MaterialTheme.typography.titleMedium)
                if (results.any { it.confidence == "low" } || results.isEmpty()) {
                    Text(
                        "Kết quả có thể không đầy đủ do giới hạn sandbox Android hoặc TRIM.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                    listOf("all", "high", "medium", "low").forEach { c ->
                        FilterChip(selected = filterConf == c, onClick = { filterConf = c }, label = { Text(c) })
                    }
                    Button(onClick = { step = 1 }) { Text("Quét lại") }
                }
                val shown = results.filter { filterConf == "all" || it.confidence == filterConf }
                LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(shown) { item ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text("${item.title} [${item.detectedExt.uppercase()}] (${item.confidence})")
                                Text(
                                    "${item.origin} • ${item.sizeBytes} B • ${item.sha256Prefix}",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

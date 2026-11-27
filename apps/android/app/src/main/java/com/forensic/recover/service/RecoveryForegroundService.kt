package com.forensic.recover.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.forensic.recover.root.RootBlockScanner
import com.forensic.recover.scanner.AndroidCandidate
import com.forensic.recover.scanner.NonRootScanner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

enum class ScanPhase {
    IDLE,
    RUNNING,
    COMPLETED,
    CANCELLED,
    ERROR
}

data class ScanServiceState(
    val scanId: Long = 0L,
    val phase: ScanPhase = ScanPhase.IDLE,
    val progressPercent: Int = 0,
    val statusText: String = "Sẵn sàng",
    val results: List<AndroidCandidate> = emptyList(),
    val errorMessage: String? = null,
    val isRootMode: Boolean = false
)

/**
 * ForegroundService keeping long-running recovery scans alive across Doze mode
 * with a partial WakeLock, live progress notifications, and a shared StateFlow
 * so the UI stays smoothly synchronized without blocking the main thread.
 */
class RecoveryForegroundService : Service() {
    companion object {
        const val CHANNEL_ID = "forensic_recovery_progress"
        const val NOTIF_ID = 1001
        const val ACTION_START = "com.forensic.recover.START_SCAN"
        const val ACTION_START_ROOT = "com.forensic.recover.START_ROOT_SCAN"
        const val ACTION_CANCEL = "com.forensic.recover.CANCEL_SCAN"

        const val EXTRA_BLOCK_DEVICE = "extra_block_device"
        const val EXTRA_DEST_IMAGE = "extra_dest_image"
        const val EXTRA_OUT_DIR = "extra_out_dir"
        const val EXTRA_KNOWN_USERDATA = "extra_known_userdata"

        private val _state = MutableStateFlow(ScanServiceState())
        val state: StateFlow<ScanServiceState> = _state.asStateFlow()

        private val cancelRequested = AtomicBoolean(false)
        private val runIdGenerator = AtomicLong(0L)
        private val activeRunId = AtomicLong(0L)

        fun nextScanId(): Long = runIdGenerator.incrementAndGet()

        fun clearCancelFlag() {
            cancelRequested.set(false)
        }

        fun updateState(newState: ScanServiceState) {
            _state.value = newState
        }

        fun resetToIdle() {
            if (activeRunId.get() == 0L) {
                _state.value = ScanServiceState(scanId = _state.value.scanId)
            }
        }

        fun requestCancelFlag() {
            cancelRequested.set(true)
            activeRunId.set(0L)
            RootBlockScanner.cancelActive()
        }

        fun isCancelRequested(): Boolean = cancelRequested.get()
    }

    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        if (action == ACTION_CANCEL) {
            cancelRequested.set(true)
            activeRunId.set(0L)
            RootBlockScanner.cancelActive()
            _state.value = _state.value.copy(
                phase = ScanPhase.CANCELLED,
                statusText = "Đã hủy quét theo yêu cầu."
            )
            releaseWakeLock()
            stopForegroundCompat(removeNotification = true)
            stopSelf()
            return START_NOT_STICKY
        }

        val myRunId = runIdGenerator.incrementAndGet()
        if (!activeRunId.compareAndSet(0L, myRunId)) {
            return START_NOT_STICKY
        }

        cancelRequested.set(false)
        val isRoot = action == ACTION_START_ROOT
        val blockDevice = intent?.getStringExtra(EXTRA_BLOCK_DEVICE).orEmpty()
        val destImagePath = intent?.getStringExtra(EXTRA_DEST_IMAGE).orEmpty()
        val outDirPath = intent?.getStringExtra(EXTRA_OUT_DIR).orEmpty()
        val knownUserdata = intent?.getStringExtra(EXTRA_KNOWN_USERDATA)

        val initialMsg = if (isRoot) {
            "Đang khởi tạo quét sâu Root + Rust JNI..."
        } else {
            "Đang khởi tạo quét chỉ-đọc..."
        }

        _state.value = ScanServiceState(
            scanId = myRunId,
            phase = ScanPhase.RUNNING,
            progressPercent = 5,
            statusText = initialMsg,
            results = emptyList(),
            errorMessage = null,
            isRootMode = isRoot
        )

        ensureChannel()
        startForegroundCompat(buildNotification(5, initialMsg))
        acquireWakeLock()

        fun isStillCurrent(): Boolean = activeRunId.get() == myRunId && !cancelRequested.get()

        thread(start = true, name = "forensic-scan-worker-$myRunId") {
            var completedNormally = false
            try {
                if (isRoot) {
                    val res = RootBlockScanner.dumpReadOnlyAndCarve(
                        blockDevice = blockDevice,
                        destImageFile = File(destImagePath),
                        outDir = File(outDirPath),
                        knownUserdataPath = knownUserdata,
                        isCancelled = { !isStillCurrent() },
                        onProgressText = { pct, msg ->
                            if (isStillCurrent()) {
                                _state.value = _state.value.copy(
                                    progressPercent = pct,
                                    statusText = msg
                                )
                                updateNotification(pct, msg)
                            }
                        }
                    )
                    if (!isStillCurrent()) {
                        if (activeRunId.get() == 0L && _state.value.scanId == myRunId) {
                            _state.value = _state.value.copy(
                                phase = ScanPhase.CANCELLED,
                                statusText = "Đã hủy quét Root/JNI."
                            )
                        }
                    } else if (res.ok) {
                        val doneMsg = "Hoàn tất quét Root/JNI: ${res.items.size} tệp"
                        _state.value = ScanServiceState(
                            scanId = myRunId,
                            phase = ScanPhase.COMPLETED,
                            progressPercent = 100,
                            statusText = doneMsg,
                            results = res.items,
                            isRootMode = true
                        )
                        updateNotification(100, doneMsg)
                        completedNormally = true
                    } else {
                        val err = res.error ?: "Quét Root/JNI thất bại."
                        _state.value = ScanServiceState(
                            scanId = myRunId,
                            phase = ScanPhase.ERROR,
                            progressPercent = 0,
                            statusText = err,
                            errorMessage = err,
                            isRootMode = true
                        )
                    }
                } else {
                    val found = NonRootScanner.scanAll(
                        context = applicationContext,
                        isCancelled = { !isStillCurrent() }
                    ) { pct, msg ->
                        if (isStillCurrent()) {
                            _state.value = _state.value.copy(
                                progressPercent = pct,
                                statusText = msg
                            )
                            updateNotification(pct, msg)
                        }
                    }
                    if (!isStillCurrent()) {
                        if (activeRunId.get() == 0L && _state.value.scanId == myRunId) {
                            _state.value = _state.value.copy(
                                phase = ScanPhase.CANCELLED,
                                statusText = "Đã hủy quét."
                            )
                        }
                    } else {
                        val doneMsg = "Hoàn tất: tìm thấy ${found.size} tệp đã xác thực"
                        _state.value = ScanServiceState(
                            scanId = myRunId,
                            phase = ScanPhase.COMPLETED,
                            progressPercent = 100,
                            statusText = doneMsg,
                            results = found,
                            isRootMode = false
                        )
                        updateNotification(100, doneMsg)
                        completedNormally = true
                    }
                }
            } catch (e: Exception) {
                if (activeRunId.get() == myRunId) {
                    val err = "Lỗi quét: ${e.message ?: e.javaClass.simpleName}"
                    _state.value = ScanServiceState(
                        scanId = myRunId,
                        phase = ScanPhase.ERROR,
                        progressPercent = 0,
                        statusText = err,
                        errorMessage = err,
                        isRootMode = isRoot
                    )
                }
            } finally {
                // Only clean up service resources if this worker is still the active run.
                if (activeRunId.compareAndSet(myRunId, 0L)) {
                    releaseWakeLock()
                    stopForegroundCompat(removeNotification = !completedNormally)
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        cancelRequested.set(true)
        activeRunId.set(0L)
        RootBlockScanner.cancelActive()
        releaseWakeLock()
        super.onDestroy()
    }

    private fun startForegroundCompat(notification: Notification) {
        try {
            val fgType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            } else {
                0
            }
            ServiceCompat.startForeground(this, NOTIF_ID, notification, fgType)
        } catch (_: Exception) {
            try {
                startForeground(NOTIF_ID, notification)
            } catch (_: Exception) {
            }
        }
    }

    private fun stopForegroundCompat(removeNotification: Boolean) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(if (removeNotification) STOP_FOREGROUND_REMOVE else STOP_FOREGROUND_DETACH)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(removeNotification)
            }
        } catch (_: Exception) {
        }
    }

    private fun acquireWakeLock() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "ForensicRecover::ScanLock")
                .apply { acquire(30 * 60 * 1000L) }
        } catch (_: Exception) {
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        } catch (_: Exception) {
        }
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "Tiến trình quét Forensic Recover",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(ch)
        }
    }

    private fun updateNotification(pct: Int, msg: String) {
        try {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify(NOTIF_ID, buildNotification(pct, msg))
        } catch (_: SecurityException) {
            // POST_NOTIFICATIONS may be declined on API 33+; scan continues silently.
        } catch (_: Exception) {
        }
    }

    private fun buildNotification(pct: Int, msg: String): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentTitle("Forensic Recover (Chỉ-đọc)")
            .setContentText(msg)
            .setProgress(100, pct.coerceIn(0, 100), false)
            .setOngoing(pct < 100)
            .build()
}

package com.forensic.recover.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.forensic.recover.scanner.AndroidCandidate
import com.forensic.recover.scanner.NonRootScanner
import kotlin.concurrent.thread

/**
 * ForegroundService keeping long-running recovery scans alive across Doze mode
 * with a partial WakeLock and live progress notifications.
 */
class RecoveryForegroundService : Service() {
    companion object {
        const val CHANNEL_ID = "forensic_recovery_progress"
        const val NOTIF_ID = 1001
        const val ACTION_START = "com.forensic.recover.START_SCAN"
        const val ACTION_CANCEL = "com.forensic.recover.CANCEL_SCAN"

        @Volatile
        var lastResults: List<AndroidCandidate> = emptyList()
        @Volatile
        var progressPercent: Int = 0
        @Volatile
        var statusText: String = "Idle"
    }

    private var wakeLock: PowerManager.WakeLock? = null
    @Volatile
    private var cancelled = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_CANCEL) {
            cancelled = true
            stopSelf()
            return START_NOT_STICKY
        }

        ensureChannel()
        startForeground(NOTIF_ID, buildNotification(0, "Starting read-only recovery scan..."))
        acquireWakeLock()

        thread(start = true, name = "forensic-scan-worker") {
            try {
                val found = NonRootScanner.scanAll(applicationContext) { pct, msg ->
                    if (cancelled) return@scanAll
                    progressPercent = pct
                    statusText = msg
                    updateNotification(pct, msg)
                }
                lastResults = found
                statusText = "Completed: ${found.size} items"
                updateNotification(100, statusText)
            } finally {
                releaseWakeLock()
                stopForeground(STOP_FOREGROUND_DETACH)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "ForensicRecover::ScanLock")
            .apply { acquire(30 * 60 * 1000L) }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) wakeLock?.release()
        } catch (_: Exception) {}
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "Forensic Recovery Scan",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(ch)
        }
    }

    private fun updateNotification(pct: Int, msg: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(pct, msg))
    }

    private fun buildNotification(pct: Int, msg: String): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentTitle("Forensic Recover (Read-Only)")
            .setContentText(msg)
            .setProgress(100, pct, false)
            .setOngoing(pct < 100)
            .build()
}

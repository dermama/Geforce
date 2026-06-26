package com.zortos.opennow

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

class QueueForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "gfn_queue_channel"
        const val NOTIFICATION_ID = 1001
        const val ACTION_START = "com.zortos.opennow.START_QUEUE"
        const val ACTION_UPDATE = "com.zortos.opennow.UPDATE_QUEUE"
        const val ACTION_STOP = "com.zortos.opennow.STOP_QUEUE"
        const val EXTRA_POSITION = "queue_position"
        const val EXTRA_ETA = "queue_eta"

        private var currentPosition: Int = 0
        private var currentEta: Int = 0

        fun start(context: Context, position: Int, eta: Int) {
            currentPosition = position
            currentEta = eta
            val intent = Intent(context, QueueForegroundService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_POSITION, position)
                putExtra(EXTRA_ETA, eta)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun update(context: Context, position: Int, eta: Int) {
            currentPosition = position
            currentEta = eta
            val intent = Intent(context, QueueForegroundService::class.java).apply {
                action = ACTION_UPDATE
                putExtra(EXTRA_POSITION, position)
                putExtra(EXTRA_ETA, eta)
            }
            context.startService(intent)
        }

        fun stop(context: Context) {
            currentPosition = 0
            currentEta = 0
            val intent = Intent(context, QueueForegroundService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }

    private lateinit var notificationManager: NotificationManager
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createNotificationChannel()
        acquireWakeLock()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val position = intent.getIntExtra(EXTRA_POSITION, 0)
                val eta = intent.getIntExtra(EXTRA_ETA, 0)
                startForeground(NOTIFICATION_ID, buildNotification(position, eta))
            }
            ACTION_UPDATE -> {
                val position = intent.getIntExtra(EXTRA_POSITION, 0)
                val eta = intent.getIntExtra(EXTRA_ETA, 0)
                notificationManager.notify(NOTIFICATION_ID, buildNotification(position, eta))
            }
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                releaseWakeLock()
                stopSelf()
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        releaseWakeLock()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "GFN Queue Monitor",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows your position in the GeForce NOW queue"
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(position: Int, eta: Int): Notification {
        val etaText = if (eta > 0) {
            if (eta >= 60) "${eta / 60}m ${eta % 60}s" else "${eta}s"
        } else "soon"

        val openIntent = packageManager.getLaunchIntentForPackage(packageName)
        val openPendingIntent = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val contentText = if (position > 0) "Position #$position · ETA $etaText" else "Almost ready!"

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("GeForce NOW Queue")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setContentIntent(openPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun acquireWakeLock() {
        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "opennow:queue_wakelock"
            ).apply {
                acquire(30 * 60 * 1000L)
            }
        } catch (_: Exception) {}
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) it.release()
            }
        } catch (_: Exception) {}
    }
}

package ua.parentcontrol

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build

class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        val prefs = sp(c)
        val status = i.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirm = if (Build.VERSION.SDK_INT >= 33)
                    i.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                else @Suppress("DEPRECATION") i.getParcelableExtra(Intent.EXTRA_INTENT)
                if (confirm != null) {
                    confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    runCatching { c.startActivity(confirm) }
                } else {
                    prefs.edit().remove("update_in_progress").remove("update_in_progress_at").putString("update_error", "Android не повернув екран підтвердження встановлення").apply()
                }
            }
            PackageInstaller.STATUS_SUCCESS -> {
                val version = i.getIntExtra("expected_version", prefs.getInt("update_in_progress", 0))
                prefs.edit().putInt("update_tried", version).remove("update_in_progress").remove("update_in_progress_at").remove("update_error").apply()
            }
            else -> {
                val message = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "код статусу $status"
                prefs.edit().remove("update_in_progress").remove("update_in_progress_at").putString("update_error", "Встановлення не виконано: $message").apply()
            }
        }
    }
}

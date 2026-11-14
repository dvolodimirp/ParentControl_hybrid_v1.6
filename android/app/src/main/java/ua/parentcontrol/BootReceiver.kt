package ua.parentcontrol

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        when (i.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> SyncScheduler.runNow(c)
            Intent.ACTION_USER_PRESENT -> {
                val pending = goAsync()
                Thread {
                    try { PolicyEnforcer.enforceStoredPolicy(c.applicationContext) }
                    finally { pending.finish() }
                }.start()
            }
        }
    }
}

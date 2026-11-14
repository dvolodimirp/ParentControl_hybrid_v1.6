package ua.parentcontrol

import android.accessibilityservice.AccessibilityService
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.os.Handler
import android.os.HandlerThread
import android.view.accessibility.AccessibilityEvent
import org.json.JSONObject

/** Accessibility fallback for devices that are not provisioned as Device Owner. */
class GuardService : AccessibilityService() {
    private var thread: HandlerThread? = null
    private var handler: Handler? = null
    @Volatile private var policy: Policy? = null
    @Volatile private var policyJson: String? = null
    @Volatile private var usage: Map<String, Int> = emptyMap()
    private var usageAt = 0L
    private var blockedAt = 0L
    private var ignored: Set<String> = emptySet()

    private val lockCheck = object : Runnable {
        override fun run() {
            if (shouldLock()) PolicyEnforcer.lockDevice(this@GuardService)
            handler?.postDelayed(this, 2_000)
        }
    }

    override fun onServiceConnected() {
        ignored = UsageHelper.ignored(this)
        refreshPolicy()
        thread = HandlerThread("pc-local-enforcement").also { it.start() }
        handler = Handler(thread!!.looper).also { it.post(lockCheck) }
    }

    override fun onDestroy() {
        handler?.removeCallbacksAndMessages(null)
        thread?.quitSafely()
        super.onDestroy()
    }

    override fun onInterrupt() = Unit

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event?.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        val pkg = event.packageName?.toString() ?: return
        if (pkg in ignored || pkg.contains("incallui") || pkg.contains("emergency")) return
        val p = policy ?: return
        if (shouldLock()) {
            PolicyEnforcer.lockDevice(this)
            return
        }
        // In Device Owner mode, blocked packages are suspended by DevicePolicyManager.
        // Accessibility remains as fallback for app-time and quiet-hour policies.
        if (DeviceCapabilities.isDeviceOwner(this) && pkg in p.blocked) return
        val reason = violation(p, pkg) ?: return
        val now = System.currentTimeMillis()
        if (now - blockedAt >= 1_500) {
            blockedAt = now
            startActivity(Intent(this, BlockedActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                .putExtra("reason", reason))
        }
    }

    private fun refreshPolicy(): Policy? {
        val raw = sp(this).getString("policy", null) ?: return policy
        if (raw != policyJson) {
            val parsed = runCatching { Policy(JSONObject(raw)) }.getOrNull()
            if (parsed != null) { policy = parsed; policyJson = raw }
        }
        return policy
    }

    private fun refreshUsage() {
        if (System.currentTimeMillis() - usageAt > 10_000 && UsageHelper.hasAccess(this)) {
            usage = UsageHelper.today(this)
            usageAt = System.currentTimeMillis()
        }
    }

    private fun shouldLock(): Boolean {
        val p = refreshPolicy() ?: return false
        if (p.locked) return true
        if (p.daily <= 0) return false
        refreshUsage()
        return usage.filter { it.key !in ignored && it.key !in p.quietAllowed }.values.sum() >= p.daily
    }

    private fun violation(p: Policy, pkg: String): String? {
        if (pkg in p.blocked) return "Додаток заблоковано батьками"
        if (p.isQuiet() && pkg !in p.quietAllowed) return "Зараз тихий час"
        refreshUsage()
        val limit = p.limits[pkg]
        if (limit != null && (usage[pkg] ?: 0) >= limit) return "Ліміт часу для додатку вичерпано"
        return null
    }
}

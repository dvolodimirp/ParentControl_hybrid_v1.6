package ua.parentcontrol

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.provider.Settings

object DeviceCapabilities {
    fun isDeviceOwner(c: Context): Boolean = runCatching {
        c.getSystemService(DevicePolicyManager::class.java)?.isDeviceOwnerApp(c.packageName) == true
    }.getOrDefault(false)

    fun isAdminActive(c: Context): Boolean = runCatching {
        c.getSystemService(DevicePolicyManager::class.java)
            ?.isAdminActive(ComponentName(c, AdminReceiver::class.java)) == true
    }.getOrDefault(false)

    fun isAccessibilityEnabled(c: Context): Boolean = runCatching {
        Settings.Secure.getString(c.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            ?.contains(c.packageName) == true
    }.getOrDefault(false)
}

object PolicyEnforcer {
    /** Apply package suspension only when Android confirms Device Owner privileges. */
    fun apply(c: Context, p: Policy, usage: Map<String, Int>, launchable: Map<String, String>): List<String> {
        if (!DeviceCapabilities.isDeviceOwner(c)) return emptyList()
        val desired = linkedSetOf<String>()
        desired += p.blocked
        if (p.isQuiet()) desired += launchable.keys.filter { it !in p.quietAllowed }
        p.limits.forEach { (pkg, limit) -> if (limit > 0 && (usage[pkg] ?: 0) >= limit) desired += pkg }
        desired.removeAll(UsageHelper.ignored(c))
        desired.remove(c.packageName)

        val prefs = sp(c)
        val old = runCatching { org.json.JSONArray(prefs.getString("suspended_packages", "[]")) }
            .getOrNull()?.let { a -> (0 until a.length()).mapNotNull { a.optString(it).takeIf(String::isNotBlank) }.toSet() }
            ?: emptySet()
        val dpm = c.getSystemService(DevicePolicyManager::class.java) ?: return listOf("DevicePolicyManager недоступний")
        val admin = ComponentName(c, AdminReceiver::class.java)
        val errors = mutableListOf<String>()
        val toUnsuspend = (old - desired).toTypedArray()
        val toSuspend = (desired - old).toTypedArray()
        try {
            if (toUnsuspend.isNotEmpty()) dpm.setPackagesSuspended(admin, toUnsuspend, false)
            if (toSuspend.isNotEmpty()) {
                val failed = dpm.setPackagesSuspended(admin, toSuspend, true)
                failed.forEach { errors += "Не вдалося призупинити $it" }
            }
            val successful = desired - errors.mapNotNull { it.substringAfter("призупинити ", "").takeIf(String::isNotBlank) }.toSet()
            prefs.edit().putString("suspended_packages", org.json.JSONArray(successful).toString()).apply()
        } catch (e: Exception) {
            errors += "Помилка Device Owner policy: ${e.message ?: e.javaClass.simpleName}"
        }
        return errors
    }

    fun shouldLock(c: Context, p: Policy, usage: Map<String, Int>): Boolean {
        if (p.locked) return true
        if (p.daily <= 0) return false
        val ignored = UsageHelper.ignored(c)
        return usage.filter { it.key !in ignored && it.key !in p.quietAllowed }.values.sum() >= p.daily
    }

    fun lockDevice(c: Context): Boolean = runCatching {
        val dpm = c.getSystemService(DevicePolicyManager::class.java) ?: return false
        if (!DeviceCapabilities.isAdminActive(c) && !DeviceCapabilities.isDeviceOwner(c)) return false
        dpm.lockNow()
        true
    }.getOrDefault(false)

    fun enforceStoredPolicy(c: Context) {
        val raw = sp(c).getString("policy", null) ?: return
        val p = runCatching { Policy(org.json.JSONObject(raw)) }.getOrNull() ?: return
        val labels = UsageHelper.launchable(c)
        val usage = if (UsageHelper.hasAccess(c)) UsageHelper.today(c) else emptyMap()
        apply(c, p, usage, labels)
        if (shouldLock(c, p, usage)) lockDevice(c)
    }
}

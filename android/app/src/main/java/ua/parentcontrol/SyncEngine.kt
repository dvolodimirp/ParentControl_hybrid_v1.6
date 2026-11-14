package ua.parentcontrol

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.VpnService
import android.os.Build
import android.Manifest
import org.json.JSONArray
import org.json.JSONObject

object SyncEngine {
    fun sync(c: Context) {
        val prefs = sp(c)
        val token = prefs.getString("token", null) ?: return
        val labels = UsageHelper.launchable(c)
        val usage = if (UsageHelper.hasAccess(c)) UsageHelper.today(c) else emptyMap()
        val traffic = TrafficTracker.todayBytes(c, UsageHelper.uids(c, labels.keys))
        val versionCode = runCatching {
            val pi = c.packageManager.getPackageInfo(c.packageName, 0)
            if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode.toInt() else @Suppress("DEPRECATION") pi.versionCode
        }.getOrDefault(0)
        val pendingResults = runCatching { JSONArray(prefs.getString("pending_command_results", "[]")) }.getOrElse { JSONArray() }
        val body = JSONObject()
            .put("day", UsageHelper.day())
            .put("admin_active", DeviceCapabilities.isAdminActive(c))
            .put("device_owner", DeviceCapabilities.isDeviceOwner(c))
            .put("accessibility_active", DeviceCapabilities.isAccessibilityEnabled(c))
            .put("app_version_code", versionCode)
            .put("last_cmd_result", prefs.getString("last_cmd_result", null) ?: JSONObject.NULL)
            .put("command_results", pendingResults)
            .put("vpn_consent", VpnService.prepare(c) == null)
            .put("net_filter_running", NetGuardService.isRunning())
            .put("net_filter_error", NetGuardService.lastError ?: JSONObject.NULL)
            .put("policy_error", prefs.getString("policy_error", null) ?: JSONObject.NULL)
            .put("location", lastKnownLocation(c) ?: JSONObject.NULL)
            .put("usage", JSONArray().also { a -> usage.filter { it.key in labels }.forEach { (pkg, minutes) ->
                a.put(JSONObject().put("pkg", pkg).put("label", labels[pkg] ?: pkg).put("minutes", minutes))
            } })
            .put("traffic", JSONArray().also { a -> traffic.forEach { (pkg, bytes) ->
                a.put(JSONObject().put("pkg", pkg).put("label", labels[pkg] ?: pkg).put("bytes", bytes))
            } })
            .put("apps", JSONArray().also { a -> labels.forEach { (pkg, label) ->
                a.put(JSONObject().put("pkg", pkg).put("label", label))
            } })

        val response = Api.call(c, "POST", "/api/device/sync", body, token)
        // A successful HTTP response means the server committed the acknowledgements.
        prefs.edit().putString("pending_command_results", "[]").apply()
        val policyJson = response.getJSONObject("policy")
        prefs.edit().putString("policy", policyJson.toString()).apply()
        val policy = Policy(policyJson)
        val policyErrors = PolicyEnforcer.apply(c, policy, usage, labels)
        applyNetFilter(c, policy)
        if (PolicyEnforcer.shouldLock(c, policy, usage)) PolicyEnforcer.lockDevice(c)
        processCommands(c, response.optJSONArray("commands") ?: JSONArray())
        if (response.has("update") && !response.isNull("update")) {
            val update = response.getJSONObject("update")
            Updater.maybeInstall(c, update.getInt("version_code"), update.getString("url"), update.optString("sha256"))
        }
        if (policyErrors.isNotEmpty()) prefs.edit().putString("policy_error", policyErrors.joinToString("; ")).apply()
        else prefs.edit().remove("policy_error").apply()
    }

    private fun processCommands(c: Context, commands: JSONArray) {
        val prefs = sp(c)
        val processed = runCatching { JSONArray(prefs.getString("processed_command_ids", "[]")) }.getOrElse { JSONArray() }
        val seen = (0 until processed.length()).mapNotNull { processed.optLong(it).takeIf { id -> id > 0 } }.toMutableSet()
        val ack = runCatching { JSONArray(prefs.getString("pending_command_results", "[]")) }.getOrElse { JSONArray() }
        for (i in 0 until commands.length()) {
            val command = commands.optJSONObject(i) ?: continue
            val id = command.optLong("id")
            val name = command.optString("cmd")
            if (id <= 0) continue
            if (id !in seen) {
                val result = when (name) {
                    "flashlight_on" -> Flashlight.set(c, true)
                    "flashlight_off" -> Flashlight.set(c, false)
                    "alarm" -> Alarm.sound(c)
                    else -> "невідома команда: $name"
                }
                prefs.edit().putString("last_cmd_result", result).apply()
                ack.put(JSONObject().put("id", id).put("result", result))
                seen += id
            } else {
                ack.put(JSONObject().put("id", id).put("result", "повторна доставка: вже оброблено"))
            }
        }
        // Keep a bounded deduplication window.
        val retained = seen.sortedDescending().take(200).sorted()
        prefs.edit()
            .putString("pending_command_results", ack.toString())
            .putString("processed_command_ids", JSONArray(retained).toString())
            .apply()
    }

    private fun applyNetFilter(c: Context, p: Policy) {
        NetGuardService.blockedDomains = p.blockedDomains
        if (p.netFilterEnabled) {
            if (VpnService.prepare(c) == null && !NetGuardService.isRunning()) {
                try {
                    val i = Intent(c, NetGuardService::class.java)
                    if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i) else c.startService(i)
                } catch (e: Exception) { NetGuardService.lastError = "не вдалося запустити VPN: ${e.message}" }
            } else if (VpnService.prepare(c) != null) {
                NetGuardService.lastError = "не надано дозвіл VPN"
            }
        } else if (NetGuardService.isRunning()) c.stopService(Intent(c, NetGuardService::class.java))
    }

    private fun lastKnownLocation(c: Context): JSONObject? {
        if (c.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) return null
        val lm = c.getSystemService(LocationManager::class.java) ?: return null
        var best: android.location.Location? = null
        for (provider in listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, "fused")) {
            try { val loc = lm.getLastKnownLocation(provider) ?: continue; if (best == null || loc.time > best!!.time) best = loc }
            catch (_: Exception) { }
        }
        val b = best ?: return null
        return JSONObject().put("lat", b.latitude).put("lon", b.longitude).put("accuracy", b.accuracy).put("ts", b.time)
    }
}

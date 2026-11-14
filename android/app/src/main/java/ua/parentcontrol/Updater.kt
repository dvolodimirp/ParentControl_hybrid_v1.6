package ua.parentcontrol

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

object Updater {
    fun maybeInstall(c: Context, versionCode: Int, path: String, expectedSha256: String?) {
        val prefs = sp(c)
        if (versionCode <= 0 || versionCode <= installedVersion(c)) return
        val inProgress = prefs.getInt("update_in_progress", 0)
        val startedAt = prefs.getLong("update_in_progress_at", 0L)
        if (inProgress == versionCode && System.currentTimeMillis() - startedAt < 30 * 60 * 1000L) return
        if (inProgress != 0) prefs.edit().remove("update_in_progress").remove("update_in_progress_at").apply()
        if (prefs.getInt("update_tried", 0) >= versionCode) return
        val token = prefs.getString("token", null) ?: return
        if (Build.VERSION.SDK_INT >= 26 && !c.packageManager.canRequestPackageInstalls()) {
            prefs.edit().putString("update_error", "Не надано дозвіл на встановлення невідомих застосунків").apply()
            return
        }
        val temp = File(c.cacheDir, "parent-control-update.apk")
        try {
            prefs.edit().putInt("update_in_progress", versionCode).putLong("update_in_progress_at", System.currentTimeMillis()).apply()
            val conn = Api.openStream(c, path, token)
            try { conn.inputStream.use { input -> temp.outputStream().use { output -> input.copyTo(output) } } }
            finally { conn.disconnect() }
            val actualHash = sha256(temp)
            if (!expectedSha256.isNullOrBlank() && !actualHash.equals(expectedSha256, true))
                throw IllegalStateException("SHA-256 APK не збігається з серверним значенням")
            verifyApk(c, temp, versionCode)

            val installer = c.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            params.setAppPackageName(c.packageName)
            if (Build.VERSION.SDK_INT >= 31 && c.packageManager.canRequestPackageInstalls()) {
                // This package is updating itself; Android still decides whether the
                // no-user-action path is eligible and may return PENDING_USER_ACTION.
                params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }
            val sessionId = installer.createSession(params)
            installer.openSession(sessionId).use { session ->
                temp.inputStream().use { input ->
                    session.openWrite("base.apk", 0, temp.length()).use { output ->
                        input.copyTo(output); session.fsync(output)
                    }
                }
                val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or
                    (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
                val callback = PendingIntent.getBroadcast(c, sessionId, Intent(c, InstallReceiver::class.java)
                    .putExtra("expected_version", versionCode), pendingFlags)
                session.commit(callback.intentSender)
            }
            prefs.edit().remove("update_error").apply()
        } catch (e: Exception) {
            prefs.edit().remove("update_in_progress").remove("update_in_progress_at")
                .putString("update_error", e.message ?: e.javaClass.simpleName).apply()
        } finally { temp.delete() }
    }

    private fun installedVersion(c: Context): Int = runCatching {
        val pi = c.packageManager.getPackageInfo(c.packageName, 0)
        if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode.toInt() else @Suppress("DEPRECATION") pi.versionCode
    }.getOrDefault(0)

    private fun verifyApk(c: Context, file: File, expectedVersion: Int) {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        val archive = c.packageManager.getPackageArchiveInfo(file.absolutePath, flags)
            ?: throw IllegalArgumentException("Серверний файл не є коректним APK")
        require(archive.packageName == c.packageName) { "Невірний applicationId у APK" }
        val archiveVersion = if (Build.VERSION.SDK_INT >= 28) archive.longVersionCode.toInt() else @Suppress("DEPRECATION") archive.versionCode
        require(archiveVersion == expectedVersion) { "versionCode APK не відповідає релізу сервера" }
        val installed = c.packageManager.getPackageInfo(c.packageName, flags)
        val installedSigners = if (Build.VERSION.SDK_INT >= 28) installed.signingInfo?.apkContentsSigners else @Suppress("DEPRECATION") installed.signatures
        val archiveSigners = if (Build.VERSION.SDK_INT >= 28) archive.signingInfo?.apkContentsSigners else @Suppress("DEPRECATION") archive.signatures
        val installedDigests = installedSigners.orEmpty().map { sha256(it.toByteArray()) }.toSet()
        val archiveDigests = archiveSigners.orEmpty().map { sha256(it.toByteArray()) }.toSet()
        require(installedDigests.isNotEmpty() && installedDigests == archiveDigests) { "Підпис APK не збігається з установленою версією" }
    }

    private fun sha256(file: File): String = file.inputStream().use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(32 * 1024)
        while (true) { val n = input.read(buf); if (n < 0) break; digest.update(buf, 0, n) }
        digest.digest().joinToString("") { "%02x".format(it) }
    }
    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}

package ua.parentcontrol

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

object SyncScheduler {
    private const val UNIQUE = "parent-control-periodic-sync"
    fun ensureScheduled(c: Context) {
        val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
        val periodic = PeriodicWorkRequestBuilder<SyncWorker>(15, TimeUnit.MINUTES)
            .setConstraints(constraints).build()
        WorkManager.getInstance(c).enqueueUniquePeriodicWork(UNIQUE, ExistingPeriodicWorkPolicy.KEEP, periodic)
    }
    fun runNow(c: Context) {
        val request = OneTimeWorkRequestBuilder<SyncWorker>()
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(c).enqueueUniqueWork("parent-control-sync-now", ExistingWorkPolicy.KEEP, request)
        ensureScheduled(c)
    }
}

class SyncWorker(c: Context, params: WorkerParameters) : Worker(c, params) {
    override fun doWork(): Result {
        return try {
            if (sp(applicationContext).getString("token", null).isNullOrBlank()) {
                Result.success()
            } else {
                SyncEngine.sync(applicationContext)
                Result.success()
            }
        } catch (e: Exception) {
            if (e.message?.startsWith("HTTP 401") == true) {
                sp(applicationContext).edit().remove("token").apply()
                Result.failure()
            } else {
                Result.retry()
            }
        }
    }
}

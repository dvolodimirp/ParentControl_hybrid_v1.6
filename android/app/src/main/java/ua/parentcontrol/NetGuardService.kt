package ua.parentcontrol

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.util.concurrent.ConcurrentHashMap
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import kotlin.concurrent.thread

/** DNS redirector. Current implementation intentionally supports IPv4/UDP DNS only. */
class NetGuardService : VpnService() {
    companion object {
        @Volatile var blockedDomains: Set<String> = emptySet()
        @Volatile private var running = false
        @Volatile var lastError: String? = null
        fun isRunning() = running
        private const val VIRTUAL_DNS = "10.111.222.2"
        private const val CHANNEL = "pc_dns_filter"
        private const val NOTIFICATION_ID = 7213
    }

    private var pfd: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var stopping = false
    @Volatile private var upstreamDns: List<InetAddress> = emptyList()
    private var connectivity: ConnectivityManager? = null
    private val networkDns = ConcurrentHashMap<Network, List<InetAddress>>()
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { refreshNetworkDns(network) }
        override fun onLinkPropertiesChanged(network: Network, linkProperties: android.net.LinkProperties) {
            refreshNetworkDns(network, linkProperties)
        }
        override fun onLost(network: Network) {
            networkDns.remove(network)
            upstreamDns = networkDns.values.firstOrNull { it.isNotEmpty() } ?: emptyList()
            if (upstreamDns.isEmpty() && running) lastError = "Втрачено активну мережу; очікується DNS"
        }
    }

    private fun refreshNetworkDns(network: Network, knownLinks: android.net.LinkProperties? = null) {
        val cm = connectivity ?: return
        val caps = try { cm.getNetworkCapabilities(network) } catch (_: Exception) { null }
        // Do not use the VPN's own virtual DNS as its upstream resolver.
        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return
        val links = knownLinks ?: try { cm.getLinkProperties(network) } catch (_: Exception) { null }
        val servers = links?.dnsServers.orEmpty()
            .filter { it.address.size == 4 && !it.isAnyLocalAddress }.distinct()
        if (servers.isNotEmpty()) {
            networkDns[network] = servers
            upstreamDns = servers
            if (running) lastError = null
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivity = getSystemService(ConnectivityManager::class.java)
        try {
            val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build()
            connectivity?.registerNetworkCallback(request, networkCallback)
        } catch (_: Exception) { }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running) return START_STICKY
        try {
            startAsForeground()
            establishTunnel()
        } catch (e: Exception) {
            lastError = "Не вдалося запустити VPN foreground service: ${e.message ?: e.javaClass.simpleName}"
            running = false
            try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) { }
            stopSelf(startId)
        }
        return if (running) START_STICKY else START_NOT_STICKY
    }

    private fun startAsForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Фільтр сайтів", NotificationManager.IMPORTANCE_LOW))
        val notification: Notification = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Parent Control")
                .setContentText("Фільтр DNS активний")
                .setOngoing(true).build()
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this).setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Parent Control").setContentText("Фільтр DNS активний").setOngoing(true).build()
        }
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(NOTIFICATION_ID, notification)
    }

    private fun establishTunnel() {
        val servers = currentDnsServers()
        if (servers.isEmpty()) {
            lastError = "Не знайдено IPv4 DNS-сервер активної мережі"
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); return
        }
        upstreamDns = servers
        val established = try {
            Builder().setSession("Parent Control DNS filter")
                .addAddress("10.111.222.1", 32)
                .addDnsServer(VIRTUAL_DNS)
                .addRoute(VIRTUAL_DNS, 32)
                .setMtu(1500)
                .establish()
        } catch (e: Exception) {
            lastError = "Не вдалося створити VPN: ${e.message ?: e.javaClass.simpleName}"
            null
        }
        if (established == null) {
            if (lastError == null) lastError = "VPN permission missing or tunnel establish failed"
            stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); return
        }
        pfd = established
        stopping = false
        running = true
        lastError = null
        worker = thread(name = "pc-dns-filter", start = true) { runLoop(established) }
    }

    private fun currentDnsServers(): List<InetAddress> {
        val cached = networkDns.values.firstOrNull { it.isNotEmpty() }
        if (cached != null) return cached
        return try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val net = cm?.activeNetwork ?: return emptyList()
            val caps = cm.getNetworkCapabilities(net)
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return emptyList()
            cm.getLinkProperties(net)?.dnsServers.orEmpty()
                .filter { it.address.size == 4 && !it.isAnyLocalAddress }.distinct()
        } catch (_: Exception) { emptyList() }
    }

    private fun runLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (!stopping) {
                val length = input.read(buffer)
                if (length <= 0) continue
                try { handlePacket(buffer, length, output) } catch (_: Exception) { /* drop malformed packet */ }
            }
        } catch (_: Exception) {
            if (!stopping) lastError = "DNS tunnel read failed"
        } finally {
            try { input.close() } catch (_: Exception) { }
            try { output.close() } catch (_: Exception) { }
        }
    }

    private fun handlePacket(packet: ByteArray, length: Int, output: FileOutputStream) {
        if (length < 28) return
        val versionIhl = packet[0].toInt() and 0xff
        if ((versionIhl ushr 4) != 4) return
        val ipHeaderLength = (versionIhl and 0x0f) * 4
        if (ipHeaderLength < 20 || length < ipHeaderLength + 8) return
        if ((packet[9].toInt() and 0xff) != 17) return // UDP only
        val udpOffset = ipHeaderLength
        val destinationPort = u16(packet, udpOffset + 2)
        if (destinationPort != 53) return
        val destination = packet.copyOfRange(16, 20)
        if (!destination.contentEquals(InetAddress.getByName(VIRTUAL_DNS).address)) return
        val source = packet.copyOfRange(12, 16)
        val sourcePort = u16(packet, udpOffset)
        val dnsOffset = udpOffset + 8
        val dnsLength = length - dnsOffset
        if (dnsLength < 12) return
        val query = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        val host = parseQName(query) ?: return
        val response = if (isBlocked(host)) nxDomain(query) else forward(query) ?: run {
            lastError = "Не отримано відповідь від upstream DNS"
            return
        }
        output.write(buildReplyPacket(source, InetAddress.getByName(VIRTUAL_DNS).address, sourcePort, response))
    }

    private fun isBlocked(host: String): Boolean {
        val normalized = normalizeDomain(host) ?: return false
        return blockedDomains.any { raw ->
            val rule = normalizeDomain(raw) ?: return@any false
            normalized == rule || normalized.endsWith(".$rule")
        }
    }

    private fun normalizeDomain(value: String): String? = try {
        val trimmed = value.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (trimmed.isBlank()) null else java.net.IDN.toASCII(trimmed).lowercase(Locale.ROOT)
    } catch (_: Exception) { null }

    private fun parseQName(dns: ByteArray): String? {
        if (dns.size < 17) return null
        var pos = 12
        val labels = mutableListOf<String>()
        while (pos < dns.size) {
            val size = dns[pos].toInt() and 0xff
            if (size == 0) break
            if ((size and 0xc0) != 0 || size > 63 || pos + 1 + size > dns.size) return null
            labels += String(dns, pos + 1, size, Charsets.US_ASCII)
            pos += size + 1
            if (labels.sumOf { it.length + 1 } > 254) return null
        }
        return labels.takeIf { it.isNotEmpty() }?.joinToString(".")
    }

    private fun nxDomain(query: ByteArray): ByteArray {
        val response = query.copyOf()
        response[2] = ((response[2].toInt() and 0x79) or 0x80).toByte() // QR=1, preserve RD
        response[3] = ((response[3].toInt() and 0xf0) or 0x83).toByte() // RA=1, NXDOMAIN
        response[6] = 0; response[7] = 0; response[8] = 0; response[9] = 0
        response[10] = 0; response[11] = 0
        return response
    }

    private fun forward(query: ByteArray): ByteArray? {
        for (server in upstreamDns) {
            val socket = DatagramSocket()
            try {
                if (!protect(socket)) continue
                socket.soTimeout = 2500
                socket.send(DatagramPacket(query, query.size, server, 53))
                val response = ByteArray(4096)
                val reply = DatagramPacket(response, response.size)
                socket.receive(reply)
                return response.copyOfRange(0, reply.length)
            } catch (_: Exception) {
            } finally { socket.close() }
        }
        return null
    }

    private fun buildReplyPacket(clientIp: ByteArray, virtualIp: ByteArray, clientPort: Int, dns: ByteArray): ByteArray {
        val udpLength = 8 + dns.size
        val totalLength = 20 + udpLength
        val b = ByteBuffer.allocate(totalLength).order(ByteOrder.BIG_ENDIAN)
        b.put(0x45.toByte()); b.put(0); b.putShort(totalLength.toShort())
        b.putShort(0); b.putShort(0x4000.toShort()); b.put(64); b.put(17); b.putShort(0)
        b.put(virtualIp); b.put(clientIp)
        b.putShort(53.toShort()); b.putShort(clientPort.toShort())
        b.putShort(udpLength.toShort()); b.putShort(0); b.put(dns)
        val bytes = b.array(); val checksum = ipChecksum(bytes)
        bytes[10] = (checksum.toInt() ushr 8).toByte(); bytes[11] = checksum.toByte()
        return bytes
    }

    private fun u16(bytes: ByteArray, offset: Int): Int = ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
    private fun ipChecksum(header: ByteArray): Short {
        var sum = 0L; var i = 0
        while (i < 20) { sum += (((header[i].toInt() and 0xff) shl 8) or (header[i + 1].toInt() and 0xff)).toLong(); i += 2 }
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return (sum.inv() and 0xffff).toShort()
    }

    override fun onRevoke() {
        lastError = "VPN permission revoked by system/user"
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopping = true; running = false
        try { pfd?.close() } catch (_: Exception) { }
        worker?.interrupt(); pfd = null; worker = null
        networkDns.clear()
        try { connectivity?.unregisterNetworkCallback(networkCallback) } catch (_: Exception) { }
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}

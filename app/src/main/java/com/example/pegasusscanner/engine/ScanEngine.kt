package com.example.pegasusscanner.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.example.pegasusscanner.model.Finding
import com.example.pegasusscanner.model.Indicator
import com.example.pegasusscanner.model.IndicatorType
import com.example.pegasusscanner.model.ScanReport
import com.example.pegasusscanner.model.Severity
import java.io.File
import java.security.MessageDigest

class ScanEngine(private val context: Context) {

    private val riskyPermissions = setOf(
        android.Manifest.permission.RECORD_AUDIO,
        android.Manifest.permission.CAMERA,
        android.Manifest.permission.READ_SMS,
        android.Manifest.permission.RECEIVE_SMS,
        android.Manifest.permission.READ_CALL_LOG,
        android.Manifest.permission.READ_CONTACTS,
        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.BIND_ACCESSIBILITY_SERVICE,
        android.Manifest.permission.BIND_DEVICE_ADMIN,
        android.Manifest.permission.SYSTEM_ALERT_WINDOW
    )

    private val trustedInstallers = setOf(
        "com.android.vending",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.sec.android.app.samsungapps"
    )

    fun runScan(indicators: List<Indicator>, hashApks: Boolean = true): ScanReport {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)
        val packages: List<PackageInfo> = pm.getInstalledPackages(flags)

        val findings = mutableListOf<Finding>()
        val domainIndicators = indicators.filter { it.type == IndicatorType.DOMAIN }
        val packageIndicators = indicators.filter { it.type == IndicatorType.PACKAGE_NAME }.map { it.value }.toSet()
        val hashIndicators = indicators.filter { it.type == IndicatorType.FILE_HASH_SHA256 }.map { it.value }.toSet()
        val certIndicators = indicators.filter { it.type == IndicatorType.CERT_SHA256 }.map { it.value }.toSet()

        for (pkg in packages) {
            val appInfo = pkg.applicationInfo ?: continue
            val pkgName = pkg.packageName

            if (pkgName.lowercase() in packageIndicators) {
                findings += Finding(
                    title = "Known indicator package installed",
                    detail = "$pkgName matches a package name in your imported indicator list.",
                    severity = Severity.HIGH,
                    packageName = pkgName
                )
            }

            if (hashApks && hashIndicators.isNotEmpty()) {
                sha256OfFile(appInfo.sourceDir)?.let { hash ->
                    if (hash in hashIndicators) {
                        findings += Finding(
                            title = "Known indicator file hash matched",
                            detail = "$pkgName's installed APK hash matches an imported indicator.",
                            severity = Severity.HIGH,
                            packageName = pkgName
                        )
                    }
                }
            }

            if (certIndicators.isNotEmpty()) {
                signingCertSha256(pkg)?.forEach { certHash ->
                    if (certHash in certIndicators) {
                        findings += Finding(
                            title = "Known indicator signing certificate matched",
                            detail = "$pkgName is signed with a certificate matching an imported indicator.",
                            severity = Severity.HIGH,
                            packageName = pkgName
                        )
                    }
                }
            }

            val isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (!isSystemApp) {
                findings += heuristicChecks(pm, pkg, appInfo)
            }
        }

        if (domainIndicators.isNotEmpty()) {
            findings += Finding(
                title = "Network-level indicators not checked",
                detail = "${domainIndicators.size} domain indicator(s) were imported, but this app " +
                    "cannot inspect network traffic without a VPN/packet-capture component. " +
                    "Use a network monitoring tool (e.g. Wireshark, NetGuard logs, or your router's " +
                    "DNS logs) to check outbound connections against these domains.",
                severity = Severity.INFO
            )
        }

        findings += Finding(
            title = "Scan limitations",
            detail = "This scan can only see installed apps, their permissions, and their files. " +
                "It cannot detect memory-resident or zero-click implants that leave no installed " +
                "package. For a rigorous check, use Amnesty International's MVT tool on a full " +
                "device backup, or consult a digital forensics professional.",
            severity = Severity.INFO
        )

        return ScanReport(
            findings = findings.sortedByDescending { it.severity.ordinal },
            scannedAppCount = packages.size,
            indicatorCount = indicators.size,
            timestampMillis = System.currentTimeMillis()
        )
    }

    private fun heuristicChecks(pm: PackageManager, pkg: PackageInfo, appInfo: ApplicationInfo): List<Finding> {
        val out = mutableListOf<Finding>()
        val pkgName = pkg.packageName
        val installerPackage = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkgName)
            }
        } catch (e: Exception) {
            null
        }
        val sideloaded = installerPackage == null || installerPackage !in trustedInstallers

        val requestedPerms = pkg.requestedPermissions?.toList() ?: emptyList()
        val grantedRisky = requestedPerms.filter { it in riskyPermissions }

        val hasNoLauncherIcon = pm.getLaunchIntentForPackage(pkgName) == null

        val usesAccessibility = android.Manifest.permission.BIND_ACCESSIBILITY_SERVICE in requestedPerms
        val usesDeviceAdmin = android.Manifest.permission.BIND_DEVICE_ADMIN in requestedPerms

        if (sideloaded && hasNoLauncherIcon && grantedRisky.size >= 2) {
            out += Finding(
                title = "Sideloaded hidden app with sensitive permissions",
                detail = "$pkgName was not installed from a known app store, has no visible launcher " +
                    "icon, and requests ${grantedRisky.size} sensitive permissions " +
                    "(${grantedRisky.joinToString { it.substringAfterLast('.') }}). This combination " +
                    "is common in stalkerware/spyware, though it can also occur with legitimate " +
                    "device-management or accessibility tools.",
                severity = Severity.HIGH,
                packageName = pkgName
            )
        } else if (usesAccessibility && sideloaded) {
            out += Finding(
                title = "Sideloaded app using Accessibility Service",
                detail = "$pkgName is sideloaded and can use Android's Accessibility Service, which " +
                    "grants broad ability to read screen content and simulate input. Worth reviewing " +
                    "if you don't recognize or use this app.",
                severity = Severity.MEDIUM,
                packageName = pkgName
            )
        } else if (usesDeviceAdmin && sideloaded) {
            out += Finding(
                title = "Sideloaded app with Device Admin rights",
                detail = "$pkgName is sideloaded and has requested Device Administrator privileges.",
                severity = Severity.MEDIUM,
                packageName = pkgName
            )
        } else if (hasNoLauncherIcon && grantedRisky.isNotEmpty() && sideloaded) {
            out += Finding(
                title = "Hidden sideloaded app with sensitive permission",
                detail = "$pkgName has no launcher icon and was not installed via a known app store.",
                severity = Severity.LOW,
                packageName = pkgName
            )
        }

        return out
    }

    private fun sha256OfFile(path: String): String? {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            File(path).inputStream().use { input ->
                val buffer = ByteArray(8192)
                var read: Int
                while (input.read(buffer).also { read = it } != -1) {
                    digest.update(buffer, 0, read)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            null
        }
    }

    private fun signingCertSha256(pkg: PackageInfo): List<String>? {
        return try {
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkg.signingInfo?.let {
                    if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory
                }
            } else {
                @Suppress("DEPRECATION")
                pkg.signatures
            }
            signatures?.map { sig ->
                val digest = MessageDigest.getInstance("SHA-256")
                digest.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }.lowercase()
            }
        } catch (e: Exception) {
            null
        }
    }
}

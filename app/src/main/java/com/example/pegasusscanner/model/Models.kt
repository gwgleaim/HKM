package com.example.pegasusscanner.model

/** Severity of a finding surfaced by the scan. This is a triage signal, not a verdict. */
enum class Severity { INFO, LOW, MEDIUM, HIGH }

/** A single observation produced by the scan engine. */
data class Finding(
    val title: String,
    val detail: String,
    val severity: Severity,
    val packageName: String? = null
)

/** A compromise indicator loaded from an IOC file (e.g. an Amnesty MVT STIX2 export). */
data class Indicator(
    val type: IndicatorType,
    val value: String,
    val description: String = ""
)

enum class IndicatorType { PACKAGE_NAME, DOMAIN, PROCESS_NAME, FILE_HASH_SHA256, CERT_SHA256 }

/** Result of a full scan pass. */
data class ScanReport(
    val findings: List<Finding>,
    val scannedAppCount: Int,
    val indicatorCount: Int,
    val timestampMillis: Long
)

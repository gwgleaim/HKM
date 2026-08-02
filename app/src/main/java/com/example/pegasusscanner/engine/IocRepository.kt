package com.example.pegasusscanner.engine

import android.content.Context
import android.net.Uri
import com.example.pegasusscanner.model.Indicator
import com.example.pegasusscanner.model.IndicatorType
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream

/**
 * Loads indicator-of-compromise data.
 *
 * IMPORTANT: this app does NOT ship with a real Pegasus indicator database, because any such
 * list goes stale within weeks and a fabricated or outdated one would give false confidence.
 * Instead, users should download current indicators from Amnesty International's Security Lab
 * (https://github.com/AmnestyTech/investigations) or run them through the official MVT project
 * (https://github.com/mvt-project/mvt) and import the resulting STIX2 file here.
 *
 * This repository understands two formats:
 *  1. A minimal custom JSON array (see assets/sample_iocs.json for the schema).
 *  2. STIX2 "indicator" bundles, from which it extracts domain-name, file hash, and process
 *     name patterns using lightweight pattern matching (a full STIX2 parser is out of scope).
 */
class IocRepository(private val context: Context) {

    fun loadBundledSample(): List<Indicator> {
        context.assets.open("sample_iocs.json").use { input ->
            return parseCustomJson(input)
        }
    }

    fun loadFromUri(uri: Uri): List<Indicator> {
        val resolver = context.contentResolver
        val text = resolver.openInputStream(uri)?.use { it.bufferedReader().readText() } ?: ""
        return if (looksLikeStix(text)) {
            parseStix2(text)
        } else {
            parseCustomJson(text.byteInputStream())
        }
    }

    private fun looksLikeStix(text: String): Boolean {
        return text.contains("\"type\": \"indicator\"") || text.contains("\"type\":\"indicator\"") ||
            text.contains("\"spec_version\"")
    }

    private fun parseCustomJson(input: InputStream): List<Indicator> {
        val text = input.bufferedReader().readText()
        val arr = JSONArray(text)
        val out = mutableListOf<Indicator>()
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            val type = when (obj.optString("type")) {
                "package_name" -> IndicatorType.PACKAGE_NAME
                "domain" -> IndicatorType.DOMAIN
                "process_name" -> IndicatorType.PROCESS_NAME
                "file_hash_sha256" -> IndicatorType.FILE_HASH_SHA256
                "cert_sha256" -> IndicatorType.CERT_SHA256
                else -> continue
            }
            out.add(
                Indicator(
                    type = type,
                    value = obj.optString("value").trim().lowercase(),
                    description = obj.optString("description", "")
                )
            )
        }
        return out
    }

    /**
     * Best-effort extraction of indicators from a STIX2 bundle's "pattern" fields, e.g.
     * "[domain-name:value = 'evil.example.com']" or "[file:hashes.'SHA-256' = 'abc123...']".
     */
    private fun parseStix2(text: String): List<Indicator> {
        val out = mutableListOf<Indicator>()
        val bundle = JSONObject(text)
        val objects: JSONArray = when {
            bundle.has("objects") -> bundle.getJSONArray("objects")
            else -> JSONArray().apply { put(bundle) }
        }
        val domainRegex = Regex("domain-name:value\\s*=\\s*'([^']+)'")
        val hashRegex = Regex("hashes\\.'?SHA-256'?\\s*=\\s*'([0-9a-fA-F]{64})'")
        val processRegex = Regex("process:name\\s*=\\s*'([^']+)'")

        for (i in 0 until objects.length()) {
            val obj = objects.getJSONObject(i)
            if (obj.optString("type") != "indicator") continue
            val pattern = obj.optString("pattern")
            val description = obj.optString("description", obj.optString("name", ""))

            domainRegex.findAll(pattern).forEach {
                out.add(Indicator(IndicatorType.DOMAIN, it.groupValues[1].trim().lowercase(), description))
            }
            hashRegex.findAll(pattern).forEach {
                out.add(Indicator(IndicatorType.FILE_HASH_SHA256, it.groupValues[1].trim().lowercase(), description))
            }
            processRegex.findAll(pattern).forEach {
                out.add(Indicator(IndicatorType.PROCESS_NAME, it.groupValues[1].trim().lowercase(), description))
            }
        }
        return out
    }
}

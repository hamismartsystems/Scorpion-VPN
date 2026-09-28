package com.v2ray.ang.handler

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.RoutingType
import java.util.Locale

/**
 * Scorpion VPN — Iranian apps go DIRECT by default.
 *
 * On first launch we scan installed packages and enable per-app proxy in
 * bypass mode with every Iranian app pre-ticked, so users do not have to
 * configure anything manually. Also keeps routing rulesets free of geosite
 * rules that the bundled geosite.dat does not contain (crash protection).
 */
object IranDirect {

    private const val SEEDED = "pref_scorpion_iran_direct_v1"
    private const val ROUTING_FIX = "pref_scorpion_routing_fix_v3"

    /** well-known Iranian apps whose package does not start with "ir." */
    private val KNOWN = setOf(
        "com.farsitel.bazaar",      // Cafe Bazaar
        "ir.mservices.market",      // Myket
        "cab.snapp.passenger",      // Snapp
        "com.tapsi.passenger",      // Tapsi
        "ir.divar",                 // Divar
        "com.aparat.android",       // Aparat
        "com.samanpr.blu",          // BluBank
        "com.asanpardakht",         // Asan Pardakht
        "com.isc.sep",              // SEP
    )

    fun seed(context: Context) {
        forceCleanIranRouting(context)
        if (MmkvManager.decodeSettingsBool(SEEDED, false)) return
        try {
            val found = linkedSetOf<String>()
            context.packageManager.getInstalledPackages(0).forEach { pi ->
                pi.packageName?.let { pkg ->
                    if (shouldBypass(pkg)) found.add(pkg)
                }
            }
            MmkvManager.encodeSettings(AppConfig.PREF_PER_APP_PROXY, true)
            MmkvManager.encodeSettings(AppConfig.PREF_BYPASS_APPS, true)
            MmkvManager.encodeSettings(AppConfig.PREF_PER_APP_PROXY_SET, found)
            MmkvManager.encodeSettings(SEEDED, true)
        } catch (_: Exception) {
            // never block app start because of a scan failure
            MmkvManager.encodeSettings(SEEDED, true)
        }
    }

    fun forceCleanIranRouting(context: Context) {
        if (MmkvManager.decodeSettingsBool(ROUTING_FIX, false)) {
            stripIllegalGeo()
            return
        }
        SettingsManager.resetRoutingRulesetsFromPresets(context, RoutingType.WHITE_IRAN)
        stripIllegalGeo()
        MmkvManager.encodeSettings(ROUTING_FIX, true)
    }

    /** remove geosite rules that the bundled geosite.dat does not have */
    fun stripIllegalGeo() {
        val rulesets = MmkvManager.decodeRoutingRulesets() ?: return
        var changed = false
        for (item in rulesets) {
            val domain = item.domain ?: continue
            val cleaned = domain.filter { isSafeDomainRule(it) }
            if (cleaned.size != domain.size) {
                item.domain = cleaned
                changed = true
            }
        }
        if (changed) MmkvManager.encodeRoutingRulesets(rulesets)
    }

    fun isSafeDomainRule(rule: String): Boolean {
        val r = rule.trim().lowercase(Locale.ROOT)
        if (r == "geosite:ir" || r == "geosite:category-ir") return false
        if (r.startsWith("geosite:")) {
            return !(r.endsWith(":ir") || r.endsWith("-ir"))
        }
        return true
    }

    private fun shouldBypass(pkg: String): Boolean {
        val p = pkg.lowercase(Locale.ROOT)
        if (p.startsWith("ir.") || p in KNOWN) return true
        // Iranian bank / payment apps
        return p.contains("shaparak") || p.contains("mellat") ||
                p.contains("saderat") || p.contains("tejarat")
    }
}

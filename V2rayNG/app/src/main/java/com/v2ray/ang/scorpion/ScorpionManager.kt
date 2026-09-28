package com.v2ray.ang.scorpion

import com.v2ray.ang.BuildConfig

/**
 * Scorpion VPN — HAMI SMART SYSTEMS
 * Brand/update anchors. The update manifest lives in the GitHub repo so a
 * new release is visible to the app without touching the website.
 * (Companion manifest file: repo root /update.json — keep the app's
 * CONTRACT (schema) identical to the site's apps/update.json.)
 */
object ScorpionManager {

    const val SITE_URL = "https://hamidesigns.shop"
    const val CONFIG_PAGE_URL = "https://hamidesigns.shop/add-config.html"

    /** Update manifest served from the repo (single source of truth). */
    const val MANIFEST_URL =
        "https://raw.githubusercontent.com/hamismartsystems/Scorpion-VPN/master/update.json"

    const val USER_AGENT = "ScorpionVPN-Android"

    fun currentAppVersion(): String = BuildConfig.VERSION_NAME

    /** semver-ish compare: returns a-b by numeric dot parts */
    fun compareVersions(a: String, b: String): Int {
        val v1 = a.split(".")
        val v2 = b.split(".")
        val n = maxOf(v1.size, v2.size)
        for (i in 0 until n) {
            val n1 = if (i < v1.size) v1[i].toIntOrNull() ?: 0 else 0
            val n2 = if (i < v2.size) v2[i].toIntOrNull() ?: 0 else 0
            if (n1 != n2) return n1 - n2
        }
        return 0
    }
}

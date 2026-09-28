package com.v2ray.ang.scorpion

import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Scorpion VPN - لایه‌ی اختصاصی scorpion://
 * معادل ۱:۱ با scorpion_config.py (AES-256-GCM)
 */
object ScorpionCodec {
    private const val MAGIC = "scorpion://v1."

    private val KEY: ByteArray by lazy {
        MessageDigest.getInstance("SHA-256")
            .digest("HSS-SCORPION-VPN-2026-SECRET".toByteArray(Charsets.UTF_8))
    }

    fun isScorpion(uri: String): Boolean =
        uri.trim().startsWith(MAGIC)

    fun decode(uri: String): String {
        val body = uri.trim().removePrefix(MAGIC)
        val raw = Base64.decode(body, Base64.URL_SAFE or Base64.NO_WRAP)
        require(raw.size >= 12 + 16 + 1) { "bad scorpion payload" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(KEY, "AES"),
            GCMParameterSpec(128, raw.copyOfRange(0, 12))
        )
        return String(cipher.doFinal(raw.copyOfRange(12, raw.size)), Charsets.UTF_8)
    }
}

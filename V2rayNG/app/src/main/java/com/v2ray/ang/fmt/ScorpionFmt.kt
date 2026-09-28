package com.v2ray.ang.fmt

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.scorpion.ScorpionCodec

/**
 * پارسر قالب اختصاصی scorpion://
 * ابتدا رمزگشایی می‌کند، سپس به پارسر استانداردِ پروتکلِ داخلش می‌سپارد.
 */
object ScorpionFmt {
    fun parse(str: String): ProfileItem? {
        val plain = try {
            ScorpionCodec.decode(str)
        } catch (e: Exception) {
            return null
        }
        return when {
            plain.startsWith("vmess://") -> VmessFmt.parse(plain)
            plain.startsWith("vless://") -> VlessFmt.parse(plain)
            plain.startsWith("ss://") -> ShadowsocksFmt.parse(plain)
            plain.startsWith("trojan://") -> TrojanFmt.parse(plain)
            plain.startsWith("socks://") -> SocksFmt.parse(plain)
            plain.startsWith("socks4://") -> SocksFmt.parse(plain)
            else -> null
        }
    }
}

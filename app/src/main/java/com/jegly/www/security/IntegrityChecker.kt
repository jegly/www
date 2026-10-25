package com.jegly.www.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/**
 * Compares the running APK's current signing certificate against the expected SHA-256 digest.
 * Returns true if the APK signature matches; false if the app has been re-signed
 * (repackaging, modding).
 *
 * Catch: trivially defeated by an attacker who can also patch this file, so it's defense-in-depth,
 * not a security boundary. Useful for detecting "casual" tampering by users running modded APKs.
 */
object IntegrityChecker {

    // Expected signing-cert SHA-256 digests, stored XOR-masked (never as greppable hex — string
    // literals survive R8) and compared as raw bytes. M = jegly key0 (98d324d4…),
    // P = ML-DSA-87 PQC key (5f99de5b…).
    // API 37+ verifies the APK Signature Scheme v3.2 hybrid block, so the current signer is the PQC
    // key there. key0 is deliberately NOT accepted on API 37+: an APK re-signed with only key0 would
    // otherwise pass. Older releases ignore v3.2 and still see key0.
    private val K = intArrayOf(0xB9, 0xAA, 0x46, 0x3F, 0xCA, 0xF4, 0x3D, 0xBC, 0x84)
    private val M = intArrayOf(
        0x21, 0x79, 0x62, 0xEB, 0xDA, 0x9E, 0x0B, 0x30, 0xE6, 0xCB, 0x30, 0x4C, 0x1B, 0x13, 0x58, 0xA7,
        0xD7, 0xC3, 0x41, 0x06, 0x0A, 0x5A, 0x4F, 0xC0, 0xB8, 0x8D, 0x74, 0x57, 0xE4, 0xF0, 0x9F, 0x86,
    )
    private val P = intArrayOf(
        0xE6, 0x33, 0x98, 0x64, 0xFB, 0x61, 0x48, 0x81, 0xCB, 0x51, 0x77, 0xED, 0xD4, 0x18, 0x0F, 0x1A,
        0x89, 0xEF, 0x98, 0xA3, 0x90, 0xC4, 0x78, 0xB3, 0x22, 0x77, 0x39, 0x4B, 0xB0, 0xD8, 0x49, 0x6C,
    )

    /** Reconstruct the expected 32-byte cert digest from the masked form (never materialized as hex). */
    private fun expected(): ByteArray {
        val masked = if (Build.VERSION.SDK_INT >= 37) P else M
        return ByteArray(masked.size) { (masked[it] xor K[it % K.size]).toByte() }
    }

    /** Returns true if the current signer matches, or the APK is debuggable. */
    fun verifySignature(context: Context): Boolean {
        // Debug builds are signed with ~/.android/debug.keystore (per-machine, per-developer).
        // The integrity check is only meaningful for released APKs distributed publicly.
        if ((context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) return true
        return runCatching { currentSignerMatches(context) }.getOrElse { false }
    }

    private fun currentSignerMatches(context: Context): Boolean {
        val pm = context.packageManager
        val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        // Current signer only — never signingCertificateHistory, which still contains key0.
        val signers = info.signingInfo?.apkContentsSigners ?: return false
        val md = MessageDigest.getInstance("SHA-256")
        val want = expected()
        return signers.any { sig ->
            md.reset()
            md.digest(sig.toByteArray()).contentEquals(want)
        }
    }
}

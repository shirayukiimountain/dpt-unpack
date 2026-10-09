package dev.shi.unpack

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.regex.Pattern
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

data class DptConfig(
    val aesKey: ByteArray,
    val appName: String,
    val acfName: String?,
    val jniClsName: String?,
    val junkClsName: String?,
    val dexSign: String?,
    val insnsXorKey: Int? = null,
    val isRc4Mode: Boolean = true
)

object DptCrypto {

    private val KNOWN_VERSIONS = listOf(
        "2.19.2", "2.19.1", "2.19.0", "2.18.0", "2.17.0",
        "2.16.1", "2.16.0", "2.15.0", "2.14.0", "2.13.0",
        "2.12.1", "2.12.0", "2.11.2", "2.11.1", "2.11.0", "2.10.0"
    )

    fun buildInsnsRc4Key(aesKey: ByteArray, methodIndex: Int): ByteArray {
        val buf = ByteBuffer.allocate(aesKey.size + 4).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(aesKey)
        buf.putInt(methodIndex)
        return buf.array()
    }

    fun rc4Crypt(key: ByteArray, data: ByteArray): ByteArray {
        val s = IntArray(256) { it }
        var j = 0
        for (i in 0 until 256) {
            j = (j + s[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
            val tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
        }
        val out = ByteArray(data.size)
        var i = 0
        j = 0
        for (k in data.indices) {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val tmp = s[i]
            s[i] = s[j]
            s[j] = tmp
            out[k] = (data[k].toInt() xor s[(s[i] + s[j]) and 0xFF]).toByte()
        }
        return out
    }

    fun hmacSha256(key: ByteArray, message: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message.toByteArray(StandardCharsets.UTF_8))
    }

    fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, cipherText: ByteArray): ByteArray? {
        return runCatching {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            cipher.doFinal(cipherText)
        }.getOrNull()
    }

    fun generateAyKey(seed: Long): Long {
        var key = seed
        key = key xor (key ushr 33)
        key *= -49064778989728563L // 0xff51afd7ed558ccdL
        key = key xor (key ushr 33)
        key *= -4265267296055464877L // 0xc4ceb9fe1a85ec53L
        key = key xor (key ushr 33)
        key = key or 0x0101010101010101L
        return key
    }

    fun parsePackageNameFromManifest(manifestFile: File): String? {
        if (!manifestFile.exists()) return null
        return runCatching {
            val data = manifestFile.readBytes()
            val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

            val stringCount = buf.getInt(16)
            val flags = buf.getInt(24)
            val stringsStart = buf.getInt(28)
            val isUtf8 = (flags and (1 shl 8)) != 0

            val stringOffsets = IntArray(stringCount) { buf.getInt(36 + it * 4) }
            val strings = ArrayList<String>(stringCount)

            for (off in stringOffsets) {
                var pos = 8 + stringsStart + off
                if (pos >= data.size) {
                    strings.add("")
                    continue
                }
                if (isUtf8) {
                    if ((data[pos].toInt() and 0x80) != 0) pos += 2 else pos += 1
                    val bLen: Int
                    if ((data[pos].toInt() and 0x80) != 0) {
                        bLen = ((data[pos].toInt() and 0x7F) shl 8) or (data[pos + 1].toInt() and 0xFF)
                        pos += 2
                    } else {
                        bLen = data[pos].toInt() and 0xFF
                        pos += 1
                    }
                    val s = if (pos + bLen <= data.size) String(data, pos, bLen, StandardCharsets.UTF_8) else ""
                    strings.add(s)
                } else {
                    val uLen = buf.getShort(pos).toInt() and 0xFFFF
                    val s = if (pos + 2 + uLen * 2 <= data.size) {
                        String(data, pos + 2, uLen * 2, StandardCharsets.UTF_16LE)
                    } else ""
                    strings.add(s)
                }
            }

            var idx = 0
            while (idx < data.size - 4) {
                if (data[idx] == 0x02.toByte() && data[idx + 1] == 0x01.toByte() &&
                    data[idx + 2] == 0x10.toByte() && data[idx + 3] == 0x00.toByte()
                ) {
                    break
                }
                idx += 4
            }
            if (idx >= data.size - 36) return@runCatching null

            val attrStart = buf.getShort(idx + 24).toInt() and 0xFFFF
            val attrCount = buf.getShort(idx + 28).toInt() and 0xFFFF

            val attrPos = idx + 16 + attrStart
            for (i in 0 until attrCount) {
                val aOffset = attrPos + i * 20
                if (aOffset + 20 > data.size) break
                val attrNameIdx = buf.getInt(aOffset + 4)
                val attrValStrIdx = buf.getInt(aOffset + 8)

                val aName = if (attrNameIdx in strings.indices) strings[attrNameIdx] else ""
                if (aName == "package" && attrValStrIdx in strings.indices) {
                    return@runCatching strings[attrValStrIdx]
                }
            }
            null
        }.getOrNull()
    }

    fun recoverDptConfig(tempApkDir: File, manualKey: String? = null): DptConfig? {
        val configFile = File(tempApkDir, "assets/d_shell_data_001")
        if (!configFile.exists()) {
            return null
        }
        val configBytes = configFile.readBytes()

        val manifestFile = File(tempApkDir, "AndroidManifest.xml")
        val packageName = parsePackageNameFromManifest(manifestFile)
        if (packageName == null) {
            System.err.println("  [WARNING] Unable to extract package name from AndroidManifest.xml")
        }

        val soFiles = findCandidateSoFiles(tempApkDir)
        if (soFiles.isEmpty()) {
            System.err.println("  [WARNING] No native shell library (.so) found in APK.")
            return null
        }

        // If manual key is provided and is a 32-byte hex AES key
        if (manualKey != null && manualKey.length == 64 && manualKey.all { it in "0123456789abcdefABCDEF" }) {
            val aesKey = manualKey.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            for (soFile in soFiles) {
                val rk = ElfParser.extractSymbol(soFile, "DPT_UNKNOWN_DATA") ?: continue
                val iv = rk.clone().apply { this[3] = 0x2f; this[9] = 0x76 }
                val dec = aesCbcDecrypt(aesKey, iv, configBytes)
                if (dec != null && String(dec).contains("app_name")) {
                    return parseJsonConfig(aesKey, String(dec, StandardCharsets.UTF_8))
                }
            }
        }

        // Search for randomKey in SO files
        var randomKey: ByteArray? = null
        for (so in soFiles) {
            val k = ElfParser.extractSymbol(so, "DPT_UNKNOWN_DATA")
            if (k != null) {
                randomKey = k
                break
            }
        }

        if (randomKey == null) {
            for (so in soFiles) {
                val bytes = so.readBytes()
                for (i in 0 until bytes.size - 16) {
                    if (bytes[i + 3] == 0x20.toByte() && bytes[i + 9] == 0x74.toByte()) {
                        randomKey = ByteArray(16)
                        System.arraycopy(bytes, i, randomKey, 0, 16)
                        break
                    }
                }
                if (randomKey != null) break
            }
        }

        if (randomKey == null) {
            System.err.println("  [WARNING] Unable to find DPT_UNKNOWN_DATA random key in native libraries.")
            return null
        }

        val iv = randomKey.clone().apply {
            this[3] = 0x2f
            this[9] = 0x76
        }

        // If manual build-key or version was passed
        if (manualKey != null && packageName != null) {
            val keyMaterial = "${packageName}_$manualKey"
            val aesKey = hmacSha256(randomKey, keyMaterial)
            val dec = aesCbcDecrypt(aesKey, iv, configBytes)
            if (dec != null && String(dec).contains("app_name")) {
                return parseJsonConfig(aesKey, String(dec, StandardCharsets.UTF_8))
            }
        }

        if (packageName != null) {
            // Step 1: Check known DPT-Shell version tags (v2.10 - v2.19)
            val versionsToTry = mutableListOf<String>()
            for (v in KNOWN_VERSIONS) {
                versionsToTry.add(v)
                versionsToTry.add("v$v")
            }
            for (ver in versionsToTry) {
                val keyMaterial = "${packageName}_$ver"
                val aesKey = hmacSha256(randomKey, keyMaterial)
                val dec = aesCbcDecrypt(aesKey, iv, configBytes)
                if (dec != null) {
                    val jsonStr = String(dec, StandardCharsets.UTF_8)
                    if (jsonStr.contains("app_name")) {
                        return parseJsonConfig(aesKey, jsonStr)
                    }
                }
            }

            // Step 2: Auto-discover buildKey from SO files (v2.20+)
            for (so in soFiles) {
                val soBytes = so.readBytes()
                val candidateBuildKeys = scanBuildKeysFromSo(soBytes)
                for (bKey in candidateBuildKeys) {
                    val keyMaterial = "${packageName}_$bKey"
                    val aesKey = hmacSha256(randomKey, keyMaterial)
                    val dec = aesCbcDecrypt(aesKey, iv, configBytes)
                    if (dec != null) {
                        val jsonStr = String(dec, StandardCharsets.UTF_8)
                        if (jsonStr.contains("app_name")) {
                            return parseJsonConfig(aesKey, jsonStr)
                        }
                    }
                }
            }
        }

        return null
    }

    private fun findCandidateSoFiles(dir: File): List<File> {
        val list = mutableListOf<File>()
        dir.walkTopDown().forEach { file ->
            if (file.isFile && file.name.endsWith(".so")) {
                if (file.path.contains("vwwwwwvwww") || file.name.startsWith("lib")) {
                    list.add(file)
                }
            }
        }
        return list.sortedWith(compareByDescending<File> {
            when {
                it.path.contains("arm64") -> 4
                it.path.contains("x86_64") -> 3
                it.path.contains("x86") -> 2
                it.path.contains("arm") -> 1
                else -> 0
            }
        }.thenByDescending { it.length() })
    }

    private fun scanBuildKeysFromSo(soBytes: ByteArray): Set<String> {
        val candidates = mutableSetOf<String>()
        if (soBytes.size < 16) return candidates

        val longToOffsets = HashMap<Long, MutableList<Int>>()
        val buf = ByteBuffer.wrap(soBytes).order(ByteOrder.LITTLE_ENDIAN)

        for (i in 0 until soBytes.size - 8 step 4) {
            val v = buf.getLong(i)
            longToOffsets.computeIfAbsent(v) { ArrayList() }.add(i)
        }

        for (line in 1..2500) {
            val k = generateAyKey(line.toLong())
            val offsets = longToOffsets[k] ?: continue

            for (found in offsets) {
                val start = maxOf(0, found - 256)
                val end = minOf(soBytes.size, found + 256)

                for (p in start until end - 16) {
                    val candidateBytes = ByteArray(16)
                    System.arraycopy(soBytes, p, candidateBytes, 0, 16)
                    for (b in 0 until 16) {
                        candidateBytes[b] = (candidateBytes[b].toLong() xor (k ushr ((b % 8) * 8))).toByte()
                    }
                    val nullIdx = candidateBytes.indexOf(0.toByte())
                    if (nullIdx in 8..16) {
                        val str = String(candidateBytes, 0, nullIdx, StandardCharsets.US_ASCII)
                        if (str.all { it in "0123456789abcdef" }) {
                            candidates.add(str)
                        }
                    }
                }
            }
        }
        return candidates
    }

    private fun parseJsonConfig(aesKey: ByteArray, json: String): DptConfig {
        fun extract(key: String): String? {
            val matcher = Pattern.compile("\"$key\"\\s*:\\s*\"([^\"]+)\"").matcher(json)
            return if (matcher.find()) matcher.group(1) else null
        }

        fun extractInt(key: String): Int? {
            val matcher = Pattern.compile("\"$key\"\\s*:\\s*(-?[0-9]+)").matcher(json)
            return if (matcher.find()) matcher.group(1).toIntOrNull() else null
        }

        val appName = extract("app_name") ?: ""
        val acfName = extract("acf_name")
        val jniClsName = extract("jni_cls_name")
        val junkClsName = extract("junk_cls_name")
        val dexSign = extract("dex_sign")
        val insnsXorKey = extractInt("insns_xor_key")
        val isRc4Mode = (insnsXorKey == null)

        return DptConfig(aesKey, appName, acfName, jniClsName, junkClsName, dexSign, insnsXorKey, isRc4Mode)
    }
}

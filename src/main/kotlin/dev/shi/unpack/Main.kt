package dev.shi.unpack

import com.android.dex.ClassData
import com.android.dex.ClassDef
import com.android.dex.Dex
import dev.shi.unpack.DexUtils
import org.apache.commons.cli.DefaultParser
import org.apache.commons.cli.HelpFormatter
import org.apache.commons.cli.Options
import java.io.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

object Main {

    data class Instruction(val methodIndex: Int, val instructionsData: ByteArray)
    data class DexCodeOffset(val dexIndex: Int, val offset: Int)

    @JvmStatic
    fun main(args: Array<String>) {
        runCatching { run(args) }
            .onFailure { e -> 
                System.err.println("[FATAL] ${e.message}")
                e.printStackTrace()
            }
    }

    private fun run(args: Array<String>) {
        val options = createOptions()
        val cmd = DefaultParser().parse(options, args)

        if (cmd.hasOption("h")) {
            HelpFormatter().printHelp("java -jar unpack-dpt.jar", options)
            return
        }

        val inputFilePath = cmd.getOptionValue("f") ?: run {
            HelpFormatter().printHelp("java -jar unpack-dpt.jar", options)
            return
        }

        val inputFile = File(inputFilePath).takeIf { it.exists() } ?: run {
            System.err.println("[ERROR] Input file not found: ${inputFilePath}")
            return
        }

        val outputDir = File(cmd.getOptionValue("o", "unpacked")).apply { mkdirs() }
        displayInitialInfo(inputFile, outputDir)

        val tempApkUnzipDir = File(outputDir, "temp_apk_unzip").apply { mkdirs() }
        println("\n[PROCESS] Extracting APK... ")
        unzip(inputFile, tempApkUnzipDir)
        println("done.")

        val classesDexFile = File(tempApkUnzipDir, "classes.dex")
        val ooooooOoooFile = File(tempApkUnzipDir, "assets/OoooooOooo")

        if (!classesDexFile.exists() || !ooooooOoooFile.exists()) {
            System.err.println("\n[ERROR] This APK does not appear to be protected by dpt-shell.")
            deleteDirectory(tempApkUnzipDir)
            return
        }

        println("[PROCESS] Extracting compressed DEX data... ")
        val extractedZipFile = extractZipFromDex(classesDexFile, outputDir)
        println("done.")

        val hollowedDexDir = File(outputDir, "patched_dex").apply { mkdirs() }
        println("[PROCESS] Extracting DEX files... ")
        unzip(extractedZipFile, hollowedDexDir)
        println("done.")

        println("\n[PROCESS] Parsing instruction data from OoooooOooo:")
        val allInstructions = parseOoooooOooo(ooooooOoooFile)
        val removeJniBridge = cmd.hasOption("r")

        println("\n[PROCESS] Patching DEX files...")
        patchDexFiles(hollowedDexDir, allInstructions, removeJniBridge)

        println("[SUCCESS] Patching completed.")
        identifyApplicationClass(hollowedDexDir)

        cleanup(extractedZipFile, tempApkUnzipDir)
    }

    private fun createOptions(): Options {
        return Options().apply {
            addOption("h", "help", false, "Print this help message")
            addOption("f", "file", true, "Path to input APK file")
            addOption("o", "output", true, "Output directory (default: unpacked)")
            addOption("r", "remove-jni-bridge", false, "Remove JNI bridge call from <clinit>")
        }
    }

    private fun displayInitialInfo(inputFile: File, outputDir: File) {
        println("=============================================")
        println("=======      DPT-Shell Unpacker       =======")
        println("=============================================\n")
        println("[INFO] Input : ${inputFile.absolutePath}")
        println("[INFO] Output: ${outputDir.absolutePath}")
    }

    private fun patchDexFiles(hollowedDexDir: File, allInstructions: Map<Int, List<Instruction>>, removeJniBridge: Boolean) {
        for ((dexIndex, instructions) in allInstructions) {
            val dexName = if (dexIndex == 0) "classes.dex" else "classes${dexIndex + 1}.dex"
            val dexFile = File(hollowedDexDir, dexName)

            when {
                dexFile.exists() && instructions.isNotEmpty() -> {
                    patchDexFile(dexFile, instructions, removeJniBridge)
                    println("  > ${dexFile.name} (${instructions.size} methods) ... OK")
                }
                dexFile.exists() -> println("  > ${dexFile.name} (no instructions)... skipped")
                else -> println("  [WARNING] DEX file not found: ${dexFile.name}")
            }
        }
    }

    private fun identifyApplicationClass(dexDir: File) {
        print("[PROCESS] Identifying Application class... ")
        val appClass = findApplicationClass(dexDir)
        println(if (appClass != null) "found." else "failed.")
        println("\n=============================================")
        println("=======       PROCESS COMPLETED          =======")
        println("=============================================")
        println("[INFO] Patched DEX files: ${dexDir.absolutePath}")
        println("[INFO] Original Application class: ${appClass ?: "unknown"}")
    }

    private fun cleanup(extractedZipFile: File, tempApkUnzipDir: File) {
        print("\n[PROCESS] Cleaning up temporary files... ")
        deleteDirectory(extractedZipFile)
        deleteDirectory(tempApkUnzipDir)
        println("done.")
    }

    private fun extractZipFromDex(classesDex: File, workDir: File): File {
        FileInputStream(classesDex).channel.use { channel ->
            val totalLen = channel.size()
            val sizeBuffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
            channel.read(sizeBuffer, totalLen - 4)
            sizeBuffer.flip()
            val zipLen = sizeBuffer.int
            val zipOffset = totalLen - zipLen - 4
            val zipBuffer = ByteBuffer.allocate(zipLen)
            channel.read(zipBuffer, zipOffset)
            zipBuffer.flip()

            val output = File(workDir, "i11111i111.zip")
            FileOutputStream(output).use { it.write(zipBuffer.array()) }
            return output
        }
    }

    private fun parseOoooooOooo(file: File): Map<Int, List<Instruction>> {
        val result = mutableMapOf<Int, List<Instruction>>()

        FileInputStream(file).channel.use { channel ->
            if (channel.size() < 4) {
                throw EOFException("OoooooOooo is too small: ${channel.size()} bytes")
            }

            val buffer = channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size()).order(ByteOrder.LITTLE_ENDIAN)
            val version = buffer.short
            val dexCount = buffer.short.toInt() and 0xFFFF
            val fileSize = buffer.limit()

            println("  - Format version: $version")
            println("  - Protected DEX: $dexCount")

            if (version != 2.toShort()) {
                println("  [WARNING] Unexpected OoooooOooo format version: $version")
            }

            val indexTableSize = dexCount * 4
            if (buffer.remaining() < indexTableSize) {
                throw EOFException(
                    "OoooooOooo index table is truncated: need $indexTableSize bytes, " +
                            "remaining ${buffer.remaining()} bytes"
                )
            }

            val offsets = IntArray(dexCount) { buffer.int }
            val validOffsets = offsets.withIndex().mapNotNull { (index, offset) ->
                when {
                    offset < 4 + indexTableSize -> {
                        println("  [WARNING] DEX #$index has invalid offset $offset before data area; skipped.")
                        null
                    }
                    offset + 2 > fileSize -> {
                        println("  [WARNING] DEX #$index has invalid offset $offset outside file size $fileSize; skipped.")
                        null
                    }
                    else -> DexCodeOffset(index, offset)
                }
            }.sortedBy { it.offset }

            validOffsets.forEachIndexed { sortedIndex, dexCodeOffset ->
                val sectionEnd = validOffsets.getOrNull(sortedIndex + 1)?.offset ?: fileSize
                val list = parseDexCodeSection(buffer, dexCodeOffset.dexIndex, dexCodeOffset.offset, sectionEnd)

                result[dexCodeOffset.dexIndex] = list
                println("  - DEX #${dexCodeOffset.dexIndex}: Found ${list.size} method instructions.")
            }
        }

        if (result.isEmpty()) {
            throw IOException("No valid instruction section found in OoooooOooo")
        }

        return result
    }

    private fun parseDexCodeSection(buffer: ByteBuffer, dexIndex: Int, offset: Int, sectionEnd: Int): List<Instruction> {
        val normalLayout = runCatching {
            parseDexCodeSectionLayout(buffer, dexIndex, offset, sectionEnd, sizeFirst = false)
        }

        if (normalLayout.isSuccess) {
            return normalLayout.getOrThrow()
        }

        val xorEncoded = isLikelyXorEncodedSizeFirstSection(buffer, offset, sectionEnd)
        val sizeFirstLayout = runCatching {
            parseDexCodeSectionLayout(buffer, dexIndex, offset, sectionEnd, sizeFirst = true, xorEncoded = xorEncoded)
        }

        if (sizeFirstLayout.isSuccess) {
            val encoding = if (xorEncoded) " XOR-encoded" else ""
            println("  [WARNING] DEX #$dexIndex uses size-first$encoding instruction records; parsed with compatibility mode.")
            return sizeFirstLayout.getOrThrow()
        }

        throw IOException(
            "Unable to parse DEX #$dexIndex instruction section at offset $offset. " +
                    "methodIndex-first error: ${normalLayout.exceptionOrNull()?.message}; " +
                    "size-first error: ${sizeFirstLayout.exceptionOrNull()?.message}"
        )
    }

    private fun parseDexCodeSectionLayout(
        buffer: ByteBuffer,
        dexIndex: Int,
        offset: Int,
        sectionEnd: Int,
        sizeFirst: Boolean,
        xorEncoded: Boolean = false
    ): List<Instruction> {
        val cursor = buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN)
        cursor.position(offset)

        if (sectionEnd - offset < 2) {
            throw EOFException("DEX #$dexIndex section is too small at offset $offset")
        }

        val methodCount = cursor.short.toInt() and 0xFFFF
        val list = ArrayList<Instruction>(methodCount)

        repeat(methodCount) { methodOrdinal ->
            val recordOffset = cursor.position()
            if (sectionEnd - recordOffset < 8) {
                throw EOFException(
                    "DEX #$dexIndex method #$methodOrdinal header is truncated at offset $recordOffset " +
                            "(section end: $sectionEnd)"
                )
            }

            val first = cursor.int
            val second = cursor.int
            val methodIndex = if (sizeFirst) second else first
            val size = if (sizeFirst) first else second
            val dataOffset = cursor.position()

            if (size < 0) {
                throw IOException("DEX #$dexIndex method #$methodOrdinal has negative instruction size $size")
            }
            if (size > sectionEnd - dataOffset) {
                throw EOFException(
                    "DEX #$dexIndex method #$methodOrdinal methodIndex=$methodIndex needs $size instruction bytes " +
                            "at offset $dataOffset, but section has only ${sectionEnd - dataOffset} bytes left"
                )
            }

            val data = ByteArray(size)
            cursor.get(data)
            if (xorEncoded) {
                for (i in data.indices) {
                    data[i] = (data[i].toInt() xor 0x6f).toByte()
                }
            }
            list.add(Instruction(methodIndex, data))
        }

        if (cursor.position() < sectionEnd) {
            val trailing = sectionEnd - cursor.position()
            println("  [WARNING] DEX #$dexIndex has $trailing trailing bytes in OoooooOooo section.")
        }

        return list
    }

    private fun isLikelyXorEncodedSizeFirstSection(buffer: ByteBuffer, offset: Int, sectionEnd: Int): Boolean {
        val cursor = buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN)
        cursor.position(offset)

        if (sectionEnd - offset < 2) return false

        val methodCount = cursor.short.toInt() and 0xFFFF
        var sampledBytes = 0
        var markerBytes = 0

        repeat(methodCount) {
            if (sectionEnd - cursor.position() < 8 || sampledBytes >= 4096) return@repeat

            val size = cursor.int
            cursor.int

            if (size < 0 || size > sectionEnd - cursor.position()) return false

            val toSample = minOf(size, 4096 - sampledBytes)
            repeat(toSample) {
                if ((cursor.get().toInt() and 0xFF) == 0x6f) {
                    markerBytes++
                }
            }
            sampledBytes += toSample
            cursor.position(cursor.position() + size - toSample)
        }

        return sampledBytes >= 16 && markerBytes * 20 >= sampledBytes * 3
    }

    private fun patchDexFile(dexFile: File, instructions: List<Instruction>, removeJniBridge: Boolean) {
        val instructionMap = instructions.associateBy { it.methodIndex }
        val dexBytes = Files.readAllBytes(dexFile.toPath())
        val dex = Dex(dexBytes)

        for (classDef in dex.classDefs()) {
            if (classDef.classDataOffset == 0) continue
            val classData = dex.readClassData(classDef)

            for (method in classData.allMethods()) {
                if (method.codeOffset == 0) continue
                val inst = instructionMap[method.methodIndex] ?: continue

                val insnOffset = method.codeOffset + 16
                if (insnOffset + inst.instructionsData.size <= dexBytes.size) {
                    System.arraycopy(inst.instructionsData, 0, dexBytes, insnOffset, inst.instructionsData.size)
                }
            }
        }

        fixSHA1Header(dexBytes)
        fixCheckSumHeader(dexBytes)
        dexFile.writeBytes(dexBytes)

        if (removeJniBridge) {
            // Remove JNI bridge call from <clinit>
            DexUtils.removeClinitJniBridgeCall(dexFile)
        }
    }

    private fun findApplicationClass(dexDir: File): String? {
        dexDir.listFiles()?.forEach { dexFile ->
            if (!dexFile.name.endsWith(".dex")) return@forEach
            try {
                val dex = Dex(dexFile)
                for (classDef in dex.classDefs()) {
                    val superIdx = classDef.supertypeIndex
                    if (superIdx >= 0 && dex.typeNames()[superIdx] == "Landroid/app/Application;") {
                        val name = dex.typeNames()[classDef.typeIndex]
                        return name.substring(1, name.length - 1).replace('/', '.')
                    }
                }
            } catch (_: Exception) {
            }
        }
        return null
    }

    private fun unzip(zipFile: File, targetDir: File) {
        ZipInputStream(FileInputStream(zipFile)).use { zis ->
            var entry: ZipEntry? = zis.nextEntry
            while (entry != null) {
                val outFile = File(targetDir, entry.name)
                if (entry.isDirectory) {
                    outFile.mkdirs()
                } else {
                    outFile.parentFile?.mkdirs()
                    FileOutputStream(outFile).use { fos -> zis.copyTo(fos) }
                }
                entry = zis.nextEntry
            }
        }
    }

    private fun fixCheckSumHeader(dexBytes: ByteArray) {
        val adler = Adler32().apply { update(dexBytes, 12, dexBytes.size - 12) }
        val value = adler.value.toInt()

        val buffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(value)
        System.arraycopy(buffer.array(), 0, dexBytes, 8, 4)
    }

    private fun fixSHA1Header(dexBytes: ByteArray) {
        val md = MessageDigest.getInstance("SHA-1").apply { update(dexBytes, 32, dexBytes.size - 32) }
        val sha1 = md.digest()
        System.arraycopy(sha1, 0, dexBytes, 12, 20)
    }

    private fun deleteDirectory(file: File) {
        if (!file.exists()) return
        if (file.isDirectory) {
            file.listFiles()?.forEach { deleteDirectory(it) }
        }
        file.delete()
    }
}

package dev.shi.unpack

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

object ElfParser {

    class Section(
        val nameIdx: Int,
        var name: String,
        val type: Int,
        val flags: Long,
        val addr: Long,
        val offset: Long,
        val size: Long
    )

    fun extractSymbol(soFile: File, symbolName: String): ByteArray? {
        if (!soFile.exists() || soFile.length() < 64) return null
        val bytes = soFile.readBytes()
        if (bytes.size < 4 || bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            return null
        }

        val is64 = bytes[4] == 2.toByte()
        val byteOrder = if (bytes[5] == 1.toByte()) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val buffer = ByteBuffer.wrap(bytes).order(byteOrder)

        val shOff: Long
        val shEntSize: Int
        val shNum: Int
        val shStrNdx: Int

        if (is64) {
            shOff = buffer.getLong(40)
            shEntSize = buffer.getShort(58).toInt() and 0xFFFF
            shNum = buffer.getShort(60).toInt() and 0xFFFF
            shStrNdx = buffer.getShort(62).toInt() and 0xFFFF
        } else {
            shOff = buffer.getInt(32).toLong() and 0xFFFFFFFFL
            shEntSize = buffer.getShort(46).toInt() and 0xFFFF
            shNum = buffer.getShort(48).toInt() and 0xFFFF
            shStrNdx = buffer.getShort(50).toInt() and 0xFFFF
        }

        val sections = mutableListOf<Section>()
        for (i in 0 until shNum) {
            val offset = (shOff + i * shEntSize).toInt()
            if (offset + shEntSize > bytes.size) break
            buffer.position(offset)
            if (is64) {
                val nameIdx = buffer.int
                val type = buffer.int
                val flags = buffer.long
                val addr = buffer.long
                val sOffset = buffer.long
                val size = buffer.long
                sections.add(Section(nameIdx, "", type, flags, addr, sOffset, size))
            } else {
                val nameIdx = buffer.int
                val type = buffer.int
                val flags = buffer.int.toLong() and 0xFFFFFFFFL
                val addr = buffer.int.toLong() and 0xFFFFFFFFL
                val sOffset = buffer.int.toLong() and 0xFFFFFFFFL
                val size = buffer.int.toLong() and 0xFFFFFFFFL
                sections.add(Section(nameIdx, "", type, flags, addr, sOffset, size))
            }
        }

        if (shStrNdx >= sections.size) return null
        val shStrSec = sections[shStrNdx]
        val shStrOffset = shStrSec.offset.toInt()
        val shStrSize = shStrSec.size.toInt()
        if (shStrOffset + shStrSize > bytes.size) return null

        for (sec in sections) {
            sec.name = readString(bytes, shStrOffset + sec.nameIdx)
        }

        // Find .dynsym and .dynstr
        val dynsymSec = sections.firstOrNull { it.type == 11 } ?: return null // SHT_DYNSYM = 11
        val dynstrSec = sections.firstOrNull { it.name == ".dynstr" } ?: return null
        val dynstrOffset = dynstrSec.offset.toInt()

        val symSize = if (is64) 24 else 16
        val symCount = (dynsymSec.size / symSize).toInt()

        for (i in 0 until symCount) {
            val sPos = (dynsymSec.offset + i * symSize).toInt()
            buffer.position(sPos)
            val stName: Int
            val stVal: Long
            val stShndx: Int
            if (is64) {
                stName = buffer.int
                val stInfo = buffer.get()
                val stOther = buffer.get()
                stShndx = buffer.short.toInt() and 0xFFFF
                stVal = buffer.long
            } else {
                stName = buffer.int
                stVal = buffer.int.toLong() and 0xFFFFFFFFL
                val stSz = buffer.int
                val stInfo = buffer.get()
                val stOther = buffer.get()
                stShndx = buffer.short.toInt() and 0xFFFF
            }

            val symNameStr = readString(bytes, dynstrOffset + stName)
            if (symNameStr == symbolName && stShndx < sections.size) {
                val targetSec = sections[stShndx]
                val fileOffset = (targetSec.offset + stVal - targetSec.addr).toInt()
                if (fileOffset >= 0 && fileOffset + 16 <= bytes.size) {
                    val res = ByteArray(16)
                    System.arraycopy(bytes, fileOffset, res, 0, 16)
                    return res
                }
            }
        }

        return null
    }

    private fun readString(bytes: ByteArray, offset: Int): String {
        var end = offset
        while (end < bytes.size && bytes[end] != 0.toByte()) {
            end++
        }
        return if (end <= bytes.size && end >= offset) {
            String(bytes, offset, end - offset, Charsets.ISO_8859_1)
        } else ""
    }
}

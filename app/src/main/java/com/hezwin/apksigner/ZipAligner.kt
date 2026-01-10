package com.hezwin.apksigner

import java.io.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class ZipAligner {

    companion object {
        private const val ALIGNMENT = 4
        private const val BUFFER_SIZE = 8192
    }

    fun alignZip(inputFile: File, outputFile: File): Boolean {
        return try {
            ZipInputStream(BufferedInputStream(FileInputStream(inputFile))).use { zis ->
                ZipOutputStream(BufferedOutputStream(FileOutputStream(outputFile))).use { zos ->
                    var entry: ZipEntry?
                    val buffer = ByteArray(BUFFER_SIZE)

                    while (zis.nextEntry.also { entry = it } != null) {
                        entry?.let { currentEntry ->
                            val newEntry = ZipEntry(currentEntry.name)
                            newEntry.method = currentEntry.method
                            newEntry.time = currentEntry.time
                            newEntry.comment = currentEntry.comment
                            newEntry.extra = currentEntry.extra

                            if (currentEntry.method == ZipEntry.STORED) {
                                // For stored entries, we need to set size and CRC
                                val data = ByteArrayOutputStream()
                                var len: Int
                                while (zis.read(buffer).also { len = it } > 0) {
                                    data.write(buffer, 0, len)
                                }
                                val bytes = data.toByteArray()
                                
                                newEntry.size = bytes.size.toLong()
                                newEntry.compressedSize = bytes.size.toLong()
                                newEntry.crc = calculateCrc32(bytes)

                                // Calculate padding for alignment
                                val offset = getOffset(zos)
                                val padding = calculatePadding(offset, ALIGNMENT)
                                
                                if (padding > 0) {
                                    newEntry.extra = ByteArray(padding)
                                }

                                zos.putNextEntry(newEntry)
                                zos.write(bytes)
                            } else {
                                // For compressed entries, just copy
                                zos.putNextEntry(newEntry)
                                var len: Int
                                while (zis.read(buffer).also { len = it } > 0) {
                                    zos.write(buffer, 0, len)
                                }
                            }
                            
                            zos.closeEntry()
                        }
                    }
                }
            }
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    private fun calculateCrc32(data: ByteArray): Long {
        val crc = java.util.zip.CRC32()
        crc.update(data)
        return crc.value
    }

    private fun getOffset(zos: ZipOutputStream): Long {
        // Use reflection to get current offset
        return try {
            val writtenField = ZipOutputStream::class.java.getDeclaredField("written")
            writtenField.isAccessible = true
            writtenField.getLong(zos)
        } catch (e: Exception) {
            0L
        }
    }

    private fun calculatePadding(offset: Long, alignment: Int): Int {
        val remainder = (offset % alignment).toInt()
        return if (remainder == 0) 0 else alignment - remainder
    }
}
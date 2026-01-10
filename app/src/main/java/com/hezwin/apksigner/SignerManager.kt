package com.hezwin.apksigner

import android.content.Context
import android.net.Uri
import android.os.Environment
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.*
import java.net.URL
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

// 1. BURASI KRİTİK: SignResult burada tanımlanmalı
data class SignResult(
    val success: Boolean,
    val message: String,
    val outputPath: String = ""
)

class SignerManager(private val context: Context) {

    companion object {
        private const val KEYSTORE_FILE = "HEZWIN_PRO.jks"
        private const val JKS_DOWNLOAD_URL = "https://github.com/HEZWIN-Proje/Apk-Signer/raw/main/app/src/main/assets/HEZWIN_PRO.jks"
        private const val KEYSTORE_PASSWORD = "hezwin2025"
        private const val KEY_ALIAS = "hezwin"
        private const val KEY_PASSWORD = "hezwin2025"
        private const val OUTPUT_FOLDER = "HEZWIN_Signed"
    }

    suspend fun signApk(apkUri: Uri, originalFileName: String, logger: (String) -> Unit): SignResult {
        var tempInputFile: File? = null
        var outputFile: File? = null

        return withContext(Dispatchers.IO) {
            try {
                logger("Adım 1: APK Kopyalanıyor...")
                tempInputFile = File(context.cacheDir, "input.apk")
                copyUriToFile(apkUri, tempInputFile!!)

                logger("Adım 2: Anahtar kontrol ediliyor...")
                val (privateKey, certificates) = loadOrDownloadKeystore(logger)

                logger("Adım 3: Çıktı klasörü hazırlanıyor...")
                val outputDir = File(
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                    OUTPUT_FOLDER
                )
                if (!outputDir.exists()) outputDir.mkdirs()

                outputFile = File(outputDir, originalFileName.replace(".apk", "_signed.apk"))

                logger("Adım 4: APK İmzalanıyor (V1+V2+V3)...")
                val signerConfig = ApkSigner.SignerConfig.Builder(
                    KEY_ALIAS, privateKey, certificates
                ).build()

                ApkSigner.Builder(listOf(signerConfig))
                    .setInputApk(tempInputFile)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build()
                    .sign()

                logger("Adım 5: Doğrulanıyor...")
                if (!verifyApk(outputFile!!)) {
                    return@withContext SignResult(false, "İmza doğrulaması başarısız oldu!")
                }

                SignResult(true, "Başarıyla imzalandı", outputFile!!.absolutePath)

            } catch (e: Exception) {
                SignResult(false, "Hata: ${e.message}")
            } finally {
                tempInputFile?.delete()
            }
        }
    }

    private fun loadOrDownloadKeystore(logger: (String) -> Unit): Pair<PrivateKey, List<X509Certificate>> {
        val ksFile = File(context.filesDir, KEYSTORE_FILE)

        if (!ksFile.exists()) {
            logger("Anahtar indiriliyor...")
            try {
                URL(JKS_DOWNLOAD_URL).openStream().use { input ->
                    FileOutputStream(ksFile).use { output ->
                        input.copyTo(output)
                    }
                }
            } catch (e: Exception) {
                throw Exception("Anahtar indirilemedi: ${e.message}")
            }
        }

        val keyStore = KeyStore.getInstance("JKS")
        FileInputStream(ksFile).use {
            keyStore.load(it, KEYSTORE_PASSWORD.toCharArray())
        }

        val privateKey = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as PrivateKey
        val certs = keyStore.getCertificateChain(KEY_ALIAS).map { it as X509Certificate }

        return privateKey to certs
    }

    private fun copyUriToFile(uri: Uri, dest: File) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(dest).use { output ->
                input.copyTo(output)
            }
        } ?: throw Exception("APK dosyası okunamadı.")
    }

    private fun verifyApk(apk: File): Boolean {
        val result = ApkVerifier.Builder(apk).build().verify()
        return result.isVerified
    }
}

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

data class SignResult(
    val success: Boolean,
    val message: String,
    val outputPath: String = ""
)

class SignerManager(private val context: Context) {

    companion object {
        private const val KEYSTORE_FILE = "HEZWIN_PRO.jks"
        private const val JKS_DOWNLOAD_URL = "https://github.com/HEZWIN-Proje/Apk-Signer/raw/main/app/src/main/assets/HEZWIN_PRO.jks"
        
        // Şifreler Termux scripti ile uyumlu hale getirildi
        private const val KEYSTORE_PASSWORD = "HEZWIN123"
        private const val KEY_ALIAS = "hezwin"
        private const val KEY_PASSWORD = "HEZWIN123"
        
        private const val OUTPUT_FOLDER = "HEZWIN_Signed"
    }

    suspend fun signApk(apkUri: Uri, originalFileName: String, logger: (String) -> Unit): SignResult {
        var tempInputFile: File? = null
        var outputFile: File? = null

        return withContext(Dispatchers.IO) {
            try {
                logger("➡️ Adım 1: APK kopyalanıyor...")
                tempInputFile = File(context.cacheDir, "input_temp.apk")
                copyUriToFile(apkUri, tempInputFile!!)
                logger("✅ APK önbelleğe alındı.")

                logger("➡️ Adım 2: JKS anahtarı yükleniyor...")
                val (privateKey, certificates) = loadOrDownloadKeystore(logger)

                logger("➡️ Adım 3: Çıktı klasörü hazırlanıyor...")
                val outputDir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), OUTPUT_FOLDER)
                if (!outputDir.exists()) outputDir.mkdirs()
                outputFile = File(outputDir, originalFileName.replace(".apk", "_signed.apk"))

                logger("➡️ Adım 4: APK İmzalanıyor (V2 + V3)...")
                val signerConfig = ApkSigner.SignerConfig.Builder(KEY_ALIAS, privateKey, certificates).build()

                ApkSigner.Builder(listOf(signerConfig))
                    .setInputApk(tempInputFile)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(false) // Scriptinizdeki gibi false yapıldı
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build()
                    .sign()
                logger("✅ İmzalama tamamlandı.")

                logger("➡️ Adım 5: Doğrulanıyor...")
                val verifier = ApkVerifier.Builder(outputFile!!).build().verify()
                if (verifier.isVerified) {
                    logger("✅ Başarılı: APK imzası geçerli!")
                    SignResult(true, "Başarılı", outputFile!!.absolutePath)
                } else {
                    logger("❌ Hata: İmza doğrulaması başarısız.")
                    SignResult(false, "Doğrulama hatası.")
                }

            } catch (e: Exception) {
                logger("❌ KRİTİK HATA: ${e.message}")
                SignResult(false, e.message ?: "Bilinmeyen hata")
            } finally {
                tempInputFile?.delete()
            }
        }
    }

    private fun loadOrDownloadKeystore(logger: (String) -> Unit): Pair<PrivateKey, List<X509Certificate>> {
        val ksFile = File(context.filesDir, KEYSTORE_FILE)

        if (!ksFile.exists()) {
            logger("⚠️ JKS bulunamadı, GitHub'dan indiriliyor...")
            try {
                URL(JKS_DOWNLOAD_URL).openStream().use { input ->
                    FileOutputStream(ksFile).use { output -> input.copyTo(output) }
                }
                logger("✅ JKS başarıyla indirildi.")
            } catch (e: Exception) {
                logger("❌ İndirme başarısız: İnternet veya URL sorunu.")
                throw Exception("JKS indirilemedi.")
            }
        }

        logger("📂 JKS açılıyor (Şifre: $KEYSTORE_PASSWORD)...")
        val keyStore = KeyStore.getInstance("JKS")
        
        FileInputStream(ksFile).use { fis ->
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray())
        }
        
        val privateKey = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as? PrivateKey
            ?: throw Exception("Alias ($KEY_ALIAS) bulunamadı!")
        
        val certs = keyStore.getCertificateChain(KEY_ALIAS)?.map { it as X509Certificate }
            ?: throw Exception("Sertifika zinciri boş!")

        logger("🔓 Anahtar ve sertifikalar başarıyla yüklendi.")
        return privateKey to certs
    }

    private fun copyUriToFile(uri: Uri, dest: File) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(dest).use { output -> input.copyTo(output) }
        } ?: throw Exception("APK dosyası okunamıyor.")
    }
}

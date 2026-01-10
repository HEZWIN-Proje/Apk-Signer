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
                logger("➡️ Adım 1: APK kopyalanıyor...")
                tempInputFile = File(context.cacheDir, "input_temp.apk")
                copyUriToFile(apkUri, tempInputFile!!)
                logger("✅ APK önbelleğe alındı.")

                logger("➡️ Adım 2: JKS anahtarı yükleniyor...")
                val (privateKey, certificates) = loadOrDownloadKeystore(logger)

                logger("➡️ Adım 3: Çıktı dosyası hazırlanıyor...")
                val outputDir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), OUTPUT_FOLDER)
                if (!outputDir.exists()) outputDir.mkdirs()
                outputFile = File(outputDir, originalFileName.replace(".apk", "_signed.apk"))
                logger("📍 Konum: ${outputFile!!.absolutePath}")

                logger("➡️ Adım 4: İmzalama işlemi başlatıldı...")
                val signerConfig = ApkSigner.SignerConfig.Builder(KEY_ALIAS, privateKey, certificates).build()

                ApkSigner.Builder(listOf(signerConfig))
                    .setInputApk(tempInputFile)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build()
                    .sign()
                logger("✅ İmzalama tamamlandı.")

                logger("➡️ Adım 5: İmza doğrulanıyor...")
                val verifier = ApkVerifier.Builder(outputFile!!).build().verify()
                if (verifier.isVerified) {
                    logger("✅ Doğrulama başarılı!")
                    SignResult(true, "Başarılı", outputFile!!.absolutePath)
                } else {
                    logger("❌ Doğrulama başarısız: Sertifika hatalı.")
                    SignResult(false, "Doğrulama hatası.")
                }

            } catch (e: java.security.UnrecoverableKeyException) {
                logger("❌ HATA: Anahtar şifresi (KEY_PASSWORD) yanlış!")
                SignResult(false, "Anahtar şifresi yanlış.")
            } catch (e: java.io.IOException) {
                if (e.message?.contains("keystore password") == true) {
                    logger("❌ HATA: Keystore şifresi (KEYSTORE_PASSWORD) yanlış!")
                    SignResult(false, "Keystore şifresi yanlış.")
                } else {
                    logger("❌ HATA: Dosya okuma/yazma hatası: ${e.message}")
                    SignResult(false, "Dosya hatası.")
                }
            } catch (e: Exception) {
                logger("❌ KRİTİK HATA: ${e.javaClass.simpleName} - ${e.message}")
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
                logger("✅ İndirme başarılı.")
            } catch (e: Exception) {
                logger("❌ İndirme başarısız: İnterneti kontrol edin.")
                throw Exception("JKS indirilemedi.")
            }
        }

        logger("📂 JKS dosyası açılıyor...")
        val keyStore = KeyStore.getInstance("JKS")
        
        try {
            FileInputStream(ksFile).use { fis ->
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray())
            }
            logger("🔓 Keystore şifresi kabul edildi.")
            
            val privateKey = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as? PrivateKey
                ?: throw Exception("Alias ($KEY_ALIAS) bulunamadı!")
            
            logger("🔑 Anahtar (Private Key) başarıyla alındı.")

            val certs = keyStore.getCertificateChain(KEY_ALIAS)?.map { it as X509Certificate }
                ?: throw Exception("Sertifika zinciri boş!")

            return privateKey to certs
        } catch (e: Exception) {
            // Şifre hatasını burada yakalayıp yukarı fırlatıyoruz
            throw e
        }
    }

    private fun copyUriToFile(uri: Uri, dest: File) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(dest).use { output -> input.copyTo(output) }
        } ?: throw Exception("APK dosyası okunamıyor.")
    }
}

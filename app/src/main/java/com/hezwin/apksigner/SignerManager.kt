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

// Sonuç modeli
data class SignResult(
    val success: Boolean,
    val message: String,
    val outputPath: String = ""
)

class SignerManager(private val context: Context) {

    companion object {
        private const val KEYSTORE_FILE = "HEZWIN_PRO.jks"
        private const val JKS_DOWNLOAD_URL = "https://github.com/HEZWIN-Proje/Apk-Signer/raw/main/app/src/main/assets/HEZWIN_PRO.jks"
        
        // Termux scriptindeki şifrelerle güncellendi
        private const val KEYSTORE_PASSWORD = "HEZWIN123"
        private const val KEY_ALIAS = "hezwin"
        private const val KEY_PASSWORD = "HEZWIN123"
        
        private const val OUTPUT_FOLDER = "HEWIN_Signed"
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
                logger("📍 Kayıt yeri: Download/$OUTPUT_FOLDER")

                logger("➡️ Adım 4: APK İmzalanıyor (V2 + V3)...")
                val signerConfig = ApkSigner.SignerConfig.Builder(KEY_ALIAS, privateKey, certificates).build()

                ApkSigner.Builder(listOf(signerConfig))
                    .setInputApk(tempInputFile)
                    .setOutputApk(outputFile)
                    .setV1SigningEnabled(false) // Scriptinizle uyumlu
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build()
                    .sign()
                logger("✅ İmzalama tamamlandı.")

                logger("➡️ Adım 5: Doğrulanıyor...")
                val verifier = ApkVerifier.Builder(outputFile!!).build().verify()
                if (verifier.isVerified) {
                    logger("✅ BAŞARILI: APK imzası geçerli!")
                    SignResult(true, "Başarıyla imzalandı", outputFile!!.absolutePath)
                } else {
                    logger("❌ HATA: İmza doğrulaması başarısız.")
                    SignResult(false, "Doğrulama hatası.")
                }

            } catch (e: Exception) {
                logger("❌ KRİTİK HATA: ${e.message}")
                SignResult(false, e.message ?: "Bilinmeyen hata")
            } finally {
                // Geçici dosyayı temizle
                try { tempInputFile?.delete() } catch (e: Exception) {}
            }
        }
    }

    private fun loadOrDownloadKeystore(logger: (String) -> Unit): Pair<PrivateKey, List<X509Certificate>> {
        val ksFile = File(context.filesDir, KEYSTORE_FILE)

        // Dosya yoksa veya 0 byte ise indir
        if (!ksFile.exists() || ksFile.length() == 0L) {
            logger("⚠️ JKS bulunamadı, GitHub'dan indiriliyor...")
            try {
                URL(JKS_DOWNLOAD_URL).openStream().use { input ->
                    FileOutputStream(ksFile).use { output ->
                        input.copyTo(output)
                    }
                }
                logger("✅ İndirme bitti (${ksFile.length()} byte).")
            } catch (e: Exception) {
                logger("🔄 İndirme başarısız, Assets deneniyor...")
                try {
                    context.assets.open(KEYSTORE_FILE).use { input ->
                        FileOutputStream(ksFile).use { output -> input.copyTo(output) }
                    }
                    logger("✅ Assets içinden kopyalandı.")
                } catch (e2: Exception) {
                    throw Exception("JKS dosyasına erişilemedi: ${e.message}")
                }
            }
        }

        logger("📂 JKS açılıyor (Şifre deneniyor)...")
        val keyStore = KeyStore.getInstance("JKS")
        
        try {
            FileInputStream(ksFile).use { fis ->
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray())
            }
        } catch (e: Exception) {
            // Eğer hala hata veriyorsa dosyayı silip tekrar indirmesi için zorla
            ksFile.delete()
            throw Exception("Keystore şifresi yanlış veya dosya bozuk!")
        }
        
        val privateKey = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as? PrivateKey
            ?: throw Exception("Alias ($KEY_ALIAS) bulunamadı!")
        
        val certs = keyStore.getCertificateChain(KEY_ALIAS)?.map { it as X509Certificate }
            ?: throw Exception("Sertifika zinciri boş!")

        logger("🔓 Anahtar başarıyla yüklendi.")
        return privateKey to certs
    }

    private fun copyUriToFile(uri: Uri, dest: File) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(dest).use { output ->
                input.copyTo(output)
            }
        } ?: throw Exception("Seçilen APK dosyası okunamadı.")
    }
}

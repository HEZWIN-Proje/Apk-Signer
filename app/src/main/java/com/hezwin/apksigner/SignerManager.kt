package com.hezwin.apksigner

import android.content.Context
import android.net.Uri
import android.os.Environment
import android.util.Base64
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.File
import java.io.FileOutputStream
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
        private const val KEYSTORE_PASSWORD = "HEZWIN123"
        private const val KEY_ALIAS = "hezwin"
        private const val KEY_PASSWORD = "HEZWIN123"
        private const val OUTPUT_FOLDER = "HEZWIN_Signed"

        // JKS dosyasının base64 hali
        private const val KEYSTORE_BASE64 = """
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
BBTtXCB2af0tLL9OuZanrqffG9baQQICJxA=
"""
    }

    fun signApk(apkUri: Uri, originalFileName: String, logger: (String) -> Unit): SignResult {
        val tempInputFile = File(context.cacheDir, "input.apk")
        val outputDir = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            OUTPUT_FOLDER
        )
        if (!outputDir.exists()) outputDir.mkdirs()

        val outputFile = File(outputDir, originalFileName.replace(".apk", "_signed.apk"))

        return try {
            logger("Step 1: Copy APK")
            copyUriToFile(apkUri, tempInputFile)

            logger("Step 2: Load keystore from base64")
            val (privateKey, certificates) = loadKeystoreFromBase64()

            logger("Step 3: Sign APK")
            val signerConfig = ApkSigner.SignerConfig.Builder(KEY_ALIAS, privateKey, certificates).build()

            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(tempInputFile)
                .setOutputApk(outputFile)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setV4SigningEnabled(false)
                .build()
                .sign()

            logger("Step 4: Verify APK")
            if (!verifyApk(outputFile)) {
                SignResult(false, "Signature verification failed")
            } else {
                SignResult(true, "APK signed successfully", outputFile.absolutePath)
            }
        } catch (e: Exception) {
            SignResult(false, e.message ?: "Unknown error")
        } finally {
            tempInputFile.delete()
        }
    }

    private fun copyUriToFile(uri: Uri, dest: File) {
        context.contentResolver.openInputStream(uri)!!.use { input ->
            FileOutputStream(dest).use { output ->
                input.copyTo(output)
            }
        }
    }

    private fun loadKeystoreFromBase64(): Pair<PrivateKey, List<X509Certificate>> {
        val ksBytes = Base64.decode(KEYSTORE_BASE64.trim(), Base64.DEFAULT)
        val ksFile = File(context.cacheDir, "HEZWIN_PRO.jks")
        FileOutputStream(ksFile).use { it.write(ksBytes) }

        val keyStore = KeyStore.getInstance("JKS")
        FileInputStream(ksFile).use { keyStore.load(it, KEYSTORE_PASSWORD.toCharArray()) }

        val privateKey = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as PrivateKey
        val certificates = keyStore.getCertificateChain(KEY_ALIAS).map { it as X509Certificate }

        return privateKey to certificates
    }

    private fun verifyApk(apk: File): Boolean {
        val result = ApkVerifier.Builder(apk).build().verify()
        return result.isVerified && !result.isVerifiedUsingV1Scheme
    }
}

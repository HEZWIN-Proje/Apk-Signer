package com.hezwin.apksigner

import android.content.Context
import android.net.Uri
import android.os.Environment
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.*
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
        private const val KEYSTORE_PASSWORD = "hezwin2025"
        private const val KEY_ALIAS = "hezwin"
        private const val KEY_PASSWORD = "hezwin2025"
        private const val OUTPUT_FOLDER = "HEZWIN_Signed"
    }

    fun signApk(apkUri: Uri, originalFileName: String, logger: (String) -> Unit): SignResult {
        var tempInputFile: File? = null
        var outputFile: File? = null

        try {
            logger("Step 1: Copy APK")
            tempInputFile = File(context.cacheDir, "input.apk")
            copyUriToFile(apkUri, tempInputFile)

            logger("Step 2: Load keystore")
            val (privateKey, certificates) = loadKeystore()

            logger("Step 3: Prepare output")
            val outputDir = File(
                Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                OUTPUT_FOLDER
            )
            if (!outputDir.exists()) outputDir.mkdirs()

            outputFile = File(
                outputDir,
                originalFileName.replace(".apk", "_signed.apk")
            )

            logger("Step 4: Sign APK")
            val signerConfig = ApkSigner.SignerConfig.Builder(
                KEY_ALIAS, privateKey, certificates
            ).build()

            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(tempInputFile)
                .setOutputApk(outputFile)
                .setV1SigningEnabled(false)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setV4SigningEnabled(false)
                .build()
                .sign()

            logger("Step 5: Verify")
            if (!verifyApk(outputFile)) {
                return SignResult(false, "Signature verification failed")
            }

            return SignResult(true, "APK signed successfully", outputFile.absolutePath)

        } catch (e: Exception) {
            return SignResult(false, e.message ?: "Unknown error")
        } finally {
            tempInputFile?.delete()
        }
    }

    private fun copyUriToFile(uri: Uri, dest: File) {
        context.contentResolver.openInputStream(uri)!!.use { input ->
            FileOutputStream(dest).use { output ->
                input.copyTo(output)
            }
        }
    }

    private fun loadKeystore(): Pair<PrivateKey, List<X509Certificate>> {
        val ksFile = File(context.cacheDir, KEYSTORE_FILE)

        if (!ksFile.exists()) {
            context.assets.open(KEYSTORE_FILE).use { input ->
                FileOutputStream(ksFile).use { output ->
                    input.copyTo(output)
                }
            }
        }

        val keyStore = KeyStore.getInstance("JKS")
        FileInputStream(ksFile).use {
            keyStore.load(it, KEYSTORE_PASSWORD.toCharArray())
        }

        val privateKey =
            keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as PrivateKey

        val certs = keyStore.getCertificateChain(KEY_ALIAS)
            .map { it as X509Certificate }

        return privateKey to certs
    }

    private fun verifyApk(apk: File): Boolean {
        val result = ApkVerifier.Builder(apk).build().verify()
        return result.isVerified && !result.isVerifiedUsingV1Scheme
    }
}

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
        var tempAlignedFile: File? = null
        var outputFile: File? = null

        try {
            // Step 1: Copy APK to temp location
            logger("Step 1: Copying APK to temporary location...")
            tempInputFile = File(context.cacheDir, "temp_input.apk")
            copyUriToFile(apkUri, tempInputFile)
            logger("✓ APK copied (${tempInputFile.length() / 1024} KB)")

            // Step 2: ZipAlign
            logger("\nStep 2: Running zipalign (4-byte alignment)...")
            tempAlignedFile = File(context.cacheDir, "temp_aligned.apk")
            val aligner = ZipAligner()
            
            if (!aligner.alignZip(tempInputFile, tempAlignedFile)) {
                return SignResult(false, "ZipAlign failed!")
            }
            logger("✓ ZipAlign completed (${tempAlignedFile.length() / 1024} KB)")

            // Step 3: Load keystore
            logger("\nStep 3: Loading keystore...")
            val (privateKey, certificates) = loadKeystore()
            logger("✓ Keystore loaded successfully")

            // Step 4: Sign APK (V2 + V3)
            logger("\nStep 4: Signing APK (V2 + V3 enabled)...")
            
            // Prepare output file
            val outputDir = File(Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS), OUTPUT_FOLDER)
            
            if (!outputDir.exists()) {
                outputDir.mkdirs()
            }

            val outputFileName = originalFileName.replace(".apk", "_signed.apk")
            outputFile = File(outputDir, outputFileName)

            // Sign the APK
            val signerConfig = ApkSigner.SignerConfig.Builder(
                "HEZWIN", privateKey, certificates
            ).build()

            val signer = ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(tempAlignedFile)
                .setOutputApk(outputFile)
                .setV1SigningEnabled(false)  // V1 disabled
                .setV2SigningEnabled(true)   // V2 enabled
                .setV3SigningEnabled(true)   // V3 enabled
                .setV4SigningEnabled(false)
                .build()

            signer.sign()
            logger("✓ APK signed successfully")

            // Step 5: Verify signature
            logger("\nStep 5: Verifying APK signature...")
            val verified = verifyApk(outputFile)
            
            if (verified) {
                logger("✓ Signature verification PASSED")
                logger("\n═══════════════════════════════════")
                return SignResult(
                    true,
                    "APK signed successfully!",
                    outputFile.absolutePath
                )
            } else {
                logger("✗ Signature verification FAILED")
                return SignResult(false, "Signature verification failed!")
            }

        } catch (e: Exception) {
            logger("✗ Exception: ${e.message}")
            e.printStackTrace()
            return SignResult(false, "Error: ${e.message}")
        } finally {
            // Cleanup temporary files
            tempInputFile?.delete()
            tempAlignedFile?.delete()
        }
    }

    private fun copyUriToFile(uri: Uri, destFile: File) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(destFile).use { output ->
                input.copyTo(output)
            }
        }
    }

    private fun loadKeystore(): Pair<PrivateKey, List<X509Certificate>> {
    val keystoreFile = File(context.filesDir, "hezwin_keystore.jks")

    if (!keystoreFile.exists()) {
        context.resources.openRawResource(R.raw.hezwin_keystore).use { input ->
            FileOutputStream(keystoreFile).use { output ->
                input.copyTo(output)
            }
        }
    }

    val keyStore = KeyStore.getInstance("JKS")
    FileInputStream(keystoreFile).use { fis ->
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray())
    }

    val privateKey = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as PrivateKey
    val certChain = keyStore.getCertificateChain(KEY_ALIAS)
    val certificates = certChain.map { it as X509Certificate }

    return Pair(privateKey, certificates)
}

    private fun verifyApk(apkFile: File): Boolean {
        return try {
            val verifier = ApkVerifier.Builder(apkFile).build()
            val result = verifier.verify()
            result.isVerified && !result.isVerifiedUsingV1Scheme
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}
        } catch (e: Exception) {
            logger("✗ Exception: ${e.message}")
            e.printStackTrace()
            return SignResult(false, "Error: ${e.message}")
        } finally {
            // Cleanup temporary files
            tempInputFile?.delete()
            tempAlignedFile?.delete()
        }
    }

    private fun copyUriToFile(uri: Uri, destFile: File) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(destFile).use { output ->
                input.copyTo(output)
            }
        }
    }

    private fun loadKeystore(): Pair<PrivateKey, List<X509Certificate>> {
        // Copy keystore from assets to internal storage
        val keystoreFile = File(context.filesDir, KEYSTORE_FILE)
        if (!keystoreFile.exists()) {
            context.assets.open(KEYSTORE_FILE).use { input ->
                FileOutputStream(keystoreFile).use { output ->
                    input.copyTo(output)
                }
            }
        }

        val keyStore = KeyStore.getInstance("JKS")
        FileInputStream(keystoreFile).use { fis ->
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray())
        }

        val privateKey = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as PrivateKey
        val certChain = keyStore.getCertificateChain(KEY_ALIAS)
        val certificates = certChain.map { it as X509Certificate }

        return Pair(privateKey, certificates)
    }

    private fun verifyApk(apkFile: File): Boolean {
        return try {
            val verifier = ApkVerifier.Builder(apkFile).build()
            val result = verifier.verify()
            result.isVerified && !result.isVerifiedUsingV1Scheme
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}

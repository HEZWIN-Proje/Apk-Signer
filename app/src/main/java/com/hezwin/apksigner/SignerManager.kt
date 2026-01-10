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
        private const val KEYSTORE_PASSWORD = "hezwin2025"
        private const val KEY_ALIAS = "hezwin"
        private const val KEY_PASSWORD = "hezwin2025"
        private const val OUTPUT_FOLDER = "HEZWIN_Signed"
    }

    fun signApk(
        apkUri: Uri,
        originalFileName: String,
        logger: (String) -> Unit
    ): SignResult {

        var tempInputFile: File? = null
        var tempAlignedFile: File? = null

        try {
            logger("Step 1: Copying APK...")
            tempInputFile = File(context.cacheDir, "input.apk")
            copyUriToFile(apkUri, tempInputFile)

            logger("Step 2: ZipAlign...")
            tempAlignedFile = File(context.cacheDir, "aligned.apk")
            if (!ZipAligner().alignZip(tempInputFile, tempAlignedFile)) {
                return SignResult(false, "ZipAlign failed")
            }

            logger("Step 3: Loading keystore...")
            val (privateKey, certs) = loadKeystore()

            val outputDir = File(
                Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS
                ),
                OUTPUT_FOLDER
            )
            outputDir.mkdirs()

            val outputFile = File(
                outputDir,
                originalFileName.replace(".apk", "_signed.apk")
            )

            val signerConfig = ApkSigner.SignerConfig.Builder(
                "HEZWIN",
                privateKey,
                certs
            ).build()

            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(tempAlignedFile)
                .setOutputApk(outputFile)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()
                .sign()

            logger("Step 4: Verifying...")
            val verified = ApkVerifier.Builder(outputFile).build().verify()

            return if (verified.isVerified) {
                SignResult(true, "Signed successfully", outputFile.absolutePath)
            } else {
                SignResult(false, "Verification failed")
            }

        } catch (e: Exception) {
            return SignResult(false, e.message ?: "Unknown error")
        } finally {
            tempInputFile?.delete()
            tempAlignedFile?.delete()
        }
    }

    private fun copyUriToFile(uri: Uri, dest: File) {
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(dest).use { output ->
                input.copyTo(output)
            }
        }
    }

    private fun loadKeystore(): Pair<PrivateKey, List<X509Certificate>> {
        val ksFile = File(context.filesDir, "hezwin_keystore.jks")

        if (!ksFile.exists()) {
            context.resources.openRawResource(R.raw.hezwin_keystore).use { input ->
                FileOutputStream(ksFile).use { output ->
                    input.copyTo(output)
                }
            }
        }

        val ks = KeyStore.getInstance("JKS")
        FileInputStream(ksFile).use {
            ks.load(it, KEYSTORE_PASSWORD.toCharArray())
        }

        val privateKey =
            ks.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray()) as PrivateKey
        val certs =
            ks.getCertificateChain(KEY_ALIAS).map { it as X509Certificate }

        return Pair(privateKey, certs)
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

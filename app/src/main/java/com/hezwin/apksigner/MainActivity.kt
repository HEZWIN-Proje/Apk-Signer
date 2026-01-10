package com.hezwin.apksigner

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.widget.TextView
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var btnSelectApk: MaterialButton
    private lateinit var btnSign: MaterialButton
    private lateinit var tvSelectedApk: TextView
    private lateinit var tvLog: TextView

    private var selectedApkUri: Uri? = null
    private var selectedApkName: String = ""

    companion object {
        private const val REQUEST_CODE_PICK_APK = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        setupListeners()
    }

    private fun initViews() {
        btnSelectApk = findViewById(R.id.btnSelectApk)
        btnSign = findViewById(R.id.btnSign)
        tvSelectedApk = findViewById(R.id.tvSelectedApk)
        tvLog = findViewById(R.id.tvLog)
    }

    private fun setupListeners() {
        btnSelectApk.setOnClickListener {
            pickApkFile()
        }

        btnSign.setOnClickListener {
            selectedApkUri?.let { uri ->
                signApk(uri)
            }
        }
    }

    private fun pickApkFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/vnd.android.package-archive"
        }
        startActivityForResult(intent, REQUEST_CODE_PICK_APK)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == REQUEST_CODE_PICK_APK && resultCode == Activity.RESULT_OK) {
            data?.data?.also { uri ->
                selectedApkUri = uri
                selectedApkName = getFileName(uri)
                tvSelectedApk.text = "Selected: $selectedApkName"
                btnSign.isEnabled = true
                appendLog("✓ APK selected: $selectedApkName")
            }
        }
    }

    private fun getFileName(uri: Uri): String {
        var fileName = "unknown.apk"
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (nameIndex != -1) {
                    fileName = cursor.getString(nameIndex)
                }
            }
        }
        return fileName
    }

    private fun signApk(apkUri: Uri) {
        btnSign.isEnabled = false
        btnSelectApk.isEnabled = false
        
        lifecycleScope.launch {
            try {
                clearLog()
                appendLog("═══════════════════════════════════")
                appendLog("Starting APK signing process...")
                appendLog("═══════════════════════════════════")
                
                val result = withContext(Dispatchers.IO) {
                    val signerManager = SignerManager(this@MainActivity)
                    signerManager.signApk(apkUri, selectedApkName) { log ->
                        lifecycleScope.launch(Dispatchers.Main) {
                            appendLog(log)
                        }
                    }
                }

                withContext(Dispatchers.Main) {
                    if (result.success) {
                        appendLog("\n✓ SUCCESS! APK signed successfully!")
                        appendLog("Output: ${result.outputPath}")
                        showSuccessDialog(result.outputPath)
                    } else {
                        appendLog("\n✗ FAILED: ${result.message}")
                        showErrorDialog(result.message)
                    }
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    appendLog("\n✗ ERROR: ${e.message}")
                    showErrorDialog(e.message ?: "Unknown error")
                }
            } finally {
                withContext(Dispatchers.Main) {
                    btnSign.isEnabled = true
                    btnSelectApk.isEnabled = true
                }
            }
        }
    }

    private fun appendLog(message: String) {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        val logMessage = "[$timestamp] $message\n"
        tvLog.append(logMessage)
        
        // Auto-scroll to bottom
        tvLog.post {
            val scrollView = tvLog.parent as? android.widget.ScrollView
            scrollView?.fullScroll(android.view.View.FOCUS_DOWN)
        }
    }

    private fun clearLog() {
        tvLog.text = ""
    }

    private fun showSuccessDialog(outputPath: String) {
        MaterialAlertDialogBuilder(this)
            .setTitle("Success!")
            .setMessage("APK signed successfully!\n\nOutput: $outputPath")
            .setPositiveButton("OK", null)
            .setNeutralButton("Sign Another") { _, _ ->
                selectedApkUri = null
                btnSign.isEnabled = false
                tvSelectedApk.text = getString(R.string.no_apk_selected)
            }
            .show()
    }

    private fun showErrorDialog(message: String) {
        MaterialAlertDialogBuilder(this)
            .setTitle("Signing Failed")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }
}
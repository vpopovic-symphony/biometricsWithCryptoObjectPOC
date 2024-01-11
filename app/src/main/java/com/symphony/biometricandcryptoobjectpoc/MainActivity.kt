package com.symphony.biometricandcryptoobjectpoc

import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.nio.charset.Charset

class MainActivity : AppCompatActivity() {
    private lateinit var cryptographyManager: CryptographyManager

    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo
    private lateinit var secretKeyName: String
    private lateinit var ciphertext: ByteArray
    private lateinit var initializationVector: ByteArray

    private lateinit var tvPreview: TextView
    private lateinit var encryptButton: Button
    private lateinit var decryptButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvPreview = findViewById(R.id.tvPreview)
        encryptButton = findViewById(R.id.btEncrypt)
        decryptButton = findViewById(R.id.btDecrypt)

        enableEncryptButton()

        cryptographyManager = CryptographyManagerImpl()
        secretKeyName = "biometric_encryption_key"
        biometricPrompt = createBiometricPrompt()
        promptInfo = createPromptInfo()

        encryptButton.setOnClickListener {
            authenticateToEncrypt()
        }

        decryptButton.setOnClickListener {
            authenticateToDecrypt()
        }
    }

    private fun enableEncryptButton() {
        encryptButton.isEnabled = true
        decryptButton.isEnabled = false
    }

    private fun enableDecryptButton() {
        decryptButton.isEnabled = true
        encryptButton.isEnabled = false
    }

    private fun createBiometricPrompt(): BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.d(TAG, "$errorCode :: $errString")
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.d(TAG, "Authentication failed for an unknown reason")
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "Authentication was successful")
                if (decryptButton.isEnabled) decryptData(result.cryptoObject)
                else encryptData(result.cryptoObject)
            }
        }

        //The API requires the client/Activity context for displaying the prompt view
        return BiometricPrompt(this, executor, callback)
    }

    private fun createPromptInfo(): BiometricPrompt.PromptInfo {
        return BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate with biometrics")
            .setSubtitle("Biometric POC App")
            .setDescription("Confirm to continue")
            .setConfirmationRequired(false)
            .setNegativeButtonText("Cancel")
            // .setDeviceCredentialAllowed(true) // Allow PIN/pattern/password authentication.
            // Also note that setDeviceCredentialAllowed and setNegativeButtonText are
            // incompatible so that if you uncomment one you must comment out the other
            .build()
    }

    private fun authenticateToEncrypt() {
        if (BiometricManager.from(applicationContext)
                .canAuthenticate(BIOMETRIC_STRONG) == BiometricManager
                .BIOMETRIC_SUCCESS
        ) {
            val cipher = cryptographyManager.getInitializedCipherForEncryption(secretKeyName)
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun authenticateToDecrypt() {
        if (BiometricManager.from(applicationContext)
                .canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        ) {
            val cipher = cryptographyManager.getInitializedCipherForDecryption(
                secretKeyName,
                initializationVector
            )
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun encryptData(cryptoObject: BiometricPrompt.CryptoObject?) {
        val encryptedData =
            cryptographyManager.encryptData(
                "recall baby black mushroom canyon place lonely learn small battle anchor sudden",
                cryptoObject?.cipher!!
            )
        ciphertext = encryptedData.ciphertext
        initializationVector = encryptedData.initializationVector

        val text = String(ciphertext, Charset.forName("UTF-8"))
        tvPreview.text = text
        enableDecryptButton()
    }

    private fun decryptData(cryptoObject: BiometricPrompt.CryptoObject?) {
        val data = cryptographyManager.decryptData(ciphertext, cryptoObject?.cipher!!)
        tvPreview.text = data
        enableEncryptButton()
    }

    companion object {
        private const val TAG = "MainActivity"
    }
}
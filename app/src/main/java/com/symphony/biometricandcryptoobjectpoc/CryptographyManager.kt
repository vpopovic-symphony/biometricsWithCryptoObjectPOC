package com.symphony.biometricandcryptoobjectpoc

import javax.crypto.Cipher

interface CryptographyManager {
    fun getInitializedCipherForEncryption(keyName: String): Cipher
    fun getInitializedCipherForDecryption(keyName: String, initializationVector: ByteArray): Cipher
    fun encryptData(plaintext: String, cipher: Cipher): EncryptedData
    fun decryptData(ciphertext: ByteArray, cipher: Cipher): String
}
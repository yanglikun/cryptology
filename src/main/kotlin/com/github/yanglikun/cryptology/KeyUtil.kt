package com.github.yanglikun.cryptology

import org.apache.commons.codec.binary.Base64
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey

//通用
fun PublicKey.encodeBase64String() = Base64.encodeBase64String(this.encoded)

fun PrivateKey.encodeBase64String() = Base64.encodeBase64String(this.encoded)
fun Key.encodeBase64String() = Base64.encodeBase64String(this.encoded)

fun String.decodeBase64() = Base64.decodeBase64(this)

fun ByteArray.encodeBase64String() = Base64.encodeBase64String(this)
fun ByteArray.decodeBase64() = Base64.decodeBase64(this)

//DH
fun String.parseToPrivateKey(algorithm: String) =
        KeyFactory.getInstance(algorithm)
                .generatePrivate(PKCS8EncodedKeySpec(Base64.decodeBase64(this)))

fun String.parseToPublicKey(algorithm: String) =
        KeyFactory.getInstance(algorithm)
                .generatePublic(X509EncodedKeySpec(Base64.decodeBase64(this)))


fun Key.encrypt(data: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(this.algorithm)
    cipher.init(Cipher.ENCRYPT_MODE, this)
    return cipher.doFinal(data)
}

fun Key.decrypt(data: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(this.algorithm)
    cipher.init(Cipher.DECRYPT_MODE, this)
    return cipher.doFinal(data)
}

//RSA
fun PublicKey.encrypt(data: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(this.algorithm)
    cipher.init(Cipher.ENCRYPT_MODE, this)
    return cipher.doFinal(data)
}

fun PublicKey.decrypt(data: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(this.algorithm)
    cipher.init(Cipher.DECRYPT_MODE, this)
    return cipher.doFinal(data)
}
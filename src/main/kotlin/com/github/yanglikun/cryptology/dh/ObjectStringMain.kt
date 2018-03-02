package com.github.yanglikun.cryptology.dh

import com.github.yanglikun.cryptology.decodeBase64
import com.github.yanglikun.cryptology.encodeBase64String
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.interfaces.DHPublicKey

/**
 * 秘钥对象和字符串之间转换
 */
fun main(args: Array<String>) {

    val keyPairGenerator = KeyPairGenerator.getInstance("DH")
    keyPairGenerator.initialize(512)

    val keyPair = keyPairGenerator.generateKeyPair()
    val publicKey = keyPair.public
    val publicKeyBase64 = publicKey.encodeBase64String()

    val publicKey2 = KeyFactory.getInstance("DH")
            .generatePublic(X509EncodedKeySpec(publicKeyBase64.decodeBase64())) as DHPublicKey

    println(publicKey.equals(publicKey2))


    val privateKey = keyPair.private
    val privateKeyBase64 = privateKey.encodeBase64String()
    val privateKey2 = KeyFactory.getInstance("DH").generatePrivate(PKCS8EncodedKeySpec(privateKeyBase64.decodeBase64()))
    println(privateKey.equals(privateKey2))

}
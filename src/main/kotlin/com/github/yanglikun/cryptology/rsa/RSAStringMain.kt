package com.github.yanglikun.cryptology.rsa

import com.github.yanglikun.cryptology.encodeBase64String
import com.github.yanglikun.cryptology.parseToPrivateKey
import com.github.yanglikun.cryptology.parseToPublicKey
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class PersonString(val name: String) {
    lateinit var publicKey: String
    lateinit var privateKey: String
}

fun main(args: Array<String>) {
    val alice = PersonString("Alice")
    val bob = PersonString("bob")

    //各自生成各自的秘钥,不需要交换
    alice.generateKeyPair()
    bob.generateKeyPair()

    val alicePublicKey = alice.publicKey.parseToPublicKey(RSA_ALGORITHM)
    val alicePrivateKey = alice.privateKey.parseToPrivateKey(RSA_ALGORITHM)

    //公钥加密,私钥解密
    encryptAndDecrypt(alicePublicKey, alicePrivateKey)
    //私钥加密,公钥解密
    encryptAndDecrypt(alicePrivateKey, alicePublicKey)

    println("alice公钥->${alice.publicKey}")
    println("alice私钥->${alice.privateKey}")
    println("bob公钥->${bob.publicKey}")
    println("bob私钥->${bob.privateKey}")
}


private fun PersonString.generateKeyPair() {
    val keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM)
    keyPairGenerator.initialize(RSA_KEY_SIZE)
    val keyPair = keyPairGenerator.generateKeyPair()
    this.privateKey = keyPair.private.encodeBase64String()
    this.publicKey = keyPair.public.encodeBase64String()
}

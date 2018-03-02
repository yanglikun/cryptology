package com.github.yanglikun.signature.rsa

import com.github.yanglikun.cryptology.decodeBase64
import com.github.yanglikun.cryptology.encodeBase64String
import com.github.yanglikun.cryptology.rsa.generateKeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey


val RSA_ALGORITHM = "RSA"
val MD5_RSA_ALGORITHM = "MD5withRSA"
val RSA_KEY_SIZE = 1024

class Person(val name: String) {
    lateinit var publicKey: RSAPublicKey
    lateinit var privateKey: RSAPrivateKey
}

fun main(args: Array<String>) {

    val alice = Person("alice")
    alice.generateKeyPair()

    val data = "abc"
    val signBase64 = sign(alice.privateKey, "abc").encodeBase64String()
    println("签名值:$signBase64")
    println(verify(alice.publicKey, data, signBase64))
    println(verify(alice.publicKey, data+"a", signBase64))

}

fun verify(publicKey: RSAPublicKey, data: String, signBase64: String): Boolean {
    val signature = Signature.getInstance(MD5_RSA_ALGORITHM)
    signature.initVerify(publicKey)
    signature.update(data.toByteArray())
    return signature.verify(signBase64.decodeBase64())
}

private fun sign(privateKey: PrivateKey, data: String): ByteArray {
    val signature = Signature.getInstance(MD5_RSA_ALGORITHM)
    signature.initSign(privateKey)
    signature.update(data.toByteArray())
    return signature.sign()
}

fun Person.generateKeyPair() {
    val keyPairGenerator = KeyPairGenerator.getInstance(com.github.yanglikun.cryptology.rsa.RSA_ALGORITHM)
    keyPairGenerator.initialize(com.github.yanglikun.cryptology.rsa.RSA_KEY_SIZE)
    val keyPair = keyPairGenerator.generateKeyPair()
    this.privateKey = keyPair.private as RSAPrivateKey
    this.publicKey = keyPair.public as RSAPublicKey
}
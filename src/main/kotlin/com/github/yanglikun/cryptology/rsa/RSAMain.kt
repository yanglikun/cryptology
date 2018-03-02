package com.github.yanglikun.cryptology.rsa

import com.github.yanglikun.cryptology.decodeBase64
import com.github.yanglikun.cryptology.decrypt
import com.github.yanglikun.cryptology.encodeBase64String
import com.github.yanglikun.cryptology.encrypt
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

val RSA_ALGORITHM = "RSA"
val RSA_KEY_SIZE = 1024

class Person(val name: String) {
    lateinit var publicKey: RSAPublicKey
    lateinit var privateKey: RSAPrivateKey
}

fun main(args: Array<String>) {
    val alice = Person("Alice")
    val bob = Person("bob")

    //各自生成各自的秘钥,不需要交换
    alice.generateKeyPair()
    bob.generateKeyPair()

    encryptAndDecrypt(alice.publicKey, alice.privateKey)

    encryptAndDecrypt(bob.publicKey, bob.privateKey)

    println("alice公钥->${alice.publicKey.encodeBase64String()}")
    println("alice私钥->${alice.privateKey.encodeBase64String()}")
    println("bob公钥->${bob.publicKey.encodeBase64String()}")
    println("bob私钥->${bob.privateKey.encodeBase64String()}")
}

fun encryptAndDecrypt(publicKey: PublicKey, privateKey: PrivateKey) {
    val plaintText = "www.jd.com"
    val cipherText = publicKey.encrypt(plaintText.toByteArray()).encodeBase64String()
    val decryptByte = privateKey.decrypt(cipherText.decodeBase64())
    println("解密后->${String(decryptByte)}")
}

fun encryptAndDecrypt(privateKey: PrivateKey, publicKey: PublicKey) {
    val plaintText = "www.jd.com"
    val cipherText = privateKey.encrypt(plaintText.toByteArray()).encodeBase64String()
    val decryptByte = publicKey.decrypt(cipherText.decodeBase64())
    println("解密后->${String(decryptByte)}")
}

fun Person.generateKeyPair() {
    val keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM)
    keyPairGenerator.initialize(RSA_KEY_SIZE)
    val keyPair = keyPairGenerator.generateKeyPair()
    this.privateKey = keyPair.private as RSAPrivateKey
    this.publicKey = keyPair.public as RSAPublicKey
}

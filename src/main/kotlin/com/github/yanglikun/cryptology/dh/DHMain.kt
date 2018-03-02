package com.github.yanglikun.cryptology.dh

import com.github.yanglikun.cryptology.decrypt
import com.github.yanglikun.cryptology.encodeBase64String
import com.github.yanglikun.cryptology.encrypt
import java.security.KeyPairGenerator
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey

val DH_ALGORITHM = "DH"
val AES_ALGORITHM = "AES"
val DH_KEY_SIZE = 512

data class Person(val name: String) {
    lateinit var publicKeyOfOpposite: DHPublicKey
    lateinit var publicKey: DHPublicKey
    lateinit var privateKey: DHPrivateKey
}


fun main(args: Array<String>) {

    val alice = Person("Alice")
    val bob = Person("Bob")

    //alice构建秘钥
    alice.generateKeyPairOfSender()
    //alice发送'alice公钥'给bob
    alice.sendPublicKey(bob)

    //bob构建秘钥
    bob.generateKeyPairOfReceiver()
    //bob发送'bob公钥'给alice
    bob.sendPublicKey(alice)

    //使用各自私钥和对方公钥生成本地秘钥
    val aliceSecretKey = alice.generateLocalSecretKey()
    val bobSecretKey = bob.generateLocalSecretKey()

    //alice加密明文
    val plainText = "www.jd.com"
    val aliceCipher = aliceSecretKey.encrypt(plainText.toByteArray())
    //bob解密明文
    val bobPlainText = bobSecretKey.decrypt(aliceCipher)

    println("解密后:" + String(bobPlainText))

    println("alice->公钥:${alice.publicKey.encodeBase64String()}")
    println("alice->私钥:${alice.privateKey.encodeBase64String()}")
    println("alice->本地秘钥:${aliceSecretKey.encodeBase64String()}")

    println("bob->公钥:${bob.publicKey.encodeBase64String()}")
    println("bob->私钥:${bob.privateKey.encodeBase64String()}")
    println("bob->本地秘钥:${bobSecretKey.encodeBase64String()}")
}

private fun Person.generateLocalSecretKey(): SecretKey {
    val keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM)
    keyAgreement.init(this.privateKey)
    keyAgreement.doPhase(this.publicKeyOfOpposite, true)
    return keyAgreement.generateSecret(AES_ALGORITHM)
}

private fun Person.sendPublicKey(receiver: Person) {
    receiver.publicKeyOfOpposite = this.publicKey
}

private fun Person.generateKeyPairOfSender() {
    val aliceKeyPairGenerator = KeyPairGenerator.getInstance(DH_ALGORITHM)
    aliceKeyPairGenerator.initialize(DH_KEY_SIZE)

    val keyPair = aliceKeyPairGenerator.generateKeyPair()
    this.publicKey = keyPair.public as DHPublicKey
    this.privateKey = keyPair.private as DHPrivateKey
}

private fun Person.generateKeyPairOfReceiver() {
    val bobKeyPairGenerator = KeyPairGenerator.getInstance(DH_ALGORITHM)
    bobKeyPairGenerator.initialize(this.publicKeyOfOpposite.params)

    val keyPair = bobKeyPairGenerator.generateKeyPair()
    this.publicKey = keyPair.public as DHPublicKey
    this.privateKey = keyPair.private as DHPrivateKey
}
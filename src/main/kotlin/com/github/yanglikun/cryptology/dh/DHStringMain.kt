package com.github.yanglikun.cryptology.dh

import com.github.yanglikun.cryptology.*
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey

data class PersonString(val name: String) {
    lateinit var publicKeyOfOpposite: String
    lateinit var publicKey: String
    lateinit var privateKey: String
}

fun main(args: Array<String>) {

    val alice = PersonString("Alice")
    val bob = PersonString("Bob")

    //alice构建秘钥,并发送自己公钥给bob
    alice.generateKeyPairOfSender()
    alice.sendPublicKey(bob)

    //bob构建秘钥,并发送自己公钥给alice
    bob.generateKeyPairOfReceiver()
    bob.sendPublicKey(alice)

    //使用各自私钥和对方公钥生成本地秘钥
    val aliceSecretKey = alice.generateLocalSecretKey()
    val bobSecretKey = bob.generateLocalSecretKey()

    //alice加密明文
    val aliceCipher = aliceSecretKey.encrypt("www.jd.com".toByteArray())
    //bob解密明文
    val bobPlainText = bobSecretKey.decrypt(aliceCipher)

    println("解密后:" + String(bobPlainText))

    println("alice->公钥:${alice.publicKey}")
    println("alice->私钥:${alice.privateKey}")
    println("alice->本地秘钥:${aliceSecretKey.encodeBase64String()}")

    println("bob->公钥:${bob.publicKey}")
    println("bob->私钥:${bob.privateKey}")
    println("bob->本地秘钥:${bobSecretKey.encodeBase64String()}")
}

private fun PersonString.generateLocalSecretKey(): SecretKey {
    val keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM)
    //转换string为秘钥对象
    val privateKey = this.privateKey.parseToPrivateKey(DH_ALGORITHM) as DHPrivateKey
    val publicKeyOfOpposite = this.publicKeyOfOpposite.parseToPublicKey(DH_ALGORITHM) as DHPublicKey

    keyAgreement.init(privateKey)
    keyAgreement.doPhase(publicKeyOfOpposite, true)
    return keyAgreement.generateSecret(AES_ALGORITHM)
}

private fun PersonString.sendPublicKey(receiver: PersonString) {
    receiver.publicKeyOfOpposite = this.publicKey
}

private fun PersonString.generateKeyPairOfSender(): Pair<String, String> {
    val aliceKeyPairGenerator = KeyPairGenerator.getInstance(DH_ALGORITHM)
    aliceKeyPairGenerator.initialize(DH_KEY_SIZE)

    val keyPair = aliceKeyPairGenerator.generateKeyPair()
    publicKey = keyPair.public.encodeBase64String()
    privateKey = keyPair.private.encodeBase64String()
    return Pair(publicKey, privateKey)
}

private fun PersonString.generateKeyPairOfReceiver():
        Pair<String, String> {
    val bobKeyPairGenerator = KeyPairGenerator.getInstance(DH_ALGORITHM)
    //转换string为秘钥对象
    val publicKeyOfOpposite = this.publicKeyOfOpposite.parseToPublicKey(DH_ALGORITHM) as DHPublicKey

    bobKeyPairGenerator.initialize(publicKeyOfOpposite.params)

    val keyPair = bobKeyPairGenerator.generateKeyPair()
    this.publicKey = keyPair.public.encodeBase64String()
    this.privateKey = keyPair.private.encodeBase64String()
    return Pair(publicKey, privateKey)
}
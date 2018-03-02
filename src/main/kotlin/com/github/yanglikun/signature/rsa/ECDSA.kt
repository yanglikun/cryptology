package com.github.yanglikun.signature.rsa

import com.github.yanglikun.cryptology.decodeBase64
import com.github.yanglikun.cryptology.encodeBase64String
import java.security.*

val ECDSA_ALGORITHM = "RSA"
val SHA_ECDSA_ALGORITHM = "MD5withRSA"

fun main(args: Array<String>) {

    val data = "abc"
    val keyPairGenerator = KeyPairGenerator.getInstance(ECDSA_ALGORITHM)
    val keyPair = keyPairGenerator.genKeyPair()


    //私钥签名
    val signBase64 = sign(keyPair.private, data)
    println("签名值->$signBase64")

    //公钥验证
    println(verify(keyPair.public, data, signBase64))
    println(verify(keyPair.public, data + "a", signBase64))


}

fun verify(public: PublicKey, data: String, signBase64: String): Boolean {
    val verify = Signature.getInstance(SHA_ECDSA_ALGORITHM)
    verify.initVerify(public)
    verify.update(data.toByteArray())
    return verify.verify(signBase64.decodeBase64())
}

private fun sign(privateKey: PrivateKey, data: String): String {
    val signature = Signature.getInstance(SHA_ECDSA_ALGORITHM)
    signature.initSign(privateKey)
    signature.update(data.toByteArray())
    return signature.sign().encodeBase64String()
}
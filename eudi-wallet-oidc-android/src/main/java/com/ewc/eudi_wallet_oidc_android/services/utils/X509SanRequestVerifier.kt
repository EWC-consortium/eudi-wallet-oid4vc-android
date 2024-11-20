package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import java.util.Base64 as base64

class X509SanRequestVerifier private constructor() {

    companion object {
        val instance = X509SanRequestVerifier()
    }

    fun extractX5cFromJWT(jwt: String): List<String>? {
        val segments = jwt.split(".")
        if (segments.size != 3) {
            println("Invalid JWT format")
            return null
        }

        val headerSegment = segments[0]
        val headerJson = String(Base64.decode(headerSegment, Base64.URL_SAFE))
        val headerMap = JSONObject(headerJson)
        return if (headerMap.has("x5c")) {
            val x5cArray = headerMap.getJSONArray("x5c")
            List(x5cArray.length()) { x5cArray.getString(it) }
        } else {
            println("x5c not found in JWT header")
            null
        }
    }

    fun validateClientIDInCertificate(x5cChain: List<String>?, clientID: String?): Boolean {
        val leafCertData = Base64.decode(x5cChain?.firstOrNull() ?: "", Base64.DEFAULT)
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(leafCertData.inputStream()) as X509Certificate

        val dnsNames = extractDNSNamesFromCertificate(certificate)
        return dnsNames.contains(clientID)
    }

    private fun extractDNSNamesFromCertificate(certificate: X509Certificate): List<String> {
        val dnsNames = mutableListOf<String>()
        val sanList = certificate.subjectAlternativeNames ?: return dnsNames

        for (san in sanList) {
            if (san[0] == 2) { // DNS Name
                dnsNames.add(san[1] as String)
            }
        }
        return dnsNames
    }

    fun validateSignatureWithCertificate(jwt: String, x5cChain: List<String>): Boolean {
        val leafCertData = Base64.decode(x5cChain.firstOrNull() ?: "", Base64.DEFAULT)
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(leafCertData.inputStream()) as X509Certificate
        val publicKey = certificate.publicKey

        val segments = jwt.split(".")
        if (segments.size != 3) {
            println("Invalid JWT format")
            return false
        }

        val signedData = "${segments[0]}.${segments[1]}"
        val signature = Base64.decode(base64UrlToBase64(segments[2]), Base64.DEFAULT)

        return verifySignature(publicKey, signedData.toByteArray(), signature)
    }

    private fun base64UrlToBase64(base64Url: String): String {
        var base64 = base64Url.replace('-', '+').replace('_', '/')
        val padding = 4 - base64.length % 4
        if (padding != 4) {
            base64 += "=".repeat(padding)
        }
        return base64
    }

    private fun verifySignature(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val signatureInstance = Signature.getInstance("SHA256withRSA")
            signatureInstance.initVerify(publicKey)
            signatureInstance.update(data)
            signatureInstance.verify(signature)
        } catch (e: Exception) {
            println("Signature verification failed: ${e.message}")
            false
        }
    }

//    fun validateTrustChain(certificates: List<ByteArray>): Boolean {
//        val certificateFactory = CertificateFactory.getInstance("X.509")
//        val x509Certificates = certificates.map {
//            certificateFactory.generateCertificate(it.inputStream()) as X509Certificate
//        }
//
//        val certPath = certificateFactory.generateCertPath(x509Certificates)
//        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
//        trustManagerFactory.init(null as KeyStore?) // Use the default trust store
//
//        // Retrieve the X509TrustManager to get the trusted issuers
//        val trustManager = trustManagerFactory.trustManagers.first() as X509TrustManager
//        val trustAnchors = trustManager.acceptedIssuers.map { TrustAnchor(it, null) }.toSet()
//
//        val pkixParams = PKIXParameters(trustAnchors).apply {
//            isRevocationEnabled = false // Disable revocation; adjust based on security needs
//        }
//
//        return try {
//            val certPathValidator = CertPathValidator.getInstance("PKIX")
//            certPathValidator.validate(certPath, pkixParams)
//            true
//        } catch (e: Exception) {
//            println("Certificate path validation failed: ${e.message}")
//            false
//        }
//    }


//    fun validateTrustChain(x5cChain: List<String>): Boolean {
//        try {
//            // Convert the Base64 encoded certificates to X509Certificate objects
//            val certificateFactory = CertificateFactory.getInstance("X.509")
//            val certificates = x5cChain.mapNotNull { certBase64 ->
//                val certData = base64.getDecoder().decode(certBase64)
//                try {
//                    certificateFactory.generateCertificate(ByteArrayInputStream(certData)) as X509Certificate
//                } catch (e: Exception) {
//                    println("Invalid certificate in chain: ${e.message}")
//                    null
//                }
//            }
//
//            // If the list of certificates is empty or contains invalid certificates, return false
//            if (certificates.isEmpty()) {
//                println("No valid certificates found in the chain.")
//                return false
//            }
//
//            // Initialize TrustManagerFactory to get the default trust managers
//            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
//            trustManagerFactory.init(null as KeyStore?) // Uses the default system trust store
//
//            // Find the first X509TrustManager
//            val x509TrustManager = trustManagerFactory.trustManagers
//                .filterIsInstance<X509TrustManager>()
//                .firstOrNull()
//                ?: throw Exception("No X509TrustManager found in the TrustManagerFactory")
//
//            // Create the CertPath from the certificates
//            val certPath = certificateFactory.generateCertPath(certificates)
//
//            // Create PKIXParameters using the accepted issuers from the trust manager
//            val acceptedIssuers = x509TrustManager.acceptedIssuers
//                .map { TrustAnchor(it, null) }
//                .toSet()
//            val pkixParams = java.security.cert.PKIXParameters(acceptedIssuers).apply {
//                isRevocationEnabled = false // Adjust this based on your requirements
//            }
//
//            // Validate the certification path using PKIX
//            val certPathValidator = CertPathValidator.getInstance("PKIX")
//            try {
//                certPathValidator.validate(certPath, pkixParams)
//                println("The certificate chain is trusted.")
//                return true
//            } catch (e: CertPathValidatorException) {
//                println("Certificate path validation failed: ${e.message}")
//                return false
//            }
//        } catch (e: Exception) {
//            println("An error occurred during trust chain validation: ${e.message}")
//            return false
//        }
//    }

    @Throws(Exception::class)
    fun validateTrustChain(x5cCertificates: List<String>): Boolean {
        val cf = CertificateFactory.getInstance("X.509")

        // Convert Base64 strings to X509Certificates
        val x509Certificates = x5cCertificates.map { x5c ->
            val certBytes = base64.getDecoder().decode(x5c)
            cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
        }

        // Create a custom KeyStore with the provided certificates as trusted anchors
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null) // Initialize an empty KeyStore
            x509Certificates.forEachIndexed { index, cert ->
                setCertificateEntry("cert$index", cert) // Add each certificate as a trusted entry
            }
        }

        // Initialize TrustManager with the custom KeyStore
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(keyStore)

        // Create CertPath from X509Certificates
        val certPath = cf.generateCertPath(x509Certificates)

        // Configure PKIXParameters to use only the provided anchors
        val params = PKIXParameters(keyStore)
        params.isRevocationEnabled = false // Disable revocation for simplicity

        // Validate CertPath
        val cpv = CertPathValidator.getInstance("PKIX")
        try{
            cpv.validate(certPath, params)
            return true
        }catch (e:Exception){
            println("${e.message}")
            return false
        }

    }

}

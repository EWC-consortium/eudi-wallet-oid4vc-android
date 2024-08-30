package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

import com.ewc.eudi_wallet_oidc_android.models.DIDDocument
import com.ewc.eudi_wallet_oidc_android.models.JwkKey
import com.ewc.eudi_wallet_oidc_android.models.JwksResponse
import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.google.gson.Gson
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import retrofit2.Response
import java.text.ParseException

class SignatureValidator {

    /**
     * Validates the signature of a JWT using a JWK fetched either from
     *    Kid or JWKS URI present in Authorisation configuration.
     *
     * @param jwt
     * @param jwksUri
     * @return
     *
     * Throws SignatureException if validation fails
     */
    @Throws(SignatureException::class)
    suspend fun validateSignature(jwt: String?,jwksUri:String?=null): Boolean {
        return try {
            jwt?.let {
                val jwsObject = JWSObject.parse(jwt)
                val header = jwsObject.header
                val kid = header.keyID
                val algorithm = jwsObject.header.algorithm

                // Check the format of kid and process accordingly
                val response = if ( kid !=null && kid.startsWith("did:key:z")) {
                    processJWKFromKID(kid,algorithm)
                } else if ( kid !=null && kid.startsWith("did:ebsi:z")){
                    processEbsiJWKFromKID(kid)
                }
                else {
                    processJWKFromJwksUri(kid,jwksUri)
                }
                if (response != null) {
                    val isSignatureValid = verifyJwtSignature(jwt, response.toJSONString())
                    isSignatureValid
                } else {
                    throw SignatureException("Invalid signature")
                }
            } ?:  throw SignatureException("Invalid signature")
        } catch (e: IllegalArgumentException) {
            throw SignatureException("Invalid signature")
        }
    }

    // This function fetches and processes the DID Document, and extracts the P-256 JWK if present.
    private suspend fun processEbsiJWKFromKID(did: String?): ECKey? {
        return try {
            // Validate DID format
            if (did == null || !did.startsWith("did:ebsi:z")) {
                throw IllegalArgumentException("Invalid DID format")
            }

            // Fetch the DID document from the API
            val response:Response<DIDDocument> = ApiManager.api.getService()?.ebsiDIDResolver(
                "https://api-conformance.ebsi.eu/did-registry/v5/identifiers/$did"
            ) ?: throw IllegalStateException("API service not available")

            // Extract the P-256 JWK from the JSON response
            val didDocument = response.body() ?: throw IllegalStateException("Empty response body")
            extractJWK(didDocument)
        } catch (e: Exception) {
            // Handle errors, possibly log or rethrow as needed
            println("Error processing DID: ${e.message}")
            null
        }
    }
    private fun extractJWK(didDocument: DIDDocument): ECKey? {
        return try {
            // Iterate through each verification method
            for (method in didDocument.verificationMethods) {
                try {
                    val publicKeyJwk = method.publicKeyJwk

                    // Check if 'crv' is 'P-256'
                    if (publicKeyJwk.crv == "P-256") {
                        // Convert the JSON JWK to a Nimbus JWK
                        val jwk = JWK.parse(
                            """{
                            "kty": "${publicKeyJwk.kty}",
                            "crv": "${publicKeyJwk.crv}",
                            "x": "${publicKeyJwk.x}",
                            "y": "${publicKeyJwk.y}"
                        }"""
                        )
                        if (jwk is ECKey) {
                            return jwk
                        }
                    }
                } catch (e: ParseException) {
                    // Handle JWK parsing exceptions
                    println("Error parsing JWK: ${e.message}")
                }
            }

            // Return null if no matching JWK is found
            null
        } catch (e: Exception) {
            // Handle any unexpected exceptions
            println("Error processing DID document: ${e.message}")
            null
        }
    }

    /**
     * Processes a JWK from a DID
     *
     * @param did
     * @return
     */
    private fun processJWKFromKID(did: String?, algorithm: JWSAlgorithm): JWK? {
        try {
            if (did == null || !did.startsWith("did:key:z")) {
                throw IllegalArgumentException("Invalid DID format")
            }
            // Extract the multiBaseEncoded part
            val multiBaseEncoded = if (did.contains("#")) {
                did.split("#")[0].substring("did:key:z".length)
            } else {
                did.substring("did:key:z".length)
            }
            // Call convertDIDToJWK function from DIDService
            return DIDService().convertDIDToJWK(multiBaseEncoded,algorithm)
        } catch (e: IllegalArgumentException) {
            // Handle specific exception if needed
            throw IllegalArgumentException("Error converting DID to JWK", e)
        } catch (e: Exception) {
            // Handle other exceptions
            throw IllegalArgumentException("Error converting DID to JWK", e)
        }

    }


    /**
     * Verifies the signature of a JWT using a JWK provided as JSON.
     *
     * @param jwt
     * @param jwkJson
     * @return
     */
    @Throws(IllegalArgumentException::class)
    private fun verifyJwtSignature(jwt: String, jwkJson: String): Boolean {
        try {
            // Parse the JWK from JSON
            val jwk = ECKey.parse(jwkJson)

            // Create a JWS object from the JWT string
            val jwsObject = JWSObject.parse(jwt)

            // Create a JWS verifier with the EC key
//            val verifier = ECDSAVerifier(jwk)
            // Get the algorithm from the JWS header
            val algorithm = jwsObject.header.algorithm

            // Create the appropriate verifier based on the algorithm
            val verifier: JWSVerifier = when (algorithm) {
                JWSAlgorithm.ES256 -> ECDSAVerifier(jwk.toECKey())
                JWSAlgorithm.ES384 -> ECDSAVerifier(jwk.toECKey())
                JWSAlgorithm.ES512 -> ECDSAVerifier(jwk.toECKey())
                else -> throw JOSEException("Unsupported JWS algorithm $algorithm")
            }
            // Verify the JWS signature
            return jwsObject.verify(verifier)
        } catch (e: Exception) {
            // Handle exceptions appropriately
            e.printStackTrace()
            throw IllegalArgumentException("Invalid signature")
        }
    }


    /**
     * Processes a JWK from a JWKS (JSON Web Key Set) URI.
     *
     * @param kid
     * @param jwksUri
     * @return
     */
    private suspend fun processJWKFromJwksUri(kid: String?, jwksUri:String?): JWK? {
        if (jwksUri != null) {
            val jwkKey = fetchJwks(jwksUri =jwksUri, kid = kid)
            return convertToJWK(jwkKey)
        }
        return null
    }

    /**
     * Converts a JwkKey object to a JWK (JSON Web Key).
     *
     * @param jwkKey The JwkKey object.
     * @return The JWK object or null if jwkKey is null.
     */
    private fun convertToJWK(jwkKey: JwkKey?): JWK? {
        return jwkKey?.let {
            val curve = when (it.crv) {
                "P-256" -> Curve.P_256
                "P-384" -> Curve.P_384
                "P-521" -> Curve.P_521
                else -> throw IllegalArgumentException("Unsupported curve: ${it.crv}")
            }

            ECKey.Builder(curve, Base64URL.from(it.x), Base64URL.from(it.y))
                .keyID(it.kid)
                .build()
        }
    }

    /**
     * Fetches a JwkKey object from a specified JWKS (JSON Web Key Set) URI.
     *
     * @param jwksUri
     * @param kid
     * @return
     */
    private suspend fun fetchJwks(jwksUri: String, kid: String?): JwkKey? {
        return withContext(Dispatchers.IO) {
            try {
                val url = URL(jwksUri)
                val json = url.readText()
                // Parse JSON into JwksResponse object
                val jwksResponse =  Gson().fromJson(json, JwksResponse::class.java)

                // Find the JWK with "use" = "sig"
                var jwkKey = jwksResponse.keys.firstOrNull { it.use == "sig" }

                // If no "sig" key is found, find by kid
                if (jwkKey == null && kid != null) {
                    jwkKey = jwksResponse.keys.firstOrNull { it.kid == kid }
                }
                return@withContext jwkKey
            } catch (e: Exception) {
                println(e.toString())
                return@withContext null
            }
        }
    }
}
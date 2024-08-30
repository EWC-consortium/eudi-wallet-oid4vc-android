package com.ewc.eudi_wallet_oidc_android.services.did

import com.ewc.eudi_wallet_oidc_android.CryptographicAlgorithms
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL

interface DIDServiceInterface {

    /**
     * Generate a did:key:jcs-pub decentralised identifier.
     * @param jwk - DID is created using the JWK
     * @return DID
     */
    fun createDID(jwk: ECKey): String

    /**
     * Generate JWK of curve P-256 for an optional seed value. (ECKey)
     * @param seed is optional, if seed is present then the JWK will be created with the seed
     *          if seed is not present, then will create a new JWK
     *
     * @return JWK
     */
    fun createJWK(seed: String? = null): ECKey

    /**
     * Create DID according to cryptographicAlgorithm
     *
     * @param jwk
     * @param cryptographicAlgorithm
     * @return
     */
    fun createDID(
        jwk: JWK,
        cryptographicAlgorithm: String? = CryptographicAlgorithms.ES256): String

    /**
     * Create JWK according to cryptographicAlgorithm
     *
     * @param seed
     * @param cryptographicAlgorithm
     * @return
     */
    fun createJWK(
        seed: String? = null,
        cryptographicAlgorithm: String? = CryptographicAlgorithms.ES256): JWK

    /**
     * Create ES256 JWK
     *
     * @param seed
     * @return
     */
    fun createES256JWK(seed: String?): JWK

    /**
     * Create ES256 DID
     *
     * @param jwk
     * @return
     */
    fun createES256DID(jwk: JWK): String

    /**
     * Create ED25519 JWK
     *
     * @param seed
     * @return
     */
    fun createEdDSAJWK(seed: String?): JWK?

    /**
     * Generate DID for the ED25519
     * @param privateKeyX - X value of the ED25519 jwk
     *
     * @return DID
     */
    fun createEdDSADID(privateKeyX: Base64URL): String

    /**
     * Converts a DID string to a JWK (JSON Web Key).
     * @param did - Decentralized Identifier (DID) string
     * @return JWK object
     * @throws IllegalArgumentException if the DID format is invalid or conversion fails
     */
    fun convertDIDToJWK(did: String, algorithm: JWSAlgorithm):JWK
}
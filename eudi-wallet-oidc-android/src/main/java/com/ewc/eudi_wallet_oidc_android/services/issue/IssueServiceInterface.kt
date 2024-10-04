package com.ewc.eudi_wallet_oidc_android.services.issue

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedTokenResponse
import com.nimbusds.jose.jwk.JWK

interface IssueServiceInterface {


    /**
     * To process the credential offer request
     * @param data - will accept the full data which is scanned from the QR code or deep link
     *                  The data can contain credential offer or credential offer uri
     * @return Credential Offer
     */
    suspend fun resolveCredentialOffer(data: String?): CredentialOffer?

    /**
     * To process the authorisation request
     * The authorisation request is to grant access to the credential endpoint
     * @param did - DID created for the issuance
     * @param subJwk - for singing the requests
     * @param credentialOffer - To build the authorisation request
     * @param codeVerifier - to build the authorisation request
     * @param authorisationEndPoint - to build the authorisation request
     *
     * @return String - Uri with query parameter code with value short-lived authorisation code
     */
    suspend fun processAuthorisationRequest(
        did: String?,
        subJwk: JWK?,
        credentialOffer: CredentialOffer?,
        codeVerifier: String,
        authConfig: AuthorisationServerWellKnownConfiguration?,
        format: String? = "jwt_vc_json",
        docType: String? =null,
        issuerConfig: IssuerWellKnownConfiguration?
    ): String?

    /**
     * To process the token,
     *
     * @param did
     * @param tokenEndPoint
     * @param code - If the credential offer is pre authorised, then use the pre authorised code from the credential offer
     *              else use the code from the previous function - processAuthorisationRequest
     * @param codeVerifier - use the same code verifier used for processAuthorisationRequest
     * @param isPreAuthorisedCodeFlow - boolean value to notify its a pre authorised request
     *                                  if pre-authorized_code is present
     * @param userPin - optional value, if the user_pin_required is true
     *              PIN will be provided by the user
     *
     * @return Token response
     */
    suspend fun processTokenRequest(
        did: String?,
        tokenEndPoint: String?,
        code: String?,
        codeVerifier: String?,
        isPreAuthorisedCodeFlow: Boolean?,
        userPin: String?,
        version: Int?
    ): WrappedTokenResponse?

    /**
     * To process the credential, credentials can be issued in two ways,
     *     intime and deferred
     *
     *     If its intime, then we will receive the credential as the response
     *     If its deferred, then we will get he acceptance token and use this acceptance token to call deferred
     *
     * @param did
     * @param subJwk
     * @param nonce
     * @param credentialOffer
     * @param issuerConfig
     * @param accessToken
     * @param format
     *
     * @return credential response
     */
    suspend fun processCredentialRequest(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        accessToken: String?,
        format: String
    ): WrappedCredentialResponse?

    /**
     * For issuance of the deferred credential.
     * @param acceptanceToken - token which we got from credential request
     * @param deferredCredentialEndPoint - end point to call the deferred credential
     *
     * @return Credential response
     */
    suspend fun processDeferredCredentialRequest(
        acceptanceToken: String?,
        deferredCredentialEndPoint: String?
    ): WrappedCredentialResponse?
    suspend fun processDeferredCredentialRequestV2(
        transactionId: String?,
        accessToken: String?,
        deferredCredentialEndPoint: String?
    ): WrappedCredentialResponse?

    /**
     * Get format from IssuerWellKnownConfiguration
     *
     * @param issuerConfig
     * @param type
     */
    fun getFormatFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): String?

    /**
     * Get types from credential offer
     *
     * @param credentialOffer
     * @return
     */
    fun getTypesFromCredentialOffer(
        credentialOffer: CredentialOffer?
    ): ArrayList<String>

    /**
     * Get types from Issuer Config
     *
     * @param issuerConfig
     * @param type
     * @return
     */
    fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): Any?
    fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?,
        version:Int? = 2,
    ): Any?

    /**
     * Get types from Issuer Config
     *
     * @param issuerConfig
     * @param type
     * @return
     */
    fun getCryptoFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): ArrayList<String>?
}
package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedAuthConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedIssuerConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.v1.IssuerWellKnownConfigurationV1
import com.ewc.eudi_wallet_oidc_android.models.v2.IssuerWellKnownConfigurationV2
import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.google.gson.Gson

class DiscoveryService : DiscoveryServiceInterface {

    /**
     * To fetch the Issue configuration
     *
     * @param credentialIssuerWellKnownURI
     * @return WrappedIssuerConfigResponse
     */
    override suspend fun getIssuerConfig(credentialIssuerWellKnownURI: String?): WrappedIssuerConfigResponse? {
        var credentialIssuer = credentialIssuerWellKnownURI?.replace("/.well-known/openid-credential-issuer","")
        credentialIssuer = removeTrailingSlash(credentialIssuer)
        credentialIssuer = "$credentialIssuer/.well-known/openid-credential-issuer"

        try {
            UrlUtils.validateUri(credentialIssuer)
            val response =
                ApiManager.api.getService()
                    ?.fetchIssuerConfig("$credentialIssuer")
            return if (response?.isSuccessful == true) {
                parseIssuerConfigurationResponse(issuerConfigResponseJson =response.body()?.string())

            } else {
                WrappedIssuerConfigResponse(issuerConfig = null, errorResponse = ErrorResponse(error = response?.code(), errorDescription = response?.message()))
            }
        } catch (exc: UriValidationFailed) {
            return WrappedIssuerConfigResponse(issuerConfig = null, errorResponse = ErrorResponse(error = null, errorDescription = "URI validation failed"))
        }
    }
    private fun removeTrailingSlash(input: String?): String? {
        return if (input?.endsWith("/")==true) {
            input?.dropLast(1) // Removes the last character
        } else {
            input
        }
    }
    private fun parseIssuerConfigurationResponse(issuerConfigResponseJson:String?): WrappedIssuerConfigResponse?{
        val gson = Gson()
        val issuerWellKnownConfigurationV2Response = try {
            gson.fromJson(issuerConfigResponseJson, IssuerWellKnownConfigurationV2::class.java)
        } catch (e: Exception) { null }
        return if (issuerWellKnownConfigurationV2Response?.credentialConfigurationsSupported == null){
            val issuerWellKnownConfigurationV1Response = try {
                gson.fromJson(issuerConfigResponseJson, IssuerWellKnownConfigurationV1::class.java)
            } catch (e: Exception) { null }
            if(issuerWellKnownConfigurationV1Response?.credentialsSupported==null){
                null
            } else{
                WrappedIssuerConfigResponse(
                    issuerConfig = IssuerWellKnownConfiguration(issuerWellKnownConfigurationV1 = issuerWellKnownConfigurationV1Response) ,
                    errorResponse = null )
            }
        } else{
            WrappedIssuerConfigResponse(
                issuerConfig =IssuerWellKnownConfiguration(issuerWellKnownConfigurationV2 = issuerWellKnownConfigurationV2Response) ,
                errorResponse = null )
        }
    }


    /**
     * To fetch the authorization server configuration
     *
     * @param authorisationServerWellKnownURI
     * @return WrappedAuthConfigResponse
     */
    override suspend fun getAuthConfig(authorisationServerWellKnownURI: String?): WrappedAuthConfigResponse {
        var authorizationServer = authorisationServerWellKnownURI?.replace("/.well-known/openid-configuration","")
        authorizationServer = removeTrailingSlash(authorizationServer)
        authorizationServer = "$authorizationServer/.well-known/openid-configuration"
        try {
            UrlUtils.validateUri(authorizationServer)

            val response =
                ApiManager.api.getService()
                    ?.fetchAuthConfig("$authorizationServer")
            return if (response?.isSuccessful == true) {
                WrappedAuthConfigResponse(authConfig = response.body(), errorResponse = null)
            } else {
                WrappedAuthConfigResponse(authConfig = null, errorResponse = ErrorResponse(error = response?.code(), errorDescription = response?.message()))
            }
        } catch (exc: UriValidationFailed) {
            return WrappedAuthConfigResponse(authConfig = null, errorResponse = ErrorResponse(error = null, errorDescription = "URI validation failed"))
        }
    }
}
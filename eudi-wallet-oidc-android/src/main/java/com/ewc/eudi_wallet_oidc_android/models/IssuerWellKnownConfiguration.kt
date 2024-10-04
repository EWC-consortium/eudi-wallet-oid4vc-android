package com.ewc.eudi_wallet_oidc_android.models

import com.ewc.eudi_wallet_oidc_android.models.v1.IssuerWellKnownConfigurationV1
import com.ewc.eudi_wallet_oidc_android.models.v2.Claims
import com.ewc.eudi_wallet_oidc_android.models.v2.IssuerWellKnownConfigurationV2
import com.google.gson.annotations.SerializedName

data class IssuerWellKnownConfiguration(
    @SerializedName("issuer") var issuer: String? = null,
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("authorization_server") var authorizationServer: String? = null,
    @SerializedName("authorization_servers") var authorizationServers: ArrayList<String>? = null,
    @SerializedName("credential_endpoint") var credentialEndpoint: String? = null,
    @SerializedName("deferred_credential_endpoint") var deferredCredentialEndpoint: String? = null,
    @SerializedName("display") var display: Any? = null,
    @SerializedName("credentials_supported") var credentialsSupported: Any? = null
){
    constructor(issuerWellKnownConfigurationV1: IssuerWellKnownConfigurationV1) : this(
        issuer = issuerWellKnownConfigurationV1.issuer,
        credentialIssuer = issuerWellKnownConfigurationV1.credentialIssuer,
        authorizationServer = issuerWellKnownConfigurationV1.authorizationServer,
        authorizationServers = issuerWellKnownConfigurationV1.authorizationServers,
        credentialEndpoint = issuerWellKnownConfigurationV1.credentialEndpoint,
        deferredCredentialEndpoint = issuerWellKnownConfigurationV1.deferredCredentialEndpoint,
        display = issuerWellKnownConfigurationV1.display,
        credentialsSupported = issuerWellKnownConfigurationV1.credentialsSupported
    )
    constructor(issuerWellKnownConfigurationV2:IssuerWellKnownConfigurationV2):this(
        issuer = issuerWellKnownConfigurationV2.issuer,
        credentialIssuer = issuerWellKnownConfigurationV2.credentialIssuer,
        authorizationServer = issuerWellKnownConfigurationV2.authorizationServer,
        authorizationServers = issuerWellKnownConfigurationV2.authorizationServers,
        credentialEndpoint = issuerWellKnownConfigurationV2.credentialEndpoint,
        deferredCredentialEndpoint = issuerWellKnownConfigurationV2.deferredCredentialEndpoint,
        display = issuerWellKnownConfigurationV2.display,
        credentialsSupported = issuerWellKnownConfigurationV2.credentialConfigurationsSupported

    )
}

data class CredentialsSupported(
    @SerializedName("format") var format: String? = null,
    @SerializedName("types") var types: ArrayList<String> = arrayListOf(),
    @SerializedName("trust_framework") var trustFramework: TrustFramework? = TrustFramework(),
    @SerializedName("display") var display: ArrayList<Display> = arrayListOf(),
    @SerializedName("cryptographic_suites_supported") var cryptographicSuitesSupported: ArrayList<String> = arrayListOf()
)
data class CredentialDetails(
    @SerializedName("format") val format: String? = null,
    @SerializedName("scope") val scope: String? = null,
    @SerializedName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerializedName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String>? = null,
    @SerializedName("display") val display: List<CredentialDisplay>? = null,
    @SerializedName("doctype") val doctype: String? = null,
    @SerializedName("credential_definition") val  credentialDefinition: Any? = null,
    @SerializedName("vct") var vct: String? = null,
    @SerializedName("claims") var claims: Claims? = null
)
data class CredentialDisplay(
    @SerializedName("name") var name: String? = null,
    @SerializedName("locale") var locale: String? = null,
    @SerializedName("logo") var logo: Image? = null,
    @SerializedName("description") var description: String? = null,
    @SerializedName("background_color") var backgroundColor: String? = null,
    @SerializedName("background_image") var backgroundImage: Image? = null,
    @SerializedName("text_color") var textColor: String? = null
)

data class Display(
    @SerializedName("name") var name: String? = null,
    @SerializedName("location") var location: String? = null,
    @SerializedName("locale") var locale: String? = null,
    @SerializedName("cover") var cover: Image? = Image(),
    @SerializedName("logo") var logo: Image? = Image(),
    @SerializedName("description") var description: String? = null
)

data class Image(
    @SerializedName("uri") var uri: String? = null,
    @SerializedName("url") var url: String? = null,
    @SerializedName("alt_text") var altText: String? = null
)
data class WrappedIssuerConfigResponse(
    var issuerConfig: IssuerWellKnownConfiguration? = null,
    var errorResponse: ErrorResponse? = null
)
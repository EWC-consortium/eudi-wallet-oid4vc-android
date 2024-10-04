package com.ewc.eudi_wallet_oidc_android.models.v1


import com.ewc.eudi_wallet_oidc_android.models.TrustFramework
import com.google.gson.annotations.SerializedName

data class IssuerWellKnownConfigurationV1(
    @SerializedName("issuer") var issuer: String? = null,
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("authorization_server") var authorizationServer: String? = null,
    @SerializedName("authorization_servers") var authorizationServers: ArrayList<String>? = null,
    @SerializedName("credential_endpoint") var credentialEndpoint: String? = null,
    @SerializedName("deferred_credential_endpoint") var deferredCredentialEndpoint: String? = null,
    @SerializedName("display") var display: Any? = null,
    @SerializedName("credentials_supported") var credentialsSupported: Any? = null
)

data class CredentialsSupportedV1(
    @SerializedName("format") var format: String? = null,
    @SerializedName("types") var types: ArrayList<String> = arrayListOf(),
    @SerializedName("trust_framework") var trustFramework: TrustFramework? = TrustFramework(),
    @SerializedName("display") var display: ArrayList<DisplayV1> = arrayListOf(),
    @SerializedName("cryptographic_suites_supported") var cryptographicSuitesSupported: ArrayList<String> = arrayListOf()
)
data class CredentialDetailsV1(
    @SerializedName("format") val format: String? = null,
    @SerializedName("scope") val scope: String? = null,
    @SerializedName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerializedName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String>? = null,
    @SerializedName("display") val display: List<CredentialDisplayV1>? = null,
    @SerializedName("doctype") val doctype: String? = null,
    @SerializedName("credential_definition") val  credentialDefinition: Any? = null
)
data class CredentialDisplayV1(
    @SerializedName("name") var name: String? = null,
    @SerializedName("locale") var locale: String? = null,
    @SerializedName("logo") var logo: ImageV1? = null,
    @SerializedName("description") var description: String? = null,
    @SerializedName("background_color") var backgroundColor: String? = null,
    @SerializedName("background_image") var backgroundImage: ImageV1? = null,
    @SerializedName("text_color") var textColor: String? = null
)

data class DisplayV1(
    @SerializedName("name") var name: String? = null,
    @SerializedName("location") var location: String? = null,
    @SerializedName("locale") var locale: String? = null,
    @SerializedName("cover") var cover: ImageV1? = ImageV1(),
    @SerializedName("logo") var logo: ImageV1? = ImageV1(),
    @SerializedName("description") var description: String? = null
)

data class ImageV1(
    @SerializedName("uri") var uri: String? = null,
    @SerializedName("url") var url: String? = null,
    @SerializedName("alt_text") var altText: String? = null
)
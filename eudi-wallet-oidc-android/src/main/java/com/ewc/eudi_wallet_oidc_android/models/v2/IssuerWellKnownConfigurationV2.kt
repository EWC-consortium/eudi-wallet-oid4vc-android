package com.ewc.eudi_wallet_oidc_android.models.v2

import com.ewc.eudi_wallet_oidc_android.models.TrustFramework

import com.google.gson.annotations.SerializedName

data class IssuerWellKnownConfigurationV2(
    @SerializedName("issuer") var issuer: String? = null,
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("authorization_server") var authorizationServer: String? = null,
    @SerializedName("authorization_servers") var authorizationServers: ArrayList<String>? = null,
    @SerializedName("credential_endpoint") var credentialEndpoint: String? = null,
    @SerializedName("deferred_credential_endpoint") var deferredCredentialEndpoint: String? = null,
    @SerializedName("display") var display: Any? = null,
    @SerializedName("credential_configurations_supported") var credentialConfigurationsSupported: Any? = null
)
data class CredentialsSupportedV2(
    @SerializedName("format") var format: String? = null,
    @SerializedName("types") var types: ArrayList<String> = arrayListOf(),
    @SerializedName("trust_framework") var trustFramework: TrustFramework? = TrustFramework(),
    @SerializedName("display") var display: ArrayList<DisplayV2> = arrayListOf(),
    @SerializedName("cryptographic_suites_supported") var cryptographicSuitesSupported: ArrayList<String> = arrayListOf(),
)
data class CredentialDetailsV2(
    @SerializedName("format") val format: String? = null,
    @SerializedName("scope") val scope: String? = null,
    @SerializedName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerializedName("credential_signing_alg_values_supported") val credentialSigningAlgValuesSupported: List<String>? = null,
    @SerializedName("display") val display: List<CredentialDisplayV2>? = null,
    @SerializedName("doctype") val doctype: String? = null,
    @SerializedName("credential_definition") val  credentialDefinition: Any? = null,
    @SerializedName("vct") var vct: String? = null,
    @SerializedName("claims") var claims: Claims? = null
)
data class Claims(
    @SerializedName("given_name") var givenName: List<DisplayInfoV2>? = null,
    @SerializedName("last_name") var lastName: List<DisplayInfoV2>? = null
)

data class DisplayInfoV2(
    @SerializedName("name") var name: String,
    @SerializedName("location") var location: String? = null,
    @SerializedName("locale") var locale: String,
    @SerializedName("description") var description: String? = null
)
data class CredentialDisplayV2(
    @SerializedName("name") var name: String? = null,
    @SerializedName("locale") var locale: String? = null,
    @SerializedName("logo") var logo: ImageV2? = null,
    @SerializedName("description") var description: String? = null,
    @SerializedName("background_color") var backgroundColor: String? = null,
    @SerializedName("background_image") var backgroundImage: ImageV2? = null,
    @SerializedName("text_color") var textColor: String? = null
)

data class DisplayV2(
    @SerializedName("name") var name: String? = null,
    @SerializedName("location") var location: String? = null,
    @SerializedName("locale") var locale: String? = null,
    @SerializedName("cover") var cover: ImageV2? = ImageV2(),
    @SerializedName("logo") var logo: ImageV2? = ImageV2(),
    @SerializedName("description") var description: String? = null
)

data class ImageV2(
    @SerializedName("uri") var uri: String? = null,
    @SerializedName("url") var url: String? = null,
    @SerializedName("alt_text") var altText: String? = null
)
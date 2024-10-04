package com.ewc.eudi_wallet_oidc_android.models
import com.google.gson.annotations.SerializedName
data class CredentialTypeDefinition(
    @SerializedName("type") var type: ArrayList<String>? = arrayListOf()
)
data class AuthorizationDetails(
    @SerializedName("type") var type: String? = "openid_credential",
    @SerializedName("format") var format: String? = null,
    @SerializedName("doctype") var doctype: String? = null,
    @SerializedName("types") var types: ArrayList<String>? = arrayListOf(),
    @SerializedName("locations") var locations: ArrayList<String>? = arrayListOf(),
    @SerializedName("credential_configuration_id") var credentialConfigurationId : String? = null,
    @SerializedName("vct") var vct: String? = null,
    @SerializedName("credential_definition") var credentialDefinition: CredentialTypeDefinition? = CredentialTypeDefinition()
)
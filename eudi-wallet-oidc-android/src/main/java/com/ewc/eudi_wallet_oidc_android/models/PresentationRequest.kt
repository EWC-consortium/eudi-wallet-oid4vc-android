package com.ewc.eudi_wallet_oidc_android.models
import com.google.gson.annotations.SerializedName
data class ClientMetaDetails(
    @SerializedName("client_name") var clientName: String? = null,
    @SerializedName("cover_uri") var coverUri: String? = null,
    @SerializedName("description") var description: String? = null,
    @SerializedName("location") var location: String? = null,
    @SerializedName("logo_uri") var logoUri: String? = null
)
data class PresentationRequest(
    @SerializedName("state") var state: String? = null,
    @SerializedName("client_id") var clientId: String? = null,
    @SerializedName("redirect_uri") var redirectUri: String? = null,
    @SerializedName("response_type") var responseType: String? = null,
    @SerializedName("response_mode") var responseMode: String? = null,
    @SerializedName("scope") var scope: String? = null,
    @SerializedName("nonce") var nonce: String? = null,
    @SerializedName("request_uri") var requestUri: String? = null,
    @SerializedName("response_uri") var responseUri: String? = null,
    @SerializedName("presentation_definition") var presentationDefinition: Any? = null,
    @SerializedName("presentation_definition_uri") var presentationDefinitionUri: String? = null,
    @SerializedName("client_metadata") var clientMetaDetails: Any? = null,
    @SerializedName("client_metadata_uri") var clientMetadataUri: String? = null,
    @SerializedName("client_id_scheme") var clientIdScheme: String? = null
)
data class WrappedPresentationRequest(
    var presentationRequest: PresentationRequest?=null,
    var errorResponse: ErrorResponse? = null
)
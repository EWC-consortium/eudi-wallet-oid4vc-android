package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class AuthorisationServerWellKnownConfiguration(

    @SerializedName("redirect_uris") var redirectUris: ArrayList<String> = arrayListOf(),
    @SerializedName("issuer") var issuer: String? = null,
    @SerializedName("authorization_endpoint") var authorizationEndpoint: String? = null,
    @SerializedName("token_endpoint") var tokenEndpoint: String? = null,
    @SerializedName("jwks_uri") var jwksUri: String? = null,
    @SerializedName("scopes_supported") var scopesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("response_types_supported") var responseTypesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("response_modes_supported") var responseModesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("grant_types_supported") var grantTypesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("subject_types_supported") var subjectTypesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("request_object_signing_alg_values_supported") var requestObjectSigningAlgValuesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("request_parameter_supported") var requestParameterSupported: Boolean? = null,
    @SerializedName("request_uri_parameter_supported") var requestUriParameterSupported: Boolean? = null,
    @SerializedName("token_endpoint_auth_methods_supported") var tokenEndpointAuthMethodsSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("request_authentication_methods_supported") var requestAuthenticationMethodsSupported: RequestAuthenticationMethodsSupported? = RequestAuthenticationMethodsSupported(),
    @SerializedName("vp_formats_supported") var vpFormatsSupported: VpFormatsSupported? = VpFormatsSupported(),
    @SerializedName("subject_syntax_types_supported") var subjectSyntaxTypesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("subject_syntax_types_discriminations") var subjectSyntaxTypesDiscriminations: ArrayList<String> = arrayListOf(),
    @SerializedName("subject_trust_frameworks_supported") var subjectTrustFrameworksSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("id_token_types_supported") var idTokenTypesSupported: ArrayList<String> = arrayListOf(),
    @SerializedName("require_pushed_authorization_requests") var requirePushedAuthorizationRequests: Boolean = false,
    @SerializedName("pushed_authorization_request_endpoint") var pushedAuthorizationRequestEndpoint: String? = null,
    )

data class RequestAuthenticationMethodsSupported(

    @SerializedName("authorization_endpoint") var authorizationEndpoint: ArrayList<String> = arrayListOf()

)

data class VpFormatsSupported(

    @SerializedName("jwt_vp") var jwtVp: Jwt? = Jwt(),
    @SerializedName("jwt_vc") var jwtVc: Jwt? = Jwt()

)

data class Jwt(

    @SerializedName("alg") var alg: ArrayList<String> = arrayListOf()

)
data class WrappedAuthConfigResponse(
    var authConfig: AuthorisationServerWellKnownConfiguration? = null,
    var errorResponse: ErrorResponse? = null
)
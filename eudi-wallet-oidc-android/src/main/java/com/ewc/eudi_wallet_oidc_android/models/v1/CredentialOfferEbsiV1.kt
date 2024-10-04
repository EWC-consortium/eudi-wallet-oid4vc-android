package com.ewc.eudi_wallet_oidc_android.models.v1

import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.google.gson.annotations.SerializedName

data class CredentialOfferEbsiV1(
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("credentials") var credentials: ArrayList<Credentials>? = null,
    @SerializedName("grants") var grants: GrantsV1? = null
)

data class GrantsV1(

    @SerializedName("authorization_code") var authorizationCode: AuthorizationCodeV1? = null,
    @SerializedName("urn:ietf:params:oauth:grant-type:pre-authorized_code") var preAuthorizationCode: PreAuthorizationCodeV1? = null

)

data class AuthorizationCodeV1(

    @SerializedName("issuer_state") var issuerState: String? = null,

)

data class PreAuthorizationCodeV1(

    @SerializedName("pre-authorized_code") var preAuthorizedCode: String? = null,
    @SerializedName("user_pin_required") var userPinRequired: Boolean? = null,

)
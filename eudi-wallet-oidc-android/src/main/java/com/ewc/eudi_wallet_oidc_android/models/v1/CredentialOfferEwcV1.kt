package com.ewc.eudi_wallet_oidc_android.models.v1

import com.google.gson.annotations.SerializedName

data class CredentialOfferEwcV1(
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("credentials") var credentials: ArrayList<String>? = null,
    @SerializedName("grants") var grants: GrantsV1? = null
)
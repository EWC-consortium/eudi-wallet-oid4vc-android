package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class ParResponse(
    @SerializedName("request_uri") val requestUri: String,
    @SerializedName("expires_in") val expiresIn: Int
)

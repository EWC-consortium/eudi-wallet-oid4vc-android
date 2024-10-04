package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class ErrorResponse(
    @SerializedName("error") var error: Int? = null,
    @SerializedName("error_description") var errorDescription: String? = null
)

data class CredentialResponse(
    @SerializedName("format") var format: String? = null,
    @SerializedName("credential") var credential: String? = null,
    @SerializedName("acceptance_token") var acceptanceToken: String? = null,
    @SerializedName("transaction_id") var transactionId: String? = null,
    @SerializedName("isDeferred") var isDeferred: Boolean? = null,
    @SerializedName("isPinRequired") var isPinRequired: Boolean? = null,
    @SerializedName("issuerConfig") var issuerConfig: IssuerWellKnownConfiguration? = null,
    @SerializedName("authorizationConfig") var authorizationConfig: AuthorisationServerWellKnownConfiguration? = null,
    @SerializedName("credentialOffer") var credentialOffer: CredentialOffer? = null
)


data class WrappedCredentialResponse(
    var credentialResponse: CredentialResponse? = null,
    var errorResponse: ErrorResponse? = null,
)

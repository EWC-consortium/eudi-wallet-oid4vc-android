package com.ewc.eudi_wallet_oidc_android.models.v2

import com.google.gson.annotations.SerializedName

data class DeferredCredentialRequestV2(

    @SerializedName("transaction_id") var transactionId: String? = null,

    )
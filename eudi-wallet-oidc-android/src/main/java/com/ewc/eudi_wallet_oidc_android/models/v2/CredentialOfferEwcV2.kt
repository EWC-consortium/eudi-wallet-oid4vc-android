package com.ewc.eudi_wallet_oidc_android.models.v2
import com.ewc.eudi_wallet_oidc_android.models.Grants
import com.google.gson.annotations.SerializedName

data class CredentialOfferEwcV2(
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("credential_configuration_ids") var credentialConfigurationIds: ArrayList<String>? = null,
    @SerializedName("grants") var grants: Grants? = null
)
package com.ewc.eudi_wallet_oidc_android.models

import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEbsiV1
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEwcV1
import com.ewc.eudi_wallet_oidc_android.models.v2.CredentialOfferEwcV2
import com.google.gson.annotations.SerializedName

data class CredentialOffer(
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("credentials") var credentials: ArrayList<Credentials>? = null,
    @SerializedName("grants") var grants: Grants? = null,
    @SerializedName("version") var version: Int? = null,
) {
    constructor(ebsiV1: CredentialOfferEbsiV1) : this(
        credentialIssuer = ebsiV1.credentialIssuer,
        credentials = ebsiV1.credentials,
        grants = Grants(
            authorizationCode = if (ebsiV1.grants?.authorizationCode == null) null else AuthorizationCode(
                issuerState = ebsiV1.grants?.authorizationCode?.issuerState,
                authorizationServer = null
            ),
            preAuthorizationCode = if (ebsiV1.grants?.preAuthorizationCode == null) null else
                PreAuthorizationCode(
                    preAuthorizedCode = ebsiV1.grants?.preAuthorizationCode?.preAuthorizedCode,
                    transactionCode = if (ebsiV1.grants?.preAuthorizationCode?.userPinRequired == true)
                        TxCode(
                            length = 4,
                            inputMode = "numeric",
                            description = null
                        )
                    else null,
                    authorizationServer = null
                )
        ),
        version = 1
    )

    constructor(ewcV1: CredentialOfferEwcV1) : this(
        credentialIssuer = ewcV1.credentialIssuer,
        credentials = arrayListOf(
            Credentials(
                format = null,
                types = ewcV1.credentials,
                trustFramework = null
            )
        ),
        grants = Grants(
            authorizationCode = if (ewcV1.grants?.authorizationCode == null) null else AuthorizationCode(
                issuerState = ewcV1.grants?.authorizationCode?.issuerState,
                authorizationServer = null
            ),
            preAuthorizationCode = if (ewcV1.grants?.preAuthorizationCode == null) null else
                PreAuthorizationCode(
                    preAuthorizedCode = ewcV1.grants?.preAuthorizationCode?.preAuthorizedCode,
                    transactionCode = if (ewcV1.grants?.preAuthorizationCode?.userPinRequired == true)
                        TxCode(
                            length = 4,
                            inputMode = "numeric",
                            description = null
                        )
                    else null,
                    authorizationServer = null
                )
        ),
        version = 1,
    )

    constructor(ewcV2: CredentialOfferEwcV2) : this(
        credentialIssuer = ewcV2.credentialIssuer,
        credentials = arrayListOf(
            Credentials(
                format = null,
                types = ewcV2.credentialConfigurationIds,
                trustFramework = null
            )
        ),
        grants = Grants(
            authorizationCode = if (ewcV2.grants?.authorizationCode == null) null else AuthorizationCode(
                issuerState = ewcV2.grants?.authorizationCode?.issuerState,
                authorizationServer = ewcV2.grants?.authorizationCode?.authorizationServer
            ),
            preAuthorizationCode = if (ewcV2.grants?.preAuthorizationCode == null) null else
                PreAuthorizationCode(
                    preAuthorizedCode = ewcV2.grants?.preAuthorizationCode?.preAuthorizedCode,
                    transactionCode = ewcV2.grants?.preAuthorizationCode?.transactionCode,
                    authorizationServer = ewcV2.grants?.authorizationCode?.authorizationServer
                )
        ),
        version = 2
    )
}

data class Credentials(
    @SerializedName("format") var format: String? = null,
    @SerializedName("types") var types: ArrayList<String>? = null,
    @SerializedName("trust_framework") var trustFramework: TrustFramework? = null
)

data class TrustFramework(
    @SerializedName("name") var name: String? = null,
    @SerializedName("type") var type: String? = null,
    @SerializedName("uri") var uri: String? = null
)

data class Grants(
    @SerializedName("authorization_code") var authorizationCode: AuthorizationCode? = null,
    @SerializedName("urn:ietf:params:oauth:grant-type:pre-authorized_code") var preAuthorizationCode: PreAuthorizationCode? = null
)

data class AuthorizationCode(
    @SerializedName("issuer_state") var issuerState: String? = null,
    @SerializedName("authorization_server") var authorizationServer: ArrayList<String>? = null
)

data class PreAuthorizationCode(
    @SerializedName("pre-authorized_code") var preAuthorizedCode: String? = null,
    @SerializedName("tx_code") var transactionCode: TxCode? = null,
    @SerializedName("authorization_server") var authorizationServer: ArrayList<String>? = null
)

data class TxCode(
    @SerializedName("length") var length: Int? = null,
    @SerializedName("input_mode") var inputMode: String? = null,
    @SerializedName("description") var description: String? = null
)

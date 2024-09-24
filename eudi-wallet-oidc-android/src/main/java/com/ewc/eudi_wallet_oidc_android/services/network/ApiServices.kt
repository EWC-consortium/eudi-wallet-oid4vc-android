package com.ewc.eudi_wallet_oidc_android.services.network

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.CredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.DIDDocument
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Field
import retrofit2.http.FieldMap
import retrofit2.http.FormUrlEncoded
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.QueryMap
import retrofit2.http.Url

interface ApiService {
    @GET
    suspend fun resolveCredentialOffer(@Url url: String): Response<CredentialOffer>

    @GET
    suspend fun fetchIssuerConfig(@Url url: String): Response<IssuerWellKnownConfiguration>

    @GET
    suspend fun fetchAuthConfig(@Url url: String): Response<AuthorisationServerWellKnownConfiguration>

    @GET
    suspend fun processAuthorisationRequest(
        @Url url: String,
        @QueryMap map: Map<String, String>
    ): Response<HashMap<String, Any>>

    @FormUrlEncoded
    @POST("")
    suspend fun sendIdTokenForCode(
        @Url url: String,
        @Field("id_token") idToken: String,
        @Field("state") state: String,
        @Header("content-type") contentType: String
    ): Response<HashMap<String, Any>>

    @FormUrlEncoded
    @POST("")
    suspend fun getAccessTokenFromCode(
        @Url url: String,
        @FieldMap map: Map<String, String?>
    ): Response<TokenResponse>

    @POST
    suspend fun getCredential(
        @Url url: String,
        @Header("content-type") contentType: String,
        @Header("Authorization") authorization: String,
        @Body body: CredentialRequest
    ): Response<CredentialResponse>

    @POST("")
    suspend fun getDifferedCredential(
        @Url url: String,
        @Header("Authorization") authorization: String,
        @Body body: CredentialRequest
    ): Response<CredentialResponse>

    @GET
    suspend fun getPresentationDefinitionFromRequestUri(@Url url: String): Response<ResponseBody>

    @FormUrlEncoded
    @POST("")
    suspend fun sendVPToken(
        @Url url: String,
        @FieldMap map: Map<String, String>
    ): Response<ResponseBody>

    @GET
    suspend fun ebsiDIDResolver(@Url url: String): Response<DIDDocument>
}
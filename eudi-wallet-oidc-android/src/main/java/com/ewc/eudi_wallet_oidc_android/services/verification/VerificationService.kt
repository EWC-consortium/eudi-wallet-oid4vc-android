package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Base64
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PathNested
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.models.VPTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.github.decentraliseddataexchange.presentationexchangesdk.PresentationExchange
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.internal.LinkedTreeMap
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.shaded.json.parser.ParseException
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import org.json.JSONArray
import org.json.JSONObject
import java.util.Date
import java.util.UUID


class VerificationService : VerificationServiceInterface {

    /**
     * Authorisation requests can be presented to the wallet by verifying in two ways:
     * 1) by value
     * 2) by reference as defined in JWT-Secured Authorization Request (JAR) via use of request_uri.
     *      The custom URL scheme for authorisation requests is openid4vp://.
     *
     * @param data - will accept the full data which is scanned from the QR code or deep link
     *
     * @return PresentationRequest
     */
    override suspend fun processAuthorisationRequest(data: String?): PresentationRequest? {
        if (data.isNullOrBlank())
            return null
        val clientId = Uri.parse(data).getQueryParameter("client_id")
        val state = Uri.parse(data).getQueryParameter("state")
        val redirectUri = Uri.parse(data).getQueryParameter("redirect_uri")
        val nonce = Uri.parse(data).getQueryParameter("nonce")
        val presentationDefinition =
            Uri.parse(data).getQueryParameter("presentation_definition")
        val responseType = Uri.parse(data).getQueryParameter("response_type")
        val scope = Uri.parse(data).getQueryParameter("scope")
        val requestUri = Uri.parse(data).getQueryParameter("request_uri")
        val responseUri = Uri.parse(data).getQueryParameter("response_uri")
        val responseMode = Uri.parse(data).getQueryParameter("response_mode")
        val clientMetadataJson = Uri.parse(data).getQueryParameter("client_metadata")
        val clientMetadetails: ClientMetaDetails? = if (!clientMetadataJson.isNullOrBlank()) {
            Gson().fromJson(clientMetadataJson, ClientMetaDetails::class.java)
        } else {
            null
        }
        if (presentationDefinition != null) {
            return PresentationRequest(
                clientId = clientId,
                state = state,
                redirectUri = redirectUri,
                nonce = nonce,
                presentationDefinition = presentationDefinition,
                responseMode = responseMode,
                responseType = responseType,
                scope = scope,
                requestUri = requestUri,
                responseUri = responseUri,
                clientMetaDetails = clientMetadetails
            )
        } else if (!requestUri.isNullOrBlank() || !responseUri.isNullOrBlank()) {
            val response =
                ApiManager.api.getService()
                    ?.getPresentationDefinitionFromRequestUri(requestUri ?: responseUri ?: "")
            if (response?.isSuccessful == true) {
                val contentType = response.headers()["Content-Type"]
                val responseString = response.body()?.string()
                val gson = Gson()
                if (contentType?.contains("application/json") == true) {
                    val json = gson.fromJson(
                        responseString,
                        PresentationRequest::class.java
                    )
                    return json
                }else{
                    if (isValidJWT(responseString?:"")) {
                        val json = gson.fromJson(
                            parseJWTForPayload(responseString?:"{}"),
                            PresentationRequest::class.java
                        )
                        return json
                    }else{
                        val json = gson.fromJson(
                            responseString?:"{}",
                            PresentationRequest::class.java
                        )
                        return json
                    }
                }
            } else {
                return null
            }
        } else if (isValidJWT(data)) {
            val split = data.split(".")
            var payload: String? = null
            if (split.size == 3) {
                payload = split[1]
                return Gson().fromJson(payload, PresentationRequest::class.java)
            } else {
                return null
            }
        } else {
            return null
        }
    }

    private fun isValidJWT(token: String): Boolean {
        try {
            // Parse the JWT token
            val parsedJWT = SignedJWT.parse(token)
            return parsedJWT.payload != null
        } catch (e: Exception) {
            println("JWT parsing failed: ${e.message}")
            return false
        }
    }

    @Throws(ParseException::class)
    private fun parseJWTForPayload(accessToken: String): String {
        try {
            val decodedJWT = SignedJWT.parse(accessToken)
            return decodedJWT.payload.toString()
        } catch (e: ParseException) {
            throw java.lang.Exception("Invalid token!")
        }
    }

    /**
     * Authorisation response is sent by constructing the vp_token and presentation_submission values.
     */
    override suspend fun sendVPToken(
        did: String?,
        subJwk: ECKey?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>
    ): String? {
        val iat = Date()
        val jti = "urn:uuid:${UUID.randomUUID()}"
        val claimsSet = JWTClaimsSet.Builder()
            .audience(presentationRequest.clientId)
            .issueTime(iat)
            .expirationTime(Date(iat.time + 600000))
            .issuer(did)
            .jwtID(jti)
            .notBeforeTime(iat)
            .claim("nonce", presentationRequest.nonce)
            .subject(did)
            .claim(
                "vp", com.nimbusds.jose.shaded.json.JSONObject(
                    hashMapOf(
                        "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                        "holder" to did,
                        "id" to jti,
                        "type" to listOf("VerifiablePresentation"),
                        "verifiableCredential" to credentialList
                    )
                )
            ).build()

        // Create JWT for ES256K alg
        val jwsHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("JWT"))
            .keyID("$did#${did?.replace("did:key:", "")}")
            .jwk(subJwk?.toPublicJWK())
            .build()

        val jwt = SignedJWT(
            jwsHeader,
            claimsSet
        )

        // Sign with private EC key
        jwt.sign(ECDSASigner(subJwk))

        val response = ApiManager.api.getService()?.sendVPToken(
            presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
            mapOf(
                "vp_token" to jwt.serialize(),
                "presentation_submission" to Gson().toJson(
                    createPresentationSubmission(
                        presentationRequest
                    )
                ),
                "state" to (presentationRequest.state ?: "")
            )
        )

        return if (response?.code() == 302 || response?.code() == 200) {
            response.headers()["Location"] ?: "https://tid-wallet-poc.azurewebsites.net?code=1"
        } else {
            null
        }
    }

    /**
     * Send VP token
     *
     * @param did
     * @param subJwk
     * @param presentationRequest
     * @param credentialList
     * @return
     */
    override suspend fun sendVPToken(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>
    ): WrappedVpTokenResponse? {
        val iat = Date()
        val jti = "urn:uuid:${UUID.randomUUID()}"
        val claimsSet = JWTClaimsSet.Builder()
            .audience(presentationRequest.clientId)
            .issueTime(iat)
            .expirationTime(Date(iat.time + 600000))
            .issuer(did)
            .jwtID(jti)
            .notBeforeTime(iat)
            .claim("nonce", presentationRequest.nonce)
            .subject(did)
            .claim(
                "vp", com.nimbusds.jose.shaded.json.JSONObject(
                    hashMapOf(
                        "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                        "holder" to did,
                        "id" to jti,
                        "type" to listOf("VerifiablePresentation"),
                        "verifiableCredential" to credentialList
                    )
                )
            ).build()

        // Create JWT for ES256K alg
        val jwsHeader =
            JWSHeader.Builder(if (subJwk is OctetKeyPair) JWSAlgorithm.EdDSA else JWSAlgorithm.ES256)
                .type(JOSEObjectType("JWT"))
                .keyID("$did#${did?.replace("did:key:", "")}")
                .jwk(subJwk?.toPublicJWK())
                .build()

        val jwt = SignedJWT(
            jwsHeader,
            claimsSet
        )

        // Sign with private EC key
        jwt.sign(if (subJwk is OctetKeyPair) Ed25519Signer(subJwk) else ECDSASigner(subJwk as ECKey))

        val response = ApiManager.api.getService()?.sendVPToken(
            presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
            mapOf(
                "vp_token" to jwt.serialize(),
                "presentation_submission" to Gson().toJson(
                    createPresentationSubmission(
                        presentationRequest
                    )
                ),
                "state" to (presentationRequest.state ?: "")
            )
        )

        val tokenResponse = when {
            response?.code() == 302 || response?.code() == 200 -> {
//                WrappedVpTokenResponse(
//                    vpTokenResponse = VPTokenResponse(
//                        location = response.headers()["Location"]
//                            ?: "https://www.example.com?code=1"
//                    )
//                )
                val locationHeader = response.headers()["Location"]
                if (locationHeader?.contains("error=") == true) {
                    // Parse the error from the location header
                    val errorParams = locationHeader.substringAfter("?").split("&").associate {
                        val (key, value) = it.split("=")
                        key to value
                    }

                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = when (errorParams["error"]) {
                                "invalid_request" -> 400
                                else -> null
                            },
                            errorDescription = errorParams["error_description"]
                        )
                    )
                } else {
                    WrappedVpTokenResponse(
                        vpTokenResponse = VPTokenResponse(
                            location = locationHeader ?: "https://www.example.com?code=1"
                        )
                    )
                }

            }

            (response?.code() ?: 0) >= 400 -> {
                WrappedVpTokenResponse(
                    errorResponse = IssueService().processError(response?.errorBody()?.string())
                )
            }

            else -> {
                null
            }
        }
        return tokenResponse
    }

    /**
     * Returns all the list of credentials matching for all input descriptors
     */
    override suspend fun filterCredentials(
        allCredentialList: List<String?>,
        presentationDefinition: PresentationDefinition
    ): List<List<String>> {
        val response: MutableList<MutableList<String>> = mutableListOf()
        val pex = PresentationExchange()

        presentationDefinition.inputDescriptors?.forEach { inputDescriptors ->
            val credentialList = splitCredentialsBySdJWT(allCredentialList, inputDescriptors.constraints?.limitDisclosure != null)
            val processedCredentials = processCredentialsToJsonString(credentialList)
            val filteredCredentialList: MutableList<String> = mutableListOf()
            val inputDescriptor = Gson().toJson(inputDescriptors)

            val matches: List<MatchedCredential> =
                pex.matchCredentials(inputDescriptor, processedCredentials)

            for (match in matches) {
                filteredCredentialList.add(credentialList[match.index] ?: "")
            }

            response.add(filteredCredentialList)
        }

        return response
    }

    private fun splitCredentialsBySdJWT(
        allCredentials: List<String?>,
        isSdJwt: Boolean
    ): ArrayList<String?> {
        val filteredCredentials: ArrayList<String?> = arrayListOf()
        for (item in allCredentials) {
            if (isSdJwt && item?.contains("~") == true)
                filteredCredentials.add(item)
            else if (!isSdJwt && item?.contains("~") == false)
                filteredCredentials.add(item)
        }
        return filteredCredentials
    }

    private fun processCredentialsToJsonString(credentialList: ArrayList<String?>):List<String>{
        var processedCredentials: List<String> = mutableListOf()
        for (cred in credentialList) {
            val split = cred?.split(".")


            val jsonString = if ((cred?.split("~")?.size ?: 0) > 0)
                SDJWTService().updateIssuerJwtWithDisclosures(cred)
            else
                Base64.decode(
                    split?.get(1) ?: "",
                    Base64.URL_SAFE
                ).toString(charset("UTF-8"))

            val json = JSONObject(jsonString ?: "{}")

            // todo known item, we are considering the path from only vc
            processedCredentials =
                processedCredentials + listOf(
                    if (json.has("vc")) json.getJSONObject("vc").toString()
                    else json.toString()
                )
        }
        return processedCredentials
    }

    /**
     * Processes the provided presentation definition and converts it into a PresentationDefinition object.
     *
     * @param presentationDefinition The presentation definition to be processed, can be of type PresentationDefinition,
     * LinkedTreeMap<*, *> representing JSON structure, or a JSON string.
     * @return The processed PresentationDefinition object.
     * @throws IllegalArgumentException if the presentation definition cannot be processed.
     */
    override fun processPresentationDefinition(presentationDefinition: Any?): PresentationDefinition {
        try {
            return when (presentationDefinition) {
                is PresentationDefinition -> presentationDefinition
                is LinkedTreeMap<*, *> -> {
                    val jsonString = Gson().toJson(presentationDefinition)
                    Gson().fromJson(jsonString, PresentationDefinition::class.java)
                }

                is String -> Gson().fromJson(
                    presentationDefinition,
                    PresentationDefinition::class.java
                )

                else -> throw IllegalArgumentException("Invalid presentation definition format")
            }
        } catch (e: Exception) {
            throw IllegalArgumentException("Error processing presentation definition", e)
        }
    }

    /**
     * To generate the presentation submission from the presentation Request
     */
    private fun createPresentationSubmission(
        presentationRequest: PresentationRequest
    ): PresentationSubmission? {
        val id = UUID.randomUUID().toString()
        val descriptorMap: ArrayList<DescriptorMap> = ArrayList()

        var presentationDefinition: PresentationDefinition? =
            processPresentationDefinition(presentationRequest.presentationDefinition)

        presentationDefinition?.inputDescriptors?.forEachIndexed { index, inputDescriptors ->
            val descriptor = DescriptorMap(
                id = inputDescriptors.id,
                path = "$",
                format = presentationDefinition.format?.keys?.firstOrNull() ?: "jwt_vp",
                pathNested = PathNested(
                    id = inputDescriptors.id,
                    format = "jwt_vc",
                    path = "$.vp.verifiableCredential[$index]"
                )
            )
            descriptorMap.add(descriptor)
        }

        val presentationSubmission = PresentationSubmission(
            id = id,
            definitionId = presentationDefinition?.id,
            descriptorMap = descriptorMap
        )
        return presentationSubmission
    }
}
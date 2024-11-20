package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMapMdoc
import com.ewc.eudi_wallet_oidc_android.models.Document
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerSigned
import com.ewc.eudi_wallet_oidc_android.models.PathNested
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmissionMdoc
import com.ewc.eudi_wallet_oidc_android.models.VPTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.VpToken
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.utils.X509SanRequestVerifier
import com.github.decentraliseddataexchange.presentationexchangesdk.PresentationExchange
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.google.gson.Gson
import com.google.gson.internal.LinkedTreeMap
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.Date
import java.util.UUID
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

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
    override suspend fun processAuthorisationRequest(data: String?): WrappedPresentationRequest? {
        if (data.isNullOrBlank())
            return null

        val gson = Gson()

        val clientId = Uri.parse(data).getQueryParameter("client_id")
        val state = Uri.parse(data).getQueryParameter("state")
        val redirectUri = Uri.parse(data).getQueryParameter("redirect_uri")
        val nonce = Uri.parse(data).getQueryParameter("nonce")
        val presentationDefinition =
            Uri.parse(data).getQueryParameter("presentation_definition")
        val presentationDefinitionUri =
            Uri.parse(data).getQueryParameter("presentation_definition_uri")
        val responseType = Uri.parse(data).getQueryParameter("response_type")
        val scope = Uri.parse(data).getQueryParameter("scope")
        val requestUri = Uri.parse(data).getQueryParameter("request_uri")
        val responseUri = Uri.parse(data).getQueryParameter("response_uri")
        val responseMode = Uri.parse(data).getQueryParameter("response_mode")
        val clientMetadataUri = Uri.parse(data).getQueryParameter("client_metadata_uri")
        val clientMetadataJson = Uri.parse(data).getQueryParameter("client_metadata")
        val clientIdScheme = Uri.parse(data).getQueryParameter("client_id_scheme")
        val clientMetadetails: ClientMetaDetails? = if (!clientMetadataJson.isNullOrBlank()) {
            gson.fromJson(clientMetadataJson, ClientMetaDetails::class.java)
        } else {
            null
        }
        if (presentationDefinition != null || presentationDefinitionUri != null) {
            val presentationRequest = PresentationRequest(
                clientId = clientId,
                state = state,
                redirectUri = redirectUri,
                nonce = nonce,
                presentationDefinition = presentationDefinition,
                presentationDefinitionUri = presentationDefinitionUri,
                responseMode = responseMode,
                responseType = responseType,
                scope = scope,
                requestUri = requestUri,
                responseUri = responseUri,
                clientMetaDetails = clientMetadetails,
                clientIdScheme = clientIdScheme
            )
            if (presentationDefinition.isNullOrBlank() && !presentationDefinitionUri.isNullOrBlank()) {
                val resolvedPresentationDefinition =
                    getPresentationDefinitionFromDefinitionUri(presentationDefinitionUri)
                presentationRequest.presentationDefinition = resolvedPresentationDefinition
            }
            if (clientMetadataJson.isNullOrBlank() && !clientMetadataUri.isNullOrBlank()) {
                val resolvedClientMetaData =
                    getClientMetaDataFromClientMetaDataUri(clientMetadataUri)
                presentationRequest.clientMetaDetails = resolvedClientMetaData
            }
            return WrappedPresentationRequest(presentationRequest = presentationRequest,errorResponse = null)

        } else if (!requestUri.isNullOrBlank() || !responseUri.isNullOrBlank()) {

            val response =
                ApiManager.api.getService()
                    ?.getPresentationDefinitionFromRequestUri(requestUri ?: responseUri ?: "")
            if (response?.isSuccessful == true) {
                val contentType = response.headers()["Content-Type"]
                val responseString = response.body()?.string()

                if (contentType?.contains("application/json") == true) {
                    val json = gson.fromJson(
                        responseString,
                        PresentationRequest::class.java
                    )
                    if (json.presentationDefinition == null && !json.presentationDefinitionUri.isNullOrBlank()) {
                        val resolvedPresentationDefinition =
                            getPresentationDefinitionFromDefinitionUri(json.presentationDefinitionUri)
                        json.presentationDefinition = resolvedPresentationDefinition
                    }
                    if (json.clientMetaDetails == null && !json.clientMetadataUri.isNullOrBlank()) {
                        val resolvedClientMetaDetails =
                            getClientMetaDataFromClientMetaDataUri(json.clientMetadataUri)
                        json.clientMetaDetails = resolvedClientMetaDetails
                    }

                    return validatePresentationRequest(WrappedPresentationRequest(presentationRequest = json) , responseString)
                } else {
                    if (isValidJWT(responseString ?: "")) {
                        val json = gson.fromJson(
                            parseJWTForPayload(responseString ?: "{}"),
                            PresentationRequest::class.java
                        )
                        if (json.presentationDefinition == null && !json.presentationDefinitionUri.isNullOrBlank()) {
                            val resolvedPresentationDefinition =
                                getPresentationDefinitionFromDefinitionUri(json.presentationDefinitionUri)
                            json.presentationDefinition = resolvedPresentationDefinition
                        }
                        if (json.clientMetaDetails == null && !json.clientMetadataUri.isNullOrBlank()) {
                            val resolvedClientMetaDetails =
                                getClientMetaDataFromClientMetaDataUri(json.clientMetadataUri)
                            json.clientMetaDetails = resolvedClientMetaDetails
                        }
                        return validatePresentationRequest(WrappedPresentationRequest(presentationRequest = json) , responseString)
                    } else {

                        val json = gson.fromJson(
                            responseString ?: "{}",
                            PresentationRequest::class.java
                        )
                        if (json.presentationDefinition == null && !json.presentationDefinitionUri.isNullOrBlank()) {
                            val resolvedPresentationDefinition =
                                getPresentationDefinitionFromDefinitionUri(json.presentationDefinitionUri)
                            json.presentationDefinition = resolvedPresentationDefinition
                        }
                        if (json.clientMetaDetails == null && !json.clientMetadataUri.isNullOrBlank()) {
                            val resolvedClientMetaDetails =
                                getClientMetaDataFromClientMetaDataUri(json.clientMetadataUri)
                            json.clientMetaDetails = resolvedClientMetaDetails
                        }
                        return validatePresentationRequest(WrappedPresentationRequest(presentationRequest = json) , responseString)
                    }
                }
            } else {
                return null
            }
        } else if (isValidJWT(data)) {
            val json = gson.fromJson(
                parseJWTForPayload(data ?: "{}"),
                PresentationRequest::class.java
            )
            if (json.presentationDefinition == null && !json.presentationDefinitionUri.isNullOrBlank()) {
                val resolvedPresentationDefinition =
                    getPresentationDefinitionFromDefinitionUri(json.presentationDefinitionUri)
                json.presentationDefinition = resolvedPresentationDefinition
            }
            if (json.clientMetaDetails == null && !json.clientMetadataUri.isNullOrBlank()) {
                val resolvedClientMetaDetails =
                    getClientMetaDataFromClientMetaDataUri(json.clientMetadataUri)
                json.clientMetaDetails = resolvedClientMetaDetails
            }
            return validatePresentationRequest(WrappedPresentationRequest(presentationRequest = json) , data)
        } else {
            return null
        }
    }

    private fun validatePresentationRequest(
        presentationRequest: WrappedPresentationRequest,
        responseString: String?
    ): WrappedPresentationRequest? {
        if (presentationRequest.presentationRequest?.clientIdScheme == "x509_san_dns" && responseString != null) {
            var x5cChain: List<String>? = null

            x5cChain = X509SanRequestVerifier.instance.extractX5cFromJWT(responseString)

            // Calling the function
            if (x5cChain != null) {
                val isClientIdInDnsNames = X509SanRequestVerifier.instance.validateClientIDInCertificate(
                    x5cChain,
                    presentationRequest.presentationRequest?.clientId
                )

                val isSignatureValid =
                    X509SanRequestVerifier.instance.validateSignatureWithCertificate(
                        responseString,
                        x5cChain
                    )

                val isTrustChainValid =
                    X509SanRequestVerifier.instance.validateTrustChain(x5cChain)

                return if(isClientIdInDnsNames && isSignatureValid && isTrustChainValid )   {
                    presentationRequest
                } else{
                    WrappedPresentationRequest(presentationRequest = null,errorResponse = ErrorResponse(error = null , errorDescription = "Invalid Request" ))
                }

            } else {
                return presentationRequest
            }


        } else {
            return presentationRequest
        }

    }

    private suspend fun processJwtFromRedirectUri(redirectUri: String): String? =
        withContext(Dispatchers.IO) {
            // Fetch JWT from the redirect URI
            val jwt = fetchJwtFromUri(redirectUri)
            jwt?.let {
                // Decode the JWT to extract the payload
                val decodedPayload = decodeJwtPayload(it)
                decodedPayload?.let { payload ->
                    // Parse JSON payload and retrieve fields
                    val jsonPayload = JSONObject(payload)
                    val clientId = jsonPayload.optString("client_id")
                    val clientIdScheme = jsonPayload.optString("client_id_scheme")

                    // Use client_id and client_id_scheme as needed
                    println("Client ID: $clientId")
                    println("Client ID Scheme: $clientIdScheme")

                    return@withContext payload // Return payload or process further as needed
                }
            }
            return@withContext null
        }

    private fun fetchJwtFromUri(uri: String): String? {
        try {
            val url = URL(uri)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"

            if (connection.responseCode == HttpURLConnection.HTTP_OK) {
                val reader = BufferedReader(InputStreamReader(connection.inputStream))
                val jwt = reader.use { it.readText() }
                connection.disconnect()
                return jwt
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    private fun decodeJwtPayload(jwt: String): String? {
        val parts = jwt.split(".")
        return if (parts.size == 3) {
            val payload = parts[1]
            val decodedBytes = Base64.decode(payload, Base64.URL_SAFE)
            String(decodedBytes, StandardCharsets.UTF_8)
        } else {
            null
        }
    }

    private suspend fun getPresentationDefinitionFromDefinitionUri(presentationDefinitionUri: String?): PresentationDefinition? {
        if (presentationDefinitionUri.isNullOrBlank())
            return null

        val response =
            ApiManager.api.getService()
                ?.resolveUrl(presentationDefinitionUri ?: "")
        if (response?.isSuccessful == true) {
            val contentType = response.headers()["Content-Type"]
            val responseString = response.body()?.string()
            val gson = Gson()
            if (contentType?.contains("application/json") == true) {
                val json = gson.fromJson(
                    responseString,
                    PresentationDefinition::class.java
                )
                return json
            } else {
                if (isValidJWT(responseString ?: "")) {
                    val json = gson.fromJson(
                        parseJWTForPayload(responseString ?: "{}"),
                        PresentationDefinition::class.java
                    )
                    return json
                } else {
                    val json = gson.fromJson(
                        responseString ?: "{}",
                        PresentationDefinition::class.java
                    )
                    return json
                }
            }
        } else {
            return null
        }
    }

    private suspend fun getClientMetaDataFromClientMetaDataUri(clientMetadataUri: String?): ClientMetaDetails? {
        if (clientMetadataUri.isNullOrBlank())
            return null

        val response =
            ApiManager.api.getService()?.resolveUrl(clientMetadataUri ?: "")
        if (response?.isSuccessful == true) {
            try {
                val contentType = response.headers()["Content-Type"]
                val responseString = response.body()?.string()
                val gson = Gson()
                if (contentType?.contains("application/json") == true) {
                    val json = gson.fromJson(
                        responseString,
                        ClientMetaDetails::class.java
                    )
                    return json
                } else {
                    if (isValidJWT(responseString ?: "")) {
                        val json = gson.fromJson(
                            parseJWTForPayload(responseString ?: "{}"),
                            ClientMetaDetails::class.java
                        )
                        return json
                    } else {
                        val json = gson.fromJson(
                            responseString ?: "{}",
                            ClientMetaDetails::class.java
                        )
                        return json
                    }
                }
            } catch (e: Exception) {
                return null
            }
        } else {
            return null
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

        val presentationDefinition =
            processPresentationDefinition(presentationRequest.presentationDefinition)
        val formatMap = presentationDefinition.format?.takeIf { it.isNotEmpty() }
            ?: presentationDefinition.inputDescriptors
                ?.flatMap { it.format?.toList() ?: emptyList() }
                ?.toMap()

        val vpToken = if (formatMap?.containsKey("mso_mdoc") == true) {
            mdocVpToken(credentialList, presentationRequest)
        } else {
            vpToken(presentationRequest, did, credentialList, subJwk)
        }
        val presentationSubmission = if (formatMap?.containsKey("mso_mdoc") == true) {
            createMdocPresentationSubmission(
                presentationRequest
            )
        } else {
            createPresentationSubmission(
                presentationRequest
            )
        }


        val response = ApiManager.api.getService()?.sendVPToken(
            presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
            mapOf(
                "vp_token" to vpToken,
                "presentation_submission" to Gson().toJson(
                    presentationSubmission
                ),
                "state" to (presentationRequest.state ?: "")
            )
        )

        val tokenResponse = when {
            response?.code() == 200 -> {
                val redirectUri = response.body()?.string()
                val gson = Gson()
                try {
                    val vpTokenResponse =
                        gson.fromJson(redirectUri, VPTokenResponse::class.java)
                    return WrappedVpTokenResponse(
                        vpTokenResponse = VPTokenResponse(
                            location = vpTokenResponse.redirectUri
                                ?: "https://www.example.com?code=1"
                        )
                    )
                } catch (e: Exception) {
                    return WrappedVpTokenResponse(
                        vpTokenResponse = VPTokenResponse(
                            location = "https://www.example.com?code=1"
                        )
                    )
                }
            }

            response?.code() == 302 || response?.code() == 200 -> {
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

    private fun vpToken(
        presentationRequest: PresentationRequest,
        did: String?,
        credentialList: List<String>,
        subJwk: JWK?,

        ): String {

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
        return jwt.serialize()
    }

    private fun mdocVpToken(
        credentialList: List<String>,
        presentationRequest: PresentationRequest
    ): String {
        // Validate input
        if (credentialList.isEmpty()) {
            throw IllegalArgumentException("Credential list cannot be empty")
        }
        return try {
            // Extract presentation definition once, as it doesn't change for different credentials
            val presentationDefinition =
                VerificationService().processPresentationDefinition(presentationRequest.presentationDefinition)

            // Create a list to hold documents
            val documentList = mutableListOf<Document>()

            // Iterate over each credential
            for (credential in credentialList) {
                // Extract issuer authentication, docType, and namespaces for each credential
                val issuerAuth = CborUtils.processExtractIssuerAuth(listOf(credential))
                val docType = CborUtils.extractDocTypeFromIssuerAuth(listOf(credential))
                val nameSpaces =
                    CborUtils.processExtractNameSpaces(listOf(credential), presentationRequest)


                // Create IssuerSigned object for this credential
                val issuerSigned = IssuerSigned(
                    nameSpaces = nameSpaces,
                    issuerAuth = issuerAuth
                )

                // For each input descriptor, create corresponding documents
                presentationDefinition.inputDescriptors?.forEach { inputDescriptor ->
                    val fieldSize = inputDescriptor.constraints?.fields?.size ?: 0

                    // Create documents based on the number of fields
                    repeat(fieldSize) {
                        documentList.add(
                            Document(
                                docType = docType ?: "",
                                issuerSigned = issuerSigned,
                                deviceSigned = null
                            )
                        )
                    }
                }
            }

            // Create VpToken object
            val generatedVpToken = VpToken(
                version = "1.0",
                documents = documentList,
                status = 0
            )

            // Encode to CBOR
            val encoded = CborUtils.encodeMDocToCbor(generatedVpToken)

            Base64.encodeToString(encoded, Base64.URL_SAFE or Base64.NO_WRAP)

        } catch (e: Exception) {
            Log.e("TAG", "Error generating VP token: ${e.message}")
            throw e // Re-throw or handle it according to your needs
        }
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
            // Retrieve formatMap from presentationDefinition or from inputDescriptors
            val formatMap = presentationDefinition.format?.takeIf { it.isNotEmpty() }
                ?: presentationDefinition.inputDescriptors
                    ?.flatMap { it.format?.toList() ?: emptyList() }
                    ?.toMap()

            // Initialize processed credentials and credentialList
            var processedCredentials: List<String> = emptyList()
            var credentialList: ArrayList<String?> = arrayListOf()

            if (formatMap != null) {
                if (formatMap.containsKey("mso_mdoc")) {
                    credentialList = ArrayList(allCredentialList)
                    processedCredentials =
                        CborUtils.processMdocCredentialToJsonString(allCredentialList)
                            ?: emptyList()
                } else {
                    credentialList = splitCredentialsBySdJWT(
                        allCredentialList,
                        inputDescriptors.constraints?.limitDisclosure != null
                    )
                    processedCredentials = processCredentialsToJsonString(credentialList)
                }
            }
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


    fun splitCredentialsBySdJWT(
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

    fun processCredentialsToJsonString(credentialList: ArrayList<String?>): List<String> {
        var processedCredentials: List<String> = mutableListOf()
        for (cred in credentialList) {
            val split = cred?.split(".")


            val jsonString = if ((cred?.split("~")?.size ?: 0) > 0)
            //SDJWTService().updateIssuerJwtWithDisclosuresForFiltering(cred)
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
                format =
                presentationDefinition.format?.keys?.firstOrNull()
                    ?: inputDescriptors.format?.keys?.firstOrNull() ?: "jwt_vp",
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

    private fun createMdocPresentationSubmission(
        presentationRequest: PresentationRequest
    ): PresentationSubmissionMdoc? {
        val id = UUID.randomUUID().toString()
        val descriptorMap: ArrayList<DescriptorMapMdoc> = ArrayList()

        var presentationDefinition: PresentationDefinition? =
            processPresentationDefinition(presentationRequest.presentationDefinition)

        presentationDefinition?.inputDescriptors?.forEachIndexed { index, inputDescriptors ->
            val descriptor = DescriptorMapMdoc(
                id = inputDescriptors.id,
                path = "$",
                format = "mso_mdoc"
            )
            descriptorMap.add(descriptor)
        }

        val presentationSubmission = PresentationSubmissionMdoc(
            id = id,
            definitionId = presentationDefinition?.id,
            descriptorMap = descriptorMap
        )
        return presentationSubmission
    }
}
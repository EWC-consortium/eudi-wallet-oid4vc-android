package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Base64
import android.util.Log
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import org.json.JSONObject
import java.io.ByteArrayInputStream
import kotlin.io.encoding.ExperimentalEncodingApi
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString as CborByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString as CborUnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.VpToken
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import co.nstant.`in`.cbor.model.UnsignedInteger as CBORInteger

class CborUtils {
    companion object {
        @OptIn(ExperimentalEncodingApi::class)
        fun decodeCborCredential(cbor: String?): JSONObject? {
            if (cbor.isNullOrBlank()) {
                return null
            }
            val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(cbor ?: "")
            return extractCborDataElements(cborInBytes)
        }

        private fun extractCborDataElements(cborBytes: ByteArray): JSONObject {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
            val nameSpaces = cbors[0]["nameSpaces"]
            val jsonObject = JSONObject()
            if (nameSpaces is CborMap) {
                Log.d("TAG", "extractIssuerNamespacedElements: Map")
                nameSpaces.let { map ->
                    // Get all keys from the nameSpaces map
                    val allKeys = map.keys.mapNotNull {
                        (it as? CborUnicodeString)?.string
                    }
                    for (key in allKeys) {
                        val elements = nameSpaces[key] as CborArray
                        val newJson = JSONObject()
                        for (item in elements.dataItems) {
                            val decoded =
                                CborDecoder(ByteArrayInputStream((item as CborByteString).bytes)).decode()
                            val identifier = decoded[0]["elementIdentifier"].toString()
                            val value = decoded[0]["elementValue"]
                            if (value.majorType == MajorType.BYTE_STRING) {
                                // Convert the ByteString into a readable format, e.g., hex string or Base64
                                val byteValue = value as CborByteString
                                val base64String =
                                    Base64.encodeToString(byteValue.bytes, Base64.NO_WRAP)
                                newJson.put(identifier, base64String)
                            } else {
                                if (identifier == "driving_privileges") {
                                    Log.d("TAG", "extractIssuerNamespacedElements: ")
                                }
                                newJson.put(identifier, value.toString())
                            }
                        }
                        jsonObject.put(key, newJson)
                    }
                }
            } else if (nameSpaces is CborArray) {
                Log.d("TAG", "extractIssuerNamespacedElements: Array")
            }
            return jsonObject
        }

        @OptIn(ExperimentalEncodingApi::class)
        fun processMdocCredentialToJsonString(allCredentialList: List<String?>?): List<String>? {
            if (allCredentialList.isNullOrEmpty()) {
                return null
            }

            // List to store the converted JSON strings
            val jsonList = mutableListOf<String>()

            for (credential in allCredentialList) {
                if (credential.isNullOrBlank()) {
                    continue
                }

                try {
                    // Decode each CBOR credential from Base64 URL Safe encoding
                    val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(credential)

                    // Extract the CBOR data elements and convert them into a JSONObject
                    val jsonObject = parseCborNamespaces(cborInBytes)

                    // Add the JSONObject as a string to the list
                    jsonList.add(jsonObject.toString())
                } catch (e: Exception) {
                    Log.e("TAG", "Error processing credential: ${e.message}")
                }
            }

            return jsonList
        }

        private fun parseCborNamespaces(cborBytes: ByteArray): JSONObject {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()
            val nameSpaces = cbors[0]["nameSpaces"]
            val jsonObject = JSONObject()

            if (nameSpaces is CborMap) {
                Log.d("TAG", "extractIssuerNamespacedElements: Map")
                nameSpaces.let { map ->
                    // Get all keys from the nameSpaces map
                    val allKeys = map.keys.mapNotNull { (it as? CborUnicodeString)?.string }

                    for (key in allKeys) {
                        val elements = nameSpaces[key] as CborArray
                        val newJson = JSONObject()

                        for (item in elements.dataItems) {
                            val decoded =
                                CborDecoder(ByteArrayInputStream((item as CborByteString).bytes)).decode()
                            val identifier = decoded[0]["elementIdentifier"].toString()
                            val value = decoded[0]["elementValue"]

                            if (value.majorType == MajorType.BYTE_STRING) {
                                // Convert the ByteString into a readable format (Base64 here)
                                val byteValue = value as CborByteString
                                val base64String =
                                    Base64.encodeToString(byteValue.bytes, Base64.NO_WRAP)
                                newJson.put(identifier, base64String)
                            } else {
                                newJson.put(identifier, value.toString())
                            }
                        }

                        jsonObject.put(key, newJson)
                    }
                }
            } else if (nameSpaces is CborArray) {
                Log.d("TAG", "extractIssuerNamespacedElements: Array")
            }

            return jsonObject
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun processExtractIssuerAuth(allCredentialList: List<String?>?): CborArray {
            var issuerAuthObject = CborArray() // Initialize as empty

            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) {
                        continue
                    }

                    try {
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(credential)
                        // Extract the CBOR data elements and convert them into a JSONObject
                        issuerAuthObject = extractIssuerAuth(cborInBytes)
                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return issuerAuthObject
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun extractDocTypeFromIssuerAuth(allCredentialList: List<String?>?): String? {
            var docType: String? = null
            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) {
                        continue
                    }

                    try {
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(credential)
                        val cbors = CborDecoder(ByteArrayInputStream(cborInBytes)).decode()
                        val issuerAuth = cbors[0]["issuerAuth"]
                        println(issuerAuth)
                        docType = getDocType(issuerAuth)


                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return docType
        }

        private fun getDocType(cborData: DataItem): String? {

            var docType: String? = null
            if (cborData is CborArray) {
                // Iterate over elements in the array
                for (element in cborData.dataItems) { // Using getDataItems() to access the elements
                    // Check if the element is a ByteString
                    if (element is CborByteString) {
                        try {
                            // Decode the ByteString as CBOR
                            val nestedCBORStream = ByteArrayInputStream(element.bytes)
                            val nestedCBOR = CborDecoder(nestedCBORStream).decode()[0]
                            if (nestedCBOR.tag.value == 24L) {
                                // Check if the item under the tag is a ByteString
                                if (nestedCBOR is CborByteString) {
                                    try {
                                        // Decode the inner ByteString
                                        val decodedInnerCBORStream =
                                            ByteArrayInputStream(nestedCBOR.bytes)
                                        val decodedInnerCBOR =
                                            CborDecoder(decodedInnerCBORStream).decode()[0]

                                        // Extract the document type
                                        docType = extractDocType(decodedInnerCBOR)

                                    } catch (e: Exception) {
                                        println("Failed to decode inner ByteString under Tag 24.")
                                    }
                                }

                            }

                        } catch (e: Exception) {
                            println("Could not decode ByteString as CBOR, inspecting data directly.")
                            println("ByteString data: ${element.bytes.joinToString(", ") { it.toString() }}")
                        }
                    } else {
                        println("Element is not a ByteString: $element")
                    }
                }
            }

            return docType ?: ""
        }

        private fun extractDocType(cborData: DataItem): String? {
            // Check if the input is a CborMap
            if (cborData is CborMap) {
                // Get the keys and values from the map
                val keys = cborData.keys
                val values = cborData.values

                // Iterate over the keys and values
                for ((index, key) in keys.withIndex()) {
                    // Check if the key is a CborTextString (UTF-8 string)
                    if (key is CborUnicodeString && key.string == "docType") {
                        // Return the corresponding value if it's a CborTextString
                        val value = values.elementAt(index)
                        if (value is CborUnicodeString) {
                            return value.string
                        } else {
                            println("The value associated with 'docType' is not a string.")
                            return null
                        }
                    }
                }
                println("docType not found in the CBOR map.")
            }
            return null
        }

        @OptIn(ExperimentalEncodingApi::class)
        fun extractCredentialExpiryFromIssuerAuth(allCredentialList: List<String?>?): String? {
            var expiryUntil: String? = null
            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) {
                        continue
                    }

                    try {
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(credential)
                        val cbors = CborDecoder(ByteArrayInputStream(cborInBytes)).decode()
                        val issuerAuth = cbors[0]["issuerAuth"]
                        println(issuerAuth)
                        expiryUntil = getCredentialExpiry(issuerAuth)


                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return expiryUntil
        }
        private fun getCredentialExpiry(cborData: DataItem): String? {

            var expiryUntil: String? = null
            if (cborData is CborArray) {
                // Iterate over elements in the array
                for (element in cborData.dataItems) {
                    // Check if the element is a ByteString
                    if (element is CborByteString) {
                        try {
                            // Decode the ByteString as CBOR
                            val nestedCBORStream = ByteArrayInputStream(element.bytes)
                            val nestedCBORDecoder = CborDecoder(nestedCBORStream)

                            // Try decoding until an exception occurs
                            while (true) {
                                try {
                                    val nestedCBOR = nestedCBORDecoder.decodeNext()

                                    if (nestedCBOR.tag.value == 24L) {
                                        // Check if the item under the tag is a ByteString
                                        if (nestedCBOR is CborByteString) {
                                            try {
                                                // Decode the inner ByteString
                                                val decodedInnerCBORStream =
                                                    ByteArrayInputStream(nestedCBOR.bytes)
                                                val decodedInnerCBORDecoder = CborDecoder(decodedInnerCBORStream)

                                                // Decode until an exception occurs
                                                while (true) {
                                                    try {
                                                        val decodedInnerCBOR = decodedInnerCBORDecoder.decodeNext()
                                                        // Extract the document type
                                                        expiryUntil = extractExpiry(decodedInnerCBOR)
                                                    } catch (innerE: Exception) {
                                                        // Break if decoding inner fails
                                                        break
                                                    }
                                                }

                                            } catch (e: Exception) {
                                                println("Failed to decode inner ByteString under Tag 24.")
                                            }
                                        }

                                    }

                                } catch (e: Exception) {
                                    // Break if decoding the nested CBOR fails
                                    break
                                }
                            }

                        } catch (e: Exception) {
                            println("Could not decode ByteString as CBOR, inspecting data directly.")
                            println("ByteString data: ${element.bytes.joinToString(", ") { it.toString() }}")
                        }
                    } else {
                        println("Element is not a ByteString: $element")
                    }
                }
            }

            return expiryUntil ?: ""
        }

        private fun extractExpiry(cborData: DataItem): String? {
            // Check if the input is a CborMap
            if (cborData is CborMap) {
                // Get the keys and values from the map
                val keys = cborData.keys
                val values = cborData.values

                // Iterate over the keys and values
                for ((index, key) in keys.withIndex()) {
                    // Check if the key is a CborTextString (UTF-8 string)
                    if (key is CborUnicodeString && key.string == "validityInfo") {
                        // Get the validityInfo value
                        val validityInfo = values.elementAt(index)

                        // Check if validityInfo is a CborMap
                        if (validityInfo is CborMap) {
                            // Access the validUntil key
                            val validUntilKey = CborUnicodeString("validUntil")
                            if (validityInfo.keys.contains(validUntilKey)) {
                                val validUntilValue = validityInfo[validUntilKey]

                                // Check if validUntilValue is a CborTextString and return its string representation
                                if (validUntilValue is CborUnicodeString) {
                                    return validUntilValue.string
                                } else {
                                    println("The value associated with 'validUntil' is not a string.")
                                    return null
                                }
                            } else {
                                println("validUntil not found in the validityInfo CBOR map.")
                                return null
                            }
                        } else {
                            println("The value associated with 'validityInfo' is not a CBOR map.")
                            return null
                        }
                    }
                }
                println("validityInfo not found in the CBOR map.")
            }
            return null
        }


        @OptIn(ExperimentalEncodingApi::class)
        fun processExtractNameSpaces(
            allCredentialList: List<String?>?,
            presentationRequest: PresentationRequest
        ): CborMap {
            var filteredNameSpaces = CborMap()

            if (allCredentialList != null) {
                for (credential in allCredentialList) {
                    if (credential.isNullOrBlank()) continue
                    // Process the presentation definition
                    val presentationDefinition =
                        VerificationService().processPresentationDefinition(presentationRequest.presentationDefinition)

                    try {
                        // Decode each CBOR credential from Base64 URL Safe encoding
                        val cborInBytes = kotlin.io.encoding.Base64.UrlSafe.decode(credential)

                        // Extract the full CBOR data elements
                        var nameSpaces = extractNameSpaces(cborInBytes)
                        filteredNameSpaces = nameSpaces
                        println("Extracted nameSpaces: $nameSpaces")

                        // If limitDisclosure is required, filter the nameSpaces
                        presentationDefinition.inputDescriptors?.forEach { inputDescriptor ->
                            if (inputDescriptor.constraints?.limitDisclosure == "required") {
                                // Initialize a list to hold the requested keys
                                val keyList = mutableListOf<String>()

                                // Populate the keyList based on the input descriptors
                                inputDescriptor.constraints?.fields?.forEach { field ->
                                    field.path?.forEach { path ->
                                        val key =
                                            extractKey(path).trim() // Extract the key and trim whitespace

                                        // Check if the key contains a single quote
                                        if (key.contains("'")) {
                                            // Remove the single quote and add to keyList
                                            keyList.add(key.replace("'", ""))
                                        } else {
                                            // Add the key as it is
                                            keyList.add(key)
                                        }
                                    }
                                }

                                if (nameSpaces is CborMap) {
                                    Log.d("TAG", "Extracting issuer namespaced elements from Map")

                                    // Iterate over the namespaces map
                                    nameSpaces.keys.mapNotNull { (it as? CborUnicodeString)?.string }
                                        .forEach { key ->
                                            val elements = nameSpaces[key] as CborArray
                                            val matchedByteStrings = CborArray()

                                            // Iterate over each ByteString in the namespace
                                            elements.dataItems.forEach { item ->
                                                val decoded =
                                                    CborDecoder(ByteArrayInputStream((item as CborByteString).bytes)).decode()
                                                val identifier =
                                                    decoded[0]["elementIdentifier"].toString()
                                                        .trim() // Trim to remove any extra spaces

                                                // If identifier is in the keyList, add the ByteString to matchedByteStrings
                                                if (keyList.contains(identifier)) {
                                                    matchedByteStrings.add(item)
                                                }
                                            }

                                            // If there are any matches, add them to the filteredNameSpaces
                                            if (matchedByteStrings.dataItems.isNotEmpty()) {
                                                filteredNameSpaces.put(
                                                    CborUnicodeString(key),
                                                    matchedByteStrings
                                                )
                                            }
                                        }
                                }
                            }
                        }

                    } catch (e: Exception) {
                        Log.e("TAG", "Error processing credential: ${e.message}")
                    }
                }
            }

            return filteredNameSpaces // Return the filtered map containing matched ByteStrings
        }

        private fun extractKey(path: String): String {
            // Remove '[' and ']' characters from the path and split by '.'
            val sanitizedPath = path.replace("[", ".").replace("]", "")
            // Split the sanitized string by '.' and take the last element
            return sanitizedPath.split(".").last()
        }


        private fun extractIssuerAuth(cborBytes: ByteArray): CborArray {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()

            val issuerAuth = cbors[0]["issuerAuth"]
            // val list = cborArrayToList(issuerAuth as CborArray)
            // return list
            return issuerAuth as CborArray
        }


        private fun extractNameSpaces(cborBytes: ByteArray): CborMap {
            val cbors = CborDecoder(ByteArrayInputStream(cborBytes)).decode()

            val nameSpaces = cbors[0]["nameSpaces"]
            //return cborMapToKotlinMap(nameSpaces as CborMap)
            return nameSpaces as CborMap
        }

        private fun cborArrayToList(cborArray: CborArray): List<Any> {
            return cborArray.dataItems.map { convertCborToKotlin(it) }
        }

        private fun convertCborToKotlin(dataItem: DataItem): Any {
            return when (dataItem) {
                is CBORInteger -> dataItem.value
                is CborUnicodeString -> dataItem.string
                is CborByteString -> dataItem.bytes
                is CborArray -> cborArrayToList(dataItem) // Recursive call for nested arrays
                is CborMap -> cborMapToKotlinMap(dataItem) // Convert CborMap to Kotlin Map
                is UnsignedInteger -> dataItem.value
                else -> throw IllegalArgumentException("Unsupported CBOR data type: ${dataItem.javaClass}")
            }
        }

        private fun cborMapToKotlinMap(cborMap: CborMap): Map<Any, Any> {
            return cborMap.keys.associate { key ->
                val kotlinKey = convertCborToKotlin(key)
                val kotlinValue = convertCborToKotlin(cborMap.get(key))
                kotlinKey to kotlinValue
            }
        }


        // Function to encode mDoc (mDL) data into CBOR format
        fun encodeMDocToCbor(mDoc: VpToken): ByteArray {
            val outputStream = ByteArrayOutputStream()
            // Build a CBOR map for the VP Token
            val builder = CborBuilder()
            val mapBuilder = builder.addMap()

            // Add version to the map
            mapBuilder.put("version", mDoc.version)

            // Add an array to the "documents" key
            val arrayBuilder = mapBuilder.putArray("documents")
            for (doc in mDoc.documents) {
                // Create a map for each document
                val docMap = arrayBuilder.addMap()
                    .put("docType", doc.docType)

                // Add issuerSigned information
                val issuerSignedMap = docMap.putMap("issuerSigned")
                //val nameSpacesMap = issuerSignedMap.putMap("nameSpaces")

                issuerSignedMap.put(CborUnicodeString("nameSpaces"), doc.issuerSigned.nameSpaces)

                val issuerAuthArray = issuerSignedMap.putArray("issuerAuth")

                val authList: List<DataItem> = doc.issuerSigned.issuerAuth.getDataItems()

                for (auth in authList) {
                    issuerAuthArray.add(auth)
                }
                issuerAuthArray.end()
                issuerSignedMap.end()
                docMap.end()
            }

            // Add status to the map
            mapBuilder.put("status", mDoc.status.toLong())

            // Finish CBOR encoding
            CborEncoder(outputStream).encode(builder.build())

            // Get CBOR bytes
            val cborBytes = outputStream.toByteArray()

            println("CBOR encoded VP Token: ${cborBytes.contentToString()}")

            return outputStream.toByteArray()
        }

    }
}

operator fun DataItem.get(name: String): DataItem {
    check(this.majorType == MajorType.MAP)
    this as CborMap
    return this.get(CborUnicodeString(name))
}

operator fun DataItem.get(index: Int): DataItem {
    check(this.majorType == MajorType.ARRAY)
    this as CborArray
    return this.dataItems[index]
}
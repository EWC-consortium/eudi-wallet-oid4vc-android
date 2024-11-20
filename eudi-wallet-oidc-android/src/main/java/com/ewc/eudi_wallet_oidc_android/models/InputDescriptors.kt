package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class InputDescriptors(

    @SerializedName("id") var id: String? = null,
    @SerializedName("name") var name: String? = null,
    @SerializedName("purpose") var purpose: String? = null,
    @SerializedName("format") var format: Map<String, Jwt>? = mapOf(),
    @SerializedName("constraints") var constraints: Constraints? = null

)

data class Constraints(

    @SerializedName("limit_disclosure") var limitDisclosure: String? = null,
    @SerializedName("fields") var fields: ArrayList<Fields>? = null

)

data class Fields(

    @SerializedName("path") var path: ArrayList<String>? = null,
    @SerializedName("filter") var filter: Filter? = null,
    @SerializedName("optional") var optional: Boolean? = null

)

data class Filter(

    @SerializedName("type") var type: String? = null,
    @SerializedName("contains") var contains: Contains? = null,
    @SerializedName("pattern") var pattern: String? = null,
    @SerializedName("const") var const: String? = null

)

data class Contains(

    @SerializedName("const") var const: String? = null,
    @SerializedName("pattern") var pattern: String? = null,
    @SerializedName("type") var type: String? = null
)
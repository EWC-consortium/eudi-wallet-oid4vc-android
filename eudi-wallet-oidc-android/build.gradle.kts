plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

android {
    namespace = "com.ewc.eudi_wallet_oidc_android"
    compileSdk = 34

    defaultConfig {
        minSdk = 26

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {

    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20220924")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")

    implementation("com.nimbusds:nimbus-jose-jwt:9.21")
    implementation("com.github.mediapark-pk:Base58-android:0.1")
    implementation("com.google.code.gson:gson:2.8.6")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.5.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.5.2")

    implementation("com.squareup.retrofit2:retrofit:2.8.0")
    implementation("com.squareup.retrofit2:converter-gson:2.8.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.3.1")
// Coroutine adapter for Retrofit
    implementation("com.jakewharton.retrofit:retrofit2-kotlin-coroutines-adapter:0.9.2")

    implementation("com.github.decentralised-dataexchange:presentation-exchange-sdk-android:2024.3.1")
    implementation("org.slf4j:slf4j-api") {
        version {
            strictly("2.0.9")
        }
    }

    implementation("com.google.crypto.tink:tink-android:1.7.0")
    implementation("co.nstant.in:cbor:0.9")
}


publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.github.decentraliseddataexchange"
            artifactId = "eudi-wallet-oidc-android"
            version = "2024.7.1"

            afterEvaluate {
                from(components["release"])
            }
        }
    }
}

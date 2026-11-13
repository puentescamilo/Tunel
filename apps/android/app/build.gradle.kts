plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "dev.tunel.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.tunel.android"
        // Android 10: BiometricPrompt y el almacén de claves que usará el desbloqueo con huella.
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "0.15.0"
        ndk {
            // Teléfonos y el emulador de los Mac con Apple silicon.
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    testOptions {
        unitTests.all { test ->
            // Las pruebas usan el núcleo de verdad, compilado para este equipo por
            // scripts/compilar-android.sh.
            test.systemProperty("jna.library.path", rootDir.resolve("nucleo-local").absolutePath)
            test.jvmArgs("--enable-native-access=ALL-UNNAMED")
        }
    }
}

dependencies {
    implementation(libs.androidx.core)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.material3)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material.icons)
    implementation(libs.coroutines.android)
    // UniFFI llama al núcleo a través de JNA; el .aar trae la parte nativa para Android.
    implementation("${libs.jna.get()}@aar")
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    // En las pruebas, la versión de JNA para el equipo de compilación.
    testImplementation(libs.jna)
}

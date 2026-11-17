import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

/**
 * La versión de rustls-platform-verifier-android en Cargo.lock: la parte en Kotlin tiene que
 * ser exactamente la que espera el núcleo, o falla al conectar.
 */
abstract class RustlsVerifierVersion : ValueSource<String, RustlsVerifierVersion.Params> {
    interface Params : ValueSourceParameters {
        val lockFile: RegularFileProperty
    }

    override fun obtain(): String {
        val crate = "rustls-platform-verifier-android"
        val lines = parameters.lockFile.get().asFile.readLines()
        val index = lines.indexOfFirst { it.trim() == "name = \"$crate\"" }
        return lines.drop(index + 1)
            .takeIf { index >= 0 }
            ?.firstOrNull { it.trimStart().startsWith("version = ") }
            ?.substringAfter('"')
            ?.substringBefore('"')
            ?.takeIf { it.isNotEmpty() }
            ?: error("$crate no está en Cargo.lock")
    }
}

val rustlsVerifierVersion = providers.of(RustlsVerifierVersion::class.java) {
    parameters.lockFile.set(rootProject.layout.projectDirectory.file("../../Cargo.lock"))
}

configurations.configureEach {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.rustls" && requested.name == "rustls-platform-verifier") {
            useVersion(rustlsVerifierVersion.get())
            because("tiene que coincidir con rustls-platform-verifier-android del núcleo")
        }
    }
}

/** La versión de la app; el `versionCode` sale de ella y crece con cada versión. */
val appVersion = "0.15.0"

/** 0.15.0 → 15000: cada parte de la versión tiene tres cifras. */
fun versionCodeOf(version: String): Int {
    val parts = version.split('.').map { it.toInt() }
    require(parts.size == 3 && parts.all { it in 0..999 }) { "versión no válida: $version" }
    return parts[0] * 1_000_000 + parts[1] * 1_000 + parts[2]
}

/** Las arquitecturas de una versión publicada: teléfonos (64 y 32 bits) y emuladores de PC. */
val publishedAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

/**
 * Para las que scripts/compilar-android.sh dejó el núcleo. El APK solo declara esas: si
 * declarara otra, se instalaría en un teléfono donde la app no puede abrir el núcleo.
 *
 * Esto y la firma se leen al configurar, sin declararlos como entradas: no activar la caché
 * de configuración de Gradle, o se quedarían con lo que había la primera vez.
 */
val builtAbis = file("src/main/jniLibs").listFiles()
    ?.filter { it.resolve("libtunel_mobile.so").isFile }
    ?.map { it.name }
    ?.sorted()
    .orEmpty()

/** Lo que hace falta para firmar con la clave de las versiones publicadas. */
data class ReleaseSigning(
    val store: File,
    val storePassword: String,
    val alias: String,
    val keyPassword: String,
)

/**
 * La clave con la que se firman las versiones publicadas. No está en el repositorio: se crea
 * una vez con scripts/crear-clave-android.sh y se guarda junto a la que firma las del
 * escritorio. Sin el archivo, la compilación release sale sin firmar; si está pero le falta
 * algo, solo falla la compilación release (las pruebas y la de depuración siguen).
 */
val signingFile: File = providers.environmentVariable("TUNEL_ANDROID_FIRMA")
    .orElse("${System.getProperty("user.home")}/.config/tunel-publicacion/android-firma.properties")
    .map { file(it) }
    .get()

var signingProblem: String? = null

val releaseSigning: ReleaseSigning? = signingFile.takeIf { it.isFile }?.let { path ->
    val properties = Properties()
    path.inputStream().use { stream -> properties.load(stream) }
    val missing = listOf("storeFile", "storePassword", "keyAlias", "keyPassword")
        .filter { properties.getProperty(it).isNullOrBlank() }
    val store = properties.getProperty("storeFile")?.let { path.parentFile.resolve(it) }
    when {
        missing.isNotEmpty() -> {
            signingProblem = "falta ${missing.joinToString()} en $path"
            null
        }
        store == null || !store.isFile -> {
            signingProblem = "no existe la clave $store"
            null
        }
        else -> ReleaseSigning(
            store,
            properties.getProperty("storePassword"),
            properties.getProperty("keyAlias"),
            properties.getProperty("keyPassword"),
        )
    }
}

android {
    namespace = "dev.tunel.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.tunel.android"
        // Android 10: BiometricPrompt y el almacén de claves que usará el desbloqueo con huella.
        minSdk = 29
        targetSdk = 37
        versionCode = versionCodeOf(appVersion)
        versionName = appVersion
        ndk {
            // Sin compilar todavía, la del teléfono: así el error al compilar es claro.
            abiFilters += builtAbis.ifEmpty { listOf("arm64-v8a") }
        }
    }

    signingConfigs {
        releaseSigning?.let { signing ->
            create("publicacion") {
                storeFile = signing.store
                storePassword = signing.storePassword
                keyAlias = signing.alias
                keyPassword = signing.keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("publicacion")
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
            test.systemProperty(
                "tunel.servidorDePruebas",
                rootDir.resolve("nucleo-local/servidor-de-pruebas").absolutePath,
            )
            test.systemProperty(
                "tunel.sshDePruebas",
                rootDir.resolve("nucleo-local/ssh-de-pruebas").absolutePath,
            )
            test.jvmArgs("--enable-native-access=ALL-UNNAMED")
        }
    }
}

/**
 * Una versión publicada lleva el núcleo para todas las arquitecturas, no solo la del teléfono,
 * y, si hay configuración de firma, tiene que estar completa.
 */
val checkReleaseCore = tasks.register("comprobarNucleoParaPublicar") {
    val missing = publishedAbis - builtAbis.toSet()
    val problem = signingProblem
    doLast {
        if (problem != null) throw GradleException("La firma no está bien configurada: $problem")
        if (missing.isNotEmpty()) {
            throw GradleException(
                "Falta el núcleo para ${missing.joinToString()}: " +
                    "ejecuta scripts/compilar-android.sh --todas",
            )
        }
    }
}
tasks.matching { it.name == "preReleaseBuild" }.configureEach { dependsOn(checkReleaseCore) }

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
    // Certificados de HTTPS con el almacén del sistema (lo llama el núcleo por JNI).
    implementation(libs.rustls.platform.verifier)
    // El inicio de sesión con Google o Microsoft se abre en una pestaña del navegador.
    implementation(libs.androidx.browser)
    // La terminal: pinta lo que llega por SSH y convierte el teclado en bytes.
    implementation(libs.termlib)
    // El desbloqueo con huella: BiometricPrompt necesita una FragmentActivity.
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment)
    debugImplementation(libs.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    // En las pruebas, la versión de JNA para el equipo de compilación.
    testImplementation(libs.jna)
}

# Túnel para Android

La interfaz es Jetpack Compose; el núcleo (bóveda, cifrado, sincronización y SSH) es el mismo
crate de Rust que usan el escritorio y iOS, expuesto con UniFFI desde `crates/tunel-mobile`.
El plan está en el bloque 9 de [la hoja de ruta](../../docs/hoja-de-ruta.md).

Necesita Android Studio con el **NDK** y las **Android SDK Command-line Tools** (Ajustes →
Languages & Frameworks → Android SDK → SDK Tools).

## Compilar el núcleo

```bash
scripts/compilar-android.sh           # release
scripts/compilar-android.sh --debug   # más rápido mientras se desarrolla
```

Deja la librería para Android en `app/src/main/jniLibs/arm64-v8a/`, el código Kotlin generado
en `app/src/main/java/uniffi/` y, en `nucleo-local/`, la librería para este equipo y un
servidor de Túnel en memoria, con los que corren las pruebas. Todo se genera: no se edita ni se guarda en git. Hay que volver a
ejecutarlo cada vez que cambia `crates/tunel-mobile`.

## Compilar y probar

Abre `apps/android` en Android Studio y pulsa ▶ con un teléfono (depuración USB activada) o un
emulador. Desde la terminal, con el Java de Android Studio:

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
cd apps/android
./gradlew testDebugUnitTest    # pruebas de Kotlin contra el núcleo real
./gradlew installDebug         # instala en el teléfono o emulador conectado
```

La parte en Kotlin de `rustls-platform-verifier` (HTTPS con los certificados del sistema) se
descarga del repositorio Maven del proyecto en GitHub, en la versión que dice `Cargo.lock`.

Solo se compila para `arm64-v8a`: los teléfonos actuales y el emulador de los Mac con Apple
silicon. Si el emulador va muy lento o se reinicia solo, dale al menos 4 núcleos en su
configuración (Device Manager → editar → Advanced).

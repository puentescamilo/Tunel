#!/usr/bin/env bash
# Compila Túnel para Android como se publica y deja dist/tunel_<versión>_android.apk: el
# núcleo para todas las arquitecturas, las pruebas de Kotlin, el código reducido por R8 y la
# firma con la clave de scripts/crear-clave-android.sh. Después, scripts/firmar-version.sh lo
# incluye en SHA256SUMS.txt con los paquetes del escritorio.
#
# Uso: scripts/empaquetar-android.sh 0.15.0
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?uso: $0 <versión>}
project=apps/android
export JAVA_HOME=${JAVA_HOME:-"/Applications/Android Studio.app/Contents/jbr/Contents/Home"}
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
sdk=$ANDROID_HOME

# La versión que se pide tiene que ser la que lleva la app.
declared=$(sed -n 's/^val appVersion = "\(.*\)"$/\1/p' "$project/app/build.gradle.kts")
if [[ "$declared" != "$version" ]]; then
  echo "error: la app dice ${declared:-?}, no $version (appVersion en app/build.gradle.kts)" >&2
  exit 1
fi

apksigner=$(ls -d "$sdk"/build-tools/*/apksigner 2>/dev/null | sort -V | tail -1 || true)
[[ -n "$apksigner" ]] || { echo "error: no encuentro apksigner en $sdk/build-tools" >&2; exit 1; }

scripts/compilar-android.sh --todas
# Sin restos de una compilación anterior: si esta sale sin firmar, que no quede un APK viejo
# firmado que pase por el nuevo.
rm -rf "$project/app/build/outputs/apk/release" "$project/app/build/outputs/mapping/release"
(cd "$project" && ./gradlew -q :app:testDebugUnitTest :app:assembleRelease)

apk="$project/app/build/outputs/apk/release/app-release.apk"
if [[ ! -f "$apk" ]]; then
  echo "error: el APK salió sin firmar: falta la clave (scripts/crear-clave-android.sh)" >&2
  exit 1
fi

# Firmado de verdad, y no con la clave de depuración de Android Studio.
certs=$("$apksigner" verify --print-certs "$apk")
if grep -q "CN=Android Debug" <<<"$certs"; then
  echo "error: el APK va firmado con la clave de depuración" >&2
  exit 1
fi

mkdir -p dist
cp "$apk" "dist/tunel_${version}_android.apk"
# Para leer los fallos de esta versión (R8 renombra las clases). Se guarda, no se publica.
cp "$project/app/build/outputs/mapping/release/mapping.txt" "dist/tunel_${version}_android-mapping.txt"
echo "Listo: dist/tunel_${version}_android.apk (guarda también su -mapping.txt; no se publica)"
sed -n 's/^Signer #1 certificate SHA-256 digest: /Huella del certificado (SHA-256): /p' <<<"$certs"

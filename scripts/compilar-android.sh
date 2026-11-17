#!/usr/bin/env bash
# Compila el núcleo (crate tunel-mobile) para Android y deja el proyecto de apps/android listo:
#   - app/src/main/jniLibs/<arquitectura>/libtunel_mobile.so: la librería para Android. Por
#     omisión solo arm64-v8a (los teléfonos actuales y el emulador de los Mac con Apple
#     silicon); con --todas, también armeabi-v7a (teléfonos de 32 bits) y x86_64 (emuladores
#     de PC), como lleva una versión publicada.
#   - app/src/main/java/uniffi/tunel_mobile/tunel_mobile.kt: el código Kotlin de UniFFI.
#   - nucleo-local/: la librería para este equipo, con la que corren las pruebas de Kotlin, un
#     servidor de Túnel en memoria para las de la cuenta y uno SSH para las de la terminal.
#
# Necesita el NDK de Android Studio (Ajustes → Android SDK → SDK Tools → NDK).
#
# Uso: scripts/compilar-android.sh            (release)
#      scripts/compilar-android.sh --debug    (más rápido, para probar)
#      scripts/compilar-android.sh --todas    (todas las arquitecturas, para publicar)
set -euo pipefail
cd "$(dirname "$0")/.."

profile=release
flag=--release
abis=(arm64-v8a)
for arg in "$@"; do
  case "$arg" in
    --debug) profile=debug; flag= ;;
    --todas) abis=(arm64-v8a armeabi-v7a x86_64) ;;
    *) echo "uso: $0 [--debug] [--todas]" >&2; exit 2 ;;
  esac
done

sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  ndk=$(ls -d "$sdk"/ndk/*/ 2>/dev/null | sort -V | tail -1 || true)
  if [[ -z "$ndk" ]]; then
    echo "No encuentro el NDK en $sdk/ndk. Instálalo desde Android Studio." >&2
    exit 1
  fi
  export ANDROID_NDK_HOME="${ndk%/}"
fi
command -v cargo-ndk >/dev/null || cargo install cargo-ndk

project=apps/android
targets=()
for abi in "${abis[@]}"; do
  case "$abi" in
    arm64-v8a) triple=aarch64-linux-android ;;
    armeabi-v7a) triple=armv7-linux-androideabi ;;
    x86_64) triple=x86_64-linux-android ;;
  esac
  rustup target list --installed | grep -qx "$triple" || rustup target add "$triple"
  targets+=(-t "$abi")
done
# Sin restos de una compilación anterior: el APK lleva todo lo que haya en jniLibs.
rm -rf "$project/app/src/main/jniLibs"
cargo ndk "${targets[@]}" -o "$project/app/src/main/jniLibs" build $flag -p tunel-mobile --lib

# La librería de este equipo: para generar el Kotlin y para las pruebas.
host=$(rustc -vV | sed -n 's/^host: //p')
cargo build $flag -p tunel-mobile --lib --target "$host"
case "$host" in
  *apple*) local_lib="target/$host/$profile/libtunel_mobile.dylib" ;;
  *) local_lib="target/$host/$profile/libtunel_mobile.so" ;;
esac
mkdir -p "$project/nucleo-local"
cp "$local_lib" "$project/nucleo-local/"
cargo build $flag -p tunel-mobile --features servidor-de-pruebas \
  --bin servidor-de-pruebas --bin ssh-de-pruebas --target "$host"
cp "target/$host/$profile/servidor-de-pruebas" "target/$host/$profile/ssh-de-pruebas" \
  "$project/nucleo-local/"

rm -rf "$project/app/src/main/java/uniffi"
cargo run -q -p tunel-mobile --features bindgen --bin uniffi-bindgen -- \
  generate --library "$local_lib" --language kotlin --no-format --out-dir "$project/app/src/main/java"
echo "Listo: $project"

#!/usr/bin/env bash
# Compila el núcleo (crate tunel-mobile) para Android y deja el proyecto de apps/android listo:
#   - app/src/main/jniLibs/arm64-v8a/libtunel_mobile.so: la librería para el teléfono y el
#     emulador de los Mac con Apple silicon.
#   - app/src/main/java/uniffi/tunel_mobile/tunel_mobile.kt: el código Kotlin de UniFFI.
#   - nucleo-local/: la librería para este equipo, con la que corren las pruebas de Kotlin, un
#     servidor de Túnel en memoria para las de la cuenta y uno SSH para las de la terminal.
#
# Necesita el NDK de Android Studio (Ajustes → Android SDK → SDK Tools → NDK).
#
# Uso: scripts/compilar-android.sh            (release)
#      scripts/compilar-android.sh --debug    (más rápido, para probar)
set -euo pipefail
cd "$(dirname "$0")/.."

profile=release
flag=--release
if [[ "${1:-}" == "--debug" ]]; then
  profile=debug
  flag=
fi

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
rustup target list --installed | grep -qx aarch64-linux-android || rustup target add aarch64-linux-android
cargo ndk -t arm64-v8a -o "$project/app/src/main/jniLibs" build $flag -p tunel-mobile --lib

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

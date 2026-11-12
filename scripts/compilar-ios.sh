#!/usr/bin/env bash
# Compila el núcleo (crate tunel-mobile) para iPhone, iPad, el simulador y este Mac, y deja
# el paquete de Swift listo en apps/ios/TunelCore:
#   - TunelCoreFFI.xcframework: la librería estática y su cabecera C.
#   - Sources/TunelCore/tunel_mobile.swift: el código Swift generado por UniFFI.
#
# Uso: scripts/compilar-ios.sh            (release)
#      scripts/compilar-ios.sh --debug    (más rápido, para probar)
set -euo pipefail
cd "$(dirname "$0")/.."

profile=release
flag=--release
if [[ "${1:-}" == "--debug" ]]; then
  profile=debug
  flag=
fi

package=apps/ios/TunelCore
targets=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
lib=libtunel_mobile.a

for target in "${targets[@]}"; do
  rustup target list --installed | grep -qx "$target" || rustup target add "$target"
  cargo build $flag -p tunel-mobile --lib --target "$target"
done

# El código Swift y la cabecera salen de los metadatos de la propia librería.
generated=$(mktemp -d)
trap 'rm -rf "$generated"' EXIT
cargo run -q -p tunel-mobile --features bindgen --bin uniffi-bindgen -- \
  generate --library "target/aarch64-apple-darwin/$profile/libtunel_mobile.dylib" \
  --language swift --out-dir "$generated"

headers="$generated/headers"
mkdir -p "$headers"
cp "$generated/tunel_mobileFFI.h" "$headers/"
# El XCFramework busca el mapa del módulo con este nombre.
cp "$generated/tunel_mobileFFI.modulemap" "$headers/module.modulemap"

rm -rf "$package/TunelCoreFFI.xcframework"
args=()
for target in "${targets[@]}"; do
  args+=(-library "target/$target/$profile/$lib" -headers "$headers")
done
xcodebuild -create-xcframework "${args[@]}" -output "$package/TunelCoreFFI.xcframework" >/dev/null

mkdir -p "$package/Sources/TunelCore"
cp "$generated/tunel_mobile.swift" "$package/Sources/TunelCore/"
echo "Listo: $package"

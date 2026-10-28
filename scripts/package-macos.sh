#!/usr/bin/env bash
# Genera dist/tunel_<versión>_universal.dmg con un binario universal (Apple Silicon + Intel).
# Requisitos: rustup target add aarch64-apple-darwin x86_64-apple-darwin
#             cargo install cargo-packager --locked
set -euo pipefail
cd "$(dirname "$0")/.."

export MACOSX_DEPLOYMENT_TARGET=11.0
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)
UNIVERSAL=target/universal-apple-darwin/release

for target in "${TARGETS[@]}"; do
  cargo build --release --locked -p tunel-app --target "$target"
done

mkdir -p "$UNIVERSAL"
lipo -create -output "$UNIVERSAL/tunel" \
  "target/aarch64-apple-darwin/release/tunel" \
  "target/x86_64-apple-darwin/release/tunel"
lipo -info "$UNIVERSAL/tunel"

# Con --target, cargo-packager toma el binario de target/<triple>/release: ahí está el universal.
# (Su opción --binaries-dir no tiene efecto en la versión 0.11.)
package() {
  rm -rf dist/*.dmg dist/*.app
  cargo packager --release -p tunel-app --formats app,dmg --target universal-apple-darwin
}

# El paso de create-dmg que coloca los iconos con el Finder falla a veces por tiempos y deja
# la imagen temporal montada: se desmonta y se reintenta una vez.
if ! package; then
  echo "create-dmg falló; desmontando imágenes temporales y reintentando…" >&2
  hdiutil info | awk '/image-path.*dist\/rw\./{found=1} found && /\/Volumes\//{print $NF; found=0}' |
    while read -r volume; do hdiutil detach "$volume" -force -quiet || true; done
  rm -f dist/rw.*.dmg
  package
fi


# Nombre final sin tilde (GitHub la quita al subirlo) y con "universal", sea cual sea el sufijo
# que ponga cargo-packager. Así coincide con SHA256SUMS.txt y con los demás paquetes.
shopt -s nullglob
for dmg in dist/*.dmg; do
  version=$(basename "$dmg" .dmg | cut -d_ -f2)
  target="dist/tunel_${version}_universal.dmg"
  [[ "$dmg" == "$target" ]] || mv "$dmg" "$target"
done
# Comprobar dentro del .dmg (lo que se distribuye) que el ejecutable es universal.
for dmg in dist/*_universal.dmg; do
  mount=$(mktemp -d)
  hdiutil attach -nobrowse -readonly -quiet -mountpoint "$mount" "$dmg"
  archs=$(lipo -archs "$mount/Túnel.app/Contents/MacOS/tunel")
  if [[ " $archs " != *" arm64 "* || " $archs " != *" x86_64 "* ]]; then
    hdiutil detach -quiet "$mount"
    echo "error: $dmg no contiene un ejecutable universal" >&2
    exit 1
  fi
  echo "$(basename "$dmg"): ejecutable universal (arm64 + x86_64)"
  hdiutil detach -quiet "$mount"
done
(cd dist && shasum -a 256 *.dmg > SHA256SUMS.txt)
ls -lh dist/

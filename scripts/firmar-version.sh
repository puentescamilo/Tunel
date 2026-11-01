#!/usr/bin/env bash
# Escribe dist/SHA256SUMS.txt con los cuatro paquetes de una versión y lo firma en
# dist/SHA256SUMS.txt.sig. Túnel solo instala por su cuenta lo que está en una lista firmada.
#
# Uso: scripts/firmar-version.sh 0.8.1
# La clave privada se toma de $TUNEL_CLAVE_FIRMA o de ~/.config/tunel-publicacion/firma_ed25519.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:?uso: $0 <versión>}
key=${TUNEL_CLAVE_FIRMA:-$HOME/.config/tunel-publicacion/firma_ed25519}
namespace=tunel-versiones
packages=(
  "tunel_${version}_universal.dmg"
  "tunel_${version}_amd64.deb"
  "tunel_${version}_x64_es-ES.msi"
  "tunel_${version}_x64-setup.exe"
)

for package in "${packages[@]}"; do
  [[ -f "dist/$package" ]] || { echo "error: falta dist/$package" >&2; exit 1; }
done

# La clave pública que lleva la app: la firma tiene que valer con ella.
public=$(sed -n 's/^pub const RELEASE_SIGNING_KEY: &str = "\(.*\)";$/\1/p' \
  crates/tunel-app/src/updates/install.rs)
[[ -n "$public" ]] || { echo "error: no encuentro RELEASE_SIGNING_KEY" >&2; exit 1; }

cd dist
shasum -a 256 "${packages[@]}" > SHA256SUMS.txt
rm -f SHA256SUMS.txt.sig
ssh-keygen -q -Y sign -f "$key" -n "$namespace" SHA256SUMS.txt

signers=$(mktemp)
trap 'rm -f "$signers"' EXIT
echo "tunel $public" > "$signers"
ssh-keygen -Y verify -f "$signers" -I tunel -n "$namespace" -s SHA256SUMS.txt.sig < SHA256SUMS.txt
cat SHA256SUMS.txt

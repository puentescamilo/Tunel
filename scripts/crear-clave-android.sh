#!/usr/bin/env bash
# Crea, una sola vez, la clave que firma las versiones de Túnel para Android:
#   ~/.config/tunel-publicacion/android.p12               la clave (PKCS12, RSA de 4096 bits)
#   ~/.config/tunel-publicacion/android-firma.properties  su contraseña, para Gradle
#
# Android solo instala una versión nueva encima de la anterior si va firmada con la misma
# clave: si se pierde, quien tenga la app tiene que desinstalarla (y perder su bóveda en el
# teléfono) para instalar la siguiente. Haz copia de los dos archivos, como de la clave que
# firma las versiones del escritorio.
#
# Uso: scripts/crear-clave-android.sh
set -euo pipefail

dir=${TUNEL_PUBLICACION:-$HOME/.config/tunel-publicacion}
store="$dir/android.p12"
properties="$dir/android-firma.properties"
alias=tunel

if [[ -e "$store" || -e "$properties" ]]; then
  echo "error: ya existe la clave en $dir; no se sobrescribe" >&2
  exit 1
fi

java_home=${JAVA_HOME:-"/Applications/Android Studio.app/Contents/jbr/Contents/Home"}
keytool="$java_home/bin/keytool"
[[ -x "$keytool" ]] || { echo "error: no encuentro keytool en $java_home" >&2; exit 1; }

umask 077
mkdir -p "$dir"
# En PKCS12 la clave y el almacén comparten contraseña. Va por el entorno, no en la línea de
# órdenes, para que no se vea en la lista de procesos.
TUNEL_CLAVE_ANDROID=$(openssl rand -base64 33 | tr -d '\n')
export TUNEL_CLAVE_ANDROID

# Si algo falla o se interrumpe a medias, no queda una clave sin su contraseña (ni al revés).
done=0
trap '[[ $done == 1 ]] || rm -f "$store" "$properties"' EXIT

# Más de 25 años: Google Play pide que el certificado dure hasta después de 2033.
"$keytool" -genkeypair -noprompt \
  -keystore "$store" -storetype PKCS12 \
  -storepass:env TUNEL_CLAVE_ANDROID -keypass:env TUNEL_CLAVE_ANDROID \
  -alias "$alias" -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=Tunel, O=Tunel"

cat > "$properties" <<EOF
# La clave que firma Túnel para Android (scripts/crear-clave-android.sh). No la subas a git.
storeFile=android.p12
storePassword=$TUNEL_CLAVE_ANDROID
keyAlias=$alias
keyPassword=$TUNEL_CLAVE_ANDROID
EOF
done=1

echo "Clave creada en $dir. Huella del certificado (se publica con cada versión):"
"$keytool" -list -keystore "$store" -storepass:env TUNEL_CLAVE_ANDROID -alias "$alias" \
  | sed -n 's/^.*(SHA-256): //p' || true
echo "Haz copia de android.p12 y android-firma.properties: sin ellos no se puede actualizar la app."

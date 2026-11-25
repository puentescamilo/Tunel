#!/usr/bin/env bash
# Genera el icono de Windows: icon.ico y windows-256.png (el de la barra de tareas).
#
# El de macOS deja aire alrededor (100 de 1024 por lado, con sombra) porque el sistema no
# recorta los iconos. Windows los muestra tal cual, y con ese margen Túnel se veía más
# pequeño que el Explorador o el navegador. Aquí el cuadrado llega casi al borde.
#
# El .ico lleva un PNG por tamaño, de 16 a 256: Windows elige el que necesita en vez de
# reducir el de 256, que a 16 o 24 píxeles queda borroso.
# Requiere macOS (swift y sips). Uso: ./generar-icono-windows.sh
set -euo pipefail
cd "$(dirname "$0")"

MARGIN=24
SIZES=(16 20 24 32 40 48 64 96 128 256)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

swift generar-icono.swift "$work/1024.png" "$MARGIN"
for size in "${SIZES[@]}"; do
  sips -z "$size" "$size" "$work/1024.png" --out "$work/$size.png" >/dev/null
done
cp "$work/256.png" windows-256.png

# Un .ico es una cabecera, una entrada por imagen y las imágenes (aquí, PNG) seguidas.
python3 -I - "$work" icon.ico "${SIZES[@]}" <<'EOF'
import struct, sys
work, out, sizes = sys.argv[1], sys.argv[2], [int(s) for s in sys.argv[3:]]
images = [open(f"{work}/{s}.png", "rb").read() for s in sizes]
header = struct.pack("<HHH", 0, 1, len(images))
offset = len(header) + 16 * len(images)
entries = b""
for size, data in zip(sizes, images):
    side = 0 if size >= 256 else size  # 0 significa 256
    entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
with open(out, "wb") as f:
    f.write(header + entries + b"".join(images))
EOF
file icon.ico

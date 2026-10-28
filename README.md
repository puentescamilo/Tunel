# Túnel

Cliente SSH multiplataforma (macOS, Windows y Linux) escrito en Rust. Guarda tus hosts,
claves y contraseñas en una bóveda cifrada y te conecta por SSH, Mosh, Telnet o puerto serie
desde una sola aplicación nativa, sin Electron ni WebView.

![Hosts organizados en grupos](docs/screenshots/hosts.png)

## Funciones

### Hosts y bóveda

- **Bóveda local cifrada** con contraseña maestra (Argon2id + XChaCha20-Poly1305). Nada sale del equipo.
- **Hosts y grupos anidados**: los hosts heredan usuario y puerto de su grupo. Etiquetas,
  búsqueda por nombre, dirección o etiqueta, y duplicar host.
- **Llavero**: identidades (usuario + contraseña, clave o agente SSH) y claves privadas
  OpenSSH/PEM, cifradas o no, con certificados OpenSSH opcionales.
- **Importar `~/.ssh/config`**: hosts, usuarios, puertos, `ProxyJump` y claves.
- **Conexión rápida** (`⌘K` / `Ctrl+K`): busca un host guardado o escribe
  `usuario@servidor:puerto` (también `ssh usuario@servidor -p 2222`) para conectar sin guardarlo.

<p>
  <img src="docs/screenshots/grupo.png" width="49%" alt="Hosts dentro de un grupo">
  <img src="docs/screenshots/conexion-rapida.png" width="49%" alt="Conexión rápida">
</p>

### Conexiones

- **SSH** con autenticación por clave, certificado, agente SSH (Unix y Windows), contraseña
  y keyboard-interactive (2FA).
- **Llaves de seguridad FIDO2** (claves `sk-ed25519` y `sk-ecdsa` de OpenSSH, como una YubiKey)
  en macOS y Linux: Túnel pide que toques la llave y, si la clave lo exige, el PIN.
- **Verificación de la clave del servidor**: pide confirmación la primera vez y avisa en rojo
  si la clave cambia, aunque sea de otro algoritmo.
- **Jump hosts encadenados** (ProxyJump) y conexión a través de **proxy SOCKS5 o HTTP**.
- **Mosh** (usa el `mosh-client` del sistema), **Telnet** y **puerto serie**.
- **Terminal local** del sistema.
- **Reenvío X11**: las aplicaciones gráficas del servidor se abren en tu equipo. Hace falta un
  servidor X local (XQuartz en macOS, VcXsrv en Windows; en Linux ya viene con el escritorio).
  Al servidor se le envía una cookie falsa, como hace OpenSSH, y la real no sale de tu equipo.
  Úsalo solo con servidores de confianza.
- Reenvío del agente SSH, variables de entorno y snippet de inicio por host.

<p>
  <img src="docs/screenshots/editor.png" width="49%" alt="Editor de host">
  <img src="docs/screenshots/clave-cambiada.png" width="49%" alt="Aviso de clave de servidor cambiada">
</p>

### Terminal

- Emulación basada en `alacritty_terminal`: 256 colores y truecolor, negrita, cursiva,
  subrayado, caracteres de doble ancho, historial desplazable y selección con copiar y pegar.
- Pestañas con indicador de estado, vista dividida y reconexión con un clic.
- Pegado seguro (bracketed paste), título de ventana por OSC y registro de la sesión en archivo.
- **13 temas incluidos**: Túnel Oscuro y Claro, Dracula, Nord, Tokyo Night, Catppuccin
  Mocha y Latte, One Dark, Gruvbox, Solarized Oscuro y Claro, Monokai y GitHub Claro.
- **Importa temas** de iTerm2 (`.itermcolors`) y Windows Terminal (`.json`).
- **Tema por host o por grupo**, por ejemplo uno distinto para producción. Los hosts sin tema
  propio usan el de su grupo y, si tampoco lo tiene, el general.
- Cursor en bloque, barra o subrayado. Los programas como vim pueden cambiarlo mientras se ejecutan.

![Terminal con el tema Túnel Oscuro](docs/screenshots/terminal.png)

<p>
  <img src="docs/screenshots/temas.png" width="49%" alt="Galería de temas de la terminal">
  <img src="docs/screenshots/terminal-tokyo.png" width="49%" alt="Terminal con el tema Tokyo Night">
</p>

### Túneles, SFTP y snippets

- **Reenvío de puertos** local (`-L`), remoto (`-R`) y dinámico (`-D`, proxy SOCKS5), con aviso
  si una regla escucha fuera de `localhost`.
- **SFTP de doble panel**: navegar, subir, descargar, renombrar, borrar y crear carpetas.
- **Snippets**: comandos guardados que se envían a la terminal activa o a todas a la vez.

![Túneles](docs/screenshots/tuneles.png)

### Interfaz

- Interfaz oscura o clara; en modo automático sigue al fondo del tema de la terminal.
- Usa la fuente del sistema: SF y SF Mono en macOS, Segoe UI y Cascadia en Windows, Inter,
  Noto y JetBrains Mono en Linux si están instaladas.
- Mientras hay una sesión abierta, el menú lateral se reduce a iconos.

<p>
  <img src="docs/screenshots/claro.png" width="49%" alt="Tema claro">
  <img src="docs/screenshots/bienvenida.png" width="49%" alt="Creación de la bóveda">
</p>

**Atajos:** `⌘K` / `Ctrl+K` conexión rápida · `⌘⇧T` / `Ctrl+Shift+T` terminal local ·
`⌘⇧W` / `Ctrl+Shift+W` cerrar pestaña.

## Instalación

### macOS

Descarga `tunel_<versión>_universal.dmg` desde [Releases](https://github.com/puentescamilo/Tunel/releases).
Funciona en Macs con Apple Silicon e Intel, con macOS 11 o posterior. Abre el `.dmg` y
arrastra **Túnel** a **Aplicaciones**.

La app está firmada de forma local (ad hoc) pero no notarizada por Apple, así que la primera
vez macOS la bloquea. Para abrirla:

1. Intenta abrir Túnel y cierra el aviso.
2. Ve a **Ajustes del Sistema → Privacidad y seguridad** y pulsa **Abrir igualmente** junto al
   mensaje sobre Túnel.

También puedes quitar la marca de cuarentena desde la terminal:

```bash
xattr -dr com.apple.quarantine /Applications/Túnel.app
```

Para Mosh hace falta `mosh` instalado en tu equipo y en el servidor.

### Linux

Descarga `tunel_<versión>_amd64.deb` desde [Releases](https://github.com/puentescamilo/Tunel/releases)
e instálalo con:

```bash
sudo apt install ./tunel_0.2.0_amd64.deb
```

Funciona en Ubuntu 22.04, Debian 12 o posteriores, en equipos x86_64. Para elegir archivos
(importar claves o temas) se usa el portal del escritorio (`xdg-desktop-portal`), que ya viene
en GNOME y KDE.

### Windows

Descarga uno de los dos instaladores desde [Releases](https://github.com/puentescamilo/Tunel/releases).
Ambos son para Windows 10 y 11 de 64 bits:

- `tunel_<versión>_x64-setup.exe`: se instala solo para tu usuario y no pide permisos de administrador.
- `tunel_<versión>_x64_es-ES.msi`: se instala para todo el equipo; es el indicado para
  distribuirlo en una empresa.

Los instaladores no están firmados, así que Windows SmartScreen avisa la primera vez. Pulsa
**Más información → Ejecutar de todas formas**. Túnel funciona también en equipos y máquinas
virtuales sin tarjeta gráfica: en ese caso dibuja por software.

### Desde el código

Hace falta [Rust](https://rustup.rs/) 1.89 o superior.

```bash
git clone https://github.com/puentescamilo/Tunel.git
cd Tunel
cargo run --release -p tunel-app
```

En Linux se necesitan además un compilador de C y `libudev` para el puerto serie:

```bash
sudo apt install build-essential pkg-config libudev-dev
```

La bóveda se guarda en el directorio de datos del usuario; en macOS es
`~/Library/Application Support/dev.tunel.tunel/vault.json`. Para usar otra ruta:

```bash
TUNEL_VAULT=/ruta/vault.json cargo run --release -p tunel-app
```

### Generar el `.dmg`

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo install cargo-packager --locked
./scripts/package-macos.sh
```

El script compila para Apple Silicon e Intel, une ambos en un binario universal, lo empaqueta
con [cargo-packager](https://github.com/crabnebula-dev/cargo-packager), comprueba dentro del
`.dmg` que el ejecutable es universal y deja el resultado y su `SHA256SUMS.txt` en `dist/`.
El icono se regenera con `swift crates/tunel-app/assets/icons/generar-icono.swift icon-1024.png`.

### Generar el `.deb`

Compílalo en Ubuntu 22.04, con las dependencias de «Desde el código»: un paquete hecho en una
distribución más nueva no funciona en las anteriores.

```bash
cargo install cargo-packager --locked
cargo build --release --locked -p tunel-app
cargo packager --release -p tunel-app --formats deb
```

### Generar los instaladores de Windows

Hacen falta las Build Tools de Visual Studio 2022 con el compilador de C++. La librería de
criptografía necesita NASM, salvo que uses los objetos ya compilados que trae:

```powershell
cargo install cargo-packager --locked
$env:AWS_LC_SYS_PREBUILT_NASM = "1"
cargo build --release --locked -p tunel-app
cargo packager --release -p tunel-app --formats wix,nsis
```

cargo-packager descarga WiX y NSIS la primera vez y deja el `.msi` y el `.exe` en `dist/`.

## Seguridad

- La contraseña maestra no se guarda. Si la olvidas, la bóveda no se puede recuperar.
- La bóveda se escribe de forma atómica: archivo temporal privado, `fsync` y renombrado, con
  permisos `0600` en Unix. Solo una instancia de Túnel puede abrirla a la vez.
- Los parámetros de Argon2 leídos del archivo tienen límites, para que uno manipulado no agote la memoria.
- El texto pegado se limpia de caracteres de control, así que no puede inyectar teclas.
- La contraseña guardada solo se envía cuando el servidor la pide; los códigos 2FA los escribe el usuario.
- Contraseñas, frases de paso y claves privadas no aparecen en los registros de depuración,
  y se borran de la memoria al bloquear la bóveda.

**Pendiente:**
- La interfaz hace copias temporales de la bóveda que no se borran de la memoria explícitamente.
- En Windows el archivo usa los permisos heredados de la carpeta del usuario.

## Estado y hoja de ruta

| Función | Estado |
|---|---|
| Bóveda, hosts, grupos, llavero, importar `~/.ssh/config` | ✅ |
| SSH (clave, certificado, agente, contraseña, 2FA), jump hosts, proxys | ✅ |
| Terminal, pestañas, vista dividida, temas e importación de temas | ✅ |
| Túneles local, remoto y SOCKS5 · SFTP · snippets | ✅ |
| Telnet, puerto serie, terminal local | ✅ |
| Mosh | ✅ con el `mosh-client` del sistema |
| Tema por grupo, reenvío X11 | ✅ |
| Llaves FIDO2 (`sk-*`) | ✅ macOS y Linux · ⏳ Windows |
| Cliente Mosh propio | ⏳ más adelante |
| Autocompletado de comandos, desbloqueo biométrico | ⏳ fase 2 |
| Importar de AWS, Azure, DigitalOcean, Docker y Kubernetes | ⏳ fase 3 |
| Sincronización entre equipos, equipos compartidos, sesiones compartidas | ⏳ fase 3 (necesita un servidor propio) |

## Desarrollo

```bash
cargo test --workspace                                  # pruebas
cargo clippy --workspace --all-targets -- -D warnings   # lint
cargo fmt --all                                         # formato
```

| Crate | Contenido |
|---|---|
| `tunel-core` | Modelos, bóveda cifrada, temas guardados, importación de `~/.ssh/config` |
| `tunel-ssh` | Cliente `russh`: autenticación, claves de host, jump hosts, proxys, shell, túneles, SFTP, Mosh |
| `tunel-term` | Emulador de terminal, temas incluidos e importadores, teclado, terminal local, Telnet, serie |
| `tunel-app` | Interfaz `egui` y sistema de diseño (`src/ui`) |

**Pruebas:** 190 unitarias y 16 de punta a punta contra un servidor SSH que arranca el propio
test (`crates/tunel-ssh/tests/end_to_end.rs`). Cubren contraseña, clave cifrada, 2FA, clave de
host nueva y cambiada, shell, túnel local, SOCKS5, jump hosts, reenvío X11 y llaves FIDO2
(con una llave simulada). Las claves de
`crates/tunel-ssh/tests/fixtures` son solo para esas pruebas. Aún no tienen pruebas automáticas
el SFTP contra un servidor real, Mosh, Telnet, el puerto serie ni la interfaz.

**Capturas y pruebas manuales:** en compilaciones de depuración, unas variables de entorno
abren la app directamente en una pantalla con datos de ejemplo:

```bash
cargo run -p tunel-core --example demo_vault -- /tmp/demo.json demo-password
TUNEL_VAULT=/tmp/demo.json TUNEL_DEV_PASSWORD=demo-password TUNEL_DEV_SECTION=settings \
  cargo run -p tunel-app
```

Otras variables: `TUNEL_DEV_GROUP=<grupo>`, `TUNEL_DEV_LOCAL=1` (con `TUNEL_DEV_RUN=<comando>`),
`TUNEL_DEV_QUICK=<texto>`, `TUNEL_DEV_EDIT=<host>`, `TUNEL_DEV_PROMPT=cambio|nuevo|llave`,
`TUNEL_DEV_THEME=<id de tema>` y `TUNEL_DEV_CURSOR=bloque|barra|subrayado`. No existen en
compilaciones `--release`.

## Licencia

Túnel se distribuye bajo la licencia [MIT](LICENSE-MIT) o la [Apache 2.0](LICENSE-APACHE), a
tu elección.

## Créditos

- Iconos de [Phosphor Icons](https://phosphoricons.com/) (MIT), incluidos en `crates/tunel-app/assets/fonts`.
- Paletas de [Dracula](https://draculatheme.com/), [Nord](https://www.nordtheme.com/),
  [Catppuccin](https://catppuccin.com/), [Tokyo Night](https://github.com/folke/tokyonight.nvim),
  [Gruvbox](https://github.com/morhetz/gruvbox), [Solarized](https://ethanschoonover.com/solarized/),
  One Dark, Monokai y GitHub, de sus respectivos autores.
- Construido sobre [russh](https://github.com/Eugeny/russh), [alacritty_terminal](https://github.com/alacritty/alacritty)
  y [egui](https://github.com/emilk/egui).

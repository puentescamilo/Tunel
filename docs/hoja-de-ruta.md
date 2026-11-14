# Hoja de ruta de Túnel

Actualizada el 10 de noviembre de 2026, con Túnel 0.14.0.

Cada entrega es un PR propio, con pruebas, que se fusiona y se publica en una versión. Las
entregas de un mismo bloque van en orden; los bloques se pueden intercalar.

## Orden propuesto

| # | Entrega | Versión | Estado |
|---|---|---|---|
| 1a | Comandos de administración del servidor | 0.7.0 | ✅ |
| 1b | Pasar una cuenta con contraseña a Google o Microsoft | 0.7.0 | ✅ |
| 4a | Restaurar las pestañas al abrir Túnel | 0.7.0 | ✅ |
| 4b | Snippets con variables | 0.7.0 | ✅ |
| 4c | Escribir en varias terminales a la vez | 0.7.0 | ✅ |
| — | Correcciones de la auditoría de seguridad (12 hallazgos) | 0.7.1 | ✅ |
| 5a | Generar claves SSH en el llavero | 0.8.0 | ✅ |
| 5b | Instalar una clave pública en un host | 0.8.0 | ✅ |
| 5c | Avisar de claves débiles | 0.8.0 | ✅ |
| 2a | Actualización automática con paquetes verificados | 0.9.0 | ✅ |
| 3a | Registro de auditoría de los Teams | 0.9.0 | ✅ |
| 3b | Grabación de sesiones (opcional por Team) | 0.9.0 | ✅ |
| 6a | Importar máquinas de AWS, Azure y DigitalOcean | 0.10.0 | ✅ |
| 6b | Shell en contenedores Docker y pods de Kubernetes de este equipo | 0.10.0 | ✅ |
| 6c | Contenedores Docker de un host SSH | 0.10.0 | ✅ |
| 7a | Desbloquear la bóveda con Touch ID o Windows Hello | 0.11.0 | ✅ |
| 7b | Autocompletado de comandos en la terminal | 0.12.0 | ✅ |
| 7c | Vista dividida de hasta cuatro terminales y terminales en otra ventana | 0.13.0 | ✅ |
| 8a | Vaultwarden: protocolo, cifrado y pruebas contra un servidor real | 0.14.0 | ✅ |
| 8b | Vaultwarden: ajustes y credenciales de Vaultwarden en las identidades | 0.14.0 | ✅ |
| 8c | Vaultwarden: mover una credencial de Túnel a Vaultwarden | 0.14.0 | ✅ |
| 8d | Vaultwarden: hosts desde las colecciones | 0.14.0 | ✅ |
| 8f | Vaultwarden: contraseña *enable* desde la pestaña | 0.14.0 | ✅ |
| — | La ventana cabe en la pantalla al pasarla a otra con distinta escala (Windows) | 0.14.0 | ✅ |
| 8f | Vaultwarden: contraseña *enable* | 0.14.0 | ✅ |
| 9a | Móvil: núcleo compartido para iOS y Android (UniFFI) | 0.15.0 | ✅ |
| 9b | iOS/iPadOS: app SwiftUI con la bóveda y la lista de hosts | 0.15.0 | ✅ |
| 9c | iOS/iPadOS: iniciar sesión en la cuenta y sincronizar | 0.15.0 | ✅ |
| 9d | iOS/iPadOS: terminal SSH | 0.15.0 | ✅ |
| 9e | iOS/iPadOS: desbloqueo con Face ID o Touch ID | 0.15.0 | ✅ |
| 9g | iOS/iPadOS: crear, editar y borrar hosts | 0.15.0 | ✅ |
| 9f1 | Android: app Compose con la bóveda y la lista de hosts | 0.15.0 | ✅ |
| 9f2 | Android: iniciar sesión en la cuenta y sincronizar | 0.15.0 | en curso |
| 9f3 | Android: terminal SSH | 0.15.0 | en curso |
| 9f4 | Android: desbloqueo con huella | 0.15.0 | en curso |
| 9f5 | Android: crear, editar y borrar hosts | 0.15.0 | en curso |
| 2b | Paquetes firmados por Apple y Microsoft | cuando estén los certificados | bloqueada |

## 1. Administración del servidor

Hoy, para borrar una cuenta hay que borrar toda la base de datos.

**1a. Comandos de administración.** Se ejecutan dentro del contenedor, con el servidor en
marcha:

```bash
docker compose -f crates/tunel-server/compose.yaml exec tunel-server tunel-server cuentas
```

- `cuentas`: lista correo, forma de entrar (contraseña o proveedor), fecha de alta, Teams,
  registros y sesiones abiertas.
- `cerrar-sesiones <correo>`: cierra todas las sesiones de la cuenta; sus equipos tendrán que
  volver a iniciar sesión.
- `borrar-cuenta <correo>`: borra la cuenta, sus registros y sus sesiones, y la saca de sus
  Teams. Si era la única admin de un Team con más miembros, hay que indicar quién pasa a
  serlo con `--nuevo-admin <correo>`. Los Teams donde solo estaba ella se borran. Los Teams
  de los que sale quedan pendientes de renovar la clave, como cuando se saca a alguien
  desde la app.

**1b. Pasar una cuenta con contraseña a un proveedor.** Desde Ajustes, con la cuenta unida:
«Pasar mi cuenta a Google». Se conservan los Teams, los equipos unidos y los datos; la
sincronización pasa a cifrarse con la contraseña maestra. Necesita versión nueva de la app
y del servidor.

## 2. Distribución

**2a. Actualización automática.** Túnel descarga el instalador de su sistema, comprueba su
firma Ed25519 con una clave pública incluida en la app y lo abre. La clave privada solo la
tiene quien publica; sin ella, nadie puede colar un instalador aunque controle la descarga.
La firma va sobre `SHA256SUMS.txt` (`scripts/firmar-version.sh`); la 0.9.0 es la primera que
la comprueba, así que el paso de la 0.8.0 a la 0.9.0 todavía se hace a mano.

**2b. Paquetes firmados.** Quitar los avisos de «aplicación no firmada»:

- macOS: cuenta de Apple Developer (99 USD al año), certificado Developer ID y notarización.
- Windows: certificado de firma de código (OV o EV) para Authenticode.

Bloqueado hasta tener los certificados. El resto de la cadena se deja preparada.

## 3. Auditoría de los Teams

**3a. Registro de auditoría.** Quién se conectó a qué host del Team y cuándo, quién vio o
cambió una contraseña, quién entró o salió del Team. Va cifrado con la clave del Team, como
el resto: el servidor guarda el registro pero no puede leerlo. Los admins lo ven en
**Ajustes → Teams**.

**3b. Grabación de sesiones.** Opcional por Team: graba las terminales de los hosts del Team
(al estilo asciinema), cifradas, para revisarlas después. Pensado para hosts críticos.

## 4. Productividad en la terminal

- **4a. Restaurar pestañas:** al abrir Túnel, vuelven las pestañas de la última vez, con sus
  nombres. Se reconectan al seleccionarlas, no todas a la vez.
- **4b. Snippets con variables:** `systemctl restart {{servicio}}` pregunta el valor antes de
  enviarlo, y recuerda el último.
- **4c. Varias terminales a la vez:** lo que se escribe va a todas las pestañas marcadas, con
  un aviso visible mientras está activo.

## 5. Claves SSH

- **5a. Generar claves:** Ed25519 (recomendada), ECDSA o RSA de 4096 bits, con frase de paso
  opcional, directamente en el llavero.
- **5b. Instalar en un host:** añade la clave pública a `~/.ssh/authorized_keys` del host,
  como `ssh-copy-id`, sin duplicarla.
- **5c. Claves débiles:** aviso en el llavero para RSA de menos de 3072 bits, DSA y claves
  sin frase de paso que no están en el llavero cifrado (las de `~/.ssh`).

## 6. Nube y contenedores

Se usan las herramientas oficiales (`aws`, `az`, `doctl`, `docker`, `kubectl`) con la sesión
que ya tenga el usuario: Túnel no guarda credenciales de la nube.

- **6a. Importar de la nube:** en **Ajustes → Importar**, elegir proveedor y cuenta, ver sus
  máquinas y marcar las que se importan como hosts. Volver a importar actualiza la IP de las
  que ya estaban sin tocar el resto de su configuración.
- **6b. Contenedores y pods de este equipo:** listar los contenedores de `docker` y los pods de
  cada contexto de `kubectl`, y abrir una shell en ellos en una pestaña.
- **6c. Docker en un host SSH:** lo mismo con los contenedores de un servidor, a través de la
  conexión SSH.

## 7. Comodidad en el día a día

- **7a. Desbloqueo biométrico:** en **Ajustes → Seguridad**, activar Touch ID (macOS) o
  Windows Hello. La clave de la bóveda se guarda en `<bóveda>.biometria`, cifrada con una clave
  que solo da el sistema tras la huella o el PIN: en macOS está en el llavero; en Windows sale
  de la firma de una clave de Windows Hello, así que no hay nada secreto en el disco. La
  primera vez de cada día se pide la contraseña maestra, para no olvidarla, como hace macOS.
  Se desactiva al cambiar la contraseña maestra. En Linux no hay un mecanismo común, así que no
  se ofrece.
- **7b. Autocompletado de comandos:** sugerencia en gris tras el cursor, como en fish, que se
  acepta con →. Sale del historial de ese host, de los snippets de una línea sin variables y del
  historial de otros hosts, por ese orden. Túnel sigue lo tecleado desde el último Enter y solo
  lo cuenta si el servidor lo repite en pantalla: no guarda lo que se escribe sin eco, deja de
  seguir la línea con flechas, Tab o Ctrl+R hasta el siguiente Enter, y no interviene a pantalla
  completa. El historial (`<bóveda>.historial`, 1000 comandos) va cifrado y no se sincroniza.

## 8. Vaultwarden

Usar desde Túnel las credenciales que una empresa guarda en Vaultwarden (o Bitwarden), cada
ingeniero con su propia cuenta. Es opcional: sin una cuenta configurada, Túnel funciona igual
que siempre. El diseño completo está en [vaultwarden.md](vaultwarden.md).

- **8a. Protocolo:** crate `tunel-vaultwarden` con inicio de sesión (incluido el segundo factor),
  sincronización, descifrado y creación de elementos, probado contra un servidor real.
- **8b. Credenciales en las identidades:** en **Ajustes → Vaultwarden** se conecta la cuenta, y
  una identidad puede tomar su usuario y contraseña o su clave de un elemento de Vaultwarden.
  Copia local cifrada que no se sincroniza, y avisos si Vaultwarden no está disponible.
- **8c. Mover a Vaultwarden:** pasar la credencial de una identidad a la bóveda personal o a una
  colección, y dejar la identidad vinculada.
- **8d. Hosts desde las colecciones:** los elementos con URI `ssh://`, `telnet://` o `mosh://`
  se importan como hosts, con su puerto, sus notas y un grupo por colección.
- **8f. Contraseña *enable*:** guardada en la identidad o en el campo oculto `enable` del
  elemento de Vaultwarden, y enviada a mano desde el menú de la pestaña o con ⌘⇧E.

## 9. Túnel en iPhone, iPad y Android

Interfaz nativa en cada sistema (SwiftUI en iOS y iPadOS, Jetpack Compose en Android) sobre el
mismo núcleo en Rust que usa el escritorio: bóveda, cifrado, SSH, sincronización, Teams y
Vaultwarden. Así hay una sola implementación del formato de la bóveda y del protocolo con el
servidor, y lo que se guarda en un equipo se abre igual en los demás.

La primera versión móvil es un **cliente sincronizado**: se inicia sesión en la cuenta, llegan
los hosts, las identidades y los Teams, y se abren terminales SSH. Editar desde el móvil llega
después.

- **9a. Núcleo compartido:** crate `tunel-mobile` que expone el núcleo a Swift y Kotlin con
  UniFFI, y un script que lo empaqueta como XCFramework para iOS. Las llaves FIDO2 por USB no
  se ofrecen en móvil (no hay acceso a USB HID).
- **9b. App de iOS y iPadOS:** proyecto en `apps/ios`. Crear o desbloquear la bóveda y ver
  hosts y grupos, con búsqueda; en iPad, con barra lateral. Se bloquea al salir de la app.
- **9c. Cuenta y sincronización:** unir el dispositivo a la cuenta con correo y contraseña o
  con Google o Microsoft (con el navegador del sistema, `ASWebAuthenticationSession`), y
  descargar la bóveda y los Teams al desbloquear o al deslizar hacia abajo. El móvil no
  crea cuentas (lo que cambia en él sube con la sincronización, ver 9g), y al salir de la cuenta borra lo descargado. El
  servidor acepta `redirect=tunel://oauth` en lugar de un puerto local para volver a la app
  (necesita la versión nueva del servidor). Las invitaciones a Teams se aceptan desde el
  escritorio.
- **9d. Terminal SSH:** la conexión, la autenticación (clave, contraseña, keyboard-interactive)
  y los jump hosts son los de `tunel-ssh`; la pantalla es SwiftTerm (MIT), con su barra sobre
  el teclado (Esc, Ctrl, Tab y flechas). Una clave de servidor nueva o cambiada se pregunta y,
  si se acepta, se guarda en la bóveda y se sincroniza como en el escritorio. iOS corta las
  conexiones poco después de pasar la app a segundo plano: al volver se reconecta. Para no
  perder la terminal al copiar algo de otra app, la bóveda ya no se bloquea al salir sino al
  volver tras más de 3 minutos fuera; mientras tanto, el selector de apps muestra una
  cubierta en lugar de la pantalla. Los hosts Mosh se abren por SSH; Telnet y serie, aún no.
  Sin llaves FIDO2, reenvío de agente, X11 ni túneles en esta entrega.
- **9e. Face ID o Touch ID:** el mismo archivo `<bóveda>.biometria` del escritorio guarda la
  clave de la bóveda sellada; la clave que abre ese sello la genera el núcleo y la app la
  guarda en el llavero de iOS con `biometryCurrentSet`, solo en este dispositivo y sin copia
  de seguridad. Si cambian las caras o huellas registradas, iOS la invalida y hay que entrar
  con la contraseña y volver a activarlo. La primera vez de cada día se pide la contraseña
  maestra, como en el escritorio. Se activa en Ajustes (pide la cara una vez para
  comprobarlo); al volver tras el bloqueo por tiempo, Face ID se pide solo.
- **9g. Editar hosts:** crear, editar y borrar hosts personales: nombre, dirección,
  puerto, protocolo (SSH, Mosh o Telnet), grupo, credencial (una identidad existente o una
  nueva con usuario y contraseña), jump hosts en orden, etiquetas y notas. Lo que el móvil
  no muestra (variables de entorno, proxy, script de inicio, reenvíos) se conserva al
  editar. Los hosts de un Team se editan desde el escritorio, donde están los permisos y el
  registro de auditoría. Cada cambio guardado en el móvil, también una clave de servidor
  aceptada en la terminal, queda en la cola de sincronización y sube enseguida.
- **9f. Android:** el mismo núcleo compilado con `cargo-ndk`, interfaz en Compose y desbloqueo
  con huella (BiometricPrompt y Android Keystore). Necesita Android Studio en el equipo de
  compilación. Va en cinco entregas, en el mismo orden que iOS:
  - **9f1:** el proyecto en `apps/android` (Gradle, Kotlin, Compose, Android 10 o más nuevo),
    `scripts/compilar-android.sh` para el núcleo y los enlaces de Kotlin, crear o desbloquear la
    bóveda y la lista de hosts con grupos en un cajón lateral (fijo en tabletas) y búsqueda. Se
    bloquea al salir de la app, el selector de apps no muestra su contenido y la bóveda queda
    fuera de las copias de seguridad de Android. Las pruebas de Kotlin corren contra el núcleo
    de verdad, compilado para el Mac.
  - **9f2:** unirse a la cuenta de Túnel con correo y contraseña o con un proveedor (Google,
    Microsoft) en una pestaña del navegador que vuelve con `tunel://oauth`, y descargar lo
    sincronizado al abrir la bóveda o deslizando la lista hacia abajo. HTTPS comprueba los
    certificados con el almacén de Android (`rustls-platform-verifier`, iniciado por JNI). Como
    en iOS, se bloquea tras 3 minutos fuera de la app, no al instante: si no, ir al navegador
    del proveedor la cerraba. Las pruebas de Kotlin usan un servidor de Túnel en memoria.
  - **9f3:** la terminal SSH con la terminal de ConnectBot (`termlib`, libvterm, para
    Compose) y una barra con Esc, Ctrl, Tab y flechas. La conexión, la pregunta por la clave
    del servidor y el inicio de sesión interactivo son los del núcleo, como en iOS. La sesión
    sobrevive a los giros de pantalla y se cierra al bloquear la bóveda; si se cortó con la
    app en segundo plano, se reconecta al volver. Las pruebas usan un servidor SSH de juguete
    (`ssh-de-pruebas`).
  - **9f4:** desbloqueo con huella. La clave que abre la bóveda (la misma del escritorio y
    de iOS, `<bóveda>.biometria`) se guarda cifrada con una clave AES del almacén de Android
    que solo se usa tras una huella (biometría fuerte), deja de servir si cambian las huellas
    y exige el teléfono desbloqueado. Se activa en Ajustes; la primera vez de cada día se
    entra con la contraseña, y tras estar fuera de la app se pide la huella sola.
  - **9f5:** crear, editar y borrar hosts de la bóveda personal, como en iOS (los de un Team,
    desde el escritorio): nombre, dirección, puerto, protocolo, credencial existente o nueva,
    grupo, saltos en orden, etiquetas y notas. El formulario sobrevive a los giros y se
    descarta al bloquear; los cambios suben a la cuenta enseguida.

Para instalar en un iPhone propio basta una cuenta de Apple gratuita (la firma caduca a los 7
días). TestFlight y la App Store necesitan la cuenta de Apple Developer de la entrega 2b.
Túnel es GPL-3.0: si alguna vez se publica en la App Store, hay que revisar antes la
compatibilidad de la licencia con sus condiciones.

## Pendiente de fases anteriores

| Función | Estado |
|---|---|
| Llaves FIDO2 en Windows | ✅ |
| Cliente Mosh propio | más adelante |
| Borrar de la memoria las copias temporales de la bóveda en la interfaz | ✅ |
| Permisos propios del archivo de la bóveda en Windows | ✅ |
| Pruebas automáticas de SFTP real, Mosh, Telnet y puerto serie | ✅ |
| Pruebas automáticas de la interfaz | ✅ |

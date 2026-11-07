# Integración con Vaultwarden

Estado: en desarrollo (bloque 8 de la [hoja de ruta](hoja-de-ruta.md)).

## Objetivo

Que una empresa guarde en [Vaultwarden](https://github.com/dani-garcia/vaultwarden) las
credenciales de sus servidores, switches y APs, y que sus ingenieros las usen desde Túnel para
conectarse, sin copiarlas a mano y sin que haya dos copias que se desincronizan.

Vaultwarden habla el mismo protocolo que Bitwarden, así que lo mismo debería servir con Bitwarden
autoalojado o en la nube. Solo se prueba contra Vaultwarden.

## Principio: Túnel funciona igual sin Vaultwarden

La integración es opcional y nada de Túnel depende de ella:

- **Desactivada por defecto.** Sin una cuenta de Vaultwarden configurada no hay llamadas de
  red, ni menús nuevos, ni cambios en el arranque.
- **Código aparte.** Todo el protocolo va en el crate `tunel-vaultwarden`. `tunel-core` solo sabe
  que una identidad puede tener su secreto en una fuente externa; la app completa la credencial
  después de `VaultData::resolve`, y sin integración ese paso no hace nada.
- **La bóveda de Túnel no cambia de formato.** Una identidad vinculada solo añade una
  referencia opcional al elemento de Vaultwarden.
- **Si Vaultwarden falla, Túnel sigue** (ver [Fallos](#fallos)).
- **Se puede salir sin perder nada:** al desconectar la cuenta se borran la sesión y la copia
  de los secretos de este equipo; las identidades siguen vinculadas y piden la contraseña al
  conectar hasta que se vuelva a conectar. Convertirlas en copias locales queda para después.
- **Las pruebas cubren los dos casos.** Toda la batería pasa sin Vaultwarden; las pruebas contra
  un servidor real se saltan si no está configurado.

## Decisiones

| Pregunta | Decisión | Por qué |
|---|---|---|
| ¿Quién inicia sesión? | Cada ingeniero con su propia cuenta de Vaultwarden. | Los permisos por colección y el registro de accesos quedan por persona; al dar de baja a alguien en Vaultwarden pierde el acceso en Túnel. |
| ¿Dónde viven los hosts? | En Túnel. Vaultwarden guarda las credenciales. | Túnel tiene datos que Vaultwarden no modela (saltos, túneles, temas, snippets). Importar hosts desde las colecciones llega después (8d). |
| ¿Y los Teams de Túnel? | Conviven: Vaultwarden para credenciales; los Teams para hosts, auditoría y grabaciones. | Una identidad de un Team puede apuntar a un elemento de una organización: cada miembro lo descifra con su propia cuenta, y quien no tiene acceso a esa colección no lo ve. |
| ¿Bitwarden Secrets Manager? | No. | No existe en Vaultwarden. Se usan las cuentas normales. |

## Cómo habla Túnel con Vaultwarden

Túnel es un cliente más, como la extensión del navegador. El cifrado es de extremo a extremo:
el servidor nunca ve las contraseñas.

1. **Parámetros de derivación:** `POST /identity/accounts/prelogin` con el correo devuelve
   PBKDF2-SHA256 (iteraciones) o Argon2id (iteraciones, memoria en MiB, paralelismo).
2. **Clave maestra:** PBKDF2 con el correo en minúsculas como sal, o Argon2id con el SHA-256 del
   correo como sal; 32 bytes.
3. **Hash para el servidor:** PBKDF2-SHA256 de la clave maestra con la contraseña como sal y una
   iteración. Es lo único derivado de la contraseña que sale del equipo.
4. **Token:** `POST /identity/connect/token` (`grant_type=password`, `client_id=desktop`,
   `scope=api offline_access` y un identificador de dispositivo fijo por equipo). Si la cuenta
   tiene segundo factor, el servidor responde 400 con la lista de proveedores y se repite con
   `twoFactorToken` y `twoFactorProvider`. Se admiten aplicación TOTP (0) y correo (1).
5. **Clave de usuario:** la respuesta trae `Key`, la clave de usuario cifrada con la clave
   maestra estirada (HKDF-Expand con `enc` y `mac`). Son 64 bytes: 32 para AES-256-CBC y 32 para
   HMAC-SHA256.
6. **Sincronización:** `GET /api/sync` devuelve el perfil (clave privada RSA cifrada con la clave
   de usuario y las claves de cada organización cifradas con RSA-OAEP), las colecciones y los
   elementos. Hace falta la cabecera `Bitwarden-Client-Version` con una versión reciente para que
   Vaultwarden incluya los elementos de tipo *SSH Key*.
7. **Descifrado:** cada campo es un *EncString*. Se admiten el tipo 2 (AES-256-CBC + HMAC-SHA256,
   se comprueba el MAC antes de descifrar) y los tipos 3, 4 y 6 (RSA-OAEP) para las claves de
   organización. Un elemento puede traer su propia clave (`key`), cifrada con la del usuario o la
   de la organización. Un tipo desconocido es un error explícito, no un elemento vacío.
8. **Crear elementos (8c):** `POST /api/ciphers` en la bóveda personal o
   `POST /api/ciphers/create` con `collectionIds` en una organización, con todos los campos
   cifrados en el equipo. Hay que mandar `encryptedFor` con el id del usuario (`profile.id`
   de la sincronización): desde web-v2025.6.0 Vaultwarden responde 422 si falta.

Detalles de Vaultwarden comprobados contra un servidor real:

- Una contraseña incorrecta llega como 400 con `"error": ""`, no `invalid_grant`. Cualquier 400
  del inicio de sesión es un rechazo.
- Limita los inicios de sesión (unos 10 por minuto) y responde 429: Túnel lo muestra como
  «demasiados intentos».
- La política «Quitar la bóveda individual» (tipo 5) llega en `policies`. Con ella activa el
  servidor rechaza crear elementos personales; Túnel solo ofrecerá colecciones (8c).
- Un miembro con rol *Usuario* solo recibe las colecciones que tiene asignadas directamente, o
  por grupo si el servidor tiene `ORG_GROUPS_ENABLED`.

El token de acceso dura poco y se renueva con el de refresco. Si el refresco falla, se pide
otra vez la contraseña maestra de Vaultwarden.

## Cómo se usa una credencial (8b)

- En **Ajustes → Vaultwarden** se conecta la cuenta (servidor, correo, contraseña maestra y, si
  la cuenta lo tiene, el código del segundo factor). Se sincroniza al desbloquear, cada 30
  minutos y con «Sincronizar ahora».
- En el editor de una identidad aparece **Credencial: Guardada en Túnel / En Vaultwarden** solo
  si hay cuenta conectada o la identidad ya está vinculada. Al elegir Vaultwarden se borra la
  contraseña local y se busca el elemento por nombre, usuario o colección.
- Una identidad de un Team solo puede vincular elementos de una organización: los personales no
  los podría descifrar ningún otro miembro.
- Al conectar se usa la contraseña o la clave SSH del elemento. El usuario es el de la
  identidad; si está vacío, el del elemento. Todo pasa por el mismo punto (`Engine::resolve`),
  así que vale igual para saltos, SFTP, túneles y contenedores.

## Correspondencia de datos

| En Vaultwarden | En Túnel |
|---|---|
| Elemento *Login*: usuario y contraseña | Secreto de una `Identity` |
| URI `ssh://host:22`, `telnet://host`, `mosh://host` | Dirección, puerto y protocolo (8d) |
| Elemento *SSH Key* | `SshKey` de la identidad |
| Campo personalizado `enable` (oculto) | Contraseña *enable* de switches (8d) |
| Colección | Grupo al importar (8d) |
| Notas | Notas del host (8d) |

Al mover una credencial de Túnel a Vaultwarden (8c) se usan las mismas convenciones, así que el
elemento se ve bien también en la web y en las extensiones de Vaultwarden.

## Qué guarda Túnel

| Dato | Dónde | ¿Se sincroniza? |
|---|---|---|
| Vínculo de una identidad (id del elemento y de la organización) | Campo opcional en `Identity`, en la bóveda | Sí, como el resto de la identidad |
| Servidor, correo e identificador de dispositivo | `<bóveda>.vaultwarden`, cifrado con la clave de la bóveda | No |
| Token de refresco y clave de usuario descifrada | `<bóveda>.vaultwarden` | No |
| Copia de los secretos usados, con fecha | `<bóveda>.vaultwarden` | No |

- Los secretos nunca entran en la bóveda: si lo hicieran, una identidad de un Team llevaría la
  contraseña a todos sus miembros, también a los que Vaultwarden no les da acceso.
- El vínculo es un campo y no un tipo de registro nuevo para que las versiones anteriores de
  Túnel no fallen al sincronizar. Límite conocido: una versión anterior que edite esa identidad
  la guarda sin el vínculo.
- Con la clave de usuario guardada, al desbloquear Túnel no hace falta volver a escribir la
  contraseña de Vaultwarden. Elegir pedirla cada vez queda para más adelante.
- La copia de los secretos caduca a los 7 días, y antes si la sincronización dice que el
  elemento cambió, se borró o ya no es accesible.

## Fallos

| Situación | Qué pasa |
|---|---|
| Servidor caído, sin red o sesión caducada | Los hosts con credenciales locales funcionan igual. Los vinculados usan la copia local si no ha caducado; si no, piden la contraseña al conectar. |
| Elemento borrado o acceso retirado | Aviso «credencial no disponible en Vaultwarden» y se pide la contraseña. |
| Formato de cifrado que Túnel no conoce | Aviso con el motivo; nunca se usa un valor vacío. |
| Sincronización lenta | En segundo plano y con tiempo límite; nunca bloquea el arranque ni una pestaña. |

## Seguridad

- Solo HTTPS, salvo `localhost` o la red local, como el servidor de sincronización de Túnel. Sin
  seguir redirecciones.
- Los MAC se comprueban antes de descifrar y en tiempo constante.
- Las claves y secretos descifrados se borran de la memoria al soltarlos (`zeroize`).
- Los errores que se muestran no incluyen la dirección del servidor ni datos del elemento.
- «Ocultar contraseñas» de una colección (8b): Túnel usa la credencial para conectar pero no la
  muestra. **No es una barrera real**: el equipo tiene que descifrarla para usarla. Para personal
  externo, la medida correcta es rotar la contraseña después o usar certificados SSH de corta
  duración.
- El vínculo de una identidad viene de la bóveda, y en un Team lo puede editar cualquier
  miembro con permiso de escritura. Por eso Túnel solo usa el secreto si es de la organización
  que dice el vínculo y, en un Team, nunca uno personal de quien conecta. Copiar una identidad a
  un Team quita su vínculo si es personal. **Límite:** quien puede editar las identidades y hosts
  de un Team decide qué credencial de la organización mandan sus miembros y a qué dirección; da
  permiso de escritura solo a quien confiarías esas credenciales.
- Solo se descifran para conectar los elementos vinculados, y la copia caduca a los 7 días
  contados desde la sincronización, aunque la app siga abierta.
- Vaultwarden registra los accesos a cada elemento; Túnel registra en el Team quién se conectó a
  qué host. Juntos dan la trazabilidad completa.

## Entregas

| # | Entrega | Estado |
|---|---|---|
| 8a | Crate `tunel-vaultwarden`: inicio de sesión con segundo factor, sincronización, descifrado y creación de elementos, con pruebas contra un servidor real | hecho |
| 8b | **Ajustes → Vaultwarden** y credenciales de Vaultwarden en las identidades, con copia local y avisos | hecho |
| 8c | «Mover a Vaultwarden» desde una identidad, a la bóveda personal o a una colección | pendiente |
| 8d | Hosts desde las colecciones (URI, puerto, protocolo y `enable`) | pendiente |
| 8e | Editar y rotar credenciales desde Túnel | más adelante |

## Pruebas

- **Unitarias:** derivación de claves, EncString (cifrar, descifrar, MAC alterado, tipos
  desconocidos), RSA-OAEP y descifrado de una respuesta de `/api/sync` de ejemplo.
- **Contra un servidor real:** se saltan si no está `TUNEL_VW_URL`. Con `TUNEL_VW_URL`,
  `TUNEL_VW_EMAIL` y `TUNEL_VW_PASSWORD` de una cuenta de prueba sin segundo factor: iniciar
  sesión, crear un elemento, sincronizar, comprobar que se lee igual y borrarlo. No se usan
  cuentas ni credenciales reales.
- **Sin Vaultwarden (8b):** un host con credencial local conecta con el servidor caído.

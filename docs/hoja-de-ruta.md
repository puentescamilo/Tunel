# Hoja de ruta de Túnel

Actualizada el 2 de noviembre de 2026, con Túnel 0.10.1.

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
| 7a | Desbloquear la bóveda con Touch ID o Windows Hello | 0.11.0 | en curso |
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
  de la firma de una clave de Windows Hello, así que no hay nada secreto en el disco. Se
  desactiva al cambiar la contraseña maestra. En Linux no hay un mecanismo común, así que no
  se ofrece.

## Pendiente de fases anteriores

| Función | Estado |
|---|---|
| Autocompletado de comandos | fase 2 |
| Llaves FIDO2 en Windows | pendiente |
| Cliente Mosh propio | más adelante |
| Borrar de la memoria las copias temporales de la bóveda en la interfaz | seguridad |
| Permisos propios del archivo de la bóveda en Windows | seguridad |
| Pruebas automáticas de SFTP real, Mosh, Telnet, puerto serie e interfaz | pruebas |

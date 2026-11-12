# Túnel para iPhone y iPad

La interfaz es SwiftUI; el núcleo (bóveda, cifrado, y más adelante SSH y sincronización) es
el mismo crate de Rust que usa el escritorio, expuesto con UniFFI desde `crates/tunel-mobile`.
El plan está en el bloque 9 de [la hoja de ruta](../../docs/hoja-de-ruta.md).

## Compilar el núcleo

```bash
scripts/compilar-ios.sh           # release
scripts/compilar-ios.sh --debug   # más rápido mientras se desarrolla
```

Deja en `TunelCore/` el `TunelCoreFFI.xcframework` (iPhone, simulador y Mac) y el código Swift
generado en `Sources/TunelCore/tunel_mobile.swift`. Los dos se generan: no se editan ni se
guardan en git. Hay que volver a ejecutarlo cada vez que cambia `crates/tunel-mobile`.

## Pruebas

```bash
cd apps/ios/TunelCore && swift test
```

Corren en el Mac contra el núcleo real, compilado para macOS dentro del mismo XCFramework.

## Instalar en un iPhone o iPad propio

Basta una cuenta de Apple gratuita en Xcode (Ajustes → Cuentas). La firma caduca a los 7
días: pasado ese tiempo hay que volver a instalar desde Xcode. TestFlight necesita la cuenta
de Apple Developer.

1. Crea `Config/Local.xcconfig` con tu Team (el código de 10 caracteres de Xcode → Ajustes →
   Cuentas) y un identificador propio; con la cuenta gratuita tiene que ser único:

   ```
   DEVELOPMENT_TEAM = ABCDE12345
   PRODUCT_BUNDLE_IDENTIFIER = dev.tunel.ios.abcde12345
   ```

2. Compila el núcleo (`scripts/compilar-ios.sh`), abre `Tunel.xcodeproj`, conecta el iPhone o
   iPad por cable, elígelo arriba como destino y pulsa ▶.
3. La primera vez, en el dispositivo: Ajustes → General → VPN y gestión de dispositivos →
   confía en tu cuenta de desarrollador. Y activa Ajustes → Privacidad y seguridad → Modo
   desarrollador, que pide reiniciar.

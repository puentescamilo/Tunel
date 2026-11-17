# Reglas de R8 para la compilación release. R8 quita y renombra lo que no ve usado desde
# Kotlin; lo que se busca por nombre desde código nativo o por reflexión hay que conservarlo.

# Los fallos de una versión publicada se leen con el mapping.txt que guarda
# scripts/empaquetar-android.sh: hacen falta el archivo y la línea de cada llamada.
-keepattributes SourceFile,LineNumberTable

# UniFFI: el Kotlin generado llama al núcleo de Rust con JNA, que lee las estructuras
# (RustBuffer…) y las devoluciones de llamada por reflexión.
-keep class uniffi.tunel_mobile.** { *; }
-keep class com.sun.jna.** { *; }
-dontwarn java.awt.**

# rustls-platform-verifier: el núcleo comprueba los certificados de HTTPS llamando por JNI a
# estas clases (así lo pide su documentación).
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }

# La terminal de ConnectBot: libvterm llama por JNI a sus clases. Su .aar solo conserva la
# parte pública; se conserva entera, que es pequeña, para no depender de qué lee el C.
-keep class org.connectbot.terminal.** { *; }

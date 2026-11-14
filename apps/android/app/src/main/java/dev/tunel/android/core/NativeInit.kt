package dev.tunel.android.core

import android.content.Context

/** Prepara el núcleo para Android: carga la biblioteca y le entrega el contexto de la app. */
object NativeInit {
    private var done = false

    /**
     * Con el contexto, HTTPS comprueba los certificados con el almacén del sistema. Hay que
     * llamarla antes de cualquier conexión; las siguientes veces no hace nada.
     */
    @Synchronized
    fun start(context: Context) {
        if (done) return
        // UniFFI llega al núcleo por JNA, pero esta función es JNI: la biblioteca se carga
        // también por el camino de Java para que la encuentre.
        System.loadLibrary("tunel_mobile")
        init(context.applicationContext)
        done = true
    }

    @JvmStatic
    private external fun init(context: Context)
}

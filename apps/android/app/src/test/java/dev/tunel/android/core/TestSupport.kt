package dev.tunel.android.core

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlin.coroutines.CoroutineContext

/** Retiene el trabajo del núcleo hasta que la prueba lo suelta. */
class GatedDispatcher : CoroutineDispatcher() {
    private val queue = ArrayDeque<Runnable>()

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        queue.addLast(block)
    }

    fun runAll() {
        while (queue.isNotEmpty()) queue.removeFirst().run()
    }
}

/** Alterna el trabajo del núcleo y el de la prueba hasta que `job` acaba. */
fun TestScope.finish(job: Job, worker: GatedDispatcher) {
    while (job.isActive) {
        worker.runAll()
        runCurrent()
    }
}

/**
 * Un servidor de Túnel en memoria con una cuenta que ya tiene `hosts`, compilado por
 * scripts/compilar-android.sh. Se apaga al cerrarlo.
 */
class TestServer(vararg hosts: String) : AutoCloseable {
    private val process: Process = ProcessBuilder(
        System.getProperty("tunel.servidorDePruebas"),
        EMAIL,
        PASSWORD,
        *hosts,
    ).redirectError(ProcessBuilder.Redirect.INHERIT).start()

    val url: String = process.inputStream.bufferedReader().readLine()
        ?: error("El servidor de pruebas no arrancó")

    override fun close() {
        process.outputStream.close()
        process.destroy()
        process.waitFor()
    }

    companion object {
        const val EMAIL = "ana@ejemplo.com"
        const val PASSWORD = "contraseña-de-la-cuenta"
    }
}

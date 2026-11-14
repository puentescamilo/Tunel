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

/**
 * Un servidor SSH de juguete (`ssh-de-pruebas`): saluda con «bienvenida», devuelve en
 * mayúsculas lo que recibe y con `exit` termina. Se apaga al cerrarlo.
 */
class TestSshServer : AutoCloseable {
    private val process: Process = ProcessBuilder(
        System.getProperty("tunel.sshDePruebas"),
        USER,
        PASSWORD,
    ).redirectError(ProcessBuilder.Redirect.INHERIT).start()

    val port: Int = process.inputStream.bufferedReader().readLine()?.toInt()
        ?: error("El servidor SSH de pruebas no arrancó")

    override fun close() {
        process.outputStream.close()
        process.destroy()
        process.waitFor()
    }

    companion object {
        const val USER = "ana"
        const val PASSWORD = "contraseña-correcta"
    }
}

/**
 * Hace de hilo principal: guarda lo que el núcleo manda a la interfaz y lo ejecuta en el
 * hilo de la prueba cuando esta espera algo.
 */
class MainQueue : java.util.concurrent.Executor {
    private val queue = java.util.concurrent.LinkedBlockingQueue<Runnable>()

    override fun execute(command: Runnable) {
        queue.put(command)
    }

    /** Ejecuta lo que llegue hasta que `done` se cumpla; falla si tarda demasiado. */
    fun runUntil(timeoutMs: Long = 15_000, done: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!done()) {
            val left = deadline - System.currentTimeMillis()
            check(left > 0) { "No llegó a tiempo" }
            queue.poll(left, java.util.concurrent.TimeUnit.MILLISECONDS)?.run()
        }
    }
}

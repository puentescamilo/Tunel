package dev.tunel.android

import android.app.Application
import dev.tunel.android.core.NativeInit

class TunelApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NativeInit.start(this)
    }
}

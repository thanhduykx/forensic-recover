package com.forensic.recover.bridge

/**
 * JNI bridge to Rust `recover-core` (compiled via `cargo-ndk` into `librecover_jni.so`).
 * All panics in Rust are caught at the FFI boundary and returned as structured JSON `{ ok, data, error }`.
 */
object NativeRecoveryBridge {
    @Volatile
    var isNativeLoaded: Boolean = false
        private set

    init {
        try {
            System.loadLibrary("recover_jni")
            isNativeLoaded = true
        } catch (_: UnsatisfiedLinkError) {
            isNativeLoaded = false
        }
    }

    external fun nativeAbiVersion(): Int
    external fun nativeInspectSource(source: String): String
    external fun nativeRunScan(configJson: String): String
    external fun nativeCancelScan(sessionKey: String): Boolean
    external fun nativeExportItems(source: String, outDir: String, idsJson: String): String
}

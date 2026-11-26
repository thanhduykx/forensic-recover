import Foundation
#if canImport(Darwin)
import Darwin
#endif

public struct JailbreakProbeResult {
    public let isJailbroken: Bool
    public let blockDeviceReadable: Bool
    public let devicePath: String
    public let advisoryNote: String
}

/// Jailbreak raw-device helper:
/// - Strictly opens `/dev/rdisk0s1s2` (or `/dev/disk0s1s2`) with `O_RDONLY` — NEVER `O_RDWR`/`O_WRONLY`.
/// - Streams chunks to an external USB-C drive for offline Desktop carving so zero writes occur on internal flash.
/// - Discloses Apple SEP per-file encryption reality honestly.
public final class JailbreakRawReader {
    public static let defaultDataPartition = "/dev/rdisk0s1s2"

    public static func probeEnvironment() -> JailbreakProbeResult {
        let jbMarkers = ["/var/jb", "/Applications/Cydia.app", "/Applications/Sileo.app", "/usr/bin/dpkg"]
        let isJb = jbMarkers.contains { FileManager.default.fileExists(atPath: $0) }

        #if canImport(Darwin)
        let fd = open(defaultDataPartition, O_RDONLY)
        let readable = fd >= 0
        if fd >= 0 { close(fd) }
        #else
        let readable = false
        #endif

        let note = readable
            ? "Block device opened O_RDONLY. Note: iOS 15+ APFS uses SEP per-file keys; permanently deleted user files without keys remain encrypted ciphertext."
            : "Raw block device inaccessible (non-jailbroken or missing root/entitlement). Use Desktop USB Companion (`idevicebackup2`) instead."

        return JailbreakProbeResult(
            isJailbroken: isJb,
            blockDeviceReadable: readable,
            devicePath: defaultDataPartition,
            advisoryNote: note
        )
    }

    /// Streams `maxBytes` strictly read-only from `blockPath` into an external destination image URL.
    public static func streamReadOnlyImage(
        blockPath: String = defaultDataPartition,
        destinationImageURL: URL,
        chunkSize: Int = 1024 * 1024,
        maxBytes: UInt64
    ) throws -> UInt64 {
        #if canImport(Darwin)
        let srcFd = open(blockPath, O_RDONLY)
        guard srcFd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(srcFd) }

        FileManager.default.createFile(atPath: destinationImageURL.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: destinationImageURL)
        defer { try? outHandle.close() }

        var buffer = [UInt8](repeating: 0, count: chunkSize)
        var totalWritten: UInt64 = 0
        while totalWritten < maxBytes {
            let toRead = Int(min(UInt64(chunkSize), maxBytes - totalWritten))
            let n = read(srcFd, &buffer, toRead)
            if n <= 0 { break }
            try outHandle.write(contentsOf: buffer[0..<n])
            totalWritten += UInt64(n)
        }
        return totalWritten
        #else
        throw NSError(domain: "ForensicRecoverIOS", code: -1)
        #endif
    }
}

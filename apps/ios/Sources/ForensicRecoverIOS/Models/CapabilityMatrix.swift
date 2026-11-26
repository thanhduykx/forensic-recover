import Foundation

public enum IosRecoveryMode: String, CaseIterable, Identifiable {
    case sideloadSandbox = "Sideload IPA (Non-Jailbreak)"
    case desktopUsbCompanion = "Desktop USB Companion (idevicebackup2)"
    case jailbreakRaw = "Jailbreak Raw Block (/dev/rdisk0s1s2)"

    public var id: String { rawValue }
}

public struct CapabilityEntry: Identifiable {
    public let id = UUID()
    public let feature: String
    public let sideloadSandbox: String
    public let desktopCompanion: String
    public let jailbreakRaw: String
}

/// Explicit iOS Capability Matrix reflecting iOS sandbox & Apple SEP hardware FBE boundaries.
public enum IosCapabilityMatrix {
    public static let entries: [CapabilityEntry] = [
        CapabilityEntry(
            feature: "Block Device Read (/dev/rdisk0s1s2)",
            sideloadSandbox: "Không (Sandbox chặn)",
            desktopCompanion: "Không (qua Backup API)",
            jailbreakRaw: "Có (root O_RDONLY stream ra USB)"
        ),
        CapabilityEntry(
            feature: "Photos.sqlite & ZTRASHEDSTATE",
            sideloadSandbox: "Qua PhotoKit API (Recently Deleted nếu được cấp quyền)",
            desktopCompanion: "Có (parse trực tiếp từ backup cục bộ)",
            jailbreakRaw: "Có (read-only copy từ /var/mobile/Media/PhotoData)"
        ),
        CapabilityEntry(
            feature: "App Group / URLCache / .ithmb Carving",
            sideloadSandbox: "Chỉ container của app & App Group được chia sẻ",
            desktopCompanion: "Có (carve .ithmb & AppDomainGroup trong backup)",
            jailbreakRaw: "Có (toàn bộ vùng được cấp key)"
        ),
        CapabilityEntry(
            feature: "File đã xóa vĩnh viễn trên APFS (SEP Per-File Key)",
            sideloadSandbox: "Không thể giải mã",
            desktopCompanion: "Chỉ cứu được nếu còn trong bản backup cũ / .ithmb",
            jailbreakRaw: "Giới hạn bởi Apple SEP: nếu per-file key đã xóa, sector là ciphertext"
        )
    ]
}

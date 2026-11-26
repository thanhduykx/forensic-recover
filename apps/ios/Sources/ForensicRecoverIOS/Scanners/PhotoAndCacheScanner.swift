import Foundation
#if canImport(Photos)
import Photos
#endif

public struct IosRecoveredCandidate: Identifiable {
    public let id: String
    public let title: String
    public let origin: String
    public let ext: String
    public let sizeBytes: Int
    public let confidence: String
    public let previewData: Data?
}

/// Scans iOS sandboxed surfaces strictly read-only:
/// - PhotoKit assets & metadata
/// - Shared App Group containers (`group.com.forensic.recover`)
/// - URLCache & `.ithmb` thumbnail blobs via magic-byte header validation
public final class PhotoAndCacheScanner {
    public init() {}

    public func scanSandboxedCaches(appGroupIdentifier: String? = nil) -> [IosRecoveredCandidate] {
        var found: [IosRecoveredCandidate] = []
        var roots: [URL] = []

        if let cacheDir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first {
            roots.append(cacheDir)
        }
        if let groupId = appGroupIdentifier,
           let groupURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupId) {
            roots.append(groupURL)
        }

        for root in roots {
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]
            ) else { continue }

            for case let fileURL as URL in enumerator {
                guard let vals = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
                      vals.isRegularFile == true,
                      let size = vals.fileSize, size >= 64, size <= 32 * 1024 * 1024 else {
                    continue
                }
                if fileURL.pathExtension.lowercased() == "ithmb" {
                    if let data = try? Data(contentsOf: fileURL, options: .mappedIfSafe) {
                        found.append(contentsOf: carveEmbeddedThumbnails(data: data, origin: fileURL.lastPathComponent))
                    }
                    continue
                }
                guard let fh = try? FileHandle(forReadingFrom: fileURL) else { continue }
                let head = fh.readData(ofLength: 16)
                try? fh.close()
                if let ext = detectMagic(head) {
                    let preview = (ext == "jpg" || ext == "png") ? (try? Data(contentsOf: fileURL)) : nil
                    found.append(IosRecoveredCandidate(
                        id: UUID().uuidString,
                        title: fileURL.lastPathComponent,
                        origin: "Sandbox/URLCache",
                        ext: ext,
                        sizeBytes: size,
                        confidence: "medium",
                        previewData: preview
                    ))
                }
            }
        }
        return found
    }

    #if canImport(Photos)
    public func requestPhotoLibrarySummary(completion: @escaping (Int) -> Void) {
        PHPhotoLibrary.requestAuthorization(for: .readWrite) { status in
            guard status == .authorized || status == .limited else {
                completion(0)
                return
            }
            let opts = PHFetchOptions()
            opts.includeHiddenAssets = true
            let assets = PHAsset.fetchAssets(with: opts)
            completion(assets.count)
        }
    }
    #endif

    private func carveEmbeddedThumbnails(data: Data, origin: String) -> [IosRecoveredCandidate] {
        var hits: [IosRecoveredCandidate] = []
        let soi: [UInt8] = [0xFF, 0xD8, 0xFF]
        let eoi: [UInt8] = [0xFF, 0xD9]
        let bytes = [UInt8](data)
        var i = 0
        while i + 128 < bytes.count {
            if bytes[i] == soi[0] && bytes[i + 1] == soi[1] && bytes[i + 2] == soi[2] {
                var j = i + 3
                var foundEnd: Int? = nil
                while j + 1 < min(bytes.count, i + 2_000_000) {
                    if bytes[j] == eoi[0] && bytes[j + 1] == eoi[1] {
                        foundEnd = j + 2
                        break
                    }
                    j += 1
                }
                if let end = foundEnd {
                    let slice = Data(bytes[i..<end])
                    hits.append(IosRecoveredCandidate(
                        id: UUID().uuidString,
                        title: "\(origin)@0x\(String(i, radix: 16))",
                        origin: ".ithmb Cache",
                        ext: "jpg",
                        sizeBytes: slice.count,
                        confidence: "medium",
                        previewData: slice
                    ))
                    i = end
                    continue
                }
            }
            i += 1
        }
        return hits
    }

    private func detectMagic(_ data: Data) -> String? {
        let b = [UInt8](data)
        if b.count >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF { return "jpg" }
        if b.count >= 8 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47 { return "png" }
        if b.count >= 12 && String(bytes: b[4..<8], encoding: .ascii) == "ftyp" { return "mp4" }
        if b.count >= 5 && String(bytes: b[0..<5], encoding: .ascii) == "%PDF-" { return "pdf" }
        return nil
    }
}

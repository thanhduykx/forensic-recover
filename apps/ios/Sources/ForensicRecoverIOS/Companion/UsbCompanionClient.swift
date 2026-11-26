import Foundation

/// Connects over USB/local loopback IPC to the Desktop Companion (`recover ui` / `recover ios-backup`),
/// which uses `libimobiledevice` + `idevicebackup2` and pure-Rust SQLite B-Tree parsing
/// (`Manifest.db`, `Photos.sqlite`) without sending data to any cloud service.
public final class UsbCompanionClient {
    private let baseURL: URL

    public init(baseURL: URL = URL(string: "http://127.0.0.1:1420")!) {
        self.baseURL = baseURL
    }

    public func checkDesktopBridge() async throws -> Bool {
        let url = baseURL.appendingPathComponent("/api/health")
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            return false
        }
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return (json?["offline"] as? Bool) == true
    }

    public func triggerBackupScan(backupDir: String, outDir: String) async throws -> Int {
        let url = baseURL.appendingPathComponent("/api/ios-backup")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "backup_dir": backupDir,
            "out_dir": outDir,
            "export_all": false
        ])
        let (data, _) = try await URLSession.shared.data(for: req)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return json?["items_count"] as? Int ?? 0
    }
}

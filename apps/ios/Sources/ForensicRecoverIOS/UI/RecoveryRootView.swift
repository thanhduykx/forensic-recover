#if canImport(SwiftUI)
import SwiftUI

public struct RecoveryRootView: View {
    @State private var step: Int = 1
    @State private var mode: IosRecoveryMode = .sideloadSandbox
    @State private var candidates: [IosRecoveredCandidate] = []
    @State private var selectedConfidence: String = "all"
    @State private var previewCandidate: IosRecoveredCandidate?
    @State private var jbProbe = JailbreakRawReader.probeEnvironment()

    public init() {}

    public var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 12) {
                // Mandatory TRIM + SEP honesty warning
                Text("Cảnh báo Flash/TRIM & Apple SEP: Điện thoại dùng flash + TRIM và mã hóa SEP per-file nên tỷ lệ phục hồi thấp. Hãy ngừng dùng máy ngay.")
                    .font(.caption)
                    .padding(10)
                    .background(Color.orange.opacity(0.2))
                    .cornerRadius(8)

                if step == 1 {
                    Picker("Chế độ", selection: $mode) {
                        ForEach(IosRecoveryMode.allCases) { m in
                            Text(m.rawValue).tag(m)
                        }
                    }
                    .pickerStyle(.segmented)

                    Text(jbProbe.advisoryNote)
                        .font(.footnote)
                        .foregroundColor(.secondary)

                    List(IosCapabilityMatrix.entries) { row in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(row.feature).font(.subheadline).bold()
                            Text("Sideload: \(row.sideloadSandbox)").font(.caption)
                            Text("USB Companion: \(row.desktopCompanion)").font(.caption)
                            Text("Jailbreak: \(row.jailbreakRaw)").font(.caption)
                        }
                    }

                    Button("Bước 2: Quét Read-Only") {
                        step = 2
                        let scanner = PhotoAndCacheScanner()
                        candidates = scanner.scanSandboxedCaches()
                        step = 3
                    }
                    .buttonStyle(.borderedProminent)
                } else if step == 2 {
                    ProgressView("Đang quét sandbox / cache / backup cục bộ...")
                } else {
                    if candidates.isEmpty || candidates.contains(where: { $0.confidence == "low" }) {
                        Text("Kết quả có thể không đầy đủ do giới hạn iOS Sandbox / SEP.")
                            .font(.caption)
                            .foregroundColor(.orange)
                    }

                    Picker("Confidence", selection: $selectedConfidence) {
                        Text("All").tag("all")
                        Text("High").tag("high")
                        Text("Medium").tag("medium")
                        Text("Low").tag("low")
                    }
                    .pickerStyle(.segmented)

                    List(candidates.filter { selectedConfidence == "all" || $0.confidence == selectedConfidence }) { item in
                        Button {
                            previewCandidate = item
                        } label: {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(item.title).font(.subheadline).bold()
                                    Text("\(item.origin) • \(item.ext.uppercased()) • \(item.sizeBytes) B")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                Text(item.confidence.uppercased()).font(.caption2).bold()
                            }
                        }
                    }

                    Button("Quét lại") { step = 1 }
                }
            }
            .padding()
            .navigationTitle("Forensic Recover iOS")
            .sheet(item: $previewCandidate) { item in
                VStack(spacing: 12) {
                    Text("Preview trước khi lưu: \(item.title)").font(.headline)
                    Text("Origin: \(item.origin) • Ext: \(item.ext) • Confidence: \(item.confidence)")
                        .font(.caption)
                    Button("Đóng") { previewCandidate = nil }
                }
                .padding()
            }
        }
    }
}
#endif

#if canImport(SwiftUI) && os(iOS)
import SwiftUI

@main
struct ForensicRecoverApp: App {
    var body: some Scene {
        WindowGroup {
            RecoveryRootView()
        }
    }
}
#endif

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdbDeviceInfo {
    pub serial: String,
    pub state: String,
    pub rooted: bool,
    pub fbe_encrypted: bool,
}

/// Queries connected Android devices over USB ADB (`adb devices`) without modifying device state.
pub fn list_adb_devices() -> Vec<AdbDeviceInfo> {
    let Ok(out) = Command::new("adb").arg("devices").output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut devices = Vec::new();
    for line in text.lines().skip(1) {
        let mut parts = line.split_whitespace();
        if let (Some(serial), Some(state)) = (parts.next(), parts.next()) {
            if state == "device" {
                let rooted = Command::new("adb")
                    .args(["-s", serial, "shell", "su", "-c", "id"])
                    .output()
                    .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("uid=0"))
                    .unwrap_or(false);
                let fbe_encrypted = Command::new("adb")
                    .args(["-s", serial, "shell", "getprop", "ro.crypto.type"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "file")
                    .unwrap_or(true);
                devices.push(AdbDeviceInfo {
                    serial: serial.to_string(),
                    state: state.to_string(),
                    rooted,
                    fbe_encrypted,
                });
            }
        }
    }
    devices
}

//! Platform detection
//!
//! This module provides platform detection for Docker networking scenarios.
//! Functions are kept for future Docker integration features.

#[allow(dead_code)] // Reserved for Docker integration features
/// Detect the platform/OS of the system
pub fn detect_platform() -> Platform {
    #[cfg(target_os = "windows")]
    {
        Platform::Windows
    }

    #[cfg(target_os = "macos")]
    {
        Platform::MacOS
    }

    #[cfg(target_os = "linux")]
    {
        Platform::Linux
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Platform::Unknown
    }
}

#[allow(dead_code)] // Reserved for Docker integration features
/// Get the default localhost URL for Docker networking
pub fn localhost_url(port: u16) -> String {
    match detect_platform() {
        Platform::Windows => format!("http://host.docker.internal:{}", port),
        Platform::MacOS => format!("http://host.docker.internal:{}", port),
        Platform::Linux => format!("http://localhost:{}", port),
        Platform::Unknown => format!("http://localhost:{}", port),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Reserved for Docker integration features
pub enum Platform {
    Windows,
    MacOS,
    Linux,
    Unknown,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Windows => write!(f, "Windows"),
            Platform::MacOS => write!(f, "macOS"),
            Platform::Linux => write!(f, "Linux"),
            Platform::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localhost_url() {
        let url = localhost_url(3000);
        assert!(url.contains("3000"));
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::Linux.to_string(), "Linux");
        assert_eq!(Platform::Windows.to_string(), "Windows");
    }
}

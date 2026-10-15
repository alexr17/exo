use serde::{Deserialize, Serialize};

/// Host-side configuration for the HTTP forwarding proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressProxyConfig {
    /// Maximum buffered request body size in bytes. Defaults to 128 MiB.
    pub max_request_body_bytes: usize,
}

impl Default for EgressProxyConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 128 * 1024 * 1024,
        }
    }
}

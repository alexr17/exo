use anyhow::{Context, Result};

/// Host-side configuration for the HTTP forwarding proxy.
#[derive(Debug, Clone, Copy)]
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

impl EgressProxyConfig {
    /// Load host settings from `EXO_EGRESS_MAX_REQUEST_BODY_BYTES`.
    pub fn from_env() -> Result<Self> {
        match std::env::var("EXO_EGRESS_MAX_REQUEST_BODY_BYTES") {
            Ok(value) => Ok(Self {
                max_request_body_bytes: value.parse().context(
                    "EXO_EGRESS_MAX_REQUEST_BODY_BYTES must be a non-negative integer in bytes",
                )?,
            }),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(error) => Err(error).context("reading EXO_EGRESS_MAX_REQUEST_BODY_BYTES"),
        }
    }
}

//! JSON-RPC server

use crate::api::RpcApi;
use std::net::SocketAddr;
use std::sync::Arc;

/// RPC server configuration
#[derive(Clone, Debug)]
pub struct RpcServerConfig {
    pub listen_addr: SocketAddr,
    pub max_connections: usize,
    pub cors_enabled: bool,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8545".parse().unwrap(),
            max_connections: 100,
            cors_enabled: true,
        }
    }
}

/// RPC server
pub struct RpcServer {
    config: RpcServerConfig,
    api: Arc<dyn RpcApi>,
}

impl RpcServer {
    pub fn new(config: RpcServerConfig, api: Arc<dyn RpcApi>) -> Self {
        Self { config, api }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("Starting RPC server on {}", self.config.listen_addr);

        // In a full implementation, this would start an axum/jsonrpsee server
        // For now, we just log that we're starting

        Ok(())
    }

    pub fn config(&self) -> &RpcServerConfig {
        &self.config
    }
}

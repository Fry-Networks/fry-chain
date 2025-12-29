//! Peer management

use crate::{NetworkError, NetworkResult};
use dashmap::DashMap;
use frychain_core::types::{BlockHeight, Hash256};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

/// Peer state
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    Connecting,
    Connected,
    Handshaking,
    Active,
    Disconnected,
}

/// Peer information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub address: String,
    pub state: PeerState,
    pub best_height: BlockHeight,
    pub best_hash: Hash256,
    pub total_difficulty: u128,
    pub client_version: String,
    pub connected_at: u64,
    pub last_seen: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_ms: u32,
}

impl PeerInfo {
    pub fn new(peer_id: String, address: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            peer_id,
            address,
            state: PeerState::Connecting,
            best_height: BlockHeight::new(0),
            best_hash: Hash256::zero(),
            total_difficulty: 0,
            client_version: String::new(),
            connected_at: now,
            last_seen: now,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: 0,
        }
    }

    pub fn update_status(
        &mut self,
        height: BlockHeight,
        hash: Hash256,
        difficulty: u128,
    ) {
        self.best_height = height;
        self.best_hash = hash;
        self.total_difficulty = difficulty;
        self.touch();
    }

    pub fn touch(&mut self) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

/// Peer manager
pub struct PeerManager {
    peers: DashMap<String, PeerInfo>,
    max_peers: usize,
    banned_peers: DashMap<String, u64>, // Peer ID -> ban expiry timestamp
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: DashMap::new(),
            max_peers,
            banned_peers: DashMap::new(),
        }
    }

    pub fn add_peer(&self, peer: PeerInfo) -> NetworkResult<()> {
        if self.peers.len() >= self.max_peers {
            return Err(NetworkError::ConnectionFailed("Max peers reached".to_string()));
        }

        if self.is_banned(&peer.peer_id) {
            return Err(NetworkError::ConnectionFailed("Peer is banned".to_string()));
        }

        self.peers.insert(peer.peer_id.clone(), peer);
        Ok(())
    }

    pub fn remove_peer(&self, peer_id: &str) {
        self.peers.remove(peer_id);
    }

    pub fn get_peer(&self, peer_id: &str) -> Option<PeerInfo> {
        self.peers.get(peer_id).map(|r| r.clone())
    }

    pub fn update_peer<F>(&self, peer_id: &str, f: F)
    where
        F: FnOnce(&mut PeerInfo),
    {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            f(&mut peer);
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn active_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .iter()
            .filter(|p| p.state == PeerState::Active)
            .map(|p| p.clone())
            .collect()
    }

    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.peers.iter().map(|p| p.clone()).collect()
    }

    pub fn best_peer(&self) -> Option<PeerInfo> {
        self.peers
            .iter()
            .filter(|p| p.state == PeerState::Active)
            .max_by_key(|p| p.total_difficulty)
            .map(|p| p.clone())
    }

    pub fn ban_peer(&self, peer_id: &str, duration_secs: u64) {
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + duration_secs;

        self.banned_peers.insert(peer_id.to_string(), expiry);
        self.remove_peer(peer_id);
    }

    pub fn is_banned(&self, peer_id: &str) -> bool {
        if let Some(expiry) = self.banned_peers.get(peer_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now < *expiry {
                return true;
            }
            // Ban expired, remove it
            self.banned_peers.remove(peer_id);
        }
        false
    }

    pub fn cleanup_stale_peers(&self, max_idle_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stale: Vec<_> = self
            .peers
            .iter()
            .filter(|p| now - p.last_seen > max_idle_secs)
            .map(|p| p.peer_id.clone())
            .collect();

        for peer_id in stale {
            self.remove_peer(&peer_id);
        }
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new(50)
    }
}

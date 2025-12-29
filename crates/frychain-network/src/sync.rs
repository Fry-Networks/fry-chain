//! Chain synchronization

use frychain_core::types::{BlockHeight, Hash256};
use std::collections::VecDeque;

/// Sync state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Not syncing
    Idle,
    /// Finding common ancestor
    FindingAncestor,
    /// Downloading headers
    DownloadingHeaders,
    /// Downloading blocks
    DownloadingBlocks,
    /// Processing blocks
    Processing,
    /// Synced
    Synced,
}

/// Chain synchronizer
pub struct ChainSync {
    state: SyncState,
    target_height: BlockHeight,
    target_hash: Hash256,
    current_height: BlockHeight,
    pending_headers: VecDeque<Hash256>,
    pending_blocks: VecDeque<Hash256>,
    start_time: u64,
}

impl ChainSync {
    pub fn new() -> Self {
        Self {
            state: SyncState::Idle,
            target_height: BlockHeight::new(0),
            target_hash: Hash256::zero(),
            current_height: BlockHeight::new(0),
            pending_headers: VecDeque::new(),
            pending_blocks: VecDeque::new(),
            start_time: 0,
        }
    }

    pub fn state(&self) -> SyncState {
        self.state
    }

    pub fn is_syncing(&self) -> bool {
        !matches!(self.state, SyncState::Idle | SyncState::Synced)
    }

    pub fn progress(&self) -> f64 {
        if self.target_height.0 == 0 {
            return 1.0;
        }
        self.current_height.0 as f64 / self.target_height.0 as f64
    }

    pub fn start_sync(&mut self, target_height: BlockHeight, target_hash: Hash256) {
        self.state = SyncState::FindingAncestor;
        self.target_height = target_height;
        self.target_hash = target_hash;
        self.start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn set_current_height(&mut self, height: BlockHeight) {
        self.current_height = height;
        if height >= self.target_height {
            self.state = SyncState::Synced;
        }
    }

    pub fn add_pending_header(&mut self, hash: Hash256) {
        self.pending_headers.push_back(hash);
    }

    pub fn add_pending_block(&mut self, hash: Hash256) {
        self.pending_blocks.push_back(hash);
    }

    pub fn next_header_to_fetch(&mut self) -> Option<Hash256> {
        self.pending_headers.pop_front()
    }

    pub fn next_block_to_fetch(&mut self) -> Option<Hash256> {
        self.pending_blocks.pop_front()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_headers.len() + self.pending_blocks.len()
    }

    pub fn reset(&mut self) {
        self.state = SyncState::Idle;
        self.pending_headers.clear();
        self.pending_blocks.clear();
    }
}

impl Default for ChainSync {
    fn default() -> Self {
        Self::new()
    }
}

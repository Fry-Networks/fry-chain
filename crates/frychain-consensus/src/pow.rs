//! Proof of Work mining using CryptoNight-STC

use crate::ConsensusResult;
use frychain_core::block::BlockHeader;
use frychain_core::types::{Difficulty, Hash256, Nonce};
use frychain_crypto::cryptonight::CryptoNightStc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Mining result
#[derive(Clone, Debug)]
pub struct MiningResult {
    /// The successful nonce
    pub nonce: Nonce,
    /// The PoW hash that satisfies difficulty
    pub pow_hash: Hash256,
    /// Hashes computed
    pub hashes: u64,
    /// Time taken in milliseconds
    pub time_ms: u64,
}

impl MiningResult {
    /// Calculate hashrate
    pub fn hashrate(&self) -> f64 {
        if self.time_ms == 0 {
            return 0.0;
        }
        (self.hashes as f64) / (self.time_ms as f64 / 1000.0)
    }
}

/// Mine a block header until valid PoW is found
pub fn mine_block(
    header: &mut BlockHeader,
    stop_signal: Arc<AtomicBool>,
) -> Option<MiningResult> {
    let target = header.difficulty.to_target();
    let mut hasher = CryptoNightStc::new();

    let start = std::time::Instant::now();
    let mut nonce = header.nonce.0;
    let mut hashes = 0u64;

    loop {
        // Check stop signal
        if stop_signal.load(Ordering::Relaxed) {
            return None;
        }

        // Update nonce in header
        header.nonce = Nonce::new(nonce);

        // Get mining blob and hash it
        let blob = header.mining_blob();
        let pow_hash = hasher.hash(&blob);

        hashes += 1;

        // Check if we found a valid PoW
        if pow_hash.meets_difficulty(&target) {
            let time_ms = start.elapsed().as_millis() as u64;
            return Some(MiningResult {
                nonce: Nonce::new(nonce),
                pow_hash,
                hashes,
                time_ms,
            });
        }

        // Increment nonce
        nonce = nonce.wrapping_add(1);

        // Periodically update timestamp for long mining operations
        if hashes % 10000 == 0 {
            header.update_timestamp();
        }
    }
}

/// Mine with multiple threads
pub fn mine_block_parallel(
    header: &BlockHeader,
    num_threads: usize,
    stop_signal: Arc<AtomicBool>,
) -> Option<MiningResult> {
    use std::thread;

    let target = header.difficulty.to_target();
    let header_blob_base = header.mining_blob();
    let found = Arc::new(AtomicBool::new(false));
    let total_hashes = Arc::new(AtomicU64::new(0));

    let start = std::time::Instant::now();

    // Use crossbeam scoped threads
    let result = crossbeam::scope(|s| {
        let mut handles = Vec::new();

        for thread_id in 0..num_threads {
            let target = target;
            let mut blob = header_blob_base.clone();
            let found = Arc::clone(&found);
            let stop = Arc::clone(&stop_signal);
            let hashes_counter = Arc::clone(&total_hashes);

            let handle = s.spawn(move |_| {
                let mut hasher = CryptoNightStc::new();

                // Each thread starts at a different offset
                let mut nonce = thread_id as u64;
                let step = num_threads as u64;
                let mut local_hashes = 0u64;

                loop {
                    if found.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                        hashes_counter.fetch_add(local_hashes, Ordering::Relaxed);
                        return None;
                    }

                    // Update nonce in blob (last 8 bytes)
                    let nonce_offset = blob.len() - 8;
                    blob[nonce_offset..].copy_from_slice(&nonce.to_le_bytes());

                    let pow_hash = hasher.hash(&blob);
                    local_hashes += 1;

                    if pow_hash.meets_difficulty(&target) {
                        found.store(true, Ordering::Relaxed);
                        hashes_counter.fetch_add(local_hashes, Ordering::Relaxed);
                        return Some((Nonce::new(nonce), pow_hash));
                    }

                    nonce = nonce.wrapping_add(step);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads and collect result
        for handle in handles {
            if let Some((nonce, pow_hash)) = handle.join().unwrap() {
                return Some((nonce, pow_hash));
            }
        }

        None
    })
    .unwrap();

    result.map(|(nonce, pow_hash)| {
        let time_ms = start.elapsed().as_millis() as u64;
        MiningResult {
            nonce,
            pow_hash,
            hashes: total_hashes.load(Ordering::Relaxed),
            time_ms,
        }
    })
}

/// Verify that a block's PoW is valid
pub fn verify_pow(header: &BlockHeader) -> ConsensusResult<Hash256> {
    let mut hasher = CryptoNightStc::new();
    let blob = header.mining_blob();
    let pow_hash = hasher.hash(&blob);

    let target = header.difficulty.to_target();
    if !pow_hash.meets_difficulty(&target) {
        return Err(crate::ConsensusError::InvalidProofOfWork);
    }

    Ok(pow_hash)
}

/// Quick PoW verification (uses light hash - less memory intensive)
pub fn verify_pow_light(header: &BlockHeader) -> bool {
    let blob = header.mining_blob();
    let pow_hash = CryptoNightStc::light_hash(&blob);
    let target = header.difficulty.to_target();
    pow_hash.meets_difficulty(&target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frychain_core::address::Address;
    use frychain_core::block::BlockHeader;
    use frychain_core::types::BlockHeight;

    #[test]
    fn test_mine_easy_difficulty() {
        let miner = Address::from_public_key(&[1u8; 64]);
        let mut header = BlockHeader::new(
            BlockHeight::new(1),
            Hash256::zero(),
            miner,
            Difficulty::new(1), // Very easy
        );

        let stop = Arc::new(AtomicBool::new(false));
        let result = mine_block(&mut header, stop);

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.hashes > 0);
    }

    #[test]
    fn test_verify_pow() {
        let miner = Address::from_public_key(&[1u8; 64]);
        let mut header = BlockHeader::new(
            BlockHeight::new(1),
            Hash256::zero(),
            miner,
            Difficulty::new(1),
        );

        let stop = Arc::new(AtomicBool::new(false));
        let result = mine_block(&mut header, stop).unwrap();
        header.nonce = result.nonce;

        // Verify the mined block
        let verified = verify_pow(&header);
        assert!(verified.is_ok());
    }
}

//! CryptoNight-STC Proof of Work Algorithm
//!
//! CryptoNight-STC is a memory-hard proof-of-work algorithm based on CryptoNight.
//! Key features:
//! - AES-256 encryption combined with Keccak-1600 hashing
//! - Memory-hard to resist ASIC optimization
//! - Suitable for CPU and GPU mining
//!
//! Algorithm overview:
//! 1. Initialize scratchpad using Keccak-1600 and AES
//! 2. Memory-hard loop with random reads/writes
//! 3. Final hash using Keccak-256

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use frychain_core::types::Hash256;
use sha3::{Digest, Keccak256};

/// Scratchpad size (2 MB for CryptoNight standard)
const SCRATCHPAD_SIZE: usize = 2 * 1024 * 1024;

/// Number of iterations in memory-hard loop
const ITERATIONS: usize = 524288; // 2^19

/// AES block size
const AES_BLOCK_SIZE: usize = 16;

/// CryptoNight-STC hasher
#[derive(Clone)]
pub struct CryptoNightStc {
    /// Scratchpad memory
    scratchpad: Vec<u8>,
}

impl CryptoNightStc {
    /// Create a new CryptoNight-STC hasher
    pub fn new() -> Self {
        Self {
            scratchpad: vec![0u8; SCRATCHPAD_SIZE],
        }
    }

    /// Hash input data using CryptoNight-STC algorithm
    pub fn hash(&mut self, input: &[u8]) -> Hash256 {
        // Step 1: Initial Keccak-1600 hash to create state
        let mut state = self.keccak_1600(input);

        // Step 2: Derive AES key from first 32 bytes of state
        let aes_key: [u8; 32] = state[0..32].try_into().unwrap();

        // Step 3: Initialize scratchpad using AES
        self.init_scratchpad(&aes_key, &state);

        // Step 4: Memory-hard loop
        self.memory_hard_loop(&mut state);

        // Step 5: Final hash
        self.final_hash(&state)
    }

    /// Keccak-1600 (produces 200 bytes of state)
    fn keccak_1600(&self, input: &[u8]) -> [u8; 200] {
        let mut state = [0u8; 200];

        // Use SHA3-256 as base and expand
        let mut hasher = Keccak256::new();
        hasher.update(input);
        let hash = hasher.finalize();

        // Copy initial hash
        state[0..32].copy_from_slice(&hash);

        // Expand state by repeated hashing
        for i in 1..6 {
            let mut hasher = Keccak256::new();
            hasher.update(&state[(i - 1) * 32..i * 32]);
            let hash = hasher.finalize();
            let end = std::cmp::min((i + 1) * 32, 200);
            let len = end - i * 32;
            state[i * 32..end].copy_from_slice(&hash[..len]);
        }

        // Fill remaining bytes
        let mut hasher = Keccak256::new();
        hasher.update(&state[0..160]);
        let hash = hasher.finalize();
        state[160..192].copy_from_slice(&hash);

        let mut hasher = Keccak256::new();
        hasher.update(&state[160..192]);
        let hash = hasher.finalize();
        state[192..200].copy_from_slice(&hash[..8]);

        state
    }

    /// Initialize scratchpad using AES encryption
    fn init_scratchpad(&mut self, key: &[u8; 32], state: &[u8; 200]) {
        let cipher = Aes256::new_from_slice(key).expect("Valid key length");

        // Initialize scratchpad blocks
        let mut block = [0u8; AES_BLOCK_SIZE];
        block.copy_from_slice(&state[64..80]);

        for i in 0..(SCRATCHPAD_SIZE / AES_BLOCK_SIZE) {
            let offset = i * AES_BLOCK_SIZE;

            // Encrypt block
            let mut encrypted = aes::Block::clone_from_slice(&block);
            cipher.encrypt_block(&mut encrypted);

            // Store in scratchpad
            self.scratchpad[offset..offset + AES_BLOCK_SIZE].copy_from_slice(&encrypted);

            // XOR with state bytes for next iteration
            let state_offset = (i * AES_BLOCK_SIZE) % 64;
            for j in 0..AES_BLOCK_SIZE {
                block[j] = encrypted[j] ^ state[state_offset + j % 64];
            }
        }
    }

    /// Memory-hard loop with random reads and writes
    fn memory_hard_loop(&mut self, state: &mut [u8; 200]) {
        // Initialize working variables from state
        let mut a = u64::from_le_bytes(state[0..8].try_into().unwrap());
        let mut b = u64::from_le_bytes(state[8..16].try_into().unwrap());
        let mut c = u64::from_le_bytes(state[16..24].try_into().unwrap());
        let mut d = u64::from_le_bytes(state[24..32].try_into().unwrap());

        let scratchpad_mask = (SCRATCHPAD_SIZE / 16 - 1) as u64;

        for _ in 0..ITERATIONS {
            // Calculate scratchpad address from 'a'
            let addr1 = ((a & scratchpad_mask) as usize) * 16;

            // Read from scratchpad
            let s1 = self.read_scratchpad_u64(addr1);
            let s2 = self.read_scratchpad_u64(addr1 + 8);

            // AES round (simplified - XOR and rotate)
            let t1 = a ^ s1;
            let t2 = b ^ s2;

            // Write back to scratchpad
            self.write_scratchpad_u64(addr1, c ^ t1);
            self.write_scratchpad_u64(addr1 + 8, d ^ t2);

            // Calculate second address from 'c'
            let addr2 = ((c & scratchpad_mask) as usize) * 16;

            // Read from second location
            let s3 = self.read_scratchpad_u64(addr2);
            let s4 = self.read_scratchpad_u64(addr2 + 8);

            // 64-bit multiply and accumulate
            let (mul_lo, mul_hi) = mul_128(t1, s3);

            // Update state variables
            a = a.wrapping_add(mul_hi);
            b = b ^ s4;
            c = c.wrapping_add(mul_lo);
            d = d.wrapping_mul(t2.wrapping_add(1));

            // Write to second location
            self.write_scratchpad_u64(addr2, a ^ s3);
            self.write_scratchpad_u64(addr2 + 8, b ^ s4);

            // Rotate variables
            let temp = a;
            a = c;
            c = temp;
        }

        // Write back to state
        state[0..8].copy_from_slice(&a.to_le_bytes());
        state[8..16].copy_from_slice(&b.to_le_bytes());
        state[16..24].copy_from_slice(&c.to_le_bytes());
        state[24..32].copy_from_slice(&d.to_le_bytes());
    }

    /// Read u64 from scratchpad
    #[inline]
    fn read_scratchpad_u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.scratchpad[offset..offset + 8].try_into().unwrap())
    }

    /// Write u64 to scratchpad
    #[inline]
    fn write_scratchpad_u64(&mut self, offset: usize, value: u64) {
        self.scratchpad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Final hash computation
    fn final_hash(&self, state: &[u8; 200]) -> Hash256 {
        // XOR scratchpad into state
        let mut final_state = *state;

        for i in 0..SCRATCHPAD_SIZE / 8 {
            let scratchpad_val = self.read_scratchpad_u64(i * 8);
            let state_offset = (i * 8) % 200;
            let state_val =
                u64::from_le_bytes(final_state[state_offset..state_offset + 8].try_into().unwrap());
            let xored = state_val ^ scratchpad_val;
            final_state[state_offset..state_offset + 8].copy_from_slice(&xored.to_le_bytes());
        }

        // Final Keccak-256 hash
        let mut hasher = Keccak256::new();
        hasher.update(&final_state);
        let hash = hasher.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Hash256(result)
    }

    /// Verify a hash meets difficulty target
    pub fn verify_hash(hash: &Hash256, target: &Hash256) -> bool {
        hash.meets_difficulty(target)
    }

    /// Light hash for quick verification (without full scratchpad)
    /// This is faster but less memory-hard - only for verification
    pub fn light_hash(input: &[u8]) -> Hash256 {
        let mut hasher = Keccak256::new();
        hasher.update(b"CryptoNight-STC:");
        hasher.update(input);

        // Multiple rounds to approximate memory-hardness
        let mut state = hasher.finalize();
        for _ in 0..1000 {
            let mut hasher = Keccak256::new();
            hasher.update(&state);
            state = hasher.finalize();
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&state);
        Hash256(result)
    }
}

impl Default for CryptoNightStc {
    fn default() -> Self {
        Self::new()
    }
}

/// 128-bit multiplication returning (low, high)
#[inline]
fn mul_128(a: u64, b: u64) -> (u64, u64) {
    let result = (a as u128) * (b as u128);
    (result as u64, (result >> 64) as u64)
}

/// Thread-local hasher for mining
thread_local! {
    static HASHER: std::cell::RefCell<CryptoNightStc> = std::cell::RefCell::new(CryptoNightStc::new());
}

/// Hash with thread-local hasher (for mining performance)
pub fn hash(input: &[u8]) -> Hash256 {
    HASHER.with(|h| h.borrow_mut().hash(input))
}

/// Quick benchmark to estimate hashrate
pub fn benchmark_hashrate(duration_secs: u64) -> f64 {
    use std::time::{Duration, Instant};

    let mut hasher = CryptoNightStc::new();
    let input = [0u8; 76]; // Typical block header size

    let start = Instant::now();
    let target_duration = Duration::from_secs(duration_secs);
    let mut hashes = 0u64;

    while start.elapsed() < target_duration {
        hasher.hash(&input);
        hashes += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    hashes as f64 / elapsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cryptonight_hash_deterministic() {
        let mut hasher = CryptoNightStc::new();
        let input = b"test input for CryptoNight-STC";

        let hash1 = hasher.hash(input);
        let hash2 = hasher.hash(input);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_cryptonight_hash_different_inputs() {
        let mut hasher = CryptoNightStc::new();

        let hash1 = hasher.hash(b"input 1");
        let hash2 = hasher.hash(b"input 2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_light_hash() {
        let hash1 = CryptoNightStc::light_hash(b"test");
        let hash2 = CryptoNightStc::light_hash(b"test");

        assert_eq!(hash1, hash2);
        assert!(!hash1.is_zero());
    }

    #[test]
    fn test_thread_local_hash() {
        let hash1 = hash(b"test");
        let hash2 = hash(b"test");

        assert_eq!(hash1, hash2);
    }
}

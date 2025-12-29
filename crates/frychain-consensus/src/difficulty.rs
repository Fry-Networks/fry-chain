//! Difficulty adjustment algorithm

use frychain_core::block::BlockHeader;
use frychain_core::types::{BlockHeight, Difficulty};

/// Difficulty adjuster for maintaining target block time
pub struct DifficultyAdjuster {
    /// Target block time in seconds
    pub target_block_time: u64,
    /// Number of blocks between adjustments
    pub adjustment_interval: u64,
    /// Maximum adjustment factor (4x up or down)
    pub max_adjustment_factor: f64,
    /// Minimum difficulty
    pub min_difficulty: Difficulty,
}

impl DifficultyAdjuster {
    /// Create a new difficulty adjuster with default parameters
    pub fn new(target_block_time: u64, adjustment_interval: u64) -> Self {
        Self {
            target_block_time,
            adjustment_interval,
            max_adjustment_factor: 4.0,
            min_difficulty: Difficulty::MIN,
        }
    }

    /// Check if difficulty should be adjusted at this height
    pub fn should_adjust(&self, height: BlockHeight) -> bool {
        height.0 > 0 && height.0 % self.adjustment_interval == 0
    }

    /// Calculate new difficulty based on actual time taken
    ///
    /// # Arguments
    /// * `current_difficulty` - Current network difficulty
    /// * `first_block_time` - Timestamp of first block in adjustment window
    /// * `last_block_time` - Timestamp of last block in adjustment window
    pub fn calculate_new_difficulty(
        &self,
        current_difficulty: Difficulty,
        first_block_time: u64,
        last_block_time: u64,
    ) -> Difficulty {
        // Calculate actual time taken for the adjustment window
        let actual_time = last_block_time.saturating_sub(first_block_time);

        // Expected time for the window
        let expected_time = self.adjustment_interval * self.target_block_time;

        if actual_time == 0 {
            // Blocks were too fast, increase difficulty significantly
            return Difficulty::new(
                (current_difficulty.0 as f64 * self.max_adjustment_factor) as u128,
            );
        }

        // Calculate adjustment ratio
        let ratio = expected_time as f64 / actual_time as f64;

        // Clamp to maximum adjustment factor
        let clamped_ratio = ratio.clamp(
            1.0 / self.max_adjustment_factor,
            self.max_adjustment_factor,
        );

        // Calculate new difficulty
        let new_difficulty = (current_difficulty.0 as f64 * clamped_ratio) as u128;

        // Ensure minimum difficulty
        Difficulty::new(new_difficulty.max(self.min_difficulty.0))
    }

    /// Calculate difficulty for the next block
    ///
    /// # Arguments
    /// * `parent_headers` - Headers of recent blocks (at least adjustment_interval)
    pub fn next_difficulty(&self, parent_headers: &[BlockHeader]) -> Difficulty {
        if parent_headers.is_empty() {
            return Difficulty::INITIAL;
        }

        let current_height = parent_headers.last().unwrap().height;
        let next_height = current_height.next();

        // Check if we need to adjust
        if !self.should_adjust(next_height) {
            // No adjustment needed, use parent's difficulty
            return parent_headers.last().unwrap().difficulty;
        }

        // Get the first block of the adjustment window
        let window_start = next_height.0.saturating_sub(self.adjustment_interval);

        let first_header = parent_headers
            .iter()
            .find(|h| h.height.0 == window_start)
            .unwrap_or_else(|| parent_headers.first().unwrap());

        let last_header = parent_headers.last().unwrap();

        self.calculate_new_difficulty(
            last_header.difficulty,
            first_header.timestamp,
            last_header.timestamp,
        )
    }

    /// Estimate time to find next block at given difficulty and hashrate
    pub fn estimate_block_time(&self, difficulty: Difficulty, hashrate: f64) -> f64 {
        if hashrate <= 0.0 {
            return f64::MAX;
        }

        // Simplified estimate based on difficulty value
        // Higher difficulty = more hashes needed on average
        (difficulty.0 as f64) / hashrate
    }

    /// Estimate network hashrate from recent blocks
    pub fn estimate_network_hashrate(&self, blocks: &[BlockHeader]) -> f64 {
        if blocks.len() < 2 {
            return 0.0;
        }

        let first = blocks.first().unwrap();
        let last = blocks.last().unwrap();

        let time_span = last.timestamp.saturating_sub(first.timestamp);
        if time_span == 0 {
            return 0.0;
        }

        // Sum of difficulties in the window
        let total_difficulty: u128 = blocks.iter().map(|b| b.difficulty.0).sum();

        // Estimated hashrate = total_difficulty / time
        (total_difficulty as f64) / (time_span as f64)
    }
}

impl Default for DifficultyAdjuster {
    fn default() -> Self {
        Self::new(
            frychain_core::TARGET_BLOCK_TIME_SECS,
            frychain_core::DIFFICULTY_ADJUSTMENT_INTERVAL,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_adjust() {
        let adjuster = DifficultyAdjuster::new(60, 2016);

        assert!(!adjuster.should_adjust(BlockHeight::new(0)));
        assert!(!adjuster.should_adjust(BlockHeight::new(1)));
        assert!(!adjuster.should_adjust(BlockHeight::new(2015)));
        assert!(adjuster.should_adjust(BlockHeight::new(2016)));
        assert!(!adjuster.should_adjust(BlockHeight::new(2017)));
        assert!(adjuster.should_adjust(BlockHeight::new(4032)));
    }

    #[test]
    fn test_difficulty_adjustment_slower() {
        let adjuster = DifficultyAdjuster::new(60, 100);

        // Blocks took twice as long as expected
        let new_diff = adjuster.calculate_new_difficulty(
            Difficulty::new(1000),
            0,
            100 * 60 * 2, // 2x expected time
        );

        // Difficulty should decrease (but not below minimum)
        assert!(new_diff.0 < 1000);
    }

    #[test]
    fn test_difficulty_adjustment_faster() {
        let adjuster = DifficultyAdjuster::new(60, 100);

        // Blocks took half as long as expected
        let new_diff = adjuster.calculate_new_difficulty(
            Difficulty::new(1000),
            0,
            100 * 60 / 2, // 0.5x expected time
        );

        // Difficulty should increase
        assert!(new_diff.0 > 1000);
    }

    #[test]
    fn test_max_adjustment() {
        let adjuster = DifficultyAdjuster::new(60, 100);

        // Blocks were instant (0 time) - should hit max adjustment
        let new_diff = adjuster.calculate_new_difficulty(
            Difficulty::new(1000),
            0,
            1, // Almost instant
        );

        // Should be clamped to 4x increase
        assert!(new_diff.0 <= 4000);
    }
}

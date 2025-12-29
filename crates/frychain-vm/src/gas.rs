//! Gas metering for VM execution

use frychain_core::types::Gas;

/// Gas costs for various operations
pub mod costs {
    use frychain_core::types::Gas;

    // Base costs
    pub const ZERO: Gas = Gas(0);
    pub const BASE: Gas = Gas(2);
    pub const VERY_LOW: Gas = Gas(3);
    pub const LOW: Gas = Gas(5);
    pub const MID: Gas = Gas(8);
    pub const HIGH: Gas = Gas(10);

    // Memory costs
    pub const MEMORY_WORD: Gas = Gas(3);
    pub const MEMORY_COPY: Gas = Gas(3);

    // Storage costs
    pub const SLOAD: Gas = Gas(800);
    pub const SSTORE_SET: Gas = Gas(20000);
    pub const SSTORE_RESET: Gas = Gas(5000);
    pub const SSTORE_REFUND: Gas = Gas(15000);

    // Call costs
    pub const CALL: Gas = Gas(700);
    pub const CALL_VALUE: Gas = Gas(9000);
    pub const CALL_NEW_ACCOUNT: Gas = Gas(25000);

    // Create costs
    pub const CREATE: Gas = Gas(32000);
    pub const CREATE_DATA: Gas = Gas(200);

    // Log costs
    pub const LOG: Gas = Gas(375);
    pub const LOG_DATA: Gas = Gas(8);
    pub const LOG_TOPIC: Gas = Gas(375);

    // Crypto costs
    pub const SHA3_WORD: Gas = Gas(6);
    pub const SHA3_BASE: Gas = Gas(30);

    // Other
    pub const BALANCE: Gas = Gas(700);
    pub const EXT_CODE_SIZE: Gas = Gas(700);
    pub const EXT_CODE_COPY: Gas = Gas(700);
    pub const SELFDESTRUCT: Gas = Gas(5000);
    pub const EXP_BYTE: Gas = Gas(50);
}

/// Gas meter for tracking gas consumption
#[derive(Clone, Debug)]
pub struct GasMeter {
    /// Gas limit
    limit: u64,
    /// Gas used so far
    used: u64,
    /// Gas refund (for storage cleanup)
    refund: u64,
}

impl GasMeter {
    /// Create a new gas meter
    pub fn new(limit: Gas) -> Self {
        Self {
            limit: limit.0,
            used: 0,
            refund: 0,
        }
    }

    /// Get remaining gas
    pub fn remaining(&self) -> Gas {
        Gas(self.limit.saturating_sub(self.used))
    }

    /// Get gas used
    pub fn used(&self) -> Gas {
        Gas(self.used)
    }

    /// Get gas limit
    pub fn limit(&self) -> Gas {
        Gas(self.limit)
    }

    /// Get refund amount
    pub fn refund(&self) -> Gas {
        Gas(self.refund)
    }

    /// Consume gas, returns error if out of gas
    pub fn consume(&mut self, amount: Gas) -> Result<(), GasError> {
        let new_used = self.used.saturating_add(amount.0);
        if new_used > self.limit {
            // Use all remaining gas on OOG
            self.used = self.limit;
            return Err(GasError::OutOfGas {
                used: self.limit,
                limit: self.limit,
            });
        }
        self.used = new_used;
        Ok(())
    }

    /// Add to refund counter
    pub fn add_refund(&mut self, amount: Gas) {
        self.refund = self.refund.saturating_add(amount.0);
    }

    /// Calculate final gas used (after refunds)
    pub fn final_used(&self) -> Gas {
        // Refund is capped at half of gas used
        let max_refund = self.used / 2;
        let actual_refund = self.refund.min(max_refund);
        Gas(self.used.saturating_sub(actual_refund))
    }

    /// Check if there's enough gas
    pub fn has_gas(&self, amount: Gas) -> bool {
        self.used.saturating_add(amount.0) <= self.limit
    }

    /// Create a sub-meter for nested calls
    pub fn sub_meter(&self, gas_limit: Gas) -> Self {
        let available = self.remaining().0;
        // 63/64 rule for nested calls
        let max_for_call = available - (available / 64);
        let actual_limit = gas_limit.0.min(max_for_call);

        Self {
            limit: actual_limit,
            used: 0,
            refund: 0,
        }
    }

    /// Return unused gas from sub-meter
    pub fn return_gas(&mut self, sub_meter: &GasMeter) {
        // Add sub-meter's refund to our refund
        self.refund = self.refund.saturating_add(sub_meter.refund);

        // Unused gas from sub-meter is returned
        let sub_remaining = sub_meter.limit.saturating_sub(sub_meter.used);
        self.used = self.used.saturating_sub(sub_remaining);
    }
}

/// Gas calculation errors
#[derive(Debug, Clone)]
pub enum GasError {
    OutOfGas { used: u64, limit: u64 },
    Overflow,
}

impl std::fmt::Display for GasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GasError::OutOfGas { used, limit } => {
                write!(f, "Out of gas: used {}, limit {}", used, limit)
            }
            GasError::Overflow => write!(f, "Gas calculation overflow"),
        }
    }
}

impl std::error::Error for GasError {}

/// Calculate memory expansion cost
pub fn memory_cost(current_size: u64, new_size: u64) -> Gas {
    if new_size <= current_size {
        return Gas(0);
    }

    let new_words = (new_size + 31) / 32;
    let current_words = (current_size + 31) / 32;

    let new_cost = (new_words * new_words) / 512 + new_words * 3;
    let current_cost = (current_words * current_words) / 512 + current_words * 3;

    Gas(new_cost.saturating_sub(current_cost))
}

/// Calculate cost for copying data
pub fn copy_cost(size: u64) -> Gas {
    let words = (size + 31) / 32;
    Gas(costs::MEMORY_COPY.0 * words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_meter() {
        let mut meter = GasMeter::new(Gas(1000));

        assert_eq!(meter.remaining().0, 1000);
        assert_eq!(meter.used().0, 0);

        meter.consume(Gas(100)).unwrap();
        assert_eq!(meter.remaining().0, 900);
        assert_eq!(meter.used().0, 100);

        meter.consume(Gas(500)).unwrap();
        assert_eq!(meter.remaining().0, 400);

        // This should fail
        assert!(meter.consume(Gas(500)).is_err());
        // All gas consumed on OOG
        assert_eq!(meter.remaining().0, 0);
    }

    #[test]
    fn test_refund() {
        let mut meter = GasMeter::new(Gas(1000));
        meter.consume(Gas(800)).unwrap();
        meter.add_refund(Gas(300));

        // Refund capped at half of used (400)
        assert_eq!(meter.final_used().0, 500); // 800 - 300 = 500
    }

    #[test]
    fn test_sub_meter() {
        let mut meter = GasMeter::new(Gas(1000));
        meter.consume(Gas(100)).unwrap();

        let sub = meter.sub_meter(Gas(500));
        assert!(sub.limit() <= Gas(500));
    }
}

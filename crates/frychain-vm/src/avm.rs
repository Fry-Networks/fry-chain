//! Algorand Virtual Machine (AVM) / TEAL interpreter
//!
//! Implements a stack-based VM compatible with Algorand's TEAL language.
//! Supports both stateless (LogicSig) and stateful (Application) programs.

use crate::gas::{costs, GasMeter};
use crate::types::{ExecutionContext, VMLog, VMResult, VMStateChanges};
use crate::VMExecutionError;
use frychain_core::types::{Gas, Hash256};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Maximum stack depth
const MAX_STACK_DEPTH: usize = 1000;

/// Maximum scratch space slots
const SCRATCH_SPACE_SIZE: usize = 256;

/// TEAL opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TealOpcode {
    // Constants
    IntConst = 0x20,
    ByteConst = 0x21,
    IntC = 0x22,
    ByteC = 0x23,
    IntC0 = 0x24,
    IntC1 = 0x25,
    IntC2 = 0x26,
    IntC3 = 0x27,
    ByteC0 = 0x28,
    ByteC1 = 0x29,
    ByteC2 = 0x2A,
    ByteC3 = 0x2B,

    // Arithmetic
    Add = 0x08,
    Sub = 0x09,
    Div = 0x0A,
    Mul = 0x0B,
    Mod = 0x0C,
    Exp = 0x0D,

    // Logic
    And = 0x10,
    Or = 0x11,
    Not = 0x12,
    Eq = 0x13,
    Neq = 0x14,
    Lt = 0x15,
    Le = 0x16,
    Gt = 0x17,
    Ge = 0x18,

    // Bitwise
    BitAnd = 0x1A,
    BitOr = 0x1B,
    BitXor = 0x1C,
    BitNot = 0x1D,

    // Stack manipulation
    Dup = 0x48,
    Dup2 = 0x49,
    Pop = 0x4A,
    Dig = 0x4B,
    Bury = 0x4C,
    Cover = 0x4D,
    Uncover = 0x4E,
    Swap = 0x4F,

    // Control flow
    Err = 0x00,
    Return = 0x43,
    Assert = 0x44,
    Bnz = 0x40,
    Bz = 0x41,
    B = 0x42,
    CallSub = 0x88,
    RetSub = 0x89,

    // Crypto
    Sha256 = 0x01,
    Keccak256 = 0x02,
    Sha3_256 = 0x03,
    Ed25519Verify = 0x04,

    // State
    AppGlobalGet = 0x60,
    AppGlobalPut = 0x61,
    AppGlobalDel = 0x62,
    AppLocalGet = 0x63,
    AppLocalPut = 0x64,
    AppLocalDel = 0x65,

    // Misc
    Len = 0x50,
    Concat = 0x51,
    Substring = 0x52,
    Log = 0xB0,
}

/// Stack value type
#[derive(Clone, Debug)]
pub enum StackValue {
    Uint64(u64),
    Bytes(Vec<u8>),
}

impl StackValue {
    pub fn as_uint64(&self) -> Result<u64, VMExecutionError> {
        match self {
            StackValue::Uint64(v) => Ok(*v),
            StackValue::Bytes(_) => Err(VMExecutionError::ExecutionError(
                "Expected uint64, got bytes".to_string(),
            )),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8], VMExecutionError> {
        match self {
            StackValue::Bytes(b) => Ok(b),
            StackValue::Uint64(_) => Err(VMExecutionError::ExecutionError(
                "Expected bytes, got uint64".to_string(),
            )),
        }
    }

    pub fn to_bool(&self) -> bool {
        match self {
            StackValue::Uint64(v) => *v != 0,
            StackValue::Bytes(b) => !b.is_empty() && b.iter().any(|&x| x != 0),
        }
    }
}

/// AVM interpreter
pub struct AVMInterpreter {
    /// Execution stack
    stack: Vec<StackValue>,
    /// Scratch space
    scratch: [Option<StackValue>; SCRATCH_SPACE_SIZE],
    /// Program counter
    pc: usize,
    /// Bytecode
    bytecode: Vec<u8>,
    /// Integer constants table
    int_constants: Vec<u64>,
    /// Byte constants table
    byte_constants: Vec<Vec<u8>>,
    /// Global state
    global_state: HashMap<Vec<u8>, StackValue>,
    /// Local state (per account)
    local_state: HashMap<Vec<u8>, HashMap<Vec<u8>, StackValue>>,
    /// Call stack for subroutines
    call_stack: Vec<usize>,
    /// Gas meter
    gas_meter: GasMeter,
    /// Logs emitted
    logs: Vec<VMLog>,
    /// Execution context
    context: ExecutionContext,
}

impl AVMInterpreter {
    /// Create a new AVM interpreter
    pub fn new(bytecode: Vec<u8>, context: ExecutionContext) -> Self {
        Self {
            stack: Vec::with_capacity(MAX_STACK_DEPTH),
            scratch: std::array::from_fn(|_| None),
            pc: 0,
            bytecode,
            int_constants: Vec::new(),
            byte_constants: Vec::new(),
            global_state: HashMap::new(),
            local_state: HashMap::new(),
            call_stack: Vec::new(),
            gas_meter: GasMeter::new(context.gas_limit),
            logs: Vec::new(),
            context,
        }
    }

    /// Execute the program
    pub fn execute(&mut self) -> VMResult {
        // Parse version pragma (first byte)
        if self.bytecode.is_empty() {
            return VMResult::failure(Gas(0), "Empty bytecode".to_string());
        }

        let version = self.bytecode[0];
        if version > 10 {
            return VMResult::failure(
                Gas(0),
                format!("Unsupported TEAL version: {}", version),
            );
        }
        self.pc = 1;

        // Main execution loop
        loop {
            if self.pc >= self.bytecode.len() {
                break;
            }

            match self.step() {
                Ok(true) => continue,
                Ok(false) => break, // Return opcode
                Err(e) => {
                    return VMResult::failure(self.gas_meter.used(), e.to_string());
                }
            }
        }

        // Check final stack state
        let success = if let Some(top) = self.stack.last() {
            top.to_bool()
        } else {
            false
        };

        let return_data = self
            .stack
            .last()
            .map(|v| match v {
                StackValue::Uint64(n) => n.to_le_bytes().to_vec(),
                StackValue::Bytes(b) => b.clone(),
            })
            .unwrap_or_default();

        let mut result = VMResult::success(self.gas_meter.used(), return_data);
        result.success = success;
        result.logs = self.logs.clone();
        result
    }

    /// Execute one instruction
    fn step(&mut self) -> Result<bool, VMExecutionError> {
        let opcode = self.bytecode[self.pc];
        self.pc += 1;

        // Charge base gas
        self.gas_meter.consume(costs::BASE)?;

        match opcode {
            // Constants
            0x20 => {
                // intcblock
                let (count, bytes_read) = self.read_varuint()?;
                for _ in 0..count {
                    let (val, br) = self.read_varuint()?;
                    self.int_constants.push(val as u64);
                    self.pc += br;
                }
                self.pc += bytes_read;
            }
            0x21 => {
                // bytecblock
                let (count, bytes_read) = self.read_varuint()?;
                self.pc += bytes_read;
                for _ in 0..count {
                    let (len, br) = self.read_varuint()?;
                    self.pc += br;
                    let bytes = self.bytecode[self.pc..self.pc + len as usize].to_vec();
                    self.byte_constants.push(bytes);
                    self.pc += len as usize;
                }
            }
            0x22 => {
                // intc
                let idx = self.bytecode[self.pc] as usize;
                self.pc += 1;
                let val = self.int_constants.get(idx).copied().unwrap_or(0);
                self.push(StackValue::Uint64(val))?;
            }
            0x23 => {
                // bytec
                let idx = self.bytecode[self.pc] as usize;
                self.pc += 1;
                let val = self.byte_constants.get(idx).cloned().unwrap_or_default();
                self.push(StackValue::Bytes(val))?;
            }
            0x24..=0x27 => {
                // intc_0 through intc_3
                let idx = (opcode - 0x24) as usize;
                let val = self.int_constants.get(idx).copied().unwrap_or(0);
                self.push(StackValue::Uint64(val))?;
            }
            0x28..=0x2B => {
                // bytec_0 through bytec_3
                let idx = (opcode - 0x28) as usize;
                let val = self.byte_constants.get(idx).cloned().unwrap_or_default();
                self.push(StackValue::Bytes(val))?;
            }

            // Arithmetic
            0x08 => {
                // add
                let b = self.pop()?.as_uint64()?;
                let a = self.pop()?.as_uint64()?;
                self.push(StackValue::Uint64(a.wrapping_add(b)))?;
            }
            0x09 => {
                // sub
                let b = self.pop()?.as_uint64()?;
                let a = self.pop()?.as_uint64()?;
                self.push(StackValue::Uint64(a.wrapping_sub(b)))?;
            }
            0x0A => {
                // div
                let b = self.pop()?.as_uint64()?;
                let a = self.pop()?.as_uint64()?;
                if b == 0 {
                    return Err(VMExecutionError::ExecutionError(
                        "Division by zero".to_string(),
                    ));
                }
                self.push(StackValue::Uint64(a / b))?;
            }
            0x0B => {
                // mul
                let b = self.pop()?.as_uint64()?;
                let a = self.pop()?.as_uint64()?;
                self.push(StackValue::Uint64(a.wrapping_mul(b)))?;
            }
            0x0C => {
                // mod
                let b = self.pop()?.as_uint64()?;
                let a = self.pop()?.as_uint64()?;
                if b == 0 {
                    return Err(VMExecutionError::ExecutionError("Modulo by zero".to_string()));
                }
                self.push(StackValue::Uint64(a % b))?;
            }

            // Logic
            0x10 => {
                // &&
                let b = self.pop()?.to_bool();
                let a = self.pop()?.to_bool();
                self.push(StackValue::Uint64(if a && b { 1 } else { 0 }))?;
            }
            0x11 => {
                // ||
                let b = self.pop()?.to_bool();
                let a = self.pop()?.to_bool();
                self.push(StackValue::Uint64(if a || b { 1 } else { 0 }))?;
            }
            0x12 => {
                // !
                let a = self.pop()?.to_bool();
                self.push(StackValue::Uint64(if a { 0 } else { 1 }))?;
            }
            0x13 => {
                // ==
                let b = self.pop()?.as_uint64()?;
                let a = self.pop()?.as_uint64()?;
                self.push(StackValue::Uint64(if a == b { 1 } else { 0 }))?;
            }

            // Stack operations
            0x48 => {
                // dup
                let val = self.stack.last().cloned().ok_or(VMExecutionError::StackUnderflow)?;
                self.push(val)?;
            }
            0x4A => {
                // pop
                self.pop()?;
            }
            0x4F => {
                // swap
                let len = self.stack.len();
                if len < 2 {
                    return Err(VMExecutionError::StackUnderflow);
                }
                self.stack.swap(len - 1, len - 2);
            }

            // Control flow
            0x00 => {
                // err
                return Err(VMExecutionError::ExecutionError("Explicit error".to_string()));
            }
            0x43 => {
                // return
                return Ok(false);
            }
            0x44 => {
                // assert
                let val = self.pop()?;
                if !val.to_bool() {
                    return Err(VMExecutionError::ExecutionError("Assertion failed".to_string()));
                }
            }
            0x40 => {
                // bnz
                let offset = self.read_i16()?;
                let cond = self.pop()?;
                if cond.to_bool() {
                    self.pc = (self.pc as i64 + offset as i64) as usize;
                }
            }
            0x41 => {
                // bz
                let offset = self.read_i16()?;
                let cond = self.pop()?;
                if !cond.to_bool() {
                    self.pc = (self.pc as i64 + offset as i64) as usize;
                }
            }
            0x42 => {
                // b
                let offset = self.read_i16()?;
                self.pc = (self.pc as i64 + offset as i64) as usize;
            }

            // Crypto
            0x01 => {
                // sha256
                self.gas_meter.consume(costs::SHA3_BASE)?;
                let data = self.pop()?.as_bytes()?.to_vec();
                self.gas_meter
                    .consume(Gas(costs::SHA3_WORD.0 * ((data.len() as u64 + 31) / 32)))?;
                let hash = sha2::Sha256::digest(&data);
                self.push(StackValue::Bytes(hash.to_vec()))?;
            }
            0x02 | 0x03 => {
                // keccak256 / sha3_256
                self.gas_meter.consume(costs::SHA3_BASE)?;
                let data = self.pop()?.as_bytes()?.to_vec();
                self.gas_meter
                    .consume(Gas(costs::SHA3_WORD.0 * ((data.len() as u64 + 31) / 32)))?;
                let hash = Sha3_256::digest(&data);
                self.push(StackValue::Bytes(hash.to_vec()))?;
            }

            // State operations
            0x60 => {
                // app_global_get
                self.gas_meter.consume(costs::SLOAD)?;
                let key = self.pop()?.as_bytes()?.to_vec();
                let val = self
                    .global_state
                    .get(&key)
                    .cloned()
                    .unwrap_or(StackValue::Uint64(0));
                self.push(val)?;
            }
            0x61 => {
                // app_global_put
                self.gas_meter.consume(costs::SSTORE_SET)?;
                let val = self.pop()?;
                let key = self.pop()?.as_bytes()?.to_vec();
                self.global_state.insert(key, val);
            }

            // Logging
            0xB0 => {
                // log
                self.gas_meter.consume(costs::LOG)?;
                let data = self.pop()?.as_bytes()?.to_vec();
                self.gas_meter
                    .consume(Gas(costs::LOG_DATA.0 * data.len() as u64))?;
                self.logs.push(VMLog {
                    address: self.context.address,
                    topics: Vec::new(),
                    data,
                });
            }

            // String operations
            0x50 => {
                // len
                let bytes = self.pop()?.as_bytes()?.to_vec();
                self.push(StackValue::Uint64(bytes.len() as u64))?;
            }
            0x51 => {
                // concat
                let b = self.pop()?.as_bytes()?.to_vec();
                let mut a = self.pop()?.as_bytes()?.to_vec();
                a.extend(b);
                self.push(StackValue::Bytes(a))?;
            }

            _ => {
                return Err(VMExecutionError::InvalidOpcode(opcode));
            }
        }

        Ok(true)
    }

    fn push(&mut self, value: StackValue) -> Result<(), VMExecutionError> {
        if self.stack.len() >= MAX_STACK_DEPTH {
            return Err(VMExecutionError::StackOverflow);
        }
        self.stack.push(value);
        Ok(())
    }

    fn pop(&mut self) -> Result<StackValue, VMExecutionError> {
        self.stack.pop().ok_or(VMExecutionError::StackUnderflow)
    }

    fn read_varuint(&self) -> Result<(u64, usize), VMExecutionError> {
        let mut result: u64 = 0;
        let mut shift = 0;
        let mut bytes_read = 0;

        loop {
            if self.pc + bytes_read >= self.bytecode.len() {
                return Err(VMExecutionError::ExecutionError(
                    "Unexpected end of bytecode".to_string(),
                ));
            }

            let byte = self.bytecode[self.pc + bytes_read];
            bytes_read += 1;

            result |= ((byte & 0x7F) as u64) << shift;

            if byte & 0x80 == 0 {
                break;
            }

            shift += 7;
            if shift > 63 {
                return Err(VMExecutionError::ExecutionError(
                    "Varuint too large".to_string(),
                ));
            }
        }

        Ok((result, bytes_read))
    }

    fn read_i16(&mut self) -> Result<i16, VMExecutionError> {
        if self.pc + 2 > self.bytecode.len() {
            return Err(VMExecutionError::ExecutionError(
                "Unexpected end of bytecode".to_string(),
            ));
        }
        let val = i16::from_be_bytes([self.bytecode[self.pc], self.bytecode[self.pc + 1]]);
        self.pc += 2;
        Ok(val)
    }
}

/// Compile simple expressions to TEAL bytecode
pub fn compile_simple_teal(source: &str) -> Result<Vec<u8>, String> {
    let mut bytecode = vec![6u8]; // TEAL version 6

    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "int" => {
                if parts.len() < 2 {
                    return Err("int requires a value".to_string());
                }
                let val: u64 = parts[1].parse().map_err(|e| format!("Invalid int: {}", e))?;
                bytecode.push(0x20); // intcblock
                bytecode.push(1); // count
                // Encode as varuint
                let mut v = val;
                loop {
                    let mut byte = (v & 0x7F) as u8;
                    v >>= 7;
                    if v != 0 {
                        byte |= 0x80;
                    }
                    bytecode.push(byte);
                    if v == 0 {
                        break;
                    }
                }
                bytecode.push(0x22); // intc 0
                bytecode.push(0);
            }
            "+" => bytecode.push(0x08),
            "-" => bytecode.push(0x09),
            "*" => bytecode.push(0x0B),
            "/" => bytecode.push(0x0A),
            "return" => bytecode.push(0x43),
            _ => return Err(format!("Unknown opcode: {}", parts[0])),
        }
    }

    Ok(bytecode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frychain_core::address::Address;
    use frychain_core::types::TokenAmount;

    fn make_context() -> ExecutionContext {
        ExecutionContext::new(
            Address::zero(),
            Address::zero(),
            TokenAmount::ZERO,
            Gas::new(1_000_000),
        )
    }

    #[test]
    fn test_simple_return_true() {
        // TEAL v6, push 1, return
        let bytecode = vec![6, 0x20, 1, 1, 0x22, 0, 0x43];
        let mut vm = AVMInterpreter::new(bytecode, make_context());
        let result = vm.execute();
        assert!(result.success);
    }

    #[test]
    fn test_arithmetic() {
        // Push 5, push 3, add, return (should be 8)
        let bytecode = vec![
            6, // version
            0x20, 2, 5, 3, // intcblock [5, 3]
            0x22, 0, // intc 0 (push 5)
            0x22, 1, // intc 1 (push 3)
            0x08, // add
            0x43, // return
        ];
        let mut vm = AVMInterpreter::new(bytecode, make_context());
        let result = vm.execute();
        assert!(result.success);
        // Result should be 8
        let val = u64::from_le_bytes(result.return_data[0..8].try_into().unwrap());
        assert_eq!(val, 8);
    }
}

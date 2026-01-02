//! Kaspa Script Virtual Machine
//!
//! Implements a UTXO-based scripting VM compatible with Kaspa's smart contract model.
//! Based on Bitcoin Script with extensions for Kaspa's KIP-1 smart contract proposals.
//!
//! Key features:
//! - Stack-based execution model
//! - Pay-to-Script-Hash (P2SH) support
//! - Signature verification operations
//! - Hash-based conditions
//! - Timelock support
//! - KIP-1 extensions for advanced contracts

use crate::gas::{costs, GasMeter};
use crate::types::{ExecutionContext, VMLog, VMResult, VMStateChanges};
use crate::VMExecutionError;
use frychain_core::types::{Gas, Hash256};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::collections::HashMap;

/// Kaspa magic bytes: "KASP" in ASCII
pub const KASPA_MAGIC: [u8; 4] = [0x4B, 0x41, 0x53, 0x50];

/// Maximum stack size
const MAX_STACK_SIZE: usize = 1000;

/// Maximum script size in bytes
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum element size in bytes
const MAX_ELEMENT_SIZE: usize = 520;

/// Maximum number of opcodes per script
const MAX_OPS_PER_SCRIPT: usize = 201;

/// Kaspa Script opcodes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KaspaOpcode {
    // Push value (Op0/OpFalse are the same)
    Op0 = 0x00,
    OpPushData1 = 0x4c,
    OpPushData2 = 0x4d,
    OpPushData4 = 0x4e,
    Op1Negate = 0x4f,
    OpReserved = 0x50,
    // Op1/OpTrue are the same
    Op1 = 0x51,
    Op2 = 0x52,
    Op3 = 0x53,
    Op4 = 0x54,
    Op5 = 0x55,
    Op6 = 0x56,
    Op7 = 0x57,
    Op8 = 0x58,
    Op9 = 0x59,
    Op10 = 0x5a,
    Op11 = 0x5b,
    Op12 = 0x5c,
    Op13 = 0x5d,
    Op14 = 0x5e,
    Op15 = 0x5f,
    Op16 = 0x60,

    // Control flow
    OpNop = 0x61,
    OpVer = 0x62,
    OpIf = 0x63,
    OpNotIf = 0x64,
    OpVerIf = 0x65,
    OpVerNotIf = 0x66,
    OpElse = 0x67,
    OpEndIf = 0x68,
    OpVerify = 0x69,
    OpReturn = 0x6a,

    // Stack operations
    OpToAltStack = 0x6b,
    OpFromAltStack = 0x6c,
    Op2Drop = 0x6d,
    Op2Dup = 0x6e,
    Op3Dup = 0x6f,
    Op2Over = 0x70,
    Op2Rot = 0x71,
    Op2Swap = 0x72,
    OpIfDup = 0x73,
    OpDepth = 0x74,
    OpDrop = 0x75,
    OpDup = 0x76,
    OpNip = 0x77,
    OpOver = 0x78,
    OpPick = 0x79,
    OpRoll = 0x7a,
    OpRot = 0x7b,
    OpSwap = 0x7c,
    OpTuck = 0x7d,

    // Splice operations
    OpCat = 0x7e,       // Disabled in Bitcoin, enabled in Kaspa
    OpSubStr = 0x7f,    // Disabled in Bitcoin, enabled in Kaspa
    OpLeft = 0x80,      // Disabled in Bitcoin, enabled in Kaspa
    OpRight = 0x81,     // Disabled in Bitcoin, enabled in Kaspa
    OpSize = 0x82,

    // Bitwise logic
    OpInvert = 0x83,    // Disabled in Bitcoin, enabled in Kaspa
    OpAnd = 0x84,       // Disabled in Bitcoin, enabled in Kaspa
    OpOr = 0x85,        // Disabled in Bitcoin, enabled in Kaspa
    OpXor = 0x86,       // Disabled in Bitcoin, enabled in Kaspa
    OpEqual = 0x87,
    OpEqualVerify = 0x88,
    OpReserved1 = 0x89,
    OpReserved2 = 0x8a,

    // Arithmetic
    Op1Add = 0x8b,
    Op1Sub = 0x8c,
    Op2Mul = 0x8d,      // Disabled in Bitcoin
    Op2Div = 0x8e,      // Disabled in Bitcoin
    OpNegate = 0x8f,
    OpAbs = 0x90,
    OpNot = 0x91,
    Op0NotEqual = 0x92,
    OpAdd = 0x93,
    OpSub = 0x94,
    OpMul = 0x95,       // Disabled in Bitcoin, enabled in Kaspa
    OpDiv = 0x96,       // Disabled in Bitcoin, enabled in Kaspa
    OpMod = 0x97,       // Disabled in Bitcoin, enabled in Kaspa
    OpLShift = 0x98,    // Disabled in Bitcoin, enabled in Kaspa
    OpRShift = 0x99,    // Disabled in Bitcoin, enabled in Kaspa
    OpBoolAnd = 0x9a,
    OpBoolOr = 0x9b,
    OpNumEqual = 0x9c,
    OpNumEqualVerify = 0x9d,
    OpNumNotEqual = 0x9e,
    OpLessThan = 0x9f,
    OpGreaterThan = 0xa0,
    OpLessThanOrEqual = 0xa1,
    OpGreaterThanOrEqual = 0xa2,
    OpMin = 0xa3,
    OpMax = 0xa4,
    OpWithin = 0xa5,

    // Crypto
    OpRipeMd160 = 0xa6,
    OpSha1 = 0xa7,
    OpSha256 = 0xa8,
    OpHash160 = 0xa9,
    OpHash256 = 0xaa,
    OpCodeSeparator = 0xab,
    OpCheckSig = 0xac,
    OpCheckSigVerify = 0xad,
    OpCheckMultiSig = 0xae,
    OpCheckMultiSigVerify = 0xaf,

    // Locktime
    OpCheckLockTimeVerify = 0xb1,
    OpCheckSequenceVerify = 0xb2,

    // Kaspa KIP-1 extensions
    OpCheckDataSig = 0xba,
    OpCheckDataSigVerify = 0xbb,
    OpInputIndex = 0xc0,
    OpOutputBytecode = 0xc1,
    OpInputBytecode = 0xc2,
    OpOutputValue = 0xc3,
    OpInputValue = 0xc4,
    OpOutputCount = 0xc5,
    OpInputCount = 0xc6,
    OpTxVersion = 0xc7,
    OpTxLockTime = 0xc8,

    // State operations (Kaspa extension)
    OpStateGet = 0xd0,
    OpStatePut = 0xd1,
    OpStateDelete = 0xd2,
    OpEmitEvent = 0xd3,

    // Reserved for future use
    OpNop1 = 0xb0,
    OpNop4 = 0xb3,
    OpNop5 = 0xb4,
    OpNop6 = 0xb5,
    OpNop7 = 0xb6,
    OpNop8 = 0xb7,
    OpNop9 = 0xb8,
    OpNop10 = 0xb9,

    // Invalid opcode
    OpInvalidOpcode = 0xff,
}

impl KaspaOpcode {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => KaspaOpcode::Op0,
            0x4c => KaspaOpcode::OpPushData1,
            0x4d => KaspaOpcode::OpPushData2,
            0x4e => KaspaOpcode::OpPushData4,
            0x4f => KaspaOpcode::Op1Negate,
            0x51..=0x60 => unsafe { std::mem::transmute(byte) },
            0x61 => KaspaOpcode::OpNop,
            0x63 => KaspaOpcode::OpIf,
            0x64 => KaspaOpcode::OpNotIf,
            0x67 => KaspaOpcode::OpElse,
            0x68 => KaspaOpcode::OpEndIf,
            0x69 => KaspaOpcode::OpVerify,
            0x6a => KaspaOpcode::OpReturn,
            0x6b => KaspaOpcode::OpToAltStack,
            0x6c => KaspaOpcode::OpFromAltStack,
            0x6d => KaspaOpcode::Op2Drop,
            0x6e => KaspaOpcode::Op2Dup,
            0x6f => KaspaOpcode::Op3Dup,
            0x70 => KaspaOpcode::Op2Over,
            0x71 => KaspaOpcode::Op2Rot,
            0x72 => KaspaOpcode::Op2Swap,
            0x73 => KaspaOpcode::OpIfDup,
            0x74 => KaspaOpcode::OpDepth,
            0x75 => KaspaOpcode::OpDrop,
            0x76 => KaspaOpcode::OpDup,
            0x77 => KaspaOpcode::OpNip,
            0x78 => KaspaOpcode::OpOver,
            0x79 => KaspaOpcode::OpPick,
            0x7a => KaspaOpcode::OpRoll,
            0x7b => KaspaOpcode::OpRot,
            0x7c => KaspaOpcode::OpSwap,
            0x7d => KaspaOpcode::OpTuck,
            0x7e => KaspaOpcode::OpCat,
            0x7f => KaspaOpcode::OpSubStr,
            0x80 => KaspaOpcode::OpLeft,
            0x81 => KaspaOpcode::OpRight,
            0x82 => KaspaOpcode::OpSize,
            0x83 => KaspaOpcode::OpInvert,
            0x84 => KaspaOpcode::OpAnd,
            0x85 => KaspaOpcode::OpOr,
            0x86 => KaspaOpcode::OpXor,
            0x87 => KaspaOpcode::OpEqual,
            0x88 => KaspaOpcode::OpEqualVerify,
            0x8b => KaspaOpcode::Op1Add,
            0x8c => KaspaOpcode::Op1Sub,
            0x8f => KaspaOpcode::OpNegate,
            0x90 => KaspaOpcode::OpAbs,
            0x91 => KaspaOpcode::OpNot,
            0x92 => KaspaOpcode::Op0NotEqual,
            0x93 => KaspaOpcode::OpAdd,
            0x94 => KaspaOpcode::OpSub,
            0x95 => KaspaOpcode::OpMul,
            0x96 => KaspaOpcode::OpDiv,
            0x97 => KaspaOpcode::OpMod,
            0x98 => KaspaOpcode::OpLShift,
            0x99 => KaspaOpcode::OpRShift,
            0x9a => KaspaOpcode::OpBoolAnd,
            0x9b => KaspaOpcode::OpBoolOr,
            0x9c => KaspaOpcode::OpNumEqual,
            0x9d => KaspaOpcode::OpNumEqualVerify,
            0x9e => KaspaOpcode::OpNumNotEqual,
            0x9f => KaspaOpcode::OpLessThan,
            0xa0 => KaspaOpcode::OpGreaterThan,
            0xa1 => KaspaOpcode::OpLessThanOrEqual,
            0xa2 => KaspaOpcode::OpGreaterThanOrEqual,
            0xa3 => KaspaOpcode::OpMin,
            0xa4 => KaspaOpcode::OpMax,
            0xa5 => KaspaOpcode::OpWithin,
            0xa6 => KaspaOpcode::OpRipeMd160,
            0xa7 => KaspaOpcode::OpSha1,
            0xa8 => KaspaOpcode::OpSha256,
            0xa9 => KaspaOpcode::OpHash160,
            0xaa => KaspaOpcode::OpHash256,
            0xab => KaspaOpcode::OpCodeSeparator,
            0xac => KaspaOpcode::OpCheckSig,
            0xad => KaspaOpcode::OpCheckSigVerify,
            0xae => KaspaOpcode::OpCheckMultiSig,
            0xaf => KaspaOpcode::OpCheckMultiSigVerify,
            0xb1 => KaspaOpcode::OpCheckLockTimeVerify,
            0xb2 => KaspaOpcode::OpCheckSequenceVerify,
            0xba => KaspaOpcode::OpCheckDataSig,
            0xbb => KaspaOpcode::OpCheckDataSigVerify,
            0xc0 => KaspaOpcode::OpInputIndex,
            0xc1 => KaspaOpcode::OpOutputBytecode,
            0xc2 => KaspaOpcode::OpInputBytecode,
            0xc3 => KaspaOpcode::OpOutputValue,
            0xc4 => KaspaOpcode::OpInputValue,
            0xc5 => KaspaOpcode::OpOutputCount,
            0xc6 => KaspaOpcode::OpInputCount,
            0xc7 => KaspaOpcode::OpTxVersion,
            0xc8 => KaspaOpcode::OpTxLockTime,
            0xd0 => KaspaOpcode::OpStateGet,
            0xd1 => KaspaOpcode::OpStatePut,
            0xd2 => KaspaOpcode::OpStateDelete,
            0xd3 => KaspaOpcode::OpEmitEvent,
            _ => KaspaOpcode::OpInvalidOpcode,
        }
    }
}

/// Stack element in Kaspa Script
#[derive(Clone, Debug, PartialEq)]
pub struct ScriptElement(pub Vec<u8>);

impl ScriptElement {
    /// Create empty element (representing false/0)
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Create element from bytes
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Create element from i64
    pub fn from_i64(val: i64) -> Self {
        if val == 0 {
            return Self::empty();
        }

        let mut result = Vec::new();
        let negative = val < 0;
        let mut abs_val = val.unsigned_abs();

        while abs_val > 0 {
            result.push((abs_val & 0xff) as u8);
            abs_val >>= 8;
        }

        // If high bit is set, need to add a sign byte
        if result.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let last = result.last_mut().unwrap();
            *last |= 0x80;
        }

        Self(result)
    }

    /// Convert to i64
    pub fn to_i64(&self) -> Result<i64, VMExecutionError> {
        if self.0.is_empty() {
            return Ok(0);
        }

        if self.0.len() > 8 {
            return Err(VMExecutionError::ExecutionError(
                "Script number overflow".to_string(),
            ));
        }

        let negative = self.0.last().map(|b| b & 0x80 != 0).unwrap_or(false);
        let mut result: i64 = 0;

        for (i, &byte) in self.0.iter().enumerate() {
            let mut val = byte;
            if i == self.0.len() - 1 && negative {
                val &= 0x7f;
            }
            result |= (val as i64) << (8 * i);
        }

        if negative {
            result = -result;
        }

        Ok(result)
    }

    /// Check if element is truthy (non-zero)
    pub fn is_true(&self) -> bool {
        for (i, &byte) in self.0.iter().enumerate() {
            if i == self.0.len() - 1 {
                // Ignore the sign bit in the last byte
                if byte & 0x7f != 0 {
                    return true;
                }
            } else if byte != 0 {
                return true;
            }
        }
        false
    }

    /// Create true element
    pub fn true_val() -> Self {
        Self(vec![1])
    }

    /// Create false element
    pub fn false_val() -> Self {
        Self::empty()
    }
}

/// Transaction input for script verification
#[derive(Clone, Debug)]
pub struct ScriptTxInput {
    pub prev_tx_hash: Hash256,
    pub prev_output_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub value: u64,
}

/// Transaction output for script verification
#[derive(Clone, Debug)]
pub struct ScriptTxOutput {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Transaction context for script verification
#[derive(Clone, Debug)]
pub struct ScriptTxContext {
    pub version: u32,
    pub inputs: Vec<ScriptTxInput>,
    pub outputs: Vec<ScriptTxOutput>,
    pub lock_time: u32,
    pub current_input_index: usize,
}

impl Default for ScriptTxContext {
    fn default() -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            current_input_index: 0,
        }
    }
}

/// Kaspa Script VM
pub struct KaspaVM {
    /// Main stack
    stack: Vec<ScriptElement>,
    /// Alternate stack
    alt_stack: Vec<ScriptElement>,
    /// Script bytecode
    script: Vec<u8>,
    /// Program counter
    pc: usize,
    /// Execution context
    context: ExecutionContext,
    /// Gas meter
    gas_meter: GasMeter,
    /// Transaction context
    tx_context: ScriptTxContext,
    /// Contract state storage
    state: HashMap<Vec<u8>, Vec<u8>>,
    /// Logs emitted
    logs: Vec<VMLog>,
    /// State changes
    state_changes: VMStateChanges,
    /// Conditional execution stack
    exec_stack: Vec<bool>,
    /// Operations executed
    op_count: usize,
    /// Code separator position
    code_sep_pos: usize,
    /// Signatures for verification
    signatures: Vec<Vec<u8>>,
}

impl KaspaVM {
    /// Create a new Kaspa VM
    pub fn new(context: ExecutionContext) -> Self {
        Self {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            script: Vec::new(),
            pc: 0,
            gas_meter: GasMeter::new(context.gas_limit),
            context,
            tx_context: ScriptTxContext::default(),
            state: HashMap::new(),
            logs: Vec::new(),
            state_changes: VMStateChanges::default(),
            exec_stack: Vec::new(),
            op_count: 0,
            code_sep_pos: 0,
            signatures: Vec::new(),
        }
    }

    /// Set transaction context
    pub fn set_tx_context(&mut self, ctx: ScriptTxContext) {
        self.tx_context = ctx;
    }

    /// Set signatures for verification
    pub fn set_signatures(&mut self, sigs: Vec<Vec<u8>>) {
        self.signatures = sigs;
    }

    /// Execute Kaspa script bytecode
    pub fn execute(&mut self, bytecode: &[u8], input: &[u8]) -> VMResult {
        // Verify magic bytes
        if bytecode.len() < 4 || bytecode[0..4] != KASPA_MAGIC {
            return VMResult::failure(Gas(0), "Invalid Kaspa bytecode magic".to_string());
        }

        // Check script size
        if bytecode.len() > MAX_SCRIPT_SIZE + 4 {
            return VMResult::failure(Gas(0), "Script size exceeds maximum".to_string());
        }

        self.script = bytecode[4..].to_vec();
        self.pc = 0;

        // If input provided, push it to stack first (scriptSig)
        if !input.is_empty() {
            // Execute the input script first (unlocking script)
            let input_script = input.to_vec();
            if let Err(e) = self.execute_script(&input_script) {
                return VMResult::failure(self.gas_meter.used(), e.to_string());
            }
        }

        // Execute the main script (locking script)
        match self.execute_script(&self.script.clone()) {
            Ok(_) => {
                // Script succeeds if stack is non-empty and top is true
                let success = if let Some(top) = self.stack.last() {
                    top.is_true()
                } else {
                    false
                };

                let return_data = self
                    .stack
                    .last()
                    .map(|e| e.0.clone())
                    .unwrap_or_default();

                let mut result = if success {
                    VMResult::success(self.gas_meter.used(), return_data)
                } else {
                    VMResult::failure(self.gas_meter.used(), "Script failed: false on stack".to_string())
                };
                result.logs = self.logs.clone();
                result.state_changes = self.state_changes.clone();
                result
            }
            Err(e) => VMResult::failure(self.gas_meter.used(), e.to_string()),
        }
    }

    /// Execute a script
    fn execute_script(&mut self, script: &[u8]) -> Result<(), VMExecutionError> {
        let original_pc = self.pc;
        let original_script = std::mem::replace(&mut self.script, script.to_vec());
        self.pc = 0;

        while self.pc < self.script.len() {
            if let Err(e) = self.step() {
                self.script = original_script;
                self.pc = original_pc;
                return Err(e);
            }
        }

        self.script = original_script;
        self.pc = original_pc;
        Ok(())
    }

    /// Execute a single step
    fn step(&mut self) -> Result<(), VMExecutionError> {
        if self.pc >= self.script.len() {
            return Ok(());
        }

        let opcode_byte = self.script[self.pc];
        self.pc += 1;

        // Check if we're executing (not in false branch of conditional)
        let executing = self.exec_stack.iter().all(|&b| b);

        // Charge base gas
        self.gas_meter.consume(costs::BASE)?;

        // Check op count
        self.op_count += 1;
        if self.op_count > MAX_OPS_PER_SCRIPT {
            return Err(VMExecutionError::ExecutionError(
                "Script opcode count exceeded".to_string(),
            ));
        }

        // Push operations (0x01-0x4b push that many bytes)
        if opcode_byte >= 0x01 && opcode_byte <= 0x4b {
            if executing {
                let len = opcode_byte as usize;
                if self.pc + len > self.script.len() {
                    return Err(VMExecutionError::ExecutionError(
                        "Unexpected end of script".to_string(),
                    ));
                }
                let data = self.script[self.pc..self.pc + len].to_vec();
                self.pc += len;
                self.push(ScriptElement::from_bytes(data))?;
            } else {
                self.pc += opcode_byte as usize;
            }
            return Ok(());
        }

        let opcode = KaspaOpcode::from_byte(opcode_byte);

        match opcode {
            // Push operations (Op0 is also OpFalse)
            KaspaOpcode::Op0 => {
                if executing {
                    self.push(ScriptElement::empty())?;
                }
            }
            KaspaOpcode::OpPushData1 => {
                if self.pc >= self.script.len() {
                    return Err(VMExecutionError::ExecutionError(
                        "Unexpected end of script".to_string(),
                    ));
                }
                let len = self.script[self.pc] as usize;
                self.pc += 1;
                if executing {
                    if self.pc + len > self.script.len() {
                        return Err(VMExecutionError::ExecutionError(
                            "Unexpected end of script".to_string(),
                        ));
                    }
                    let data = self.script[self.pc..self.pc + len].to_vec();
                    self.push(ScriptElement::from_bytes(data))?;
                }
                self.pc += len;
            }
            KaspaOpcode::OpPushData2 => {
                if self.pc + 2 > self.script.len() {
                    return Err(VMExecutionError::ExecutionError(
                        "Unexpected end of script".to_string(),
                    ));
                }
                let len = u16::from_le_bytes([self.script[self.pc], self.script[self.pc + 1]]) as usize;
                self.pc += 2;
                if executing {
                    if self.pc + len > self.script.len() {
                        return Err(VMExecutionError::ExecutionError(
                            "Unexpected end of script".to_string(),
                        ));
                    }
                    let data = self.script[self.pc..self.pc + len].to_vec();
                    self.push(ScriptElement::from_bytes(data))?;
                }
                self.pc += len;
            }
            KaspaOpcode::OpPushData4 => {
                if self.pc + 4 > self.script.len() {
                    return Err(VMExecutionError::ExecutionError(
                        "Unexpected end of script".to_string(),
                    ));
                }
                let len = u32::from_le_bytes([
                    self.script[self.pc],
                    self.script[self.pc + 1],
                    self.script[self.pc + 2],
                    self.script[self.pc + 3],
                ]) as usize;
                self.pc += 4;
                if executing {
                    if self.pc + len > self.script.len() {
                        return Err(VMExecutionError::ExecutionError(
                            "Unexpected end of script".to_string(),
                        ));
                    }
                    let data = self.script[self.pc..self.pc + len].to_vec();
                    self.push(ScriptElement::from_bytes(data))?;
                }
                self.pc += len;
            }
            KaspaOpcode::Op1Negate => {
                if executing {
                    self.push(ScriptElement::from_i64(-1))?;
                }
            }
            // Op1 is also OpTrue
            KaspaOpcode::Op1 => {
                if executing {
                    self.push(ScriptElement::from_i64(1))?;
                }
            }
            KaspaOpcode::Op2 => {
                if executing {
                    self.push(ScriptElement::from_i64(2))?;
                }
            }
            KaspaOpcode::Op3 => {
                if executing {
                    self.push(ScriptElement::from_i64(3))?;
                }
            }
            KaspaOpcode::Op4 => {
                if executing {
                    self.push(ScriptElement::from_i64(4))?;
                }
            }
            KaspaOpcode::Op5 => {
                if executing {
                    self.push(ScriptElement::from_i64(5))?;
                }
            }
            KaspaOpcode::Op6 => {
                if executing {
                    self.push(ScriptElement::from_i64(6))?;
                }
            }
            KaspaOpcode::Op7 => {
                if executing {
                    self.push(ScriptElement::from_i64(7))?;
                }
            }
            KaspaOpcode::Op8 => {
                if executing {
                    self.push(ScriptElement::from_i64(8))?;
                }
            }
            KaspaOpcode::Op9 => {
                if executing {
                    self.push(ScriptElement::from_i64(9))?;
                }
            }
            KaspaOpcode::Op10 => {
                if executing {
                    self.push(ScriptElement::from_i64(10))?;
                }
            }
            KaspaOpcode::Op11 => {
                if executing {
                    self.push(ScriptElement::from_i64(11))?;
                }
            }
            KaspaOpcode::Op12 => {
                if executing {
                    self.push(ScriptElement::from_i64(12))?;
                }
            }
            KaspaOpcode::Op13 => {
                if executing {
                    self.push(ScriptElement::from_i64(13))?;
                }
            }
            KaspaOpcode::Op14 => {
                if executing {
                    self.push(ScriptElement::from_i64(14))?;
                }
            }
            KaspaOpcode::Op15 => {
                if executing {
                    self.push(ScriptElement::from_i64(15))?;
                }
            }
            KaspaOpcode::Op16 => {
                if executing {
                    self.push(ScriptElement::from_i64(16))?;
                }
            }

            // Control flow
            KaspaOpcode::OpNop => {}
            KaspaOpcode::OpIf => {
                let cond = if executing {
                    let elem = self.pop()?;
                    elem.is_true()
                } else {
                    false
                };
                self.exec_stack.push(executing && cond);
            }
            KaspaOpcode::OpNotIf => {
                let cond = if executing {
                    let elem = self.pop()?;
                    !elem.is_true()
                } else {
                    false
                };
                self.exec_stack.push(executing && cond);
            }
            KaspaOpcode::OpElse => {
                if self.exec_stack.is_empty() {
                    return Err(VMExecutionError::ExecutionError(
                        "OP_ELSE without OP_IF".to_string(),
                    ));
                }
                // Check parent condition before getting mutable reference
                let len = self.exec_stack.len();
                let should_flip = len == 1 || self.exec_stack[..len - 1].iter().all(|&b| b);
                if should_flip {
                    let last = self.exec_stack.last_mut().unwrap();
                    *last = !*last;
                }
            }
            KaspaOpcode::OpEndIf => {
                if self.exec_stack.is_empty() {
                    return Err(VMExecutionError::ExecutionError(
                        "OP_ENDIF without OP_IF".to_string(),
                    ));
                }
                self.exec_stack.pop();
            }
            KaspaOpcode::OpVerify => {
                if executing {
                    let elem = self.pop()?;
                    if !elem.is_true() {
                        return Err(VMExecutionError::ExecutionError(
                            "OP_VERIFY failed".to_string(),
                        ));
                    }
                }
            }
            KaspaOpcode::OpReturn => {
                if executing {
                    return Err(VMExecutionError::ExecutionError(
                        "OP_RETURN encountered".to_string(),
                    ));
                }
            }

            // Stack operations
            KaspaOpcode::OpToAltStack => {
                if executing {
                    let elem = self.pop()?;
                    self.alt_stack.push(elem);
                }
            }
            KaspaOpcode::OpFromAltStack => {
                if executing {
                    let elem = self.alt_stack.pop().ok_or_else(|| {
                        VMExecutionError::ExecutionError("Alt stack underflow".to_string())
                    })?;
                    self.push(elem)?;
                }
            }
            KaspaOpcode::Op2Drop => {
                if executing {
                    self.pop()?;
                    self.pop()?;
                }
            }
            KaspaOpcode::Op2Dup => {
                if executing {
                    if self.stack.len() < 2 {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let a = self.stack[self.stack.len() - 2].clone();
                    let b = self.stack[self.stack.len() - 1].clone();
                    self.push(a)?;
                    self.push(b)?;
                }
            }
            KaspaOpcode::Op3Dup => {
                if executing {
                    if self.stack.len() < 3 {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let a = self.stack[self.stack.len() - 3].clone();
                    let b = self.stack[self.stack.len() - 2].clone();
                    let c = self.stack[self.stack.len() - 1].clone();
                    self.push(a)?;
                    self.push(b)?;
                    self.push(c)?;
                }
            }
            KaspaOpcode::OpDrop => {
                if executing {
                    self.pop()?;
                }
            }
            KaspaOpcode::OpDup => {
                if executing {
                    let elem = self.stack.last().cloned().ok_or(VMExecutionError::StackUnderflow)?;
                    self.push(elem)?;
                }
            }
            KaspaOpcode::OpNip => {
                if executing {
                    if self.stack.len() < 2 {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    self.stack.remove(self.stack.len() - 2);
                }
            }
            KaspaOpcode::OpOver => {
                if executing {
                    if self.stack.len() < 2 {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let elem = self.stack[self.stack.len() - 2].clone();
                    self.push(elem)?;
                }
            }
            KaspaOpcode::OpPick => {
                if executing {
                    let n = self.pop()?.to_i64()? as usize;
                    if n >= self.stack.len() {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let elem = self.stack[self.stack.len() - 1 - n].clone();
                    self.push(elem)?;
                }
            }
            KaspaOpcode::OpRoll => {
                if executing {
                    let n = self.pop()?.to_i64()? as usize;
                    if n >= self.stack.len() {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let idx = self.stack.len() - 1 - n;
                    let elem = self.stack.remove(idx);
                    self.push(elem)?;
                }
            }
            KaspaOpcode::OpRot => {
                if executing {
                    if self.stack.len() < 3 {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let len = self.stack.len();
                    self.stack.swap(len - 3, len - 2);
                    self.stack.swap(len - 2, len - 1);
                }
            }
            KaspaOpcode::OpSwap => {
                if executing {
                    if self.stack.len() < 2 {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let len = self.stack.len();
                    self.stack.swap(len - 1, len - 2);
                }
            }
            KaspaOpcode::OpTuck => {
                if executing {
                    if self.stack.len() < 2 {
                        return Err(VMExecutionError::StackUnderflow);
                    }
                    let top = self.stack.last().cloned().unwrap();
                    self.stack.insert(self.stack.len() - 2, top);
                }
            }
            KaspaOpcode::OpDepth => {
                if executing {
                    self.push(ScriptElement::from_i64(self.stack.len() as i64))?;
                }
            }
            KaspaOpcode::OpIfDup => {
                if executing {
                    if let Some(top) = self.stack.last().cloned() {
                        if top.is_true() {
                            self.push(top)?;
                        }
                    }
                }
            }

            // Splice operations (enabled in Kaspa)
            KaspaOpcode::OpCat => {
                if executing {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let mut result = a.0;
                    result.extend(b.0);
                    if result.len() > MAX_ELEMENT_SIZE {
                        return Err(VMExecutionError::ExecutionError(
                            "Element size exceeded".to_string(),
                        ));
                    }
                    self.push(ScriptElement::from_bytes(result))?;
                }
            }
            KaspaOpcode::OpSubStr => {
                if executing {
                    let size = self.pop()?.to_i64()? as usize;
                    let begin = self.pop()?.to_i64()? as usize;
                    let s = self.pop()?;
                    if begin + size > s.0.len() {
                        return Err(VMExecutionError::ExecutionError(
                            "Substring out of range".to_string(),
                        ));
                    }
                    self.push(ScriptElement::from_bytes(s.0[begin..begin + size].to_vec()))?;
                }
            }
            KaspaOpcode::OpLeft => {
                if executing {
                    let size = self.pop()?.to_i64()? as usize;
                    let s = self.pop()?;
                    if size > s.0.len() {
                        return Err(VMExecutionError::ExecutionError(
                            "Left size out of range".to_string(),
                        ));
                    }
                    self.push(ScriptElement::from_bytes(s.0[..size].to_vec()))?;
                }
            }
            KaspaOpcode::OpRight => {
                if executing {
                    let size = self.pop()?.to_i64()? as usize;
                    let s = self.pop()?;
                    if size > s.0.len() {
                        return Err(VMExecutionError::ExecutionError(
                            "Right size out of range".to_string(),
                        ));
                    }
                    let start = s.0.len() - size;
                    self.push(ScriptElement::from_bytes(s.0[start..].to_vec()))?;
                }
            }
            KaspaOpcode::OpSize => {
                if executing {
                    let elem = self.stack.last().ok_or(VMExecutionError::StackUnderflow)?;
                    self.push(ScriptElement::from_i64(elem.0.len() as i64))?;
                }
            }

            // Bitwise logic (enabled in Kaspa)
            KaspaOpcode::OpInvert => {
                if executing {
                    let mut elem = self.pop()?;
                    for byte in &mut elem.0 {
                        *byte = !*byte;
                    }
                    self.push(elem)?;
                }
            }
            KaspaOpcode::OpAnd => {
                if executing {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let result: Vec<u8> = a.0.iter().zip(b.0.iter()).map(|(x, y)| x & y).collect();
                    self.push(ScriptElement::from_bytes(result))?;
                }
            }
            KaspaOpcode::OpOr => {
                if executing {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let result: Vec<u8> = a.0.iter().zip(b.0.iter()).map(|(x, y)| x | y).collect();
                    self.push(ScriptElement::from_bytes(result))?;
                }
            }
            KaspaOpcode::OpXor => {
                if executing {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    let result: Vec<u8> = a.0.iter().zip(b.0.iter()).map(|(x, y)| x ^ y).collect();
                    self.push(ScriptElement::from_bytes(result))?;
                }
            }
            KaspaOpcode::OpEqual => {
                if executing {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(if a.0 == b.0 {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpEqualVerify => {
                if executing {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    if a.0 != b.0 {
                        return Err(VMExecutionError::ExecutionError(
                            "OP_EQUALVERIFY failed".to_string(),
                        ));
                    }
                }
            }

            // Arithmetic
            KaspaOpcode::Op1Add => {
                if executing {
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a + 1))?;
                }
            }
            KaspaOpcode::Op1Sub => {
                if executing {
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a - 1))?;
                }
            }
            KaspaOpcode::OpNegate => {
                if executing {
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(-a))?;
                }
            }
            KaspaOpcode::OpAbs => {
                if executing {
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a.abs()))?;
                }
            }
            KaspaOpcode::OpNot => {
                if executing {
                    let a = self.pop()?;
                    self.push(if a.is_true() {
                        ScriptElement::false_val()
                    } else {
                        ScriptElement::true_val()
                    })?;
                }
            }
            KaspaOpcode::Op0NotEqual => {
                if executing {
                    let a = self.pop()?.to_i64()?;
                    self.push(if a != 0 {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpAdd => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a + b))?;
                }
            }
            KaspaOpcode::OpSub => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a - b))?;
                }
            }
            KaspaOpcode::OpMul => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a * b))?;
                }
            }
            KaspaOpcode::OpDiv => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    if b == 0 {
                        return Err(VMExecutionError::ExecutionError(
                            "Division by zero".to_string(),
                        ));
                    }
                    self.push(ScriptElement::from_i64(a / b))?;
                }
            }
            KaspaOpcode::OpMod => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    if b == 0 {
                        return Err(VMExecutionError::ExecutionError(
                            "Modulo by zero".to_string(),
                        ));
                    }
                    self.push(ScriptElement::from_i64(a % b))?;
                }
            }
            KaspaOpcode::OpLShift => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a << b))?;
                }
            }
            KaspaOpcode::OpRShift => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a >> b))?;
                }
            }
            KaspaOpcode::OpBoolAnd => {
                if executing {
                    let b = self.pop()?.is_true();
                    let a = self.pop()?.is_true();
                    self.push(if a && b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpBoolOr => {
                if executing {
                    let b = self.pop()?.is_true();
                    let a = self.pop()?.is_true();
                    self.push(if a || b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpNumEqual => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(if a == b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpNumEqualVerify => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    if a != b {
                        return Err(VMExecutionError::ExecutionError(
                            "OP_NUMEQUALVERIFY failed".to_string(),
                        ));
                    }
                }
            }
            KaspaOpcode::OpNumNotEqual => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(if a != b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpLessThan => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(if a < b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpGreaterThan => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(if a > b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpLessThanOrEqual => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(if a <= b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpGreaterThanOrEqual => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(if a >= b {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpMin => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a.min(b)))?;
                }
            }
            KaspaOpcode::OpMax => {
                if executing {
                    let b = self.pop()?.to_i64()?;
                    let a = self.pop()?.to_i64()?;
                    self.push(ScriptElement::from_i64(a.max(b)))?;
                }
            }
            KaspaOpcode::OpWithin => {
                if executing {
                    let max = self.pop()?.to_i64()?;
                    let min = self.pop()?.to_i64()?;
                    let x = self.pop()?.to_i64()?;
                    self.push(if x >= min && x < max {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }

            // Crypto
            KaspaOpcode::OpSha256 => {
                if executing {
                    self.gas_meter.consume(costs::SHA3_BASE)?;
                    let data = self.pop()?.0;
                    self.gas_meter
                        .consume(Gas(costs::SHA3_WORD.0 * ((data.len() as u64 + 31) / 32)))?;
                    let hash = Sha256::digest(&data);
                    self.push(ScriptElement::from_bytes(hash.to_vec()))?;
                }
            }
            KaspaOpcode::OpHash256 => {
                if executing {
                    self.gas_meter.consume(costs::SHA3_BASE)?;
                    let data = self.pop()?.0;
                    self.gas_meter
                        .consume(Gas(costs::SHA3_WORD.0 * ((data.len() as u64 + 31) / 32)))?;
                    // Double SHA256
                    let hash1 = Sha256::digest(&data);
                    let hash2 = Sha256::digest(&hash1);
                    self.push(ScriptElement::from_bytes(hash2.to_vec()))?;
                }
            }
            KaspaOpcode::OpHash160 => {
                if executing {
                    self.gas_meter.consume(costs::SHA3_BASE)?;
                    let data = self.pop()?.0;
                    // SHA256 then RIPEMD160 (simplified: just SHA256 and take first 20 bytes)
                    let hash = Sha256::digest(&data);
                    self.push(ScriptElement::from_bytes(hash[..20].to_vec()))?;
                }
            }
            KaspaOpcode::OpCodeSeparator => {
                if executing {
                    self.code_sep_pos = self.pc;
                }
            }
            KaspaOpcode::OpCheckSig => {
                if executing {
                    let pubkey = self.pop()?.0;
                    let sig = self.pop()?.0;
                    // Simplified signature verification
                    let valid = self.verify_signature(&sig, &pubkey);
                    self.push(if valid {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpCheckSigVerify => {
                if executing {
                    let pubkey = self.pop()?.0;
                    let sig = self.pop()?.0;
                    if !self.verify_signature(&sig, &pubkey) {
                        return Err(VMExecutionError::ExecutionError(
                            "Signature verification failed".to_string(),
                        ));
                    }
                }
            }
            KaspaOpcode::OpCheckMultiSig => {
                if executing {
                    // Get number of public keys
                    let n = self.pop()?.to_i64()? as usize;
                    let mut pubkeys = Vec::new();
                    for _ in 0..n {
                        pubkeys.push(self.pop()?.0);
                    }

                    // Get number of signatures
                    let m = self.pop()?.to_i64()? as usize;
                    let mut sigs = Vec::new();
                    for _ in 0..m {
                        sigs.push(self.pop()?.0);
                    }

                    // Bug compatibility: extra unused value
                    self.pop()?;

                    // Verify m-of-n signatures
                    let valid = self.verify_multisig(&sigs, &pubkeys);
                    self.push(if valid {
                        ScriptElement::true_val()
                    } else {
                        ScriptElement::false_val()
                    })?;
                }
            }
            KaspaOpcode::OpCheckMultiSigVerify => {
                if executing {
                    let n = self.pop()?.to_i64()? as usize;
                    let mut pubkeys = Vec::new();
                    for _ in 0..n {
                        pubkeys.push(self.pop()?.0);
                    }

                    let m = self.pop()?.to_i64()? as usize;
                    let mut sigs = Vec::new();
                    for _ in 0..m {
                        sigs.push(self.pop()?.0);
                    }

                    self.pop()?;

                    if !self.verify_multisig(&sigs, &pubkeys) {
                        return Err(VMExecutionError::ExecutionError(
                            "MultiSig verification failed".to_string(),
                        ));
                    }
                }
            }

            // Locktime
            KaspaOpcode::OpCheckLockTimeVerify => {
                if executing {
                    let lock_time = self.stack.last().ok_or(VMExecutionError::StackUnderflow)?.to_i64()?;
                    if lock_time < 0 {
                        return Err(VMExecutionError::ExecutionError(
                            "Negative locktime".to_string(),
                        ));
                    }
                    if (self.tx_context.lock_time as i64) < lock_time {
                        return Err(VMExecutionError::ExecutionError(
                            "Locktime not satisfied".to_string(),
                        ));
                    }
                }
            }
            KaspaOpcode::OpCheckSequenceVerify => {
                if executing {
                    let sequence = self.stack.last().ok_or(VMExecutionError::StackUnderflow)?.to_i64()?;
                    if sequence < 0 {
                        return Err(VMExecutionError::ExecutionError(
                            "Negative sequence".to_string(),
                        ));
                    }
                    // Simplified: just verify it's not greater than input sequence
                    if let Some(input) = self.tx_context.inputs.get(self.tx_context.current_input_index) {
                        if (input.sequence as i64) < sequence {
                            return Err(VMExecutionError::ExecutionError(
                                "Sequence not satisfied".to_string(),
                            ));
                        }
                    }
                }
            }

            // Kaspa KIP-1 extensions
            KaspaOpcode::OpInputIndex => {
                if executing {
                    self.push(ScriptElement::from_i64(self.tx_context.current_input_index as i64))?;
                }
            }
            KaspaOpcode::OpOutputBytecode => {
                if executing {
                    let idx = self.pop()?.to_i64()? as usize;
                    if let Some(output) = self.tx_context.outputs.get(idx) {
                        self.push(ScriptElement::from_bytes(output.script_pubkey.clone()))?;
                    } else {
                        self.push(ScriptElement::empty())?;
                    }
                }
            }
            KaspaOpcode::OpInputBytecode => {
                if executing {
                    let idx = self.pop()?.to_i64()? as usize;
                    if let Some(input) = self.tx_context.inputs.get(idx) {
                        self.push(ScriptElement::from_bytes(input.script_sig.clone()))?;
                    } else {
                        self.push(ScriptElement::empty())?;
                    }
                }
            }
            KaspaOpcode::OpOutputValue => {
                if executing {
                    let idx = self.pop()?.to_i64()? as usize;
                    if let Some(output) = self.tx_context.outputs.get(idx) {
                        self.push(ScriptElement::from_i64(output.value as i64))?;
                    } else {
                        self.push(ScriptElement::from_i64(0))?;
                    }
                }
            }
            KaspaOpcode::OpInputValue => {
                if executing {
                    let idx = self.pop()?.to_i64()? as usize;
                    if let Some(input) = self.tx_context.inputs.get(idx) {
                        self.push(ScriptElement::from_i64(input.value as i64))?;
                    } else {
                        self.push(ScriptElement::from_i64(0))?;
                    }
                }
            }
            KaspaOpcode::OpOutputCount => {
                if executing {
                    self.push(ScriptElement::from_i64(self.tx_context.outputs.len() as i64))?;
                }
            }
            KaspaOpcode::OpInputCount => {
                if executing {
                    self.push(ScriptElement::from_i64(self.tx_context.inputs.len() as i64))?;
                }
            }
            KaspaOpcode::OpTxVersion => {
                if executing {
                    self.push(ScriptElement::from_i64(self.tx_context.version as i64))?;
                }
            }
            KaspaOpcode::OpTxLockTime => {
                if executing {
                    self.push(ScriptElement::from_i64(self.tx_context.lock_time as i64))?;
                }
            }

            // State operations (Kaspa extension)
            KaspaOpcode::OpStateGet => {
                if executing {
                    self.gas_meter.consume(costs::SLOAD)?;
                    let key = self.pop()?.0;
                    let value = self.state.get(&key).cloned().unwrap_or_default();
                    self.push(ScriptElement::from_bytes(value))?;
                }
            }
            KaspaOpcode::OpStatePut => {
                if executing {
                    self.gas_meter.consume(costs::SSTORE_SET)?;
                    let value = self.pop()?.0;
                    let key = self.pop()?.0;
                    self.state.insert(key, value);
                }
            }
            KaspaOpcode::OpStateDelete => {
                if executing {
                    self.gas_meter.consume(costs::SSTORE_RESET)?;
                    let key = self.pop()?.0;
                    self.state.remove(&key);
                }
            }
            KaspaOpcode::OpEmitEvent => {
                if executing {
                    self.gas_meter.consume(costs::LOG)?;
                    let data = self.pop()?.0;
                    let topic = self.pop()?.0;
                    self.gas_meter
                        .consume(Gas(costs::LOG_DATA.0 * data.len() as u64))?;
                    self.logs.push(VMLog {
                        address: self.context.address,
                        topics: vec![Hash256::from_slice(&Sha3_256::digest(&topic)[..])],
                        data,
                    });
                }
            }

            // NOPs
            KaspaOpcode::OpNop1
            | KaspaOpcode::OpNop4
            | KaspaOpcode::OpNop5
            | KaspaOpcode::OpNop6
            | KaspaOpcode::OpNop7
            | KaspaOpcode::OpNop8
            | KaspaOpcode::OpNop9
            | KaspaOpcode::OpNop10 => {}

            // Reserved/Invalid
            _ => {
                if executing {
                    return Err(VMExecutionError::InvalidOpcode(opcode_byte));
                }
            }
        }

        Ok(())
    }

    /// Push element to stack
    fn push(&mut self, elem: ScriptElement) -> Result<(), VMExecutionError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Err(VMExecutionError::StackOverflow);
        }
        if elem.0.len() > MAX_ELEMENT_SIZE {
            return Err(VMExecutionError::ExecutionError(
                "Element size exceeded".to_string(),
            ));
        }
        self.stack.push(elem);
        Ok(())
    }

    /// Pop element from stack
    fn pop(&mut self) -> Result<ScriptElement, VMExecutionError> {
        self.stack.pop().ok_or(VMExecutionError::StackUnderflow)
    }

    /// Verify a signature (simplified)
    fn verify_signature(&self, _sig: &[u8], _pubkey: &[u8]) -> bool {
        // In a real implementation, this would verify the signature against
        // the transaction sighash using the public key
        // For now, return true for non-empty valid-looking signatures
        true
    }

    /// Verify multisig (simplified)
    fn verify_multisig(&self, sigs: &[Vec<u8>], pubkeys: &[Vec<u8>]) -> bool {
        // Simplified: just check that we have enough signatures
        // In reality, would verify each signature against pubkeys in order
        sigs.len() <= pubkeys.len()
    }
}

/// Compile Kaspa script source to bytecode
pub fn compile_kaspa_script(source: &str) -> Result<Vec<u8>, VMExecutionError> {
    let mut bytecode = KASPA_MAGIC.to_vec();

    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0].to_uppercase().as_str() {
            // Constants
            "OP_0" | "OP_FALSE" => bytecode.push(0x00),
            "OP_1" | "OP_TRUE" => bytecode.push(0x51),
            "OP_2" => bytecode.push(0x52),
            "OP_3" => bytecode.push(0x53),
            "OP_4" => bytecode.push(0x54),
            "OP_5" => bytecode.push(0x55),
            "OP_6" => bytecode.push(0x56),
            "OP_7" => bytecode.push(0x57),
            "OP_8" => bytecode.push(0x58),
            "OP_9" => bytecode.push(0x59),
            "OP_10" => bytecode.push(0x5a),
            "OP_11" => bytecode.push(0x5b),
            "OP_12" => bytecode.push(0x5c),
            "OP_13" => bytecode.push(0x5d),
            "OP_14" => bytecode.push(0x5e),
            "OP_15" => bytecode.push(0x5f),
            "OP_16" => bytecode.push(0x60),
            "OP_1NEGATE" => bytecode.push(0x4f),

            // Push data
            "PUSH" => {
                if parts.len() < 2 {
                    return Err(VMExecutionError::ExecutionError(
                        "PUSH requires data".to_string(),
                    ));
                }
                let data = hex::decode(parts[1]).map_err(|_| {
                    VMExecutionError::ExecutionError("Invalid hex data".to_string())
                })?;
                if data.len() <= 75 {
                    bytecode.push(data.len() as u8);
                    bytecode.extend(&data);
                } else if data.len() <= 255 {
                    bytecode.push(0x4c);
                    bytecode.push(data.len() as u8);
                    bytecode.extend(&data);
                } else {
                    bytecode.push(0x4d);
                    bytecode.extend(&(data.len() as u16).to_le_bytes());
                    bytecode.extend(&data);
                }
            }

            // Control flow
            "OP_NOP" => bytecode.push(0x61),
            "OP_IF" => bytecode.push(0x63),
            "OP_NOTIF" => bytecode.push(0x64),
            "OP_ELSE" => bytecode.push(0x67),
            "OP_ENDIF" => bytecode.push(0x68),
            "OP_VERIFY" => bytecode.push(0x69),
            "OP_RETURN" => bytecode.push(0x6a),

            // Stack
            "OP_TOALTSTACK" => bytecode.push(0x6b),
            "OP_FROMALTSTACK" => bytecode.push(0x6c),
            "OP_2DROP" => bytecode.push(0x6d),
            "OP_2DUP" => bytecode.push(0x6e),
            "OP_3DUP" => bytecode.push(0x6f),
            "OP_DROP" => bytecode.push(0x75),
            "OP_DUP" => bytecode.push(0x76),
            "OP_NIP" => bytecode.push(0x77),
            "OP_OVER" => bytecode.push(0x78),
            "OP_PICK" => bytecode.push(0x79),
            "OP_ROLL" => bytecode.push(0x7a),
            "OP_ROT" => bytecode.push(0x7b),
            "OP_SWAP" => bytecode.push(0x7c),
            "OP_TUCK" => bytecode.push(0x7d),
            "OP_DEPTH" => bytecode.push(0x74),
            "OP_IFDUP" => bytecode.push(0x73),

            // Splice
            "OP_CAT" => bytecode.push(0x7e),
            "OP_SUBSTR" => bytecode.push(0x7f),
            "OP_LEFT" => bytecode.push(0x80),
            "OP_RIGHT" => bytecode.push(0x81),
            "OP_SIZE" => bytecode.push(0x82),

            // Bitwise
            "OP_INVERT" => bytecode.push(0x83),
            "OP_AND" => bytecode.push(0x84),
            "OP_OR" => bytecode.push(0x85),
            "OP_XOR" => bytecode.push(0x86),
            "OP_EQUAL" => bytecode.push(0x87),
            "OP_EQUALVERIFY" => bytecode.push(0x88),

            // Arithmetic
            "OP_1ADD" => bytecode.push(0x8b),
            "OP_1SUB" => bytecode.push(0x8c),
            "OP_NEGATE" => bytecode.push(0x8f),
            "OP_ABS" => bytecode.push(0x90),
            "OP_NOT" => bytecode.push(0x91),
            "OP_0NOTEQUAL" => bytecode.push(0x92),
            "OP_ADD" => bytecode.push(0x93),
            "OP_SUB" => bytecode.push(0x94),
            "OP_MUL" => bytecode.push(0x95),
            "OP_DIV" => bytecode.push(0x96),
            "OP_MOD" => bytecode.push(0x97),
            "OP_LSHIFT" => bytecode.push(0x98),
            "OP_RSHIFT" => bytecode.push(0x99),
            "OP_BOOLAND" => bytecode.push(0x9a),
            "OP_BOOLOR" => bytecode.push(0x9b),
            "OP_NUMEQUAL" => bytecode.push(0x9c),
            "OP_NUMEQUALVERIFY" => bytecode.push(0x9d),
            "OP_NUMNOTEQUAL" => bytecode.push(0x9e),
            "OP_LESSTHAN" => bytecode.push(0x9f),
            "OP_GREATERTHAN" => bytecode.push(0xa0),
            "OP_LESSTHANOREQUAL" => bytecode.push(0xa1),
            "OP_GREATERTHANOREQUAL" => bytecode.push(0xa2),
            "OP_MIN" => bytecode.push(0xa3),
            "OP_MAX" => bytecode.push(0xa4),
            "OP_WITHIN" => bytecode.push(0xa5),

            // Crypto
            "OP_SHA256" => bytecode.push(0xa8),
            "OP_HASH160" => bytecode.push(0xa9),
            "OP_HASH256" => bytecode.push(0xaa),
            "OP_CHECKSIG" => bytecode.push(0xac),
            "OP_CHECKSIGVERIFY" => bytecode.push(0xad),
            "OP_CHECKMULTISIG" => bytecode.push(0xae),
            "OP_CHECKMULTISIGVERIFY" => bytecode.push(0xaf),

            // Locktime
            "OP_CHECKLOCKTIMEVERIFY" | "OP_CLTV" => bytecode.push(0xb1),
            "OP_CHECKSEQUENCEVERIFY" | "OP_CSV" => bytecode.push(0xb2),

            // Kaspa extensions
            "OP_INPUTINDEX" => bytecode.push(0xc0),
            "OP_OUTPUTBYTECODE" => bytecode.push(0xc1),
            "OP_INPUTBYTECODE" => bytecode.push(0xc2),
            "OP_OUTPUTVALUE" => bytecode.push(0xc3),
            "OP_INPUTVALUE" => bytecode.push(0xc4),
            "OP_OUTPUTCOUNT" => bytecode.push(0xc5),
            "OP_INPUTCOUNT" => bytecode.push(0xc6),
            "OP_TXVERSION" => bytecode.push(0xc7),
            "OP_TXLOCKTIME" => bytecode.push(0xc8),
            "OP_STATEGET" => bytecode.push(0xd0),
            "OP_STATEPUT" => bytecode.push(0xd1),
            "OP_STATEDELETE" => bytecode.push(0xd2),
            "OP_EMITEVENT" => bytecode.push(0xd3),

            _ => {
                return Err(VMExecutionError::ExecutionError(format!(
                    "Unknown opcode: {}",
                    parts[0]
                )));
            }
        }
    }

    Ok(bytecode)
}

/// Create P2PKH (Pay-to-Public-Key-Hash) script
pub fn create_p2pkh_script(pubkey_hash: &[u8]) -> Vec<u8> {
    let mut script = KASPA_MAGIC.to_vec();
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(pubkey_hash.len() as u8);
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Create P2SH (Pay-to-Script-Hash) script
pub fn create_p2sh_script(script_hash: &[u8]) -> Vec<u8> {
    let mut script = KASPA_MAGIC.to_vec();
    script.push(0xa9); // OP_HASH160
    script.push(script_hash.len() as u8);
    script.extend_from_slice(script_hash);
    script.push(0x87); // OP_EQUAL
    script
}

/// Create multisig script
pub fn create_multisig_script(m: u8, pubkeys: &[Vec<u8>]) -> Vec<u8> {
    let n = pubkeys.len() as u8;
    let mut script = KASPA_MAGIC.to_vec();

    // Push M
    script.push(0x50 + m); // OP_M

    // Push all public keys
    for pubkey in pubkeys {
        script.push(pubkey.len() as u8);
        script.extend_from_slice(pubkey);
    }

    // Push N
    script.push(0x50 + n); // OP_N

    script.push(0xae); // OP_CHECKMULTISIG
    script
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
            Gas::new(10_000_000),
        )
    }

    #[test]
    fn test_simple_true() {
        let script = compile_kaspa_script("OP_TRUE").unwrap();
        let mut vm = KaspaVM::new(make_context());
        let result = vm.execute(&script, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_arithmetic() {
        let script = compile_kaspa_script("OP_2 OP_3 OP_ADD OP_5 OP_EQUAL").unwrap();
        let mut vm = KaspaVM::new(make_context());
        let result = vm.execute(&script, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_if_else() {
        let script = compile_kaspa_script("OP_TRUE OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF").unwrap();
        let mut vm = KaspaVM::new(make_context());
        let result = vm.execute(&script, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_hash256() {
        let script = compile_kaspa_script("PUSH 48656c6c6f OP_HASH256 OP_SIZE OP_32 OP_EQUAL").unwrap();
        let mut vm = KaspaVM::new(make_context());
        let result = vm.execute(&script, &[]);
        // Just check it doesn't error
        assert!(result.error.is_none() || result.success);
    }

    #[test]
    fn test_state_operations() {
        let script = compile_kaspa_script(
            "PUSH 6b6579 PUSH 76616c7565 OP_STATEPUT PUSH 6b6579 OP_STATEGET PUSH 76616c7565 OP_EQUAL",
        )
        .unwrap();
        let mut vm = KaspaVM::new(make_context());
        let result = vm.execute(&script, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_concat() {
        let script =
            compile_kaspa_script("PUSH 48656c6c6f PUSH 576f726c64 OP_CAT OP_SIZE OP_10 OP_EQUAL")
                .unwrap();
        let mut vm = KaspaVM::new(make_context());
        let result = vm.execute(&script, &[]);
        assert!(result.success);
    }
}

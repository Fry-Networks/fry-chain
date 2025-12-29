//! Solana BPF (SBF) Virtual Machine
//!
//! Implements a register-based VM compatible with Solana's sBPF format.
//! This allows running Rust-compiled smart contracts.

use crate::gas::{costs, GasMeter};
use crate::types::{ExecutionContext, VMLog, VMResult, VMStateChanges};
use crate::VMExecutionError;
use frychain_core::address::Address;
use frychain_core::types::{Gas, Hash256};
use std::collections::HashMap;

/// Number of registers
const NUM_REGISTERS: usize = 11;

/// Stack size (4KB per frame)
const STACK_SIZE: usize = 4096;

/// Heap size
const HEAP_SIZE: usize = 32 * 1024; // 32KB

/// Max call depth
const MAX_CALL_DEPTH: usize = 64;

/// SBF opcodes (simplified subset)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbfOpcode {
    // ALU 64-bit
    Add = 0x07,
    Sub = 0x17,
    Mul = 0x27,
    Div = 0x37,
    Or = 0x47,
    And = 0x57,
    Lsh = 0x67,
    Rsh = 0x77,
    Neg = 0x87,
    Mod = 0x97,
    Xor = 0xa7,
    Mov = 0xb7,

    // ALU 32-bit
    Add32 = 0x04,
    Sub32 = 0x14,
    Mul32 = 0x24,
    Div32 = 0x34,

    // Memory
    Ldxb = 0x71,
    Ldxh = 0x69,
    Ldxw = 0x61,
    Ldxdw = 0x79,
    Stb = 0x72,
    Sth = 0x6a,
    Stw = 0x62,
    Stdw = 0x7a,
    Stxb = 0x73,
    Stxh = 0x6b,
    Stxw = 0x63,
    Stxdw = 0x7b,

    // Branches
    Ja = 0x05,
    Jeq = 0x15,
    Jgt = 0x25,
    Jge = 0x35,
    Jlt = 0xa5,
    Jle = 0xb5,
    Jset = 0x45,
    Jne = 0x55,

    // Call/Exit
    Call = 0x85,
    Exit = 0x95,
}

/// SBF instruction
#[derive(Clone, Copy, Debug)]
pub struct SbfInstruction {
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub offset: i16,
    pub imm: i32,
}

impl SbfInstruction {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        Some(Self {
            opcode: bytes[0],
            dst: bytes[1] & 0x0F,
            src: (bytes[1] >> 4) & 0x0F,
            offset: i16::from_le_bytes([bytes[2], bytes[3]]),
            imm: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

/// SBF VM state
pub struct SbfVM {
    /// Registers (R0-R10)
    registers: [u64; NUM_REGISTERS],
    /// Program counter
    pc: usize,
    /// Bytecode (as instructions)
    instructions: Vec<SbfInstruction>,
    /// Memory (heap)
    heap: Vec<u8>,
    /// Stack
    stack: Vec<u8>,
    /// Call stack
    call_stack: Vec<usize>,
    /// Gas meter
    gas_meter: GasMeter,
    /// Logs
    logs: Vec<VMLog>,
    /// Context
    context: ExecutionContext,
    /// Account data (for Solana-style account access)
    accounts: HashMap<Address, AccountData>,
}

/// Account data for Solana-style programs
#[derive(Clone, Debug, Default)]
pub struct AccountData {
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: Address,
    pub executable: bool,
    pub rent_epoch: u64,
}

impl SbfVM {
    /// Create a new SBF VM
    pub fn new(bytecode: &[u8], context: ExecutionContext) -> Result<Self, VMExecutionError> {
        // Parse ELF header and extract instructions
        let instructions = Self::parse_elf(bytecode)?;

        Ok(Self {
            registers: [0; NUM_REGISTERS],
            pc: 0,
            instructions,
            heap: vec![0; HEAP_SIZE],
            stack: vec![0; STACK_SIZE],
            call_stack: Vec::new(),
            gas_meter: GasMeter::new(context.gas_limit),
            logs: Vec::new(),
            context,
            accounts: HashMap::new(),
        })
    }

    /// Parse ELF bytecode (simplified)
    fn parse_elf(bytecode: &[u8]) -> Result<Vec<SbfInstruction>, VMExecutionError> {
        // Check ELF magic
        if bytecode.len() < 4 || &bytecode[0..4] != b"\x7fELF" {
            return Err(VMExecutionError::InvalidContract(
                "Invalid ELF header".to_string(),
            ));
        }

        // For simplicity, assume the code section starts after a 64-byte header
        // In a real implementation, we'd parse the full ELF structure
        let code_start = 64.min(bytecode.len());
        let code = &bytecode[code_start..];

        let mut instructions = Vec::new();
        let mut offset = 0;

        while offset + 8 <= code.len() {
            if let Some(inst) = SbfInstruction::decode(&code[offset..]) {
                instructions.push(inst);
            }
            offset += 8;
        }

        if instructions.is_empty() {
            // Create a minimal valid program that returns 0
            instructions.push(SbfInstruction {
                opcode: 0xb7, // mov64 r0, 0
                dst: 0,
                src: 0,
                offset: 0,
                imm: 0,
            });
            instructions.push(SbfInstruction {
                opcode: 0x95, // exit
                dst: 0,
                src: 0,
                offset: 0,
                imm: 0,
            });
        }

        Ok(instructions)
    }

    /// Execute the program
    pub fn execute(&mut self) -> VMResult {
        // Set up initial register state
        // R1 = pointer to input data
        // R10 = stack pointer
        self.registers[1] = 0; // Would point to serialized account data
        self.registers[10] = STACK_SIZE as u64;

        loop {
            if self.pc >= self.instructions.len() {
                break;
            }

            match self.step() {
                Ok(true) => continue,
                Ok(false) => break,
                Err(e) => {
                    return VMResult::failure(self.gas_meter.used(), e.to_string());
                }
            }
        }

        // R0 contains the return value
        let success = self.registers[0] == 0; // 0 = success in Solana
        let return_data = self.registers[0].to_le_bytes().to_vec();

        let mut result = VMResult::success(self.gas_meter.used(), return_data);
        result.success = success;
        result.logs = self.logs.clone();
        result
    }

    /// Execute one instruction
    fn step(&mut self) -> Result<bool, VMExecutionError> {
        let inst = self.instructions[self.pc];
        self.pc += 1;

        // Charge gas
        self.gas_meter.consume(costs::BASE)?;

        let dst = inst.dst as usize;
        let src = inst.src as usize;
        let imm = inst.imm as u64;

        match inst.opcode {
            // 64-bit ALU immediate
            0x07 => {
                // add64 imm
                self.registers[dst] = self.registers[dst].wrapping_add(imm);
            }
            0x17 => {
                // sub64 imm
                self.registers[dst] = self.registers[dst].wrapping_sub(imm);
            }
            0x27 => {
                // mul64 imm
                self.registers[dst] = self.registers[dst].wrapping_mul(imm);
            }
            0x37 => {
                // div64 imm
                if imm == 0 {
                    return Err(VMExecutionError::ExecutionError(
                        "Division by zero".to_string(),
                    ));
                }
                self.registers[dst] = self.registers[dst] / imm;
            }
            0x47 => {
                // or64 imm
                self.registers[dst] |= imm;
            }
            0x57 => {
                // and64 imm
                self.registers[dst] &= imm;
            }
            0x67 => {
                // lsh64 imm
                self.registers[dst] <<= imm;
            }
            0x77 => {
                // rsh64 imm
                self.registers[dst] >>= imm;
            }
            0x87 => {
                // neg64
                self.registers[dst] = (-(self.registers[dst] as i64)) as u64;
            }
            0x97 => {
                // mod64 imm
                if imm == 0 {
                    return Err(VMExecutionError::ExecutionError("Modulo by zero".to_string()));
                }
                self.registers[dst] %= imm;
            }
            0xa7 => {
                // xor64 imm
                self.registers[dst] ^= imm;
            }
            0xb7 => {
                // mov64 imm
                self.registers[dst] = imm;
            }

            // 64-bit ALU register
            0x0f => {
                // add64 reg
                self.registers[dst] = self.registers[dst].wrapping_add(self.registers[src]);
            }
            0x1f => {
                // sub64 reg
                self.registers[dst] = self.registers[dst].wrapping_sub(self.registers[src]);
            }
            0x2f => {
                // mul64 reg
                self.registers[dst] = self.registers[dst].wrapping_mul(self.registers[src]);
            }
            0x3f => {
                // div64 reg
                if self.registers[src] == 0 {
                    return Err(VMExecutionError::ExecutionError(
                        "Division by zero".to_string(),
                    ));
                }
                self.registers[dst] /= self.registers[src];
            }
            0xbf => {
                // mov64 reg
                self.registers[dst] = self.registers[src];
            }

            // Memory load
            0x71 => {
                // ldxb (load byte)
                let addr = (self.registers[src] as i64 + inst.offset as i64) as usize;
                self.gas_meter.consume(costs::VERY_LOW)?;
                self.registers[dst] = self.read_memory_u8(addr)? as u64;
            }
            0x69 => {
                // ldxh (load half-word)
                let addr = (self.registers[src] as i64 + inst.offset as i64) as usize;
                self.gas_meter.consume(costs::VERY_LOW)?;
                self.registers[dst] = self.read_memory_u16(addr)? as u64;
            }
            0x61 => {
                // ldxw (load word)
                let addr = (self.registers[src] as i64 + inst.offset as i64) as usize;
                self.gas_meter.consume(costs::VERY_LOW)?;
                self.registers[dst] = self.read_memory_u32(addr)? as u64;
            }
            0x79 => {
                // ldxdw (load double-word)
                let addr = (self.registers[src] as i64 + inst.offset as i64) as usize;
                self.gas_meter.consume(costs::LOW)?;
                self.registers[dst] = self.read_memory_u64(addr)?;
            }

            // Memory store
            0x72 | 0x73 => {
                // stb/stxb
                let addr = (self.registers[dst] as i64 + inst.offset as i64) as usize;
                let val = if inst.opcode == 0x72 {
                    imm as u8
                } else {
                    self.registers[src] as u8
                };
                self.gas_meter.consume(costs::VERY_LOW)?;
                self.write_memory_u8(addr, val)?;
            }
            0x6a | 0x6b => {
                // sth/stxh
                let addr = (self.registers[dst] as i64 + inst.offset as i64) as usize;
                let val = if inst.opcode == 0x6a {
                    imm as u16
                } else {
                    self.registers[src] as u16
                };
                self.gas_meter.consume(costs::VERY_LOW)?;
                self.write_memory_u16(addr, val)?;
            }
            0x62 | 0x63 => {
                // stw/stxw
                let addr = (self.registers[dst] as i64 + inst.offset as i64) as usize;
                let val = if inst.opcode == 0x62 {
                    imm as u32
                } else {
                    self.registers[src] as u32
                };
                self.gas_meter.consume(costs::VERY_LOW)?;
                self.write_memory_u32(addr, val)?;
            }
            0x7a | 0x7b => {
                // stdw/stxdw
                let addr = (self.registers[dst] as i64 + inst.offset as i64) as usize;
                let val = if inst.opcode == 0x7a {
                    imm
                } else {
                    self.registers[src]
                };
                self.gas_meter.consume(costs::LOW)?;
                self.write_memory_u64(addr, val)?;
            }

            // Branches
            0x05 => {
                // ja (jump always)
                self.pc = (self.pc as i64 + inst.offset as i64) as usize;
            }
            0x15 => {
                // jeq imm
                if self.registers[dst] == imm {
                    self.pc = (self.pc as i64 + inst.offset as i64) as usize;
                }
            }
            0x1d => {
                // jeq reg
                if self.registers[dst] == self.registers[src] {
                    self.pc = (self.pc as i64 + inst.offset as i64) as usize;
                }
            }
            0x25 => {
                // jgt imm
                if self.registers[dst] > imm {
                    self.pc = (self.pc as i64 + inst.offset as i64) as usize;
                }
            }
            0x35 => {
                // jge imm
                if self.registers[dst] >= imm {
                    self.pc = (self.pc as i64 + inst.offset as i64) as usize;
                }
            }
            0x55 => {
                // jne imm
                if self.registers[dst] != imm {
                    self.pc = (self.pc as i64 + inst.offset as i64) as usize;
                }
            }
            0xa5 => {
                // jlt imm
                if self.registers[dst] < imm {
                    self.pc = (self.pc as i64 + inst.offset as i64) as usize;
                }
            }
            0xb5 => {
                // jle imm
                if self.registers[dst] <= imm {
                    self.pc = (self.pc as i64 + inst.offset as i64) as usize;
                }
            }

            // Function calls
            0x85 => {
                // call
                self.gas_meter.consume(costs::CALL)?;

                if self.call_stack.len() >= MAX_CALL_DEPTH {
                    return Err(VMExecutionError::StackOverflow);
                }

                // Handle syscalls
                match inst.imm {
                    // sol_log_
                    1 => {
                        // Log syscall - read string from memory
                        let ptr = self.registers[1] as usize;
                        let len = self.registers[2] as usize;
                        if let Ok(data) = self.read_memory_slice(ptr, len) {
                            self.logs.push(VMLog {
                                address: self.context.address,
                                topics: Vec::new(),
                                data: data.to_vec(),
                            });
                        }
                        self.registers[0] = 0;
                    }
                    // sol_sha256
                    2 => {
                        self.gas_meter.consume(costs::SHA3_BASE)?;
                        // Simplified - actual implementation would hash memory
                        self.registers[0] = 0;
                    }
                    _ => {
                        // Internal call
                        self.call_stack.push(self.pc);
                        self.pc = inst.imm as usize;
                    }
                }
            }

            // Exit
            0x95 => {
                // exit
                if let Some(return_addr) = self.call_stack.pop() {
                    self.pc = return_addr;
                } else {
                    return Ok(false); // Program exit
                }
            }

            _ => {
                return Err(VMExecutionError::InvalidOpcode(inst.opcode));
            }
        }

        Ok(true)
    }

    // Memory access helpers
    fn read_memory_u8(&self, addr: usize) -> Result<u8, VMExecutionError> {
        self.heap
            .get(addr)
            .copied()
            .ok_or(VMExecutionError::InvalidMemoryAccess { address: addr as u64 })
    }

    fn read_memory_u16(&self, addr: usize) -> Result<u16, VMExecutionError> {
        if addr + 2 > self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        Ok(u16::from_le_bytes([self.heap[addr], self.heap[addr + 1]]))
    }

    fn read_memory_u32(&self, addr: usize) -> Result<u32, VMExecutionError> {
        if addr + 4 > self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        Ok(u32::from_le_bytes(
            self.heap[addr..addr + 4].try_into().unwrap(),
        ))
    }

    fn read_memory_u64(&self, addr: usize) -> Result<u64, VMExecutionError> {
        if addr + 8 > self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        Ok(u64::from_le_bytes(
            self.heap[addr..addr + 8].try_into().unwrap(),
        ))
    }

    fn read_memory_slice(&self, addr: usize, len: usize) -> Result<&[u8], VMExecutionError> {
        if addr + len > self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        Ok(&self.heap[addr..addr + len])
    }

    fn write_memory_u8(&mut self, addr: usize, val: u8) -> Result<(), VMExecutionError> {
        if addr >= self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        self.heap[addr] = val;
        Ok(())
    }

    fn write_memory_u16(&mut self, addr: usize, val: u16) -> Result<(), VMExecutionError> {
        if addr + 2 > self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        self.heap[addr..addr + 2].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_memory_u32(&mut self, addr: usize, val: u32) -> Result<(), VMExecutionError> {
        if addr + 4 > self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        self.heap[addr..addr + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    fn write_memory_u64(&mut self, addr: usize, val: u64) -> Result<(), VMExecutionError> {
        if addr + 8 > self.heap.len() {
            return Err(VMExecutionError::InvalidMemoryAccess { address: addr as u64 });
        }
        self.heap[addr..addr + 8].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_sbf_simple_return() {
        // Create minimal ELF-like bytecode
        let mut bytecode = b"\x7fELF".to_vec();
        bytecode.resize(64, 0); // Header padding

        // mov r0, 0
        bytecode.extend_from_slice(&[0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // exit
        bytecode.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let mut vm = SbfVM::new(&bytecode, make_context()).unwrap();
        let result = vm.execute();

        assert!(result.success);
    }

    #[test]
    fn test_sbf_arithmetic() {
        let mut bytecode = b"\x7fELF".to_vec();
        bytecode.resize(64, 0);

        // mov r0, 10
        bytecode.extend_from_slice(&[0xb7, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00]);
        // add r0, 5
        bytecode.extend_from_slice(&[0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]);
        // sub r0, 15 (result = 0 = success)
        bytecode.extend_from_slice(&[0x17, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00]);
        // exit
        bytecode.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let mut vm = SbfVM::new(&bytecode, make_context()).unwrap();
        let result = vm.execute();

        assert!(result.success); // r0 = 0 means success
    }
}

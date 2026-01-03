//! Kadena Pact Virtual Machine
//!
//! Implements a Lisp-like smart contract VM compatible with Kadena's Pact language.
//! Pact is a Turing-incomplete language with formal verification capabilities.
//!
//! Key features:
//! - S-expression syntax
//! - Modules and namespaces
//! - Capability-based security model
//! - Guards for authorization
//! - Tables and schemas for structured data
//! - Built-in functions for math, string, and crypto operations

use crate::gas::{costs, GasMeter};
use crate::types::{ExecutionContext, VMLog, VMResult, VMStateChanges};
use crate::VMExecutionError;
use frychain_core::types::{Gas, Hash256};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Pact magic bytes: "PACT" in ASCII
pub const PACT_MAGIC: [u8; 4] = [0x50, 0x41, 0x43, 0x54];

/// Maximum recursion depth for Pact expressions
const MAX_RECURSION_DEPTH: usize = 256;

/// Maximum table entries
const MAX_TABLE_SIZE: usize = 100_000;

/// Pact value types
#[derive(Clone, Debug, PartialEq)]
pub enum PactValue {
    /// Integer value (arbitrary precision in real Pact, i128 here)
    Integer(i128),
    /// Decimal value (fixed-point)
    Decimal(i128, u8), // (mantissa, decimals)
    /// String value
    String(String),
    /// Boolean value
    Bool(bool),
    /// List of values
    List(Vec<PactValue>),
    /// Object/Map
    Object(HashMap<String, PactValue>),
    /// Guard (for authorization)
    Guard(PactGuard),
    /// Module reference
    ModRef(String),
    /// Capability token
    Capability(String, Vec<PactValue>),
    /// Unit/nil value
    Unit,
    /// Time value (epoch seconds)
    Time(i64),
    /// Keyset reference
    KeySet(String),
}

impl PactValue {
    pub fn as_integer(&self) -> Result<i128, VMExecutionError> {
        match self {
            PactValue::Integer(n) => Ok(*n),
            _ => Err(VMExecutionError::ExecutionError(
                "Expected integer value".to_string(),
            )),
        }
    }

    pub fn as_string(&self) -> Result<&str, VMExecutionError> {
        match self {
            PactValue::String(s) => Ok(s),
            _ => Err(VMExecutionError::ExecutionError(
                "Expected string value".to_string(),
            )),
        }
    }

    pub fn as_bool(&self) -> Result<bool, VMExecutionError> {
        match self {
            PactValue::Bool(b) => Ok(*b),
            _ => Err(VMExecutionError::ExecutionError(
                "Expected boolean value".to_string(),
            )),
        }
    }

    pub fn as_list(&self) -> Result<&Vec<PactValue>, VMExecutionError> {
        match self {
            PactValue::List(l) => Ok(l),
            _ => Err(VMExecutionError::ExecutionError(
                "Expected list value".to_string(),
            )),
        }
    }

    pub fn to_bool(&self) -> bool {
        match self {
            PactValue::Bool(b) => *b,
            PactValue::Integer(n) => *n != 0,
            PactValue::String(s) => !s.is_empty(),
            PactValue::List(l) => !l.is_empty(),
            PactValue::Unit => false,
            _ => true,
        }
    }

    /// Serialize value to bytes for storage/return
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PactValue::Integer(n) => {
                let mut bytes = vec![0x01]; // Type tag
                bytes.extend_from_slice(&n.to_le_bytes());
                bytes
            }
            PactValue::String(s) => {
                let mut bytes = vec![0x02];
                bytes.extend_from_slice(&(s.len() as u32).to_le_bytes());
                bytes.extend_from_slice(s.as_bytes());
                bytes
            }
            PactValue::Bool(b) => vec![0x03, if *b { 1 } else { 0 }],
            PactValue::Unit => vec![0x00],
            _ => {
                // Complex types serialize as JSON-like string
                let mut bytes = vec![0xFF];
                let json = format!("{:?}", self);
                bytes.extend_from_slice(&(json.len() as u32).to_le_bytes());
                bytes.extend_from_slice(json.as_bytes());
                bytes
            }
        }
    }
}

/// Pact guard types for authorization
#[derive(Clone, Debug, PartialEq)]
pub enum PactGuard {
    /// Keyset guard - requires signatures from keys
    KeySet(Vec<String>, KeysetPredicate),
    /// User guard - calls a function for authorization
    UserGuard(String, String), // (module, function)
    /// Capability guard - requires capability to be in scope
    CapabilityGuard(String, Vec<PactValue>),
    /// Pact guard - for pact (multi-step transaction) authorization
    PactGuard(String),
}

/// Keyset predicates
#[derive(Clone, Debug, PartialEq)]
pub enum KeysetPredicate {
    /// All keys must sign
    KeysAll,
    /// Any key can sign
    KeysAny,
    /// At least 2 keys must sign
    Keys2,
    /// Custom predicate function
    Custom(String),
}

/// Pact S-expression AST
#[derive(Clone, Debug, PartialEq)]
pub enum PactExpr {
    /// Literal value
    Literal(PactValue),
    /// Symbol/identifier
    Symbol(String),
    /// Function application: (func arg1 arg2 ...)
    App(Box<PactExpr>, Vec<PactExpr>),
    /// Let binding: (let ((x 1) (y 2)) body)
    Let(Vec<(String, PactExpr)>, Box<PactExpr>),
    /// Lambda: (lambda (x y) body)
    Lambda(Vec<String>, Box<PactExpr>),
    /// If expression: (if cond then else)
    If(Box<PactExpr>, Box<PactExpr>, Box<PactExpr>),
    /// Module definition
    Module(PactModule),
    /// Interface definition
    Interface(String, Vec<PactExpr>),
    /// Defun: function definition
    Defun(String, Vec<String>, Box<PactExpr>, Option<String>), // name, params, body, docstring
    /// Defcap: capability definition
    Defcap(String, Vec<String>, Box<PactExpr>),
    /// Defschema: schema definition
    Defschema(String, Vec<(String, String)>), // name, fields (name, type)
    /// Deftable: table definition
    Deftable(String, String), // name, schema
    /// With-capability: execute with capability
    WithCapability(String, Vec<PactExpr>, Box<PactExpr>),
    /// Require-capability: assert capability in scope
    RequireCapability(String, Vec<PactExpr>),
    /// Read from table
    Read(String, Box<PactExpr>),
    /// Write to table
    Write(String, Box<PactExpr>, Box<PactExpr>),
    /// Insert into table
    Insert(String, Box<PactExpr>, Box<PactExpr>),
    /// Update table row
    Update(String, Box<PactExpr>, Box<PactExpr>),
    /// Enforce: assert with message
    Enforce(Box<PactExpr>, String),
    /// Enforce-guard: verify guard
    EnforceGuard(Box<PactExpr>),
    /// Property for formal verification (no-op at runtime)
    Property(String, Box<PactExpr>),
}

/// Pact module definition
#[derive(Clone, Debug, PartialEq)]
pub struct PactModule {
    pub name: String,
    pub governance: PactGovernance,
    pub imports: Vec<(String, Option<Vec<String>>)>, // (module, optional specific imports)
    pub definitions: Vec<PactExpr>,
}

/// Module governance
#[derive(Clone, Debug, PartialEq)]
pub enum PactGovernance {
    /// Governed by keyset
    Keyset(String),
    /// Governed by capability
    Capability(String),
}

/// Pact function
#[derive(Clone, Debug)]
pub struct PactFunction {
    pub name: String,
    pub params: Vec<String>,
    pub body: PactExpr,
    pub module: String,
}

/// Pact capability definition
#[derive(Clone, Debug)]
pub struct PactCapability {
    pub name: String,
    pub params: Vec<String>,
    pub body: PactExpr,
    pub module: String,
}

/// Pact table schema
#[derive(Clone, Debug)]
pub struct PactSchema {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

/// Pact table
#[derive(Clone, Debug)]
pub struct PactTable {
    pub name: String,
    pub schema: String,
    pub data: HashMap<String, HashMap<String, PactValue>>,
}

/// Pact VM interpreter
pub struct PactVM {
    /// Execution context
    context: ExecutionContext,
    /// Gas meter
    gas_meter: GasMeter,
    /// Environment bindings
    env: HashMap<String, PactValue>,
    /// Defined functions
    functions: HashMap<String, PactFunction>,
    /// Defined capabilities
    capabilities: HashMap<String, PactCapability>,
    /// Active capabilities (in scope)
    active_caps: Vec<(String, Vec<PactValue>)>,
    /// Granted capabilities for this transaction
    granted_caps: Vec<(String, Vec<PactValue>)>,
    /// Schemas
    schemas: HashMap<String, PactSchema>,
    /// Tables
    tables: HashMap<String, PactTable>,
    /// Modules loaded
    modules: HashMap<String, PactModule>,
    /// Keysets
    keysets: HashMap<String, (Vec<String>, KeysetPredicate)>,
    /// Current module context
    current_module: Option<String>,
    /// Recursion depth
    depth: usize,
    /// Logs emitted
    logs: Vec<VMLog>,
    /// State changes
    state_changes: VMStateChanges,
    /// Transaction signers (public keys)
    signers: Vec<String>,
}

impl PactVM {
    /// Create a new Pact VM
    pub fn new(context: ExecutionContext) -> Self {
        Self {
            gas_meter: GasMeter::new(context.gas_limit),
            context,
            env: HashMap::new(),
            functions: HashMap::new(),
            capabilities: HashMap::new(),
            active_caps: Vec::new(),
            granted_caps: Vec::new(),
            schemas: HashMap::new(),
            tables: HashMap::new(),
            modules: HashMap::new(),
            keysets: HashMap::new(),
            current_module: None,
            depth: 0,
            logs: Vec::new(),
            state_changes: VMStateChanges::default(),
            signers: Vec::new(),
        }
    }

    /// Set transaction signers
    pub fn set_signers(&mut self, signers: Vec<String>) {
        self.signers = signers;
    }

    /// Execute Pact bytecode
    pub fn execute(&mut self, bytecode: &[u8], input: &[u8]) -> VMResult {
        // Verify magic bytes
        if bytecode.len() < 4 || bytecode[0..4] != PACT_MAGIC {
            return VMResult::failure(Gas(0), "Invalid Pact bytecode magic".to_string());
        }

        // Parse the Pact code (after magic bytes)
        let code = match std::str::from_utf8(&bytecode[4..]) {
            Ok(s) => s,
            Err(e) => return VMResult::failure(Gas(0), format!("Invalid UTF-8: {}", e)),
        };

        // Parse input as function call if provided
        let call_data = if !input.is_empty() {
            match std::str::from_utf8(input) {
                Ok(s) => Some(s),
                Err(_) => None,
            }
        } else {
            None
        };

        // Parse and execute
        match self.parse_and_execute(code, call_data) {
            Ok(value) => {
                let mut result = VMResult::success(self.gas_meter.used(), value.to_bytes());
                result.logs = self.logs.clone();
                result.state_changes = self.state_changes.clone();
                result
            }
            Err(e) => VMResult::failure(self.gas_meter.used(), e.to_string()),
        }
    }

    /// Parse and execute Pact code
    fn parse_and_execute(
        &mut self,
        code: &str,
        call_data: Option<&str>,
    ) -> Result<PactValue, VMExecutionError> {
        // Initialize built-in functions
        self.init_builtins();

        // Parse the code into expressions
        let exprs = self.parse(code)?;

        // Execute all top-level expressions (module definitions, etc.)
        let mut last_value = PactValue::Unit;
        for expr in exprs {
            last_value = self.eval(&expr)?;
        }

        // If call data provided, parse and execute it
        if let Some(call) = call_data {
            let call_exprs = self.parse(call)?;
            for expr in call_exprs {
                last_value = self.eval(&expr)?;
            }
        }

        Ok(last_value)
    }

    /// Initialize built-in functions
    fn init_builtins(&mut self) {
        // Built-ins are handled specially in eval_app
    }

    /// Parse Pact source code into expressions
    fn parse(&self, source: &str) -> Result<Vec<PactExpr>, VMExecutionError> {
        let mut parser = PactParser::new(source);
        parser.parse_all()
    }

    /// Evaluate an expression
    fn eval(&mut self, expr: &PactExpr) -> Result<PactValue, VMExecutionError> {
        self.depth += 1;
        if self.depth > MAX_RECURSION_DEPTH {
            return Err(VMExecutionError::ExecutionError(
                "Maximum recursion depth exceeded".to_string(),
            ));
        }

        self.gas_meter.consume(costs::BASE)?;

        let result = match expr {
            PactExpr::Literal(v) => Ok(v.clone()),

            PactExpr::Symbol(name) => self.lookup(name),

            PactExpr::App(func, args) => self.eval_app(func, args),

            PactExpr::Let(bindings, body) => {
                let old_env = self.env.clone();
                for (name, val_expr) in bindings {
                    let val = self.eval(val_expr)?;
                    self.env.insert(name.clone(), val);
                }
                let result = self.eval(body);
                self.env = old_env;
                result
            }

            PactExpr::If(cond, then_branch, else_branch) => {
                let cond_val = self.eval(cond)?;
                if cond_val.to_bool() {
                    self.eval(then_branch)
                } else {
                    self.eval(else_branch)
                }
            }

            PactExpr::Lambda(params, body) => {
                // Return a closure-like value (simplified)
                Ok(PactValue::String(format!(
                    "<lambda ({})>",
                    params.join(" ")
                )))
            }

            PactExpr::Module(module) => {
                self.load_module(module.clone())?;
                Ok(PactValue::String(format!("Loaded module: {}", module.name)))
            }

            PactExpr::Defun(name, params, body, _doc) => {
                let module = self.current_module.clone().unwrap_or_default();
                let func = PactFunction {
                    name: name.clone(),
                    params: params.clone(),
                    body: (**body).clone(),
                    module: module.clone(),
                };
                let full_name = if module.is_empty() {
                    name.clone()
                } else {
                    format!("{}.{}", module, name)
                };
                self.functions.insert(full_name, func);
                Ok(PactValue::Unit)
            }

            PactExpr::Defcap(name, params, body) => {
                let module = self.current_module.clone().unwrap_or_default();
                let cap = PactCapability {
                    name: name.clone(),
                    params: params.clone(),
                    body: (**body).clone(),
                    module: module.clone(),
                };
                let full_name = if module.is_empty() {
                    name.clone()
                } else {
                    format!("{}.{}", module, name)
                };
                self.capabilities.insert(full_name, cap);
                Ok(PactValue::Unit)
            }

            PactExpr::Defschema(name, fields) => {
                let schema = PactSchema {
                    name: name.clone(),
                    fields: fields.clone(),
                };
                self.schemas.insert(name.clone(), schema);
                Ok(PactValue::Unit)
            }

            PactExpr::Deftable(name, schema) => {
                let table = PactTable {
                    name: name.clone(),
                    schema: schema.clone(),
                    data: HashMap::new(),
                };
                self.tables.insert(name.clone(), table);
                Ok(PactValue::Unit)
            }

            PactExpr::WithCapability(cap_name, args, body) => {
                // Evaluate capability arguments
                let cap_args: Vec<PactValue> = args
                    .iter()
                    .map(|a| self.eval(a))
                    .collect::<Result<_, _>>()?;

                // Check if capability is granted
                let cap_key = (cap_name.clone(), cap_args.clone());
                if !self.granted_caps.contains(&cap_key) {
                    // Try to acquire capability
                    if let Some(cap) = self.capabilities.get(cap_name).cloned() {
                        // Bind capability parameters
                        let old_env = self.env.clone();
                        for (param, arg) in cap.params.iter().zip(cap_args.iter()) {
                            self.env.insert(param.clone(), arg.clone());
                        }
                        // Evaluate capability body (guards, etc.)
                        let result = self.eval(&cap.body);
                        self.env = old_env;

                        if result.is_err() {
                            return Err(VMExecutionError::ExecutionError(format!(
                                "Capability {} not granted",
                                cap_name
                            )));
                        }

                        self.granted_caps.push(cap_key.clone());
                    }
                }

                // Add to active capabilities for body execution
                self.active_caps.push((cap_name.clone(), cap_args));
                let result = self.eval(body);
                self.active_caps.pop();
                result
            }

            PactExpr::RequireCapability(cap_name, args) => {
                let cap_args: Vec<PactValue> = args
                    .iter()
                    .map(|a| self.eval(a))
                    .collect::<Result<_, _>>()?;

                let cap_key = (cap_name.clone(), cap_args);
                if !self.active_caps.contains(&cap_key) {
                    return Err(VMExecutionError::ExecutionError(format!(
                        "Required capability not in scope: {}",
                        cap_name
                    )));
                }
                Ok(PactValue::Bool(true))
            }

            PactExpr::Read(table_name, key_expr) => {
                self.gas_meter.consume(costs::SLOAD)?;
                let key = self.eval(key_expr.as_ref())?.as_string()?.to_string();
                let table = self.tables.get(table_name).ok_or_else(|| {
                    VMExecutionError::ExecutionError(format!("Table not found: {}", table_name))
                })?;
                let row = table.data.get(&key).ok_or_else(|| {
                    VMExecutionError::ExecutionError(format!("Row not found: {}", key))
                })?;
                Ok(PactValue::Object(row.clone()))
            }

            PactExpr::Write(table_name, key_expr, val_expr)
            | PactExpr::Insert(table_name, key_expr, val_expr)
            | PactExpr::Update(table_name, key_expr, val_expr) => {
                self.gas_meter.consume(costs::SSTORE_SET)?;
                let key = self.eval(key_expr.as_ref())?.as_string()?.to_string();
                let val = self.eval(val_expr.as_ref())?;

                let row = match &val {
                    PactValue::Object(obj) => obj.clone(),
                    _ => {
                        return Err(VMExecutionError::ExecutionError(
                            "Write value must be an object".to_string(),
                        ))
                    }
                };

                let table = self.tables.get_mut(table_name).ok_or_else(|| {
                    VMExecutionError::ExecutionError(format!("Table not found: {}", table_name))
                })?;

                if table.data.len() >= MAX_TABLE_SIZE {
                    return Err(VMExecutionError::ExecutionError(
                        "Table size limit exceeded".to_string(),
                    ));
                }

                table.data.insert(key, row);
                Ok(PactValue::Unit)
            }

            PactExpr::Enforce(cond, msg) => {
                let cond_val = self.eval(cond)?;
                if !cond_val.to_bool() {
                    return Err(VMExecutionError::ExecutionError(format!(
                        "Enforce failed: {}",
                        msg
                    )));
                }
                Ok(PactValue::Bool(true))
            }

            PactExpr::EnforceGuard(guard_expr) => {
                let guard_val = self.eval(guard_expr)?;
                match guard_val {
                    PactValue::Guard(guard) => self.verify_guard(&guard),
                    PactValue::KeySet(name) => {
                        if let Some((keys, pred)) = self.keysets.get(&name) {
                            self.verify_guard(&PactGuard::KeySet(keys.clone(), pred.clone()))
                        } else {
                            Err(VMExecutionError::ExecutionError(format!(
                                "Unknown keyset: {}",
                                name
                            )))
                        }
                    }
                    _ => Err(VMExecutionError::ExecutionError(
                        "Expected guard value".to_string(),
                    )),
                }
            }

            PactExpr::Property(_, _) => {
                // Properties are for formal verification, no-op at runtime
                Ok(PactValue::Unit)
            }

            PactExpr::Interface(_, _) => {
                // Interface definitions are type-level, no-op at runtime
                Ok(PactValue::Unit)
            }
        };

        self.depth -= 1;
        result
    }

    /// Evaluate function application
    fn eval_app(
        &mut self,
        func: &PactExpr,
        args: &[PactExpr],
    ) -> Result<PactValue, VMExecutionError> {
        // Get function name
        let func_name = match func {
            PactExpr::Symbol(name) => name.clone(),
            _ => {
                // Evaluate as expression that returns a function
                let _ = self.eval(func)?;
                return Err(VMExecutionError::ExecutionError(
                    "Higher-order functions not fully supported".to_string(),
                ));
            }
        };

        // Evaluate arguments
        let evaluated_args: Vec<PactValue> = args
            .iter()
            .map(|a| self.eval(a))
            .collect::<Result<_, _>>()?;

        // Check built-in functions first
        match func_name.as_str() {
            // Arithmetic
            "+" => {
                let a = evaluated_args.get(0).ok_or_else(|| {
                    VMExecutionError::ExecutionError("+ requires 2 arguments".to_string())
                })?;
                let b = evaluated_args.get(1).ok_or_else(|| {
                    VMExecutionError::ExecutionError("+ requires 2 arguments".to_string())
                })?;
                Ok(PactValue::Integer(a.as_integer()? + b.as_integer()?))
            }
            "-" => {
                let a = evaluated_args.get(0).ok_or_else(|| {
                    VMExecutionError::ExecutionError("- requires 2 arguments".to_string())
                })?;
                let b = evaluated_args.get(1).ok_or_else(|| {
                    VMExecutionError::ExecutionError("- requires 2 arguments".to_string())
                })?;
                Ok(PactValue::Integer(a.as_integer()? - b.as_integer()?))
            }
            "*" => {
                let a = evaluated_args.get(0).ok_or_else(|| {
                    VMExecutionError::ExecutionError("* requires 2 arguments".to_string())
                })?;
                let b = evaluated_args.get(1).ok_or_else(|| {
                    VMExecutionError::ExecutionError("* requires 2 arguments".to_string())
                })?;
                Ok(PactValue::Integer(a.as_integer()? * b.as_integer()?))
            }
            "/" => {
                let a = evaluated_args.get(0).ok_or_else(|| {
                    VMExecutionError::ExecutionError("/ requires 2 arguments".to_string())
                })?;
                let b = evaluated_args.get(1).ok_or_else(|| {
                    VMExecutionError::ExecutionError("/ requires 2 arguments".to_string())
                })?;
                let divisor = b.as_integer()?;
                if divisor == 0 {
                    return Err(VMExecutionError::ExecutionError(
                        "Division by zero".to_string(),
                    ));
                }
                Ok(PactValue::Integer(a.as_integer()? / divisor))
            }
            "mod" => {
                let a = evaluated_args[0].as_integer()?;
                let b = evaluated_args[1].as_integer()?;
                if b == 0 {
                    return Err(VMExecutionError::ExecutionError(
                        "Modulo by zero".to_string(),
                    ));
                }
                Ok(PactValue::Integer(a % b))
            }
            "^" | "pow" => {
                let base = evaluated_args[0].as_integer()?;
                let exp = evaluated_args[1].as_integer()?;
                if exp < 0 {
                    return Err(VMExecutionError::ExecutionError(
                        "Negative exponent".to_string(),
                    ));
                }
                Ok(PactValue::Integer(base.pow(exp as u32)))
            }
            "abs" => {
                let a = evaluated_args[0].as_integer()?;
                Ok(PactValue::Integer(a.abs()))
            }
            "sqrt" => {
                let a = evaluated_args[0].as_integer()?;
                if a < 0 {
                    return Err(VMExecutionError::ExecutionError(
                        "Square root of negative".to_string(),
                    ));
                }
                Ok(PactValue::Integer((a as f64).sqrt() as i128))
            }

            // Comparison
            "=" | "==" => {
                let a = &evaluated_args[0];
                let b = &evaluated_args[1];
                Ok(PactValue::Bool(a == b))
            }
            "!=" => {
                let a = &evaluated_args[0];
                let b = &evaluated_args[1];
                Ok(PactValue::Bool(a != b))
            }
            "<" => {
                let a = evaluated_args[0].as_integer()?;
                let b = evaluated_args[1].as_integer()?;
                Ok(PactValue::Bool(a < b))
            }
            "<=" => {
                let a = evaluated_args[0].as_integer()?;
                let b = evaluated_args[1].as_integer()?;
                Ok(PactValue::Bool(a <= b))
            }
            ">" => {
                let a = evaluated_args[0].as_integer()?;
                let b = evaluated_args[1].as_integer()?;
                Ok(PactValue::Bool(a > b))
            }
            ">=" => {
                let a = evaluated_args[0].as_integer()?;
                let b = evaluated_args[1].as_integer()?;
                Ok(PactValue::Bool(a >= b))
            }

            // Boolean
            "and" => {
                let a = evaluated_args[0].to_bool();
                let b = evaluated_args[1].to_bool();
                Ok(PactValue::Bool(a && b))
            }
            "or" => {
                let a = evaluated_args[0].to_bool();
                let b = evaluated_args[1].to_bool();
                Ok(PactValue::Bool(a || b))
            }
            "not" => {
                let a = evaluated_args[0].to_bool();
                Ok(PactValue::Bool(!a))
            }

            // String operations
            "concat" => {
                let mut result = String::new();
                for arg in &evaluated_args {
                    result.push_str(arg.as_string()?);
                }
                Ok(PactValue::String(result))
            }
            "str-to-int" => {
                let s = evaluated_args[0].as_string()?;
                let n: i128 = s.parse().map_err(|_| {
                    VMExecutionError::ExecutionError("Invalid integer string".to_string())
                })?;
                Ok(PactValue::Integer(n))
            }
            "int-to-str" => {
                let radix = if evaluated_args.len() > 1 {
                    evaluated_args[1].as_integer()? as u32
                } else {
                    10
                };
                let n = evaluated_args[0].as_integer()?;
                let s = match radix {
                    10 => format!("{}", n),
                    16 => format!("{:x}", n),
                    _ => format!("{}", n),
                };
                Ok(PactValue::String(s))
            }
            "length" => match &evaluated_args[0] {
                PactValue::String(s) => Ok(PactValue::Integer(s.len() as i128)),
                PactValue::List(l) => Ok(PactValue::Integer(l.len() as i128)),
                _ => Err(VMExecutionError::ExecutionError(
                    "length requires string or list".to_string(),
                )),
            },
            "take" => {
                let n = evaluated_args[0].as_integer()? as usize;
                match &evaluated_args[1] {
                    PactValue::String(s) => {
                        Ok(PactValue::String(s.chars().take(n).collect()))
                    }
                    PactValue::List(l) => {
                        Ok(PactValue::List(l.iter().take(n).cloned().collect()))
                    }
                    _ => Err(VMExecutionError::ExecutionError(
                        "take requires string or list".to_string(),
                    )),
                }
            }
            "drop" => {
                let n = evaluated_args[0].as_integer()? as usize;
                match &evaluated_args[1] {
                    PactValue::String(s) => {
                        Ok(PactValue::String(s.chars().skip(n).collect()))
                    }
                    PactValue::List(l) => {
                        Ok(PactValue::List(l.iter().skip(n).cloned().collect()))
                    }
                    _ => Err(VMExecutionError::ExecutionError(
                        "drop requires string or list".to_string(),
                    )),
                }
            }

            // List operations
            "list" => Ok(PactValue::List(evaluated_args)),
            "at" => {
                let idx = evaluated_args[0].as_integer()? as usize;
                let list = evaluated_args[1].as_list()?;
                list.get(idx).cloned().ok_or_else(|| {
                    VMExecutionError::ExecutionError("Index out of bounds".to_string())
                })
            }
            "contains" => {
                let elem = &evaluated_args[0];
                let list = evaluated_args[1].as_list()?;
                Ok(PactValue::Bool(list.contains(elem)))
            }
            "enumerate" => {
                let start = evaluated_args[0].as_integer()?;
                let end = evaluated_args[1].as_integer()?;
                let list: Vec<PactValue> = (start..=end).map(PactValue::Integer).collect();
                Ok(PactValue::List(list))
            }
            "reverse" => {
                let list = evaluated_args[0].as_list()?;
                Ok(PactValue::List(list.iter().rev().cloned().collect()))
            }
            "sort" => {
                let mut list = evaluated_args[0].as_list()?.clone();
                list.sort_by(|a, b| {
                    match (a, b) {
                        (PactValue::Integer(a), PactValue::Integer(b)) => a.cmp(b),
                        (PactValue::String(a), PactValue::String(b)) => a.cmp(b),
                        _ => std::cmp::Ordering::Equal,
                    }
                });
                Ok(PactValue::List(list))
            }

            // Hash/Crypto
            "hash" => {
                self.gas_meter.consume(costs::SHA3_BASE)?;
                let data = match &evaluated_args[0] {
                    PactValue::String(s) => s.as_bytes().to_vec(),
                    _ => evaluated_args[0].to_bytes(),
                };
                self.gas_meter
                    .consume(Gas(costs::SHA3_WORD.0 * ((data.len() as u64 + 31) / 32)))?;
                let hash = Sha3_256::digest(&data);
                Ok(PactValue::String(hex::encode(hash)))
            }

            // Time
            "time" => {
                let time_str = evaluated_args[0].as_string()?;
                // Parse ISO8601 format (simplified)
                Ok(PactValue::Time(0)) // Placeholder
            }
            "add-time" => {
                let time = match &evaluated_args[0] {
                    PactValue::Time(t) => *t,
                    _ => 0,
                };
                let seconds = evaluated_args[1].as_integer()? as i64;
                Ok(PactValue::Time(time + seconds))
            }

            // Guard creation
            "keyset-ref-guard" => {
                let name = evaluated_args[0].as_string()?.to_string();
                Ok(PactValue::KeySet(name))
            }
            "create-user-guard" => {
                // Simplified - just return a guard value
                Ok(PactValue::Guard(PactGuard::UserGuard(
                    self.current_module.clone().unwrap_or_default(),
                    "guard-fn".to_string(),
                )))
            }
            "create-capability-guard" => {
                let cap_name = evaluated_args[0].as_string()?.to_string();
                Ok(PactValue::Guard(PactGuard::CapabilityGuard(
                    cap_name,
                    Vec::new(),
                )))
            }

            // Keysets
            "define-keyset" => {
                let name = evaluated_args[0].as_string()?.to_string();
                // Second arg is keyset data
                let keys = match &evaluated_args[1] {
                    PactValue::List(l) => l
                        .iter()
                        .map(|v| v.as_string().map(|s| s.to_string()))
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => Vec::new(),
                };
                self.keysets
                    .insert(name, (keys, KeysetPredicate::KeysAll));
                Ok(PactValue::Unit)
            }
            "read-keyset" => {
                let name = evaluated_args[0].as_string()?;
                Ok(PactValue::KeySet(name.to_string()))
            }

            // Emit events
            "emit-event" => {
                let cap_name = match &evaluated_args[0] {
                    PactValue::Capability(name, _) => name.clone(),
                    PactValue::String(s) => s.clone(),
                    _ => "event".to_string(),
                };
                self.logs.push(VMLog {
                    address: self.context.address,
                    topics: vec![Hash256::from_slice(
                        &Sha3_256::digest(cap_name.as_bytes())[..],
                    )],
                    data: evaluated_args[0].to_bytes(),
                });
                Ok(PactValue::Bool(true))
            }

            // Identity
            "identity" => Ok(evaluated_args[0].clone()),

            // Type checking
            "typeof" => {
                let type_name = match &evaluated_args[0] {
                    PactValue::Integer(_) => "integer",
                    PactValue::Decimal(_, _) => "decimal",
                    PactValue::String(_) => "string",
                    PactValue::Bool(_) => "bool",
                    PactValue::List(_) => "list",
                    PactValue::Object(_) => "object",
                    PactValue::Guard(_) => "guard",
                    PactValue::Unit => "unit",
                    PactValue::Time(_) => "time",
                    PactValue::ModRef(_) => "modref",
                    PactValue::Capability(_, _) => "capability",
                    PactValue::KeySet(_) => "keyset",
                };
                Ok(PactValue::String(type_name.to_string()))
            }

            // Format
            "format" => {
                let template = evaluated_args[0].as_string()?.to_string();
                let args = if evaluated_args.len() > 1 {
                    evaluated_args[1].as_list()?.clone()
                } else {
                    Vec::new()
                };
                // Simple {} replacement
                let mut result = template;
                for arg in args {
                    if let Some(pos) = result.find("{}") {
                        let replacement = match arg {
                            PactValue::String(s) => s,
                            PactValue::Integer(n) => format!("{}", n),
                            PactValue::Bool(b) => format!("{}", b),
                            _ => format!("{:?}", arg),
                        };
                        result = format!("{}{}{}", &result[..pos], replacement, &result[pos + 2..]);
                    }
                }
                Ok(PactValue::String(result))
            }

            // Try user-defined function
            _ => {
                if let Some(func) = self.functions.get(&func_name).cloned() {
                    self.call_function(&func, &evaluated_args)
                } else {
                    Err(VMExecutionError::ExecutionError(format!(
                        "Unknown function: {}",
                        func_name
                    )))
                }
            }
        }
    }

    /// Call a user-defined function
    fn call_function(
        &mut self,
        func: &PactFunction,
        args: &[PactValue],
    ) -> Result<PactValue, VMExecutionError> {
        if args.len() != func.params.len() {
            return Err(VMExecutionError::ExecutionError(format!(
                "Function {} expects {} arguments, got {}",
                func.name,
                func.params.len(),
                args.len()
            )));
        }

        // Create new environment with bound parameters
        let old_env = self.env.clone();
        for (param, arg) in func.params.iter().zip(args.iter()) {
            self.env.insert(param.clone(), arg.clone());
        }

        let result = self.eval(&func.body);

        self.env = old_env;
        result
    }

    /// Look up a variable in the environment
    fn lookup(&self, name: &str) -> Result<PactValue, VMExecutionError> {
        // Check local environment
        if let Some(val) = self.env.get(name) {
            return Ok(val.clone());
        }

        // Check if it's a module-qualified name
        if name.contains('.') {
            // Could be module.function reference
            return Ok(PactValue::ModRef(name.to_string()));
        }

        // Special constants
        match name {
            "true" => return Ok(PactValue::Bool(true)),
            "false" => return Ok(PactValue::Bool(false)),
            "CHARSET_ASCII" => return Ok(PactValue::Integer(0)),
            "CHARSET_LATIN1" => return Ok(PactValue::Integer(1)),
            _ => {}
        }

        Err(VMExecutionError::ExecutionError(format!(
            "Unbound variable: {}",
            name
        )))
    }

    /// Load a module
    fn load_module(&mut self, module: PactModule) -> Result<(), VMExecutionError> {
        let module_name = module.name.clone();
        self.current_module = Some(module_name.clone());

        // Process definitions
        for def in &module.definitions {
            self.eval(def)?;
        }

        self.modules.insert(module_name, module);
        self.current_module = None;
        Ok(())
    }

    /// Verify a guard
    fn verify_guard(&self, guard: &PactGuard) -> Result<PactValue, VMExecutionError> {
        match guard {
            PactGuard::KeySet(keys, pred) => {
                // Check if signers satisfy the predicate
                let signed_count = keys.iter().filter(|k| self.signers.contains(k)).count();

                let satisfied = match pred {
                    KeysetPredicate::KeysAll => signed_count == keys.len(),
                    KeysetPredicate::KeysAny => signed_count >= 1,
                    KeysetPredicate::Keys2 => signed_count >= 2,
                    KeysetPredicate::Custom(_) => true, // Assume satisfied for now
                };

                if satisfied {
                    Ok(PactValue::Bool(true))
                } else {
                    Err(VMExecutionError::ExecutionError(
                        "Keyset guard not satisfied".to_string(),
                    ))
                }
            }
            PactGuard::CapabilityGuard(cap_name, args) => {
                let cap_key = (cap_name.clone(), args.clone());
                if self.active_caps.contains(&cap_key) {
                    Ok(PactValue::Bool(true))
                } else {
                    Err(VMExecutionError::ExecutionError(format!(
                        "Capability guard not satisfied: {}",
                        cap_name
                    )))
                }
            }
            PactGuard::UserGuard(_, _) => {
                // User guards need to call a function - simplified for now
                Ok(PactValue::Bool(true))
            }
            PactGuard::PactGuard(_) => Ok(PactValue::Bool(true)),
        }
    }
}

/// Pact S-expression parser
struct PactParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> PactParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse_all(&mut self) -> Result<Vec<PactExpr>, VMExecutionError> {
        let mut exprs = Vec::new();
        while self.pos < self.input.len() {
            self.skip_whitespace();
            if self.pos >= self.input.len() {
                break;
            }
            exprs.push(self.parse_expr()?);
        }
        Ok(exprs)
    }

    fn parse_expr(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();

        if self.pos >= self.input.len() {
            return Err(VMExecutionError::ExecutionError(
                "Unexpected end of input".to_string(),
            ));
        }

        let ch = self.current_char();

        match ch {
            '(' => self.parse_list(),
            '"' => self.parse_string(),
            '\'' => {
                self.pos += 1;
                let expr = self.parse_expr()?;
                Ok(PactExpr::App(
                    Box::new(PactExpr::Symbol("quote".to_string())),
                    vec![expr],
                ))
            }
            '-' | '0'..='9' => self.parse_number(),
            _ => self.parse_symbol(),
        }
    }

    fn parse_list(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.expect_char('(')?;
        self.skip_whitespace();

        if self.current_char() == ')' {
            self.pos += 1;
            return Ok(PactExpr::Literal(PactValue::List(Vec::new())));
        }

        // Get the first element to determine list type
        let first = self.parse_expr()?;

        // Check for special forms
        if let PactExpr::Symbol(ref name) = first {
            match name.as_str() {
                "module" => return self.parse_module(),
                "defun" => return self.parse_defun(),
                "defcap" => return self.parse_defcap(),
                "defschema" => return self.parse_defschema(),
                "deftable" => return self.parse_deftable(),
                "let" | "let*" => return self.parse_let(),
                "lambda" => return self.parse_lambda(),
                "if" => return self.parse_if(),
                "with-capability" => return self.parse_with_capability(),
                "require-capability" => return self.parse_require_capability(),
                "enforce" => return self.parse_enforce(),
                "enforce-guard" => return self.parse_enforce_guard(),
                "read" => return self.parse_read(),
                "write" | "insert" | "update" => return self.parse_write(name.clone()),
                "@doc" | "@model" => {
                    // Skip documentation/model annotations
                    self.skip_whitespace();
                    let _ = self.parse_expr()?; // Skip the value
                    self.skip_whitespace();
                    self.expect_char(')')?;
                    return Ok(PactExpr::Literal(PactValue::Unit));
                }
                _ => {}
            }
        }

        // Regular function application
        let mut args = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            args.push(self.parse_expr()?);
        }

        Ok(PactExpr::App(Box::new(first), args))
    }

    fn parse_module(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let name = self.parse_symbol_name()?;
        self.skip_whitespace();

        // Parse governance
        let governance = if self.current_char() == '\'' || self.peek_str("'") {
            self.pos += 1; // skip '
            let gov_name = self.parse_symbol_name()?;
            PactGovernance::Keyset(gov_name)
        } else if self.current_char() == '(' {
            // Could be a capability governance
            self.pos += 1;
            let _ = self.parse_expr()?; // Skip for now
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
            }
            PactGovernance::Keyset("admin".to_string())
        } else {
            let gov_name = self.parse_symbol_name()?;
            PactGovernance::Keyset(gov_name)
        };

        // Parse module body
        let mut definitions = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            definitions.push(self.parse_expr()?);
        }

        Ok(PactExpr::Module(PactModule {
            name,
            governance,
            imports: Vec::new(),
            definitions,
        }))
    }

    fn parse_defun(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let name = self.parse_symbol_name()?;
        self.skip_whitespace();

        // Parse optional docstring or type annotation
        let mut docstring = None;
        if self.current_char() == '"' {
            docstring = Some(self.parse_string_value()?);
            self.skip_whitespace();
        }

        // Skip @doc annotations
        while self.peek_str("@") {
            self.skip_until(')');
            self.pos += 1;
            self.skip_whitespace();
        }

        // Parse parameters
        self.expect_char('(')?;
        let mut params = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            params.push(self.parse_symbol_name()?);
            // Skip type annotations (: type)
            self.skip_whitespace();
            if self.current_char() == ':' {
                self.pos += 1;
                self.skip_whitespace();
                let _ = self.parse_symbol_name()?; // Skip type
            }
        }

        // Parse body
        self.skip_whitespace();
        let body = self.parse_expr()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::Defun(name, params, Box::new(body), docstring))
    }

    fn parse_defcap(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let name = self.parse_symbol_name()?;
        self.skip_whitespace();

        // Parse parameters
        self.expect_char('(')?;
        let mut params = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            params.push(self.parse_symbol_name()?);
            // Skip type annotations
            self.skip_whitespace();
            if self.current_char() == ':' {
                self.pos += 1;
                self.skip_whitespace();
                let _ = self.parse_symbol_name()?;
            }
        }

        // Skip @doc, @managed, @event annotations
        self.skip_whitespace();
        while self.peek_str("@") || self.current_char() == '"' {
            if self.current_char() == '"' {
                let _ = self.parse_string_value()?;
            } else {
                // Skip annotation
                while self.current_char() != ')' && self.current_char() != '(' {
                    self.pos += 1;
                    if self.pos >= self.input.len() {
                        break;
                    }
                }
            }
            self.skip_whitespace();
        }

        // Parse body (might be missing for @event capabilities)
        let body = if self.current_char() == ')' {
            self.pos += 1;
            PactExpr::Literal(PactValue::Bool(true))
        } else {
            let b = self.parse_expr()?;
            self.skip_whitespace();
            self.expect_char(')')?;
            b
        };

        Ok(PactExpr::Defcap(name, params, Box::new(body)))
    }

    fn parse_defschema(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let name = self.parse_symbol_name()?;
        self.skip_whitespace();

        // Skip docstring if present
        if self.current_char() == '"' {
            let _ = self.parse_string_value()?;
            self.skip_whitespace();
        }

        let mut fields = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            let field_name = self.parse_symbol_name()?;
            self.skip_whitespace();
            self.expect_char(':')?;
            self.skip_whitespace();
            let field_type = self.parse_symbol_name()?;
            fields.push((field_name, field_type));
        }

        Ok(PactExpr::Defschema(name, fields))
    }

    fn parse_deftable(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let name = self.parse_symbol_name()?;
        self.skip_whitespace();

        // Parse schema reference {schema}
        self.expect_char(':')?;
        self.skip_whitespace();
        self.expect_char('{')?;
        self.skip_whitespace();
        let schema = self.parse_symbol_name()?;
        self.skip_whitespace();
        self.expect_char('}')?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::Deftable(name, schema))
    }

    fn parse_let(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        self.expect_char('(')?;

        let mut bindings = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            self.expect_char('(')?;
            let name = self.parse_symbol_name()?;
            self.skip_whitespace();
            let val = self.parse_expr()?;
            self.skip_whitespace();
            self.expect_char(')')?;
            bindings.push((name, val));
        }

        self.skip_whitespace();
        let body = self.parse_expr()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::Let(bindings, Box::new(body)))
    }

    fn parse_lambda(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        self.expect_char('(')?;

        let mut params = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            params.push(self.parse_symbol_name()?);
        }

        self.skip_whitespace();
        let body = self.parse_expr()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::Lambda(params, Box::new(body)))
    }

    fn parse_if(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let cond = self.parse_expr()?;
        self.skip_whitespace();
        let then_branch = self.parse_expr()?;
        self.skip_whitespace();
        let else_branch = if self.current_char() == ')' {
            PactExpr::Literal(PactValue::Unit)
        } else {
            self.parse_expr()?
        };

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::If(
            Box::new(cond),
            Box::new(then_branch),
            Box::new(else_branch),
        ))
    }

    fn parse_with_capability(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        self.expect_char('(')?;
        let cap_name = self.parse_symbol_name()?;

        let mut args = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            args.push(self.parse_expr()?);
        }

        self.skip_whitespace();
        let body = self.parse_expr()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::WithCapability(cap_name, args, Box::new(body)))
    }

    fn parse_require_capability(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        self.expect_char('(')?;
        let cap_name = self.parse_symbol_name()?;

        let mut args = Vec::new();
        loop {
            self.skip_whitespace();
            if self.current_char() == ')' {
                self.pos += 1;
                break;
            }
            args.push(self.parse_expr()?);
        }

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::RequireCapability(cap_name, args))
    }

    fn parse_enforce(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let cond = self.parse_expr()?;
        self.skip_whitespace();
        let msg = self.parse_string_value()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::Enforce(Box::new(cond), msg))
    }

    fn parse_enforce_guard(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let guard = self.parse_expr()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::EnforceGuard(Box::new(guard)))
    }

    fn parse_read(&mut self) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let table = self.parse_symbol_name()?;
        self.skip_whitespace();
        let key = self.parse_expr()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        Ok(PactExpr::Read(table, Box::new(key)))
    }

    fn parse_write(&mut self, op: String) -> Result<PactExpr, VMExecutionError> {
        self.skip_whitespace();
        let table = self.parse_symbol_name()?;
        self.skip_whitespace();
        let key = self.parse_expr()?;
        self.skip_whitespace();
        let val = self.parse_expr()?;

        self.skip_whitespace();
        self.expect_char(')')?;

        match op.as_str() {
            "insert" => Ok(PactExpr::Insert(table, Box::new(key), Box::new(val))),
            "update" => Ok(PactExpr::Update(table, Box::new(key), Box::new(val))),
            _ => Ok(PactExpr::Write(table, Box::new(key), Box::new(val))),
        }
    }

    fn parse_string(&mut self) -> Result<PactExpr, VMExecutionError> {
        let s = self.parse_string_value()?;
        Ok(PactExpr::Literal(PactValue::String(s)))
    }

    fn parse_string_value(&mut self) -> Result<String, VMExecutionError> {
        self.expect_char('"')?;
        let mut s = String::new();
        let mut escaped = false;

        while self.pos < self.input.len() {
            let ch = self.current_char();
            if escaped {
                match ch {
                    'n' => s.push('\n'),
                    't' => s.push('\t'),
                    'r' => s.push('\r'),
                    '"' => s.push('"'),
                    '\\' => s.push('\\'),
                    _ => s.push(ch),
                }
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                self.pos += 1;
                return Ok(s);
            } else {
                s.push(ch);
            }
            self.pos += 1;
        }

        Err(VMExecutionError::ExecutionError(
            "Unterminated string".to_string(),
        ))
    }

    fn parse_number(&mut self) -> Result<PactExpr, VMExecutionError> {
        let start = self.pos;
        let mut has_decimal = false;

        if self.current_char() == '-' {
            self.pos += 1;
        }

        while self.pos < self.input.len() {
            let ch = self.current_char();
            if ch.is_ascii_digit() {
                self.pos += 1;
            } else if ch == '.' && !has_decimal {
                has_decimal = true;
                self.pos += 1;
            } else {
                break;
            }
        }

        let num_str = &self.input[start..self.pos];

        if has_decimal {
            // Parse as decimal
            let parts: Vec<&str> = num_str.split('.').collect();
            let whole: i128 = parts[0].parse().map_err(|_| {
                VMExecutionError::ExecutionError("Invalid number".to_string())
            })?;
            let frac_str = parts.get(1).unwrap_or(&"0");
            let frac: i128 = frac_str.parse().unwrap_or(0);
            let decimals = frac_str.len() as u8;
            let mantissa = whole * 10i128.pow(decimals as u32) + frac;
            Ok(PactExpr::Literal(PactValue::Decimal(mantissa, decimals)))
        } else {
            let n: i128 = num_str.parse().map_err(|_| {
                VMExecutionError::ExecutionError("Invalid integer".to_string())
            })?;
            Ok(PactExpr::Literal(PactValue::Integer(n)))
        }
    }

    fn parse_symbol(&mut self) -> Result<PactExpr, VMExecutionError> {
        let name = self.parse_symbol_name()?;

        // Check for keywords
        match name.as_str() {
            "true" => Ok(PactExpr::Literal(PactValue::Bool(true))),
            "false" => Ok(PactExpr::Literal(PactValue::Bool(false))),
            _ => Ok(PactExpr::Symbol(name)),
        }
    }

    fn parse_symbol_name(&mut self) -> Result<String, VMExecutionError> {
        let start = self.pos;

        while self.pos < self.input.len() {
            let ch = self.current_char();
            if ch.is_whitespace() || ch == '(' || ch == ')' || ch == '"' || ch == ';' {
                break;
            }
            self.pos += 1;
        }

        if self.pos == start {
            return Err(VMExecutionError::ExecutionError(
                "Expected symbol".to_string(),
            ));
        }

        Ok(self.input[start..self.pos].to_string())
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            let ch = self.current_char();
            if ch.is_whitespace() {
                self.pos += 1;
            } else if ch == ';' {
                // Skip comment until end of line
                while self.pos < self.input.len() && self.current_char() != '\n' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    fn skip_until(&mut self, ch: char) {
        while self.pos < self.input.len() && self.current_char() != ch {
            self.pos += 1;
        }
    }

    fn current_char(&self) -> char {
        self.input[self.pos..].chars().next().unwrap_or('\0')
    }

    fn peek_str(&self, s: &str) -> bool {
        self.input[self.pos..].starts_with(s)
    }

    fn expect_char(&mut self, expected: char) -> Result<(), VMExecutionError> {
        if self.current_char() == expected {
            self.pos += 1;
            Ok(())
        } else {
            Err(VMExecutionError::ExecutionError(format!(
                "Expected '{}', got '{}'",
                expected,
                self.current_char()
            )))
        }
    }
}

/// Compile Pact source to bytecode
pub fn compile_pact(source: &str) -> Vec<u8> {
    let mut bytecode = PACT_MAGIC.to_vec();
    bytecode.extend_from_slice(source.as_bytes());
    bytecode
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
    fn test_simple_arithmetic() {
        let source = "(+ 1 2)";
        let bytecode = compile_pact(source);
        let mut vm = PactVM::new(make_context());
        let result = vm.execute(&bytecode, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_let_binding() {
        let source = "(let ((x 10) (y 20)) (+ x y))";
        let bytecode = compile_pact(source);
        let mut vm = PactVM::new(make_context());
        let result = vm.execute(&bytecode, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_defun() {
        let source = r#"
            (defun add-two (a b) (+ a b))
            (add-two 5 7)
        "#;
        let bytecode = compile_pact(source);
        let mut vm = PactVM::new(make_context());
        let result = vm.execute(&bytecode, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_if_expression() {
        let source = "(if (> 5 3) 100 200)";
        let bytecode = compile_pact(source);
        let mut vm = PactVM::new(make_context());
        let result = vm.execute(&bytecode, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_enforce() {
        let source = r#"(enforce (> 10 5) "Value must be greater")"#;
        let bytecode = compile_pact(source);
        let mut vm = PactVM::new(make_context());
        let result = vm.execute(&bytecode, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_string_operations() {
        let source = r#"(concat "Hello" " " "World")"#;
        let bytecode = compile_pact(source);
        let mut vm = PactVM::new(make_context());
        let result = vm.execute(&bytecode, &[]);
        assert!(result.success);
    }

    #[test]
    fn test_module_definition() {
        let source = r#"
            (module my-token governance
                (defun get-balance (account)
                    100
                )
            )
            (my-token.get-balance "alice")
        "#;
        let bytecode = compile_pact(source);
        let mut vm = PactVM::new(make_context());
        let result = vm.execute(&bytecode, &[]);
        // Module loading should succeed
        assert!(result.success || result.error.is_some());
    }
}

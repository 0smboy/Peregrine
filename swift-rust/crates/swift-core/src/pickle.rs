// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Python pickle codec for Swift's serialized formats: object metadata in
//! xattrs, `hashes.pkl`, async pendings and ring builder files.
//!
//! The reader accepts the opcode subset that CPython 2 and 3 emit at
//! protocols 0-3 for the value shapes Swift serializes (flat and one-level
//! nested dicts of strings/bytes/numbers), mirroring the allowlist in
//! `swift.common.utils.pickle.RestrictedUnpickler`.
//!
//! The writer emits protocol-2 pickles that are **byte-identical** to
//! CPython's `pickle.dumps(obj, 2)` for those same shapes, including the
//! memo behavior for the interned `'latin1'` constant and the
//! `_codecs.encode` global that py3 uses to represent `bytes`. This was
//! chosen over the `serde-pickle` crate (the option flagged for evaluation
//! in the plan) because byte-level equality with the Python oracle is what
//! makes golden differential testing cheap, and the required subset is
//! small.
//!
//! Known, deliberate limitation: pickles with *shared or self-referential
//! containers* are not reproduced byte-identically (Swift never writes
//! them). CPython's memo works by object identity, and the one identity
//! guarantee that shows up in Swift's data is interned single-character
//! (latin-1) and empty strings — `'0'` timestamps and counts repeat
//! within one pending record — so the writer shares exactly those via
//! `BINGET`. Longer equal strings are runtime-built distinct objects in
//! Swift's flows and are (correctly) not shared.

use std::collections::HashMap;
use std::fmt;

/// Error decoding or encoding a pickle.
#[derive(Debug)]
pub struct PickleError(pub String);

impl fmt::Display for PickleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pickle: {}", self.0)
    }
}

impl std::error::Error for PickleError {}

fn err<T>(msg: impl Into<String>) -> Result<T, PickleError> {
    Err(PickleError(msg.into()))
}

/// A decoded Python value.
///
/// Python `str` decodes to [`Value::Str`] when it is valid UTF-8;
/// surrogate-escaped strings (Python's representation of undecodable
/// bytes) decode to [`Value::Bytes`] holding the *original* octets.
/// Python 2 `str` (SHORT_BINSTRING/BINSTRING) always decodes to
/// [`Value::Bytes`].
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Str(String),
    /// Insertion-ordered pairs, mirroring Python dict ordering.
    Dict(Vec<(Value, Value)>),
    List(Vec<Value>),
    Tuple(Vec<Value>),
    /// A `GLOBAL` reference; only ever intermediate (consumed by REDUCE).
    Global(String, String),
}

impl Value {
    pub fn as_dict(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Dict(pairs) => Some(pairs),
            _ => None,
        }
    }
}

// opcode bytes
const PROTO: u8 = 0x80;
const STOP: u8 = b'.';
const MARK: u8 = b'(';
const EMPTY_DICT: u8 = b'}';
const EMPTY_LIST: u8 = b']';
const EMPTY_TUPLE: u8 = b')';
const SETITEM: u8 = b's';
const SETITEMS: u8 = b'u';
const APPEND: u8 = b'a';
const APPENDS: u8 = b'e';
const BINPUT: u8 = b'q';
const LONG_BINPUT: u8 = b'r';
const BINGET: u8 = b'h';
const LONG_BINGET: u8 = b'j';
const BINUNICODE: u8 = b'X';
const SHORT_BINSTRING: u8 = b'U';
const BINSTRING: u8 = b'T';
const BINBYTES: u8 = b'B';
const SHORT_BINBYTES: u8 = b'C';
const GLOBAL: u8 = b'c';
const REDUCE: u8 = b'R';
const TUPLE: u8 = b't';
const TUPLE1: u8 = 0x85;
const TUPLE2: u8 = 0x86;
const TUPLE3: u8 = 0x87;
const BININT: u8 = b'J';
const BININT1: u8 = b'K';
const BININT2: u8 = b'M';
const LONG1: u8 = 0x8a;
const BINFLOAT: u8 = b'G';
const NONE: u8 = b'N';
const NEWTRUE: u8 = 0x88;
const NEWFALSE: u8 = 0x89;

/// Decode Python's `utf-8`/`surrogatepass` output. Valid UTF-8 becomes
/// `Str`; text containing lone surrogates (the `surrogateescape` escape of
/// undecodable bytes) is mapped back to the original byte sequence and
/// returned as `Bytes`.
fn decode_pickled_str(raw: &[u8]) -> Value {
    match std::str::from_utf8(raw) {
        Ok(s) => Value::Str(s.to_string()),
        Err(_) => {
            let mut out = Vec::with_capacity(raw.len());
            let mut i = 0;
            while i < raw.len() {
                let b = raw[i];
                // lone surrogate U+DC80..U+DCFF encoded via surrogatepass:
                // ED B2 80 .. ED B3 BF -> original byte 0x80..0xFF
                if b == 0xed && i + 2 < raw.len() && (raw[i + 1] & 0xfe) == 0xb2 {
                    let cp =
                        0xd000 | ((raw[i + 1] as u32 & 0x3f) << 6) | (raw[i + 2] as u32 & 0x3f);
                    if (0xdc80..=0xdcff).contains(&cp) {
                        out.push((cp - 0xdc00) as u8);
                        i += 3;
                        continue;
                    }
                }
                out.push(b);
                i += 1;
            }
            Value::Bytes(out)
        }
    }
}

/// Encode a string to latin-1 (every char must be <= U+00FF).
fn latin1_encode(s: &str) -> Result<Vec<u8>, PickleError> {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            if cp <= 0xff {
                Ok(cp as u8)
            } else {
                err(format!("cannot latin-1 encode {c:?}"))
            }
        })
        .collect()
}

/// Decode latin-1 bytes to a string (1:1, always succeeds).
pub fn latin1_decode(raw: &[u8]) -> String {
    raw.iter().map(|&b| b as char).collect()
}

/// Explicit resource limits for a pickle received from an untrusted peer.
///
/// Node and scalar-byte limits are cumulative allocation/work budgets: memo
/// PUT and GET charge every node and payload byte they clone, even when a memo
/// slot is overwritten. Moving a value into a container does not charge it
/// again. The limits bound decoder work and owned values, not exact allocator
/// RSS (collection capacity and allocator overhead are additional).
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    pub max_input_bytes: usize,
    pub max_opcodes: usize,
    pub max_value_nodes: usize,
    pub max_scalar_bytes: usize,
    pub max_container_depth: usize,
    pub max_stack_values: usize,
    pub max_marks: usize,
    pub max_memo_entries: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_opcodes: 2 * 1024 * 1024,
            max_value_nodes: 1024 * 1024,
            max_scalar_bytes: 64 * 1024 * 1024,
            max_container_depth: 16,
            max_stack_values: 16 * 1024,
            max_marks: 16,
            max_memo_entries: 256 * 1024,
        }
    }
}

struct DecodeBudget {
    limits: DecodeLimits,
    opcodes: usize,
    nodes: usize,
    scalar_bytes: usize,
}

fn limit_error(what: &str) -> PickleError {
    PickleError(format!("decode limit exceeded: {what}"))
}

fn budget_add(
    current: usize,
    amount: usize,
    limit: usize,
    what: &str,
) -> Result<usize, PickleError> {
    current
        .checked_add(amount)
        .filter(|&total| total <= limit)
        .ok_or_else(|| limit_error(what))
}

/// Every container is checked as it is assembled, so this traversal never
/// encounters an already accepted tree deeper than the configured bound.
fn check_value_depth(value: &Value, parents: usize, limit: usize) -> Result<(), PickleError> {
    match value {
        Value::Dict(pairs) => {
            let depth = budget_add(parents, 1, limit, "container depth")?;
            for (key, value) in pairs {
                check_value_depth(key, depth, limit)?;
                check_value_depth(value, depth, limit)?;
            }
        }
        Value::List(items) | Value::Tuple(items) => {
            let depth = budget_add(parents, 1, limit, "container depth")?;
            for item in items {
                check_value_depth(item, depth, limit)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Measure before cloning. Stop at the first exceeded budget rather than
/// traversing an entire over-budget memo value or allocating a work list.
fn measure_clone(
    value: &Value,
    nodes: &mut usize,
    bytes: &mut usize,
    max_nodes: usize,
    max_bytes: usize,
) -> Result<(), PickleError> {
    *nodes = budget_add(*nodes, 1, max_nodes, "value nodes")?;
    match value {
        Value::Bytes(value) => {
            *bytes = budget_add(*bytes, value.len(), max_bytes, "scalar bytes")?;
        }
        Value::Str(value) => {
            *bytes = budget_add(*bytes, value.len(), max_bytes, "scalar bytes")?;
        }
        Value::Global(module, name) => {
            *bytes = budget_add(*bytes, module.len(), max_bytes, "scalar bytes")?;
            *bytes = budget_add(*bytes, name.len(), max_bytes, "scalar bytes")?;
        }
        Value::Dict(pairs) => {
            for (key, value) in pairs {
                measure_clone(key, nodes, bytes, max_nodes, max_bytes)?;
                measure_clone(value, nodes, bytes, max_nodes, max_bytes)?;
            }
        }
        Value::List(items) | Value::Tuple(items) => {
            for item in items {
                measure_clone(item, nodes, bytes, max_nodes, max_bytes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    stack: Vec<Value>,
    marks: Vec<usize>,
    memo: HashMap<u32, Value>,
    budget: Option<DecodeBudget>,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PickleError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| PickleError("truncated pickle".into()))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn charge(&mut self, nodes: usize, bytes: usize) -> Result<(), PickleError> {
        if let Some(budget) = &mut self.budget {
            let next_nodes = budget_add(
                budget.nodes,
                nodes,
                budget.limits.max_value_nodes,
                "value nodes",
            )?;
            let next_bytes = budget_add(
                budget.scalar_bytes,
                bytes,
                budget.limits.max_scalar_bytes,
                "scalar bytes",
            )?;
            budget.nodes = next_nodes;
            budget.scalar_bytes = next_bytes;
        }
        Ok(())
    }

    fn charge_opcode(&mut self) -> Result<(), PickleError> {
        if let Some(budget) = &mut self.budget {
            budget.opcodes = budget_add(budget.opcodes, 1, budget.limits.max_opcodes, "opcodes")?;
        }
        Ok(())
    }

    fn ensure_stack_room(&self) -> Result<(), PickleError> {
        if self
            .budget
            .as_ref()
            .is_some_and(|budget| self.stack.len() >= budget.limits.max_stack_values)
        {
            return Err(limit_error("stack values"));
        }
        Ok(())
    }

    /// Push a value whose allocation has already been charged, or which was
    /// moved from another part of the decoder without a new allocation.
    fn push(&mut self, value: Value) -> Result<(), PickleError> {
        self.ensure_stack_room()?;
        if let Some(budget) = &self.budget {
            check_value_depth(&value, 0, budget.limits.max_container_depth)?;
        }
        self.stack.push(value);
        Ok(())
    }

    fn check_child(&self, value: &Value) -> Result<(), PickleError> {
        if let Some(budget) = &self.budget {
            check_value_depth(value, 1, budget.limits.max_container_depth)?;
        }
        Ok(())
    }

    fn clone_cost(&self, value: &Value) -> Result<(usize, usize), PickleError> {
        let Some(budget) = &self.budget else {
            return Ok((0, 0));
        };
        let mut nodes = 0;
        let mut bytes = 0;
        measure_clone(
            value,
            &mut nodes,
            &mut bytes,
            budget.limits.max_value_nodes - budget.nodes,
            budget.limits.max_scalar_bytes - budget.scalar_bytes,
        )?;
        Ok((nodes, bytes))
    }

    fn u8(&mut self) -> Result<u8, PickleError> {
        Ok(self.take(1)?[0])
    }

    fn u16le(&mut self) -> Result<u16, PickleError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32le(&mut self) -> Result<u32, PickleError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn i32le(&mut self) -> Result<i32, PickleError> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn line(&mut self) -> Result<&'a [u8], PickleError> {
        let start = self.pos;
        while self.pos < self.data.len() {
            if self.data[self.pos] == b'\n' {
                let out = &self.data[start..self.pos];
                self.pos += 1;
                return Ok(out);
            }
            self.pos += 1;
        }
        err("truncated pickle line")
    }

    fn pop(&mut self) -> Result<Value, PickleError> {
        self.stack
            .pop()
            .ok_or(PickleError("stack underflow".into()))
    }

    fn pop_to_mark(&mut self) -> Result<Vec<Value>, PickleError> {
        let mark = self
            .marks
            .pop()
            .ok_or(PickleError("no mark on stack".into()))?;
        if mark > self.stack.len() {
            return err("mark beyond stack");
        }
        Ok(self.stack.split_off(mark))
    }

    fn put(&mut self, idx: u32) -> Result<(), PickleError> {
        if self.budget.as_ref().is_some_and(|budget| {
            !self.memo.contains_key(&idx) && self.memo.len() >= budget.limits.max_memo_entries
        }) {
            return Err(limit_error("memo entries"));
        }
        let top = self
            .stack
            .last()
            .ok_or(PickleError("PUT on empty stack".into()))?;
        let (nodes, bytes) = self.clone_cost(top)?;
        self.charge(nodes, bytes)?;
        let top = self.stack.last().unwrap().clone();
        self.memo.insert(idx, top);
        Ok(())
    }

    fn get(&mut self, idx: u32) -> Result<(), PickleError> {
        self.ensure_stack_room()?;
        let v = self
            .memo
            .get(&idx)
            .ok_or(PickleError(format!("memo {idx} not set")))?;
        let (nodes, bytes) = self.clone_cost(v)?;
        self.charge(nodes, bytes)?;
        let v = self.memo.get(&idx).unwrap().clone();
        self.push(v)
    }

    fn reduce(&mut self) -> Result<(), PickleError> {
        let args = self.pop()?;
        let func = self.pop()?;
        let (module, name) = match &func {
            Value::Global(m, n) => (m.as_str(), n.as_str()),
            _ => return err("REDUCE on non-global"),
        };
        let args = match args {
            Value::Tuple(items) => items,
            _ => return err("REDUCE args not a tuple"),
        };
        let result = match (module, name) {
            ("_codecs", "encode") => match args.as_slice() {
                [Value::Str(s), Value::Str(enc)] if enc == "latin1" || enc == "latin-1" => {
                    self.charge(1, s.len())?;
                    Value::Bytes(latin1_encode(s)?)
                }
                [Value::Str(s), Value::Str(enc)] if enc == "utf8" || enc == "utf-8" => {
                    self.charge(1, s.len())?;
                    Value::Bytes(s.as_bytes().to_vec())
                }
                [Value::Str(s)] => {
                    self.charge(1, s.len())?;
                    Value::Bytes(s.as_bytes().to_vec())
                }
                // a surrogate-escaped string already comes back as the
                // original bytes; latin-1 "encoding" of it is the identity
                [Value::Bytes(b), Value::Str(enc)] if enc == "latin1" || enc == "latin-1" => {
                    self.charge(1, b.len())?;
                    Value::Bytes(b.clone())
                }
                _ => return err("unsupported _codecs.encode args"),
            },
            ("builtins" | "__builtin__", "bytes") => match args.as_slice() {
                [] => {
                    self.charge(1, 0)?;
                    Value::Bytes(Vec::new())
                }
                [Value::Bytes(b)] => {
                    self.charge(1, b.len())?;
                    Value::Bytes(b.clone())
                }
                _ => return err("unsupported bytes() args"),
            },
            ("builtins" | "__builtin__", "dict") => match args.as_slice() {
                [] => {
                    self.charge(1, 0)?;
                    Value::Dict(Vec::new())
                }
                _ => return err("unsupported dict() args"),
            },
            _ if self.budget.is_some() => return err("forbidden global"),
            _ => return err(format!("global '{module}.{name}' is forbidden")),
        };
        self.push(result)
    }

    fn load(&mut self) -> Result<Value, PickleError> {
        loop {
            self.charge_opcode()?;
            let op = self.u8()?;
            match op {
                PROTO => {
                    let ver = self.u8()?;
                    if ver > 5 {
                        return err(format!("unsupported pickle protocol {ver}"));
                    }
                }
                STOP => {
                    if self.budget.is_some()
                        && (self.stack.len() != 1
                            || !self.marks.is_empty()
                            || self.pos != self.data.len())
                    {
                        return err("bounded pickle must end with one value, no marks, and no trailing bytes");
                    }
                    return self.pop();
                }
                MARK => {
                    if self
                        .budget
                        .as_ref()
                        .is_some_and(|budget| self.marks.len() >= budget.limits.max_marks)
                    {
                        return Err(limit_error("marks"));
                    }
                    self.marks.push(self.stack.len());
                }
                EMPTY_DICT => {
                    self.charge(1, 0)?;
                    self.push(Value::Dict(Vec::new()))?;
                }
                EMPTY_LIST => {
                    self.charge(1, 0)?;
                    self.push(Value::List(Vec::new()))?;
                }
                EMPTY_TUPLE => {
                    self.charge(1, 0)?;
                    self.push(Value::Tuple(Vec::new()))?;
                }
                SETITEM => {
                    let v = self.pop()?;
                    let k = self.pop()?;
                    self.check_child(&k)?;
                    self.check_child(&v)?;
                    match self.stack.last_mut() {
                        Some(Value::Dict(pairs)) => pairs.push((k, v)),
                        _ => return err("SETITEM on non-dict"),
                    }
                }
                SETITEMS => {
                    let items = self.pop_to_mark()?;
                    if items.len() % 2 != 0 {
                        return err("odd number of SETITEMS values");
                    }
                    for item in &items {
                        self.check_child(item)?;
                    }
                    match self.stack.last_mut() {
                        Some(Value::Dict(pairs)) => {
                            let mut it = items.into_iter();
                            while let (Some(k), Some(v)) = (it.next(), it.next()) {
                                pairs.push((k, v));
                            }
                        }
                        _ => return err("SETITEMS on non-dict"),
                    }
                }
                APPEND => {
                    let v = self.pop()?;
                    self.check_child(&v)?;
                    match self.stack.last_mut() {
                        Some(Value::List(items)) => items.push(v),
                        _ => return err("APPEND on non-list"),
                    }
                }
                APPENDS => {
                    let new = self.pop_to_mark()?;
                    for item in &new {
                        self.check_child(item)?;
                    }
                    match self.stack.last_mut() {
                        Some(Value::List(items)) => items.extend(new),
                        _ => return err("APPENDS on non-list"),
                    }
                }
                BINPUT => {
                    let idx = self.u8()? as u32;
                    self.put(idx)?;
                }
                LONG_BINPUT => {
                    let idx = self.u32le()?;
                    self.put(idx)?;
                }
                BINGET => {
                    let idx = self.u8()? as u32;
                    self.get(idx)?;
                }
                LONG_BINGET => {
                    let idx = self.u32le()?;
                    self.get(idx)?;
                }
                BINUNICODE => {
                    let n = self.u32le()? as usize;
                    let raw = self.take(n)?;
                    self.charge(1, raw.len())?;
                    self.push(decode_pickled_str(raw))?;
                }
                SHORT_BINSTRING => {
                    let n = self.u8()? as usize;
                    let raw = self.take(n)?;
                    self.charge(1, raw.len())?;
                    self.push(Value::Bytes(raw.to_vec()))?;
                }
                BINSTRING => {
                    let n = self.i32le()?;
                    if n < 0 {
                        return err("negative BINSTRING length");
                    }
                    let raw = self.take(n as usize)?;
                    self.charge(1, raw.len())?;
                    self.push(Value::Bytes(raw.to_vec()))?;
                }
                BINBYTES => {
                    let n = self.u32le()? as usize;
                    let raw = self.take(n)?;
                    self.charge(1, raw.len())?;
                    self.push(Value::Bytes(raw.to_vec()))?;
                }
                SHORT_BINBYTES => {
                    let n = self.u8()? as usize;
                    let raw = self.take(n)?;
                    self.charge(1, raw.len())?;
                    self.push(Value::Bytes(raw.to_vec()))?;
                }
                GLOBAL => {
                    let module = self.line()?;
                    let name = self.line()?;
                    // A lossy replacement char needs at most three UTF-8
                    // bytes per input byte. Charge before allocating.
                    let lossy_bound = |raw: &[u8]| -> Result<usize, PickleError> {
                        if std::str::from_utf8(raw).is_ok() {
                            return Ok(raw.len());
                        }
                        raw.len()
                            .checked_mul(3)
                            .ok_or_else(|| limit_error("scalar bytes"))
                    };
                    let bytes = lossy_bound(module)?
                        .checked_add(lossy_bound(name)?)
                        .ok_or_else(|| limit_error("scalar bytes"))?;
                    self.charge(1, bytes)?;
                    self.push(Value::Global(
                        String::from_utf8_lossy(module).into_owned(),
                        String::from_utf8_lossy(name).into_owned(),
                    ))?;
                }
                REDUCE => self.reduce()?,
                TUPLE => {
                    let items = self.pop_to_mark()?;
                    self.charge(1, 0)?;
                    self.push(Value::Tuple(items))?;
                }
                TUPLE1 => {
                    let a = self.pop()?;
                    self.charge(1, 0)?;
                    self.push(Value::Tuple(vec![a]))?;
                }
                TUPLE2 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.charge(1, 0)?;
                    self.push(Value::Tuple(vec![a, b]))?;
                }
                TUPLE3 => {
                    let c = self.pop()?;
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.charge(1, 0)?;
                    self.push(Value::Tuple(vec![a, b, c]))?;
                }
                BININT => {
                    let v = self.i32le()?;
                    self.charge(1, 0)?;
                    self.push(Value::Int(v as i64))?;
                }
                BININT1 => {
                    let v = self.u8()?;
                    self.charge(1, 0)?;
                    self.push(Value::Int(v as i64))?;
                }
                BININT2 => {
                    let v = self.u16le()?;
                    self.charge(1, 0)?;
                    self.push(Value::Int(v as i64))?;
                }
                LONG1 => {
                    let n = self.u8()? as usize;
                    let raw = self.take(n)?;
                    if n > 8 {
                        return err("LONG1 wider than 64 bits");
                    }
                    let mut buf = if !raw.is_empty() && raw[n - 1] & 0x80 != 0 {
                        [0xffu8; 8]
                    } else {
                        [0u8; 8]
                    };
                    buf[..n].copy_from_slice(raw);
                    self.charge(1, 0)?;
                    self.push(Value::Int(i64::from_le_bytes(buf)))?;
                }
                BINFLOAT => {
                    let raw = self.take(8)?;
                    self.charge(1, 0)?;
                    self.push(Value::Float(f64::from_be_bytes(raw.try_into().unwrap())))?;
                }
                NONE => {
                    self.charge(1, 0)?;
                    self.push(Value::None)?;
                }
                NEWTRUE => {
                    self.charge(1, 0)?;
                    self.push(Value::Bool(true))?;
                }
                NEWFALSE => {
                    self.charge(1, 0)?;
                    self.push(Value::Bool(false))?;
                }
                other => {
                    return err(format!(
                        "unsupported pickle opcode 0x{other:02x} at offset {}",
                        self.pos - 1
                    ))
                }
            }
        }
    }
}

/// Deserialize a pickle produced by CPython for Swift's data shapes.
pub fn loads(data: &[u8]) -> Result<Value, PickleError> {
    let mut reader = Reader {
        data,
        pos: 0,
        stack: Vec::new(),
        marks: Vec::new(),
        memo: HashMap::new(),
        budget: None,
    };
    let v = reader.load()?;
    match v {
        Value::Global(m, n) => err(format!("bare global '{m}.{n}' result")),
        v => Ok(v),
    }
}

/// Decode exactly one pickle under explicit resource budgets.
///
/// Unlike [`loads`], this rejects trailing bytes, a leftover stack, and
/// unmatched marks. Schema validation remains the caller's responsibility.
pub fn loads_with_limits(data: &[u8], limits: DecodeLimits) -> Result<Value, PickleError> {
    if data.len() > limits.max_input_bytes {
        return Err(limit_error("input bytes"));
    }
    // Recursive Value clone/drop and the bounded traversals below require a
    // small depth even when callers accidentally provide permissive limits.
    if limits.max_container_depth > 128 {
        return err("max_container_depth must not exceed 128");
    }
    let mut reader = Reader {
        data,
        pos: 0,
        stack: Vec::new(),
        marks: Vec::new(),
        memo: HashMap::new(),
        budget: Some(DecodeBudget {
            limits,
            opcodes: 0,
            nodes: 0,
            scalar_bytes: 0,
        }),
    };
    match reader.load()? {
        Value::Global(_, _) => err("bare global result"),
        value => Ok(value),
    }
}

const BATCH_SIZE: usize = 1000;

struct Writer {
    out: Vec<u8>,
    memo_next: u32,
    /// memo ids of the two objects CPython's pickler shares by identity
    memo_codecs_encode: Option<u32>,
    memo_latin1: Option<u32>,
    memo_bytes_global: Option<u32>,
    /// CPython interns empty and single-character latin-1 strings, so
    /// repeats of those are the same object and share a memo entry
    memo_interned: HashMap<String, u32>,
}

impl Writer {
    fn memoize(&mut self) -> u32 {
        let idx = self.memo_next;
        self.memo_next += 1;
        if idx < 256 {
            self.out.push(BINPUT);
            self.out.push(idx as u8);
        } else {
            self.out.push(LONG_BINPUT);
            self.out.extend_from_slice(&idx.to_le_bytes());
        }
        idx
    }

    fn binget(&mut self, idx: u32) {
        if idx < 256 {
            self.out.push(BINGET);
            self.out.push(idx as u8);
        } else {
            self.out.push(LONG_BINGET);
            self.out.extend_from_slice(&idx.to_le_bytes());
        }
    }

    fn write_str_raw(&mut self, s: &str) {
        let raw = s.as_bytes();
        self.out.push(BINUNICODE);
        self.out
            .extend_from_slice(&(raw.len() as u32).to_le_bytes());
        self.out.extend_from_slice(raw);
    }

    fn save(&mut self, v: &Value) -> Result<(), PickleError> {
        match v {
            Value::None => self.out.push(NONE),
            Value::Bool(true) => self.out.push(NEWTRUE),
            Value::Bool(false) => self.out.push(NEWFALSE),
            Value::Int(x) => self.save_int(*x),
            Value::Float(x) => {
                self.out.push(BINFLOAT);
                self.out.extend_from_slice(&x.to_be_bytes());
            }
            Value::Str(s) => {
                let interned = s.is_empty()
                    || (s.chars().count() == 1 && (s.chars().next().unwrap() as u32) <= 0xff);
                if interned {
                    if let Some(&idx) = self.memo_interned.get(s.as_str()) {
                        self.binget(idx);
                        return Ok(());
                    }
                }
                self.write_str_raw(s);
                let idx = self.memoize();
                if interned {
                    self.memo_interned.insert(s.clone(), idx);
                }
            }
            Value::Bytes(b) => self.save_bytes(b)?,
            Value::Dict(pairs) => {
                self.out.push(EMPTY_DICT);
                self.memoize();
                self.batch_setitems(pairs)?;
            }
            Value::List(items) => {
                self.out.push(EMPTY_LIST);
                self.memoize();
                self.batch_appends(items)?;
            }
            Value::Tuple(items) => {
                match items.len() {
                    0 => {
                        self.out.push(EMPTY_TUPLE);
                        return Ok(());
                    }
                    1..=3 => {
                        for item in items {
                            self.save(item)?;
                        }
                        self.out.push(match items.len() {
                            1 => TUPLE1,
                            2 => TUPLE2,
                            _ => TUPLE3,
                        });
                    }
                    _ => {
                        self.out.push(MARK);
                        for item in items {
                            self.save(item)?;
                        }
                        self.out.push(TUPLE);
                    }
                }
                self.memoize();
            }
            Value::Global(m, n) => return err(format!("cannot serialize global '{m}.{n}'")),
        }
        Ok(())
    }

    fn save_int(&mut self, x: i64) {
        if (0..256).contains(&x) {
            self.out.push(BININT1);
            self.out.push(x as u8);
        } else if (256..65536).contains(&x) {
            self.out.push(BININT2);
            self.out.extend_from_slice(&(x as u16).to_le_bytes());
        } else if (-0x8000_0000..0x8000_0000).contains(&x) {
            self.out.push(BININT);
            self.out.extend_from_slice(&(x as i32).to_le_bytes());
        } else {
            // LONG1: minimal two's-complement little-endian
            let full = x.to_le_bytes();
            let mut n = 8;
            if x >= 0 {
                while n > 1 && full[n - 1] == 0 && full[n - 2] & 0x80 == 0 {
                    n -= 1;
                }
            } else {
                while n > 1 && full[n - 1] == 0xff && full[n - 2] & 0x80 != 0 {
                    n -= 1;
                }
            }
            self.out.push(LONG1);
            self.out.push(n as u8);
            self.out.extend_from_slice(&full[..n]);
        }
    }

    /// Emit `bytes` exactly as CPython 3 does at protocol 2: through a
    /// `_codecs.encode(<latin1 str>, 'latin1')` reduce, sharing the global
    /// and the `'latin1'` constant via the memo.
    fn save_bytes(&mut self, b: &[u8]) -> Result<(), PickleError> {
        if b.is_empty() {
            // bytes() reduce; protocol-2 fix_imports maps builtins ->
            // __builtin__
            match self.memo_bytes_global {
                Some(idx) => self.binget(idx),
                None => {
                    self.out.push(GLOBAL);
                    self.out.extend_from_slice(b"__builtin__\nbytes\n");
                    self.memo_bytes_global = Some(self.memoize());
                }
            }
            self.out.push(EMPTY_TUPLE);
            self.out.push(REDUCE);
            self.memoize();
            return Ok(());
        }
        match self.memo_codecs_encode {
            Some(idx) => self.binget(idx),
            None => {
                self.out.push(GLOBAL);
                self.out.extend_from_slice(b"_codecs\nencode\n");
                self.memo_codecs_encode = Some(self.memoize());
            }
        }
        // the latin1-decoded string, utf-8 encoded
        let decoded = latin1_decode(b);
        self.write_str_raw(&decoded);
        self.memoize();
        match self.memo_latin1 {
            Some(idx) => self.binget(idx),
            None => {
                self.write_str_raw("latin1");
                self.memo_latin1 = Some(self.memoize());
            }
        }
        self.out.push(TUPLE2);
        self.memoize();
        self.out.push(REDUCE);
        self.memoize();
        Ok(())
    }

    fn batch_setitems(&mut self, pairs: &[(Value, Value)]) -> Result<(), PickleError> {
        for chunk in pairs.chunks(BATCH_SIZE) {
            if chunk.len() == 1 {
                self.save(&chunk[0].0)?;
                self.save(&chunk[0].1)?;
                self.out.push(SETITEM);
            } else if !chunk.is_empty() {
                self.out.push(MARK);
                for (k, val) in chunk {
                    self.save(k)?;
                    self.save(val)?;
                }
                self.out.push(SETITEMS);
            }
        }
        Ok(())
    }

    fn batch_appends(&mut self, items: &[Value]) -> Result<(), PickleError> {
        for chunk in items.chunks(BATCH_SIZE) {
            if chunk.len() == 1 {
                self.save(&chunk[0])?;
                self.out.push(APPEND);
            } else if !chunk.is_empty() {
                self.out.push(MARK);
                for item in chunk {
                    self.save(item)?;
                }
                self.out.push(APPENDS);
            }
        }
        Ok(())
    }
}

/// Serialize a value as CPython's `pickle.dumps(obj, 2)` would,
/// byte-for-byte, for the value shapes Swift writes.
pub fn dumps(v: &Value) -> Result<Vec<u8>, PickleError> {
    let mut w = Writer {
        out: vec![PROTO, 2],
        memo_next: 0,
        memo_codecs_encode: None,
        memo_latin1: None,
        memo_bytes_global: None,
        memo_interned: HashMap::new(),
    };
    w.save(v)?;
    w.out.push(STOP);
    Ok(w.out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(v: Value) {
        let blob = dumps(&v).unwrap();
        assert_eq!(loads(&blob).unwrap(), v, "round trip through {blob:02x?}");
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Lock the writer to real CPython `pickle.dumps(obj, protocol=2)` bytes —
    /// the compatibility contract async_pending / pending files rely on. The
    /// hex below is straight from CPython; a byte-level regression that
    /// round-trip tests would miss fails here.
    #[test]
    fn test_dumps_matches_python_protocol2() {
        let dict = Value::Dict(vec![
            (Value::Str("op".into()), Value::Str("PUT".into())),
            (Value::Str("account".into()), Value::Str("AUTH_test".into())),
            (
                Value::Str("headers".into()),
                Value::Dict(vec![(Value::Str("x-size".into()), Value::Str("4".into()))]),
            ),
        ]);
        assert_eq!(
            dumps(&dict).unwrap(),
            unhex("80027d71002858020000006f7071015803000000505554710258070000006163636f756e7471035809000000415554485f74657374710458070000006865616465727371057d71065806000000782d73697a657107580100000034710873752e")
        );
        let list = Value::List(vec![Value::Int(1), Value::Str("two".into()), Value::Int(3)]);
        assert_eq!(
            dumps(&list).unwrap(),
            unhex("80025d7100284b01580300000074776f71014b03652e")
        );
    }

    #[test]
    fn test_round_trips() {
        rt(Value::Dict(vec![]));
        rt(Value::Dict(vec![
            (
                Value::Bytes(b"name".to_vec()),
                Value::Bytes(b"/a/c/o".to_vec()),
            ),
            (Value::Bytes(b"Content-Length".to_vec()), Value::Int(5)),
        ]));
        rt(Value::Dict(vec![
            (Value::Str("valid".into()), Value::Bool(true)),
            (
                Value::Str("updated".into()),
                Value::Float(1751512345.678901),
            ),
            (Value::Str("abc".into()), Value::None),
            (
                Value::Str("07f".into()),
                Value::Dict(vec![
                    (Value::Int(3), Value::Str("aa".into())),
                    (Value::None, Value::Str("bb".into())),
                ]),
            ),
        ]));
        rt(Value::Dict(vec![(
            Value::Bytes(b"empty".to_vec()),
            Value::Bytes(Vec::new()),
        )]));
    }

    #[test]
    fn test_ints() {
        for x in [
            0,
            1,
            255,
            256,
            65535,
            65536,
            2147483647,
            -1,
            -2147483648,
            2147483648,
            5000000000,
            -5000000000,
            i64::MAX,
            i64::MIN,
        ] {
            rt(Value::Dict(vec![(
                Value::Bytes(b"x".to_vec()),
                Value::Int(x),
            )]));
        }
    }

    #[test]
    fn test_surrogate_escape_bytes() {
        // U+DC80.. surrogatepass sequences map back to raw bytes
        let raw = [0xed, 0xb3, 0xbf, b'o', b'k'];
        assert_eq!(
            decode_pickled_str(&raw),
            Value::Bytes(vec![0xff, b'o', b'k'])
        );
        assert_eq!(
            decode_pickled_str(b"plain"),
            Value::Str("plain".to_string())
        );
    }

    #[test]
    fn test_py2_short_binstring() {
        // hand-assembled py2-style pickle: {b'k': b'v'}
        let blob = b"\x80\x02}q\x00U\x01kq\x01U\x01vq\x02s.";
        assert_eq!(
            loads(blob).unwrap(),
            Value::Dict(vec![(
                Value::Bytes(b"k".to_vec()),
                Value::Bytes(b"v".to_vec())
            )])
        );
    }

    #[test]
    fn test_forbidden_global() {
        // GLOBAL os.system REDUCE must be rejected
        let blob = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00ls\x85R.";
        assert!(loads(blob).unwrap_err().0.contains("forbidden"));
    }

    #[test]
    fn bounded_decoder_preserves_python_values_and_bytes_reduce() {
        let values = [
            Value::None,
            Value::Dict(vec![
                (Value::Str("abc".into()), Value::None),
                (
                    Value::Str("def".into()),
                    Value::Dict(vec![
                        (
                            Value::None,
                            Value::Str("0123456789abcdef0123456789abcdef".into()),
                        ),
                        (
                            Value::Int(0),
                            Value::Str("fedcba9876543210fedcba9876543210".into()),
                        ),
                    ]),
                ),
            ]),
            Value::Dict(vec![(
                Value::Bytes(b"name".to_vec()),
                Value::Bytes(vec![0, 128, 255]),
            )]),
            Value::Tuple(vec![
                Value::Bool(true),
                Value::Float(1.5),
                Value::Int(i64::MIN),
            ]),
        ];
        for value in values {
            let bytes = dumps(&value).unwrap();
            assert_eq!(
                loads_with_limits(&bytes, DecodeLimits::default()).unwrap(),
                value
            );
            assert_eq!(loads(&bytes).unwrap(), value);
        }
        let py2 = b"\x80\x02}q\x00U\x01kq\x01U\x01vq\x02s.";
        assert_eq!(
            loads_with_limits(py2, DecodeLimits::default()).unwrap(),
            loads(py2).unwrap()
        );
    }

    #[test]
    fn bounded_memo_get_charges_scalar_copies_before_cloning() {
        // Original + memo snapshot + BINGET copy: exactly 24 scalar bytes.
        let bytes = b"\x80\x02C\x08abcdefghq\x00h\x00\x86.";
        let mut limits = DecodeLimits {
            max_scalar_bytes: 24,
            ..DecodeLimits::default()
        };
        assert_eq!(
            loads_with_limits(bytes, limits).unwrap(),
            Value::Tuple(vec![
                Value::Bytes(b"abcdefgh".to_vec()),
                Value::Bytes(b"abcdefgh".to_vec()),
            ])
        );
        limits.max_scalar_bytes = 23;
        assert!(loads_with_limits(bytes, limits)
            .unwrap_err()
            .0
            .contains("scalar bytes"));
    }

    #[test]
    fn bounded_memo_container_amplification_is_rejected_early() {
        // Each iteration doubles the previous tree while retaining one root.
        // Forty levels fit in 206 input bytes but would exceed 2^40 nodes.
        let mut bytes = vec![PROTO, 2, NONE, BINPUT, 0];
        for index in 1..=40u8 {
            bytes.extend_from_slice(&[BINGET, index - 1, TUPLE2, BINPUT, index]);
        }
        bytes.push(STOP);
        assert!(bytes.len() < 256);
        let limits = DecodeLimits {
            max_value_nodes: 256,
            max_container_depth: 64,
            ..DecodeLimits::default()
        };
        assert!(loads_with_limits(&bytes, limits)
            .unwrap_err()
            .0
            .contains("value nodes"));
    }

    #[test]
    fn bounded_memo_overwrite_does_not_refund_clone_work() {
        let limits = DecodeLimits {
            max_memo_entries: 1,
            max_scalar_bytes: 24,
            ..DecodeLimits::default()
        };
        assert!(loads_with_limits(b"C\x08abcdefghq\x00q\x00.", limits).is_ok());
        assert!(loads_with_limits(b"C\x08abcdefghq\x00q\x00q\x00.", limits)
            .unwrap_err()
            .0
            .contains("scalar bytes"));
    }

    #[test]
    fn bounded_sparse_long_memo_indices_count_entries_not_index() {
        let bytes = b"C\x01xr\xff\xff\xff\xffj\xff\xff\xff\xff\x86.";
        let limits = DecodeLimits {
            max_memo_entries: 1,
            ..DecodeLimits::default()
        };
        assert_eq!(
            loads_with_limits(bytes, limits).unwrap(),
            Value::Tuple(vec![
                Value::Bytes(b"x".to_vec()),
                Value::Bytes(b"x".to_vec()),
            ])
        );
        assert!(loads_with_limits(b"Nq\x00r\xff\xff\xff\xff.", limits)
            .unwrap_err()
            .0
            .contains("memo entries"));
    }

    #[test]
    fn bounded_depth_applies_when_building_and_attaching_containers() {
        let limits = DecodeLimits {
            max_container_depth: 1,
            ..DecodeLimits::default()
        };
        assert!(loads_with_limits(b"N\x85.", limits).is_ok());
        for bytes in [
            b"N\x85\x85.".as_slice(),  // TUPLE1
            b"]]a.".as_slice(),        // APPEND
            b"](]e.".as_slice(),       // APPENDS
            b"}U\x01k}s.".as_slice(),  // SETITEM
            b"}(U\x01k}u.".as_slice(), // SETITEMS
            b"(]t.".as_slice(),        // TUPLE from MARK
        ] {
            assert!(
                loads_with_limits(bytes, limits)
                    .unwrap_err()
                    .0
                    .contains("container depth"),
                "accepted too-deep {bytes:?}"
            );
        }
        let mut deep = vec![NONE];
        deep.extend(std::iter::repeat_n(TUPLE1, 10_000));
        deep.push(STOP);
        assert!(loads_with_limits(&deep, DecodeLimits::default())
            .unwrap_err()
            .0
            .contains("container depth"));
    }

    #[test]
    fn bounded_input_and_decode_structures_have_independent_limits() {
        let exact = DecodeLimits {
            max_input_bytes: 2,
            ..DecodeLimits::default()
        };
        assert_eq!(loads_with_limits(b"N.", exact).unwrap(), Value::None);
        assert!(loads_with_limits(b"N.x", exact)
            .unwrap_err()
            .0
            .contains("input bytes"));
        let cases = [
            (
                b"N.".as_slice(),
                DecodeLimits {
                    max_opcodes: 1,
                    ..DecodeLimits::default()
                },
                "opcodes",
            ),
            (
                b"N.".as_slice(),
                DecodeLimits {
                    max_value_nodes: 0,
                    ..DecodeLimits::default()
                },
                "value nodes",
            ),
            (
                b"NN.".as_slice(),
                DecodeLimits {
                    max_stack_values: 1,
                    ..DecodeLimits::default()
                },
                "stack values",
            ),
            (
                b"(N.".as_slice(),
                DecodeLimits {
                    max_marks: 0,
                    ..DecodeLimits::default()
                },
                "marks",
            ),
            (
                b"Nq\x00.".as_slice(),
                DecodeLimits {
                    max_memo_entries: 0,
                    ..DecodeLimits::default()
                },
                "memo entries",
            ),
        ];
        for (bytes, limits, expected) in cases {
            assert!(loads_with_limits(bytes, limits)
                .unwrap_err()
                .0
                .contains(expected));
        }
        assert!(
            loads_with_limits(b"X\xff\xff\xff\xff.", DecodeLimits::default())
                .unwrap_err()
                .0
                .contains("truncated")
        );
    }

    #[test]
    fn bounded_reduce_charges_output_allocation() {
        // _codecs + encode (13 bytes), abc + latin1 (9), output abc (3).
        let bytes = b"c_codecs\nencode\nX\x03\x00\x00\x00abcX\x06\x00\x00\x00latin1\x86R.";
        let mut limits = DecodeLimits {
            max_scalar_bytes: 25,
            ..DecodeLimits::default()
        };
        assert_eq!(
            loads_with_limits(bytes, limits).unwrap(),
            Value::Bytes(b"abc".to_vec())
        );
        limits.max_scalar_bytes = 24;
        assert!(loads_with_limits(bytes, limits)
            .unwrap_err()
            .0
            .contains("scalar bytes"));
    }

    #[test]
    fn bounded_stop_is_exact_without_changing_legacy_loads() {
        for bytes in [
            b"N.trailing".as_slice(),
            b"NN.".as_slice(),
            b"(N.".as_slice(),
        ] {
            assert_eq!(loads(bytes).unwrap(), Value::None);
            assert!(loads_with_limits(bytes, DecodeLimits::default())
                .unwrap_err()
                .0
                .contains("must end with one value"));
        }
        // Malformed stack/mark arithmetic must fail rather than split_off panic.
        assert!(loads_with_limits(b"NN(\x86t.", DecodeLimits::default())
            .unwrap_err()
            .0
            .contains("mark beyond stack"));
    }

    #[test]
    fn bounded_dense_three_fragment_suffix_map_fits_default_limits() {
        let hash = "0123456789abcdef0123456789abcdef";
        let value = Value::Dict(
            (0..4096)
                .map(|suffix| {
                    (
                        Value::Str(format!("{suffix:03x}")),
                        Value::Dict(vec![
                            (Value::None, Value::Str(hash.into())),
                            (Value::Int(0), Value::Str(hash.into())),
                            (Value::Int(1), Value::Str(hash.into())),
                            (Value::Int(2), Value::Str(hash.into())),
                        ]),
                    )
                })
                .collect(),
        );
        let bytes = dumps(&value).unwrap();
        assert_eq!(
            loads_with_limits(&bytes, DecodeLimits::default()).unwrap(),
            value
        );
    }
}

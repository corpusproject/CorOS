//! Kernel Livepatching (`livepatch`)
//!
//! Provides `fentry` 5-byte trampoline patching (`CALL` / `JMP`),
//! atomic multi-byte code replacement using staged `INT3` breakpoints,
//! consistency state machines, and revert capabilities.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub const FENTRY_NOP5: [u8; 5] = [0x0F, 0x1F, 0x44, 0x00, 0x00];
pub const JMP_OPCODE: u8 = 0xE9;
pub const CALL_OPCODE: u8 = 0xE8;
pub const INT3_OPCODE: u8 = 0xCC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchState {
    Registered,
    Enabled,
    Disabled,
    Reverted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivepatchError {
    DisplacementOverflow { source: u64, target: u64, diff: i64 },
    PatchNotFound(String),
    AlreadyActive,
    NotActive,
    InvalidMemoryOffset(u64),
    StackCheckFailed(String),
}

#[derive(Debug, Clone)]
pub struct PatchFunction {
    pub name: String,
    pub old_addr: u64,
    pub new_addr: u64,
    pub original_bytes: [u8; 5],
    pub patched_bytes: [u8; 5],
    pub active: bool,
}

impl PatchFunction {
    pub fn new(name: &str, old_addr: u64, new_addr: u64) -> Result<Self, LivepatchError> {
        let diff = (new_addr as i64).wrapping_sub((old_addr as i64).wrapping_add(5));
        if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
            return Err(LivepatchError::DisplacementOverflow {
                source: old_addr,
                target: new_addr,
                diff,
            });
        }

        let rel = diff as i32;
        let rel_bytes = rel.to_le_bytes();
        let patched = [
            JMP_OPCODE,
            rel_bytes[0],
            rel_bytes[1],
            rel_bytes[2],
            rel_bytes[3],
        ];

        Ok(Self {
            name: String::from(name),
            old_addr,
            new_addr,
            original_bytes: FENTRY_NOP5,
            patched_bytes: patched,
            active: false,
        })
    }
}

pub struct Livepatch {
    pub id: String,
    pub state: PatchState,
    pub functions: Vec<PatchFunction>,
}

impl Livepatch {
    pub fn new(id: &str) -> Self {
        Self {
            id: String::from(id),
            state: PatchState::Registered,
            functions: Vec::new(),
        }
    }

    pub fn add_function(&mut self, func: PatchFunction) {
        self.functions.push(func);
    }
}

pub struct MemoryPokingEngine;

impl MemoryPokingEngine {
    pub fn poke_5byte_atomic(memory: &mut [u8], offset: usize, payload: &[u8; 5]) {
        if offset + 5 > memory.len() {
            return;
        }

        // Staged atomic patching sequence:
        // 1. Write INT3 (0xCC) to byte 0 so any concurrent CPU safely traps
        memory[offset] = INT3_OPCODE;

        // 2. Write payload bytes 1..4 (the rel32 displacement)
        memory[offset + 1..offset + 5].copy_from_slice(&payload[1..5]);

        // 3. Atomically overwrite byte 0 with final opcode (JMP or CALL)
        memory[offset] = payload[0];
    }

    pub fn revert_5byte_atomic(memory: &mut [u8], offset: usize, original: &[u8; 5]) {
        if offset + 5 > memory.len() {
            return;
        }

        // 1. Write INT3 to byte 0
        memory[offset] = INT3_OPCODE;

        // 2. Restore bytes 1..4
        memory[offset + 1..offset + 5].copy_from_slice(&original[1..5]);

        // 3. Restore byte 0
        memory[offset] = original[0];
    }
}

pub struct LivepatchManager {
    patches: BTreeMap<String, Livepatch>,
}

impl LivepatchManager {
    pub fn new() -> Self {
        Self {
            patches: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, patch: Livepatch) {
        self.patches.insert(patch.id.clone(), patch);
    }

    pub fn enable(
        &mut self,
        id: &str,
        text_buffer: &mut [u8],
        base_addr: u64,
        active_stack_ips: &[u64],
    ) -> Result<u32, LivepatchError> {
        let patch = self.patches.get_mut(id).ok_or_else(|| LivepatchError::PatchNotFound(String::from(id)))?;
        if patch.state == PatchState::Enabled {
            return Err(LivepatchError::AlreadyActive);
        }

        // 1. Stack check: ensure no active thread is running the function being patched
        for func in &patch.functions {
            for &ip in active_stack_ips {
                if ip >= func.old_addr && ip < func.old_addr + 0x100 {
                    return Err(LivepatchError::StackCheckFailed(format!(
                        "Function {} active on stack at 0x{:x}",
                        func.name, ip
                    )));
                }
            }
        }

        // 2. Apply patches
        let mut count = 0u32;
        for func in &mut patch.functions {
            if func.old_addr < base_addr {
                return Err(LivepatchError::InvalidMemoryOffset(func.old_addr));
            }
            let offset = (func.old_addr - base_addr) as usize;
            if offset + 5 > text_buffer.len() {
                return Err(LivepatchError::InvalidMemoryOffset(func.old_addr));
            }

            // Save actual existing bytes before overwriting
            func.original_bytes.copy_from_slice(&text_buffer[offset..offset + 5]);
            MemoryPokingEngine::poke_5byte_atomic(text_buffer, offset, &func.patched_bytes);
            func.active = true;
            count += 1;
        }

        patch.state = PatchState::Enabled;
        Ok(count)
    }

    pub fn disable(
        &mut self,
        id: &str,
        text_buffer: &mut [u8],
        base_addr: u64,
    ) -> Result<u32, LivepatchError> {
        let patch = self.patches.get_mut(id).ok_or_else(|| LivepatchError::PatchNotFound(String::from(id)))?;
        if patch.state != PatchState::Enabled {
            return Err(LivepatchError::NotActive);
        }

        let mut count = 0u32;
        for func in &mut patch.functions {
            let offset = (func.old_addr - base_addr) as usize;
            MemoryPokingEngine::revert_5byte_atomic(text_buffer, offset, &func.original_bytes);
            func.active = false;
            count += 1;
        }

        patch.state = PatchState::Disabled;
        Ok(count)
    }

    pub fn get_state(&self, id: &str) -> Option<PatchState> {
        self.patches.get(id).map(|p| p.state)
    }
}

pub fn verify_livepatch() -> u32 {
    let mut check_count = 0u32;

    // Test 1: PatchFunction construction and rel32 calculation
    // Old: 0x401000, New: 0x402000
    // Diff = 0x402000 - (0x401000 + 5) = 0xFFB (4091)
    let pf = PatchFunction::new("sys_lookup", 0x401000, 0x402000);
    if let Ok(func) = pf {
        if func.patched_bytes[0] == JMP_OPCODE {
            let rel = i32::from_le_bytes(func.patched_bytes[1..5].try_into().unwrap());
            if rel == 4091 {
                check_count += 1;
            }
        }
    }

    // Test 2: Out of range displacement error (> 2GB)
    let pf_overflow = PatchFunction::new("bad_target", 0x401000, 0xffff_ffff_8000_0000);
    if let Err(LivepatchError::DisplacementOverflow { .. }) = pf_overflow {
        check_count += 1;
    }

    // Test 3: LivepatchManager apply and revert
    let mut text_mock = [0x90u8; 64];
    // Place original NOP5 at offset 0x10
    text_mock[0x10..0x15].copy_from_slice(&FENTRY_NOP5);

    let mut patch = Livepatch::new("klp_cve_2026_01");
    // Target old_addr = base (0x1000) + 0x10 = 0x1010. New addr = 0x1030.
    let f1 = PatchFunction::new("vulnerable_func", 0x1010, 0x1030).unwrap();
    patch.add_function(f1);

    let mut mgr = LivepatchManager::new();
    mgr.register(patch);

    // Apply patch with clear stack
    let empty_stack = [];
    let enable_res = mgr.enable("klp_cve_2026_01", &mut text_mock, 0x1000, &empty_stack);
    if enable_res == Ok(1) && mgr.get_state("klp_cve_2026_01") == Some(PatchState::Enabled) {
        // Verify patched bytes at offset 0x10
        if text_mock[0x10] == JMP_OPCODE {
            let rel = i32::from_le_bytes(text_mock[0x11..0x15].try_into().unwrap());
            // 0x1030 - (0x1010 + 5) = 0x1B (27)
            if rel == 27 {
                check_count += 1;
            }
        }
    }

    // Test 4: Disable and revert patch
    let disable_res = mgr.disable("klp_cve_2026_01", &mut text_mock, 0x1000);
    if disable_res == Ok(1) && mgr.get_state("klp_cve_2026_01") == Some(PatchState::Disabled) {
        // Verify original bytes restored
        if text_mock[0x10..0x15] == FENTRY_NOP5 {
            check_count += 1;
        }
    }

    // Test 5: Stack check prevents patching if thread is inside function
    let mut patch2 = Livepatch::new("klp_safety");
    patch2.add_function(PatchFunction::new("safety_func", 0x2000, 0x2050).unwrap());
    mgr.register(patch2);

    let active_threads = [0x2010]; // thread is inside safety_func!
    let blocked_res = mgr.enable("klp_safety", &mut text_mock, 0x2000, &active_threads);
    if let Err(LivepatchError::StackCheckFailed(_)) = blocked_res {
        check_count += 1;
    }

    check_count
}

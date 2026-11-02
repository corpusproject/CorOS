//! CorOS Linux eBPF (Extended Berkeley Packet Filter) In-Kernel Virtual Machine
//!
//! Provides bare-metal 64-bit eBPF bytecode execution, maps, and safety verification:
//! - 64-bit eBPF Virtual Machine runtime (`EbpfVm`, `EbpfInstruction`)
//! - Key-Value storage maps (`EbpfMap`, `EbpfMapRegistry`, `EbpfMapDef`)
//! - Static safety verifier (`EbpfVerifier`, `VerifierState`, `RegType`)

pub mod vm;
pub mod maps;
pub mod verifier;

pub use vm::{EbpfVm, EbpfInstruction, BPF_STACK_SIZE};
pub use maps::{EbpfMap, EbpfMapRegistry, EbpfMapDef, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY};
pub use verifier::{EbpfVerifier, VerifierState, RegType};

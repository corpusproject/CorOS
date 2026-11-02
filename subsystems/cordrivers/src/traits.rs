//! `traits` — Universal Device Model Driver Interface Traits & Re-exports.
//!
//! Re-exports universal driver traits and adapters defined in `universal_device`:
//! - `BlockDeviceDriver`, `NetworkDeviceDriver`, `DrmKmsDriver`, `InputDeviceDriver`, `AudioDeviceDriver`
//! - Adapters: `NvmeBlockAdapter`, `AhciBlockAdapter`, `VirtioBlkAdapter`, `E1000NetAdapter`, `Ac97AudioAdapter`

pub use crate::universal_device::*;

/// Verification stub forwarding to `universal_device::verify_driver_module_universal_device`.
pub fn verify_driver_module_traits() -> u32 {
    crate::universal_device::verify_driver_module_universal_device()
}

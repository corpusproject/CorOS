//! CorOS ACPI Power Management & Sleep States (`power_states.rs`)
//!
//! Implements hardware power state transitions via ACPI FADT registers:
//! - ACPI System Sleep States:
//!   - S0: Full Working state
//!   - S1: CPU Stopped (Power On Suspend - POS)
//!   - S2: CPU powered off, dirty cache flushed
//!   - S3: Suspend-to-RAM (STR), RAM in self-refresh
//!   - S4: Suspend-to-Disk (STD / Hibernation)
//!   - S5: Soft-Off (Full system shutdown)
//! - Fixed ACPI Description Table (FADT):
//!   - SMI_CMD (Port to enable ACPI via ACPI_ENABLE)
//!   - PM1a_CNT_BLK / PM1b_CNT_BLK (Power Management 1 Control Register block)
//!   - PM1a_EVT_BLK / PM1b_EVT_BLK (Power Management 1 Event Register block)
//!   - PM_TMR_BLK (ACPI 24-bit/32-bit 3.579545 MHz Power Management Timer)
//!   - RESET_REG & RESET_VALUE (ACPI 2.0+ hardware system reset)
//! - SLP_TYP and SLP_EN bit manipulation on PM1a_CNT / PM1b_CNT ports

extern crate alloc;

use crate::arch::x86_64::cpu;

pub const ACPI_SLEEP_S0: u8 = 0;
pub const ACPI_SLEEP_S1: u8 = 1;
pub const ACPI_SLEEP_S2: u8 = 2;
pub const ACPI_SLEEP_S3: u8 = 3;
pub const ACPI_SLEEP_S4: u8 = 4;
pub const ACPI_SLEEP_S5: u8 = 5;

pub const PM1_SLP_EN: u16 = 1 << 13;

/// FADT Header and Register Offsets
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AcpiFadt {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    pub firmware_ctrl: u32,
    pub dsdt_addr: u32,
    pub reserved1: u8,
    pub preferred_pm_profile: u8,
    pub sci_int: u16,
    pub smi_cmd: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4bios_req: u8,
    pub pstate_cnt: u8,
    pub pm1a_evt_blk: u32,
    pub pm1b_evt_blk: u32,
    pub pm1a_cnt_blk: u32,
    pub pm1b_cnt_blk: u32,
    pub pm2_cnt_blk: u32,
    pub pm_tmr_blk: u32,
    pub gpe0_blk: u32,
    pub gpe1_blk: u32,
    pub pm1_evt_len: u8,
    pub pm1_cnt_len: u8,
    pub pm2_cnt_len: u8,
    pub pm_tmr_len: u8,
    pub gpe0_len: u8,
    pub gpe1_len: u8,
    pub gpe1_base: u8,
    pub cst_cnt: u8,
    pub p_lvl2_lat: u16,
    pub p_lvl3_lat: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alrm: u8,
    pub mon_alrm: u8,
    pub century: u8,
    pub iapc_boot_arch: u16,
    pub reserved2: u8,
    pub flags: u32,
    pub reset_reg: [u8; 12],
    pub reset_value: u8,
}

/// ACPI Power State Manager
pub struct AcpiPowerManager {
    pub fadt: Option<AcpiFadt>,
    pub s5_slp_typa: u16,
    pub s5_slp_typb: u16,
    pub s3_slp_typa: u16,
    pub s3_slp_typb: u16,
    pub acpi_enabled: bool,
}

impl AcpiPowerManager {
    pub fn new() -> Self {
        Self {
            fadt: None,
            // Typical QEMU / VirtualBox / Bochs SLP_TYP values for S5 shutdown
            s5_slp_typa: 0x2000, // SLP_TYP = 5 << 10
            s5_slp_typb: 0x2000,
            s3_slp_typa: 0x0C00, // SLP_TYP = 3 << 10
            s3_slp_typb: 0x0C00,
            acpi_enabled: false,
        }
    }

    /// Load FADT table
    pub fn init_fadt(&mut self, fadt_bytes: &[u8]) -> bool {
        if fadt_bytes.len() < core::mem::size_of::<AcpiFadt>() || &fadt_bytes[0..4] != b"FACP" {
            return false;
        }

        let fadt: AcpiFadt = unsafe {
            core::ptr::read_unaligned(fadt_bytes.as_ptr() as *const AcpiFadt)
        };

        // Enable ACPI hardware mode if SMI_CMD is present
        if fadt.smi_cmd != 0 && fadt.acpi_enable != 0 {
            unsafe {
                cpu::out8(fadt.smi_cmd as u16, fadt.acpi_enable);
                // Wait briefly for hardware handshake
                for _ in 0..10_000 {
                    if (cpu::in16(fadt.pm1a_cnt_blk as u16) & 1) != 0 {
                        break;
                    }
                }
            }
        }

        self.fadt = Some(fadt);
        self.acpi_enabled = true;
        true
    }

    /// Enter Sleep State (S1, S3, S5)
    pub fn enter_sleep_state(&self, state: u8) -> Result<(), &'static str> {
        let fadt = self.fadt.as_ref().ok_or("FADT not initialized")?;

        let (slp_typa, slp_typb) = match state {
            ACPI_SLEEP_S3 => (self.s3_slp_typa, self.s3_slp_typb),
            ACPI_SLEEP_S5 => (self.s5_slp_typa, self.s5_slp_typb),
            _ => return Err("Unsupported sleep state"),
        };

        let cmd_a = slp_typa | PM1_SLP_EN;
        let cmd_b = slp_typb | PM1_SLP_EN;

        unsafe {
            if fadt.pm1a_cnt_blk != 0 {
                cpu::out16(fadt.pm1a_cnt_blk as u16, cmd_a);
            }
            if fadt.pm1b_cnt_blk != 0 {
                cpu::out16(fadt.pm1b_cnt_blk as u16, cmd_b);
            }
        }

        Ok(())
    }

    /// Trigger ACPI Hardware Reset
    pub fn reboot(&self) {
        if let Some(ref fadt) = self.fadt {
            // Check ACPI 2.0 RESET_REG
            let space_id = fadt.reset_reg[0];
            let address = u64::from_le_bytes([
                fadt.reset_reg[4], fadt.reset_reg[5], fadt.reset_reg[6], fadt.reset_reg[7],
                fadt.reset_reg[8], fadt.reset_reg[9], fadt.reset_reg[10], fadt.reset_reg[11],
            ]);

            if space_id == 1 && address != 0 { // System I/O space
                unsafe {
                    cpu::out8(address as u16, fadt.reset_value);
                }
            }
        }

        // Fallback: 8042 keyboard controller reset (Port 0x64 = 0xFE)
        unsafe {
            cpu::out8(0x64, 0xFE);
        }
    }
}

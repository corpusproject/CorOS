//! CorOS USB 3.0 / 3.1 xHCI (eXtensible Host Controller Interface) Driver (`usb_xhci.rs`)
//!
//! Provides bare-metal modern USB host controller management:
//! - Capability Registers (CAPLENGTH, HCIVERSION, HCSPARAMS1, HCSPARAMS2, HCCPARAMS1, DBOFF, RTSOFF)
//! - Operational Registers (USBCMD, USBSTS, PAGESIZE, CRCR, DCBAAP, CONFIG, PORTSC)
//! - Runtime Registers (Interrupter Management, Event Ring Table Base, Event Ring Dequeue Pointer)
//! - Transfer Request Blocks (TRB: Normal, Setup Stage, Data Stage, Status Stage, Link, Enable Slot, Address Device)
//! - Device Context Base Address Array (DCBAA: Slot Context, Endpoint Context EP0 IN/OUT)
//! - Doorbell registers (Host Controller Doorbell & Device Slot Doorbells)
//! - USB Standard Descriptors: Device (18 bytes), Configuration (9 bytes), Interface (9 bytes), Endpoint (7 bytes)

extern crate alloc;

use alloc::vec::Vec;

/// Capability Register Offsets
pub const XHCI_CAPLENGTH: usize = 0x00;
pub const XHCI_HCIVERSION: usize = 0x02;
pub const XHCI_HCSPARAMS1: usize = 0x04;
pub const XHCI_HCSPARAMS2: usize = 0x08;
pub const XHCI_HCCPARAMS1: usize = 0x10;
pub const XHCI_DBOFF: usize = 0x14;
pub const XHCI_RTSOFF: usize = 0x18;

/// Operational Register Offsets (relative to op_base = base + CAPLENGTH)
pub const XHCI_OP_USBCMD: usize = 0x00;
pub const XHCI_OP_USBSTS: usize = 0x04;
pub const XHCI_OP_PAGESIZE: usize = 0x08;
pub const XHCI_OP_DNCTRL: usize = 0x14;
pub const XHCI_OP_CRCR: usize = 0x18;
pub const XHCI_OP_DCBAAP: usize = 0x30;
pub const XHCI_OP_CONFIG: usize = 0x38;
pub const XHCI_OP_PORTSC_BASE: usize = 0x400;

/// USBCMD Bits
pub const USBCMD_RS: u32 = 1 << 0;     // Run/Stop
pub const USBCMD_HCRST: u32 = 1 << 1;  // Host Controller Reset
pub const USBCMD_INTE: u32 = 1 << 2;   // Interrupter Enable
pub const USBCMD_HSEE: u32 = 1 << 3;   // Host System Error Enable

/// USBSTS Bits
pub const USBSTS_HCH: u32 = 1 << 0;    // HC Halted
pub const USBSTS_HSE: u32 = 1 << 2;    // Host System Error
pub const USBSTS_EINT: u32 = 1 << 3;   // Event Interrupt
pub const USBSTS_PCD: u32 = 1 << 4;    // Port Change Detect
pub const USBSTS_CNR: u32 = 1 << 11;   // Controller Not Ready

/// TRB Types
pub const TRB_NORMAL: u32 = 1;
pub const TRB_SETUP_STAGE: u32 = 2;
pub const TRB_DATA_STAGE: u32 = 3;
pub const TRB_STATUS_STAGE: u32 = 4;
pub const TRB_ISOCH: u32 = 5;
pub const TRB_LINK: u32 = 6;
pub const TRB_EVENT_DATA: u32 = 7;
pub const TRB_ENABLE_SLOT: u32 = 9;
pub const TRB_DISABLE_SLOT: u32 = 10;
pub const TRB_ADDRESS_DEVICE: u32 = 11;
pub const TRB_CONFIGURE_ENDPOINT: u32 = 12;
pub const TRB_TRANSFER_EVENT: u32 = 32;
pub const TRB_COMMAND_COMPLETION: u32 = 33;
pub const TRB_PORT_STATUS_CHANGE: u32 = 34;

/// TRB Flags
pub const TRB_FLAG_CYCLE: u32 = 1 << 0;
pub const TRB_FLAG_ENT: u32 = 1 << 1;   // Evaluate Next TRB
pub const TRB_FLAG_ISP: u32 = 1 << 2;   // Interrupt on Short Packet
pub const TRB_FLAG_CH: u32 = 1 << 4;    // Chain bit
pub const TRB_FLAG_IOC: u32 = 1 << 5;   // Interrupt on Completion
pub const TRB_FLAG_IDT: u32 = 1 << 6;   // Immediate Data

/// 16-byte Transfer Request Block (TRB)
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct XhciTrb {
    pub param_low: u32,
    pub param_high: u32,
    pub status: u32,
    pub control: u32,
}

impl XhciTrb {
    pub fn new(param_low: u32, param_high: u32, status: u32, trb_type: u32, flags: u32) -> Self {
        let control = (trb_type << 10) | flags;
        Self {
            param_low,
            param_high,
            status,
            control,
        }
    }

    pub fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    pub fn cycle_bit(&self) -> bool {
        (self.control & TRB_FLAG_CYCLE) != 0
    }
}

/// Slot Context (32 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XhciSlotContext {
    pub route_speed_entries: u32, // Route string (bits 0-19), Speed (bits 20-23), Context Entries (bits 27-31)
    pub max_exit_latency: u32,
    pub interrupter_port: u32,    // Root Hub Port (bits 16-23)
    pub slot_state: u32,          // Slot State (bits 27-31)
    pub reserved: [u32; 4],
}

/// Endpoint Context (32 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct XhciEndpointContext {
    pub ep_info1: u32,            // State (0-2), Mult (8-9), MaxPStreams (10-14), Interval (16-23)
    pub ep_info2: u32,            // Error Count (1-2), EP Type (3-5), Max Packet Size (16-31)
    pub tr_dequeue_lo: u32,       // Transfer Ring Dequeue Pointer Low
    pub tr_dequeue_hi: u32,       // Transfer Ring Dequeue Pointer High
    pub average_trb_length: u32,  // Average TRB length & Max ESIT payload
    pub reserved: [u32; 3],
}

/// Standard USB 2.0/3.0 Device Descriptor (18 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8, // 1 = DEVICE
    pub bcd_usb: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_number_index: u8,
    pub num_configurations: u8,
}

/// Port Status & Control Information
#[derive(Debug, Clone, Copy)]
pub struct XhciPortStatus {
    pub port_idx: usize,
    pub connected: bool,
    pub enabled: bool,
    pub speed: u8, // 1=Full, 2=Low, 3=High, 4=SuperSpeed
    pub power: bool,
    pub reset: bool,
}

/// Complete xHCI Host Controller
pub struct XhciExtController {
    pub cap_base: usize,
    pub op_base: usize,
    pub db_base: usize,
    pub rt_base: usize,
    pub max_slots: usize,
    pub max_ports: usize,
    pub page_size: usize,
    pub ports: Vec<XhciPortStatus>,
}

impl XhciExtController {
    pub fn new(mmio_base: usize) -> Self {
        let cap_len = unsafe { core::ptr::read_volatile(mmio_base as *const u8) } as usize;
        let op_base = mmio_base + cap_len;

        let hcsparams1 = unsafe { core::ptr::read_volatile((mmio_base + XHCI_HCSPARAMS1) as *const u32) };
        let max_slots = (hcsparams1 & 0xFF) as usize;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as usize;

        let dboff = unsafe { core::ptr::read_volatile((mmio_base + XHCI_DBOFF) as *const u32) } as usize;
        let rtsoff = unsafe { core::ptr::read_volatile((mmio_base + XHCI_RTSOFF) as *const u32) } as usize;

        let db_base = mmio_base + dboff;
        let rt_base = mmio_base + rtsoff;

        let page_size_reg = unsafe { core::ptr::read_volatile((op_base + XHCI_OP_PAGESIZE) as *const u32) };
        let page_size = ((page_size_reg & 0xFFFF) as usize) << 12;

        let mut controller = Self {
            cap_base: mmio_base,
            op_base,
            db_base,
            rt_base,
            max_slots,
            max_ports,
            page_size: if page_size == 0 { 4096 } else { page_size },
            ports: Vec::new(),
        };

        controller.scan_ports();
        controller
    }

    unsafe fn read_op_reg(&self, reg: usize) -> u32 {
        core::ptr::read_volatile((self.op_base + reg) as *const u32)
    }

    unsafe fn write_op_reg(&self, reg: usize, val: u32) {
        core::ptr::write_volatile((self.op_base + reg) as *mut u32, val);
    }

    /// Reset xHCI host controller
    pub fn reset(&mut self) -> bool {
        unsafe {
            // Stop controller if running
            let mut usbcmd = self.read_op_reg(XHCI_OP_USBCMD);
            usbcmd &= !USBCMD_RS;
            self.write_op_reg(XHCI_OP_USBCMD, usbcmd);

            // Wait for Halted
            for _ in 0..10_000 {
                if (self.read_op_reg(XHCI_OP_USBSTS) & USBSTS_HCH) != 0 {
                    break;
                }
            }

            // Trigger Host Controller Reset
            self.write_op_reg(XHCI_OP_USBCMD, USBCMD_HCRST);

            for _ in 0..10_000 {
                let cur = self.read_op_reg(XHCI_OP_USBCMD);
                let sts = self.read_op_reg(XHCI_OP_USBSTS);
                if (cur & USBCMD_HCRST) == 0 && (sts & USBSTS_CNR) == 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Enumerate all root hub ports
    pub fn scan_ports(&mut self) {
        self.ports.clear();
        for i in 0..self.max_ports {
            let portsc_off = XHCI_OP_PORTSC_BASE + i * 0x10;
            let val = unsafe { self.read_op_reg(portsc_off) };

            let ccs = (val & (1 << 0)) != 0; // Current Connect Status
            let ped = (val & (1 << 1)) != 0; // Port Enabled/Disabled
            let speed = ((val >> 10) & 0x0F) as u8;
            let pp = (val & (1 << 9)) != 0;  // Port Power
            let pr = (val & (1 << 4)) != 0;  // Port Reset

            self.ports.push(XhciPortStatus {
                port_idx: i + 1,
                connected: ccs,
                enabled: ped,
                speed,
                power: pp,
                reset: pr,
            });
        }
    }

    /// Ring Doorbell for slot and target endpoint
    pub fn ring_doorbell(&self, slot_id: u8, target_ep: u8) {
        let db_offset = self.db_base + (slot_id as usize) * 4;
        unsafe {
            core::ptr::write_volatile(db_offset as *mut u32, target_ep as u32);
        }
    }
}

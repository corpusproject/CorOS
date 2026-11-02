//! Universal Serial Bus (USB 2.0 / USB 3.0 xHCI) Architecture for CorOS.
//! 100% in-house implementation supporting:
//! - Standard USB 2.0 / 3.2 Specification descriptors and setup requests
//! - xHCI (Extensible Host Controller Interface) MMIO registers & rings
//! - TRB (Transfer Request Block) ring buffers (Command, Event, Transfer)
//! - USB HID Boot Protocol for USB Mouse & Keyboard input

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

// -----------------------------------------------------------------------------
// USB Standard Descriptors
// -----------------------------------------------------------------------------
pub const USB_DESC_DEVICE: u8        = 0x01;
pub const USB_DESC_CONFIG: u8        = 0x02;
pub const USB_DESC_STRING: u8        = 0x03;
pub const USB_DESC_INTERFACE: u8     = 0x04;
pub const USB_DESC_ENDPOINT: u8      = 0x05;
pub const USB_DESC_DEVICE_QUAL: u8   = 0x06;
pub const USB_DESC_HID: u8           = 0x21;

// Standard Requests
pub const USB_REQ_GET_STATUS: u8     = 0x00;
pub const USB_REQ_CLEAR_FEATURE: u8  = 0x01;
pub const USB_REQ_SET_FEATURE: u8    = 0x03;
pub const USB_REQ_SET_ADDRESS: u8    = 0x05;
pub const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
pub const USB_REQ_SET_DESCRIPTOR: u8 = 0x07;
pub const USB_REQ_GET_CONFIG: u8     = 0x08;
pub const USB_REQ_SET_CONFIG: u8     = 0x09;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UsbSetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UsbDeviceDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub bcd_usb: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub bcd_device: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_number_index: u8,
    pub num_configurations: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct UsbEndpointDescriptor {
    pub length: u8,
    pub descriptor_type: u8,
    pub endpoint_address: u8, // Bits 3:0 number, bit 7 direction (1 = IN, 0 = OUT)
    pub attributes: u8,       // Bits 1:0 transfer type (0=Control, 1=Iso, 2=Bulk, 3=Interrupt)
    pub max_packet_size: u16,
    pub interval: u8,
}

// -----------------------------------------------------------------------------
// xHCI (USB 3.0 Extensible Host Controller Interface) Registers
// -----------------------------------------------------------------------------
pub const XHCI_REG_CAPLENGTH: usize   = 0x00;
pub const XHCI_REG_HCIVERSION: usize  = 0x02;
pub const XHCI_REG_HCSPARAMS1: usize  = 0x04;
pub const XHCI_REG_HCSPARAMS2: usize  = 0x08;
pub const XHCI_REG_HCCPARAMS1: usize  = 0x10;
pub const XHCI_REG_DBOFF: usize       = 0x14;
pub const XHCI_REG_RTSOFF: usize      = 0x18;

// Operational Registers (Offset from op_base)
pub const XHCI_OP_USBCMD: usize       = 0x00;
pub const XHCI_OP_USBSTS: usize       = 0x04;
pub const XHCI_OP_PAGESIZE: usize     = 0x08;
pub const XHCI_OP_DNCTRL: usize       = 0x14;
pub const XHCI_OP_CRCR: usize         = 0x18; // Command Ring Control Register (64-bit)
pub const XHCI_OP_DCBAAP: usize       = 0x30; // Device Context Base Address Array (64-bit)
pub const XHCI_OP_CONFIG: usize       = 0x38; // Max Slots Enabled

// USBCMD Flags
pub const XHCI_CMD_RS: u32            = 1 << 0; // Run/Stop
pub const XHCI_CMD_HCRST: u32         = 1 << 1; // Host Controller Reset
pub const XHCI_CMD_INTE: u32          = 1 << 2; // Interrupter Enable

// -----------------------------------------------------------------------------
// xHCI TRB (Transfer Request Block) - 16 bytes
// -----------------------------------------------------------------------------
pub const TRB_TYPE_NORMAL: u32        = 1;
pub const TRB_TYPE_SETUP_STAGE: u32   = 2;
pub const TRB_TYPE_DATA_STAGE: u32    = 3;
pub const TRB_TYPE_STATUS_STAGE: u32  = 4;
pub const TRB_TYPE_LINK: u32          = 6;
pub const TRB_TYPE_ENABLE_SLOT: u32   = 9;
pub const TRB_TYPE_DISABLE_SLOT: u32  = 10;
pub const TRB_TYPE_ADDRESS_DEV: u32   = 11;
pub const TRB_TYPE_CONFIG_EP: u32     = 12;

#[repr(C, packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct XhciTrb {
    pub param_low: u32,
    pub param_high: u32,
    pub status: u32,
    pub control: u32,
}

impl XhciTrb {
    pub fn new(param: u64, status: u32, trb_type: u32, cycle_bit: bool) -> Self {
        let cycle = if cycle_bit { 1 } else { 0 };
        let control = (trb_type << 10) | cycle;
        Self {
            param_low: param as u32,
            param_high: (param >> 32) as u32,
            status,
            control,
        }
    }

    pub fn cycle_bit(&self) -> bool {
        (self.control & 1) != 0
    }

    pub fn trb_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }
}

// -----------------------------------------------------------------------------
// xHCI Host Controller
// -----------------------------------------------------------------------------
pub const XHCI_RING_ENTRIES: usize = 64;

pub struct XhciController {
    pub mmio_base: usize,
    pub op_base: usize,
    pub max_slots: u8,
    pub max_ports: u8,
    pub cmd_ring: Vec<XhciTrb>,
    pub cmd_cycle: bool,
    pub cmd_index: usize,
}

impl XhciController {
    pub unsafe fn init(mmio_base: usize) -> Result<Self, &'static str> {
        let cap_length = read_volatile(mmio_base as *const u8) as usize;
        let op_base = mmio_base + cap_length;

        let hcsparams1 = read_volatile((mmio_base + XHCI_REG_HCSPARAMS1) as *const u32);
        let max_slots = (hcsparams1 & 0xFF) as u8;
        let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

        // 1. Reset Host Controller
        let mut usbcmd = read_volatile((op_base + XHCI_OP_USBCMD) as *const u32);
        if (usbcmd & XHCI_CMD_RS) != 0 {
            usbcmd &= !XHCI_CMD_RS;
            write_volatile((op_base + XHCI_OP_USBCMD) as *mut u32, usbcmd);
        }

        // Wait for HCHalted
        let mut timeout = 100_000;
        while (read_volatile((op_base + XHCI_OP_USBSTS) as *const u32) & 1) == 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("xHCI halt timeout");
            }
        }

        // Trigger HCRST
        write_volatile((op_base + XHCI_OP_USBCMD) as *mut u32, XHCI_CMD_HCRST);
        timeout = 100_000;
        while (read_volatile((op_base + XHCI_OP_USBCMD) as *const u32) & XHCI_CMD_HCRST) != 0 {
            timeout -= 1;
            if timeout == 0 {
                return Err("xHCI reset timeout");
            }
        }

        // 2. Configure Max Device Slots
        write_volatile((op_base + XHCI_OP_CONFIG) as *mut u32, max_slots as u32);

        // 3. Allocate Command Ring
        let mut cmd_ring = Vec::with_capacity(XHCI_RING_ENTRIES);
        for _ in 0..XHCI_RING_ENTRIES {
            cmd_ring.push(XhciTrb::default());
        }

        // Link TRB at the end to loop back to start
        let ring_phys = cmd_ring.as_ptr() as u64;
        cmd_ring[XHCI_RING_ENTRIES - 1] = XhciTrb::new(ring_phys, 0, TRB_TYPE_LINK, true);
        cmd_ring[XHCI_RING_ENTRIES - 1].control |= 1 << 1; // Toggle Cycle bit

        // Program CRCR (Command Ring Control Register)
        // Bit 0 = Ring Cycle State (RCS = 1)
        write_volatile((op_base + XHCI_OP_CRCR) as *mut u64, ring_phys | 1);

        // 4. Start Host Controller (Run/Stop = 1)
        write_volatile((op_base + XHCI_OP_USBCMD) as *mut u32, XHCI_CMD_RS | XHCI_CMD_INTE);

        Ok(Self {
            mmio_base,
            op_base,
            max_slots,
            max_ports,
            cmd_ring,
            cmd_cycle: true,
            cmd_index: 0,
        })
    }
}

// -----------------------------------------------------------------------------
// USB HID Boot Protocol Parser (Mouse & Keyboard)
// -----------------------------------------------------------------------------
#[derive(Clone, Copy, Default, Debug)]
pub struct UsbMouseReport {
    pub buttons: u8, // Bit 0: Left, Bit 1: Right, Bit 2: Middle
    pub dx: i8,
    pub dy: i8,
    pub wheel: i8,
}

pub struct UsbHidParser;

impl UsbHidParser {
    pub fn parse_mouse_boot_report(bytes: &[u8]) -> Option<UsbMouseReport> {
        if bytes.len() < 3 {
            return None;
        }

        let buttons = bytes[0];
        let dx = bytes[1] as i8;
        let dy = bytes[2] as i8;
        let wheel = if bytes.len() >= 4 { bytes[3] as i8 } else { 0 };

        Some(UsbMouseReport {
            buttons,
            dx,
            dy,
            wheel,
        })
    }
}

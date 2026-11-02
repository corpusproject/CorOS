//! CorOS Hardware Driver Module: `xhci_usb3`
//!
//! Extensible Host Controller Interface (xHCI 1.2) Capability & Operational registers,
//! 16-byte Transfer Request Block (`XhciTrb`) encoders/decoders (`Normal`, `SetupStage`,
//! `DataStage`, `StatusStage`, `Link`, `EnableSlot`, `AddressDevice`, `ConfigureEndpoint`,
//! `TransferEvent`, `CommandCompletionEvent`, `PortStatusChangeEvent`), and Producer/Consumer
//! TRB Ring with hardware Cycle Bit management.

/// xHCI Capability Register offsets (relative to BAR0 base).
pub mod xhci_cap_regs {
    pub const CAPLENGTH: usize = 0x00;
    pub const HCIVERSION: usize = 0x02;
    pub const HCSPARAMS1: usize = 0x04;
    pub const HCSPARAMS2: usize = 0x08;
    pub const HCSPARAMS3: usize = 0x0C;
    pub const HCCPARAMS1: usize = 0x10;
    pub const DBOFF: usize = 0x14;
    pub const RTSOFF: usize = 0x18;
    pub const HCCPARAMS2: usize = 0x1C;
}

/// xHCI Operational Register offsets (relative to `BAR0 + CAPLENGTH`).
pub mod xhci_op_regs {
    pub const USBCMD: usize = 0x00;
    pub const USBSTS: usize = 0x04;
    pub const PAGESIZE: usize = 0x08;
    pub const DNCTRL: usize = 0x14;
    pub const CRCR: usize = 0x18;
    pub const DCBAAP: usize = 0x30;
    pub const CONFIG: usize = 0x38;
    pub const PORTSC_BASE: usize = 0x400;
    pub const PORTSC_STRIDE: usize = 0x10;
}

/// xHCI `PORTSC` bitflags.
pub mod portsc_flags {
    pub const CCS: u32 = 1 << 0;
    pub const PED: u32 = 1 << 1;
    pub const OCA: u32 = 1 << 3;
    pub const PR: u32 = 1 << 4;
    pub const PP: u32 = 1 << 9;
    pub const CSC: u32 = 1 << 17;
    pub const PRC: u32 = 1 << 21;
}

/// xHCI Transfer Request Block (TRB) 6-bit Type IDs (`control[15:10]`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XhciTrbType {
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    Isoch = 5,
    Link = 6,
    EventData = 7,
    NoOpTransfer = 8,
    EnableSlotCmd = 9,
    DisableSlotCmd = 10,
    AddressDeviceCmd = 11,
    ConfigureEndpointCmd = 12,
    EvaluateContextCmd = 13,
    ResetEndpointCmd = 14,
    StopEndpointCmd = 15,
    SetTrDequeuePtrCmd = 16,
    NoOpCmd = 23,
    TransferEvent = 32,
    CommandCompletionEvent = 33,
    PortStatusChangeEvent = 34,
    HostControllerEvent = 37,
}

/// xHCI TRB Completion Codes (`status[31:24]`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XhciCompletionCode {
    Invalid = 0,
    Success = 1,
    DataBufferError = 2,
    BabbleDetected = 3,
    UsbTransactionError = 4,
    TrbError = 5,
    StallError = 6,
    ShortPacket = 13,
    RingUnderrun = 14,
    RingOverrun = 15,
    Unknown(u8),
}

impl XhciCompletionCode {
    #[inline]
    pub const fn from_raw(code: u8) -> Self {
        match code {
            0 => Self::Invalid,
            1 => Self::Success,
            2 => Self::DataBufferError,
            3 => Self::BabbleDetected,
            4 => Self::UsbTransactionError,
            5 => Self::TrbError,
            6 => Self::StallError,
            13 => Self::ShortPacket,
            14 => Self::RingUnderrun,
            15 => Self::RingOverrun,
            other => Self::Unknown(other),
        }
    }
}

/// 16-byte xHCI Transfer Request Block (`XhciTrb`).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XhciTrb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl XhciTrb {
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
        }
    }

    #[inline]
    pub const fn cycle_bit(&self) -> bool {
        (self.control & 0x01) != 0
    }

    #[inline]
    pub const fn set_cycle_bit(&mut self, cycle: bool) {
        if cycle {
            self.control |= 0x01;
        } else {
            self.control &= !0x01;
        }
    }

    #[inline]
    pub const fn trb_type_raw(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    #[inline]
    pub const fn completion_code(&self) -> XhciCompletionCode {
        XhciCompletionCode::from_raw(((self.status >> 24) & 0xFF) as u8)
    }

    /// Builds a Command Ring `Enable Slot` TRB.
    #[inline]
    pub const fn enable_slot_cmd() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: (XhciTrbType::EnableSlotCmd as u32) << 10,
        }
    }

    /// Builds a Command Ring `Address Device` TRB with an Input Context physical pointer.
    #[inline]
    pub const fn address_device_cmd(
        input_context_phys: u64,
        slot_id: u8,
        block_set_address_request: bool,
    ) -> Self {
        let bsr_bit = if block_set_address_request {
            1u32 << 9
        } else {
            0
        };
        Self {
            parameter: input_context_phys & !0x0Fu64,
            status: 0,
            control: ((slot_id as u32) << 24)
                | ((XhciTrbType::AddressDeviceCmd as u32) << 10)
                | bsr_bit,
        }
    }

    /// Builds a Command Ring `Configure Endpoint` TRB.
    #[inline]
    pub const fn configure_endpoint_cmd(input_context_phys: u64, slot_id: u8) -> Self {
        Self {
            parameter: input_context_phys & !0x0Fu64,
            status: 0,
            control: ((slot_id as u32) << 24)
                | ((XhciTrbType::ConfigureEndpointCmd as u32) << 10),
        }
    }

    /// Builds an Endpoint 0 Control Transfer `Setup Stage` TRB containing the 8-byte USB setup packet as Immediate Data (`IDT`).
    #[inline]
    pub const fn setup_stage(setup_packet_u64: u64, transfer_type: u8) -> Self {
        let trt_bits = ((transfer_type & 0x03) as u32) << 16;
        let idt_bit = 1u32 << 6; // Immediate Data
        Self {
            parameter: setup_packet_u64,
            status: 8, // Setup stage length is always 8 bytes
            control: trt_bits | ((XhciTrbType::SetupStage as u32) << 10) | idt_bit,
        }
    }

    /// Builds a Control Transfer `Data Stage` TRB.
    #[inline]
    pub const fn data_stage(data_buf_phys: u64, length: u16, dir_in: bool) -> Self {
        let dir_bit = if dir_in { 1u32 << 16 } else { 0 };
        Self {
            parameter: data_buf_phys,
            status: (length as u32) & 0x1FFFF,
            control: dir_bit | ((XhciTrbType::DataStage as u32) << 10),
        }
    }

    /// Builds a Control Transfer `Status Stage` TRB with Interrupt On Completion (`IOC`).
    #[inline]
    pub const fn status_stage(dir_in: bool, ioc: bool) -> Self {
        let dir_bit = if dir_in { 1u32 << 16 } else { 0 };
        let ioc_bit = if ioc { 1u32 << 5 } else { 0 };
        Self {
            parameter: 0,
            status: 0,
            control: dir_bit | ((XhciTrbType::StatusStage as u32) << 10) | ioc_bit,
        }
    }

    /// Builds a `Link` TRB at the end of a ring segment pointing back to `ring_segment_phys` with Toggle Cycle (`TC`).
    #[inline]
    pub const fn link_trb(ring_segment_phys: u64, toggle_cycle: bool, cycle: bool) -> Self {
        let tc_bit = if toggle_cycle { 1u32 << 1 } else { 0 };
        let c_bit = if cycle { 1u32 } else { 0 };
        Self {
            parameter: ring_segment_phys & !0x0Fu64,
            status: 0,
            control: ((XhciTrbType::Link as u32) << 10) | tc_bit | c_bit,
        }
    }
}

/// Producer TRB Ring state machine (used for Command Ring and Transfer Rings)
/// where the last slot (`N - 1`) is reserved for a `Link` TRB with `Toggle Cycle = 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XhciProducerRing {
    pub ring_phys_base: u64,
    pub total_slots: usize,
    pub enqueue_index: usize,
    pub producer_cycle_state: bool,
}

impl XhciProducerRing {
    pub fn new(ring_phys_base: u64, ring: &mut [XhciTrb]) -> Self {
        let total_slots = ring.len();
        if total_slots >= 2 {
            ring[total_slots - 1] = XhciTrb::link_trb(ring_phys_base, true, false);
        }
        Self {
            ring_phys_base,
            total_slots,
            enqueue_index: 0,
            producer_cycle_state: true,
        }
    }

    /// Enqueues a TRB into `ring`, automatically stamping the current `producer_cycle_state`
    /// and toggling the cycle state when wrapping across the trailing `Link` TRB.
    pub fn enqueue(&mut self, ring: &mut [XhciTrb], mut trb: XhciTrb) -> u64 {
        let trb_phys = self.ring_phys_base + (self.enqueue_index as u64) * 16;
        trb.set_cycle_bit(self.producer_cycle_state);
        ring[self.enqueue_index] = trb;
        self.enqueue_index += 1;

        if self.enqueue_index >= self.total_slots - 1 {
            // Update the Link TRB's cycle bit and wrap back to slot 0 with inverted cycle state
            ring[self.total_slots - 1] =
                XhciTrb::link_trb(self.ring_phys_base, true, self.producer_cycle_state);
            self.enqueue_index = 0;
            self.producer_cycle_state = !self.producer_cycle_state;
        }
        trb_phys
    }
}

/// Decodes the negotiated USB port speed ID (`PORTSC[13:10]`) into Mbps.
#[inline]
pub const fn decode_portsc_speed_mbps(portsc: u32) -> u32 {
    match (portsc >> 10) & 0x0F {
        1 => 12,    // Full Speed (12 Mbps)
        2 => 1,     // Low Speed (1.5 Mbps rounded)
        3 => 480,   // High Speed (480 Mbps)
        4 => 5000,  // SuperSpeed Gen1x1 (5 Gbps)
        5 => 10000, // SuperSpeedPlus Gen2x1 (10 Gbps)
        6 => 10000, // SuperSpeedPlus Gen1x2 (10 Gbps)
        7 => 20000, // SuperSpeedPlus Gen2x2 (20 Gbps)
        _ => 0,
    }
}

/// Self-test for `xhci_usb3` 16-byte TRB layout, Producer Ring cycle toggling, and PORTSC decoding.
pub fn verify_driver_module_xhci_usb3() -> u32 {
    let mut passed = 0u32;

    // 1. Verify XhciTrb size is 16 bytes
    if core::mem::size_of::<XhciTrb>() == 16 {
        passed += 1;
    }

    // 2. Verify Producer Ring enqueue and automatic Link TRB cycle bit inversion on wrap
    let mut trb_buf = [XhciTrb::zeroed(); 4]; // 3 usable slots + 1 Link TRB at index 3
    let mut prod_ring = XhciProducerRing::new(0x9000_0000, &mut trb_buf);

    let p0 = prod_ring.enqueue(&mut trb_buf, XhciTrb::enable_slot_cmd());
    let _p1 = prod_ring.enqueue(&mut trb_buf, XhciTrb::address_device_cmd(0x9001_0000, 1, false));
    let _p2 = prod_ring.enqueue(&mut trb_buf, XhciTrb::configure_endpoint_cmd(0x9001_0000, 1));

    // After 3 enqueues, ring must wrap to index 0 and invert producer_cycle_state from true -> false
    if p0 == 0x9000_0000
        && prod_ring.enqueue_index == 0
        && !prod_ring.producer_cycle_state
        && trb_buf[3].trb_type_raw() == (XhciTrbType::Link as u8)
        && trb_buf[3].cycle_bit()
    {
        passed += 1;
    }

    // 3. Verify Control Transfer Setup/Data/Status TRB builders
    let setup = XhciTrb::setup_stage(0x0100_0680_0000_0012, 3);
    let data = XhciTrb::data_stage(0xA000_0000, 18, true);
    let status = XhciTrb::status_stage(false, true);
    if setup.trb_type_raw() == (XhciTrbType::SetupStage as u8)
        && data.trb_type_raw() == (XhciTrbType::DataStage as u8)
        && status.trb_type_raw() == (XhciTrbType::StatusStage as u8)
    {
        passed += 1;
    }

    // 4. Verify PORTSC USB3 SuperSpeed 5 Gbps decoding
    let portsc = portsc_flags::CCS | portsc_flags::PED | (4u32 << 10);
    if decode_portsc_speed_mbps(portsc) == 5000 {
        passed += 1;
    }

    passed
}

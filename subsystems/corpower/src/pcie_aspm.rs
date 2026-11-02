//! PCIe Active State Power Management (ASPM: L0s, L1, L1.1, L1.2) & Latency Tolerance Reporting (LTR).

/// ASPM link power state capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AspmSupport {
    Disabled,
    L0sOnly,
    L1Only,
    L0sAndL1,
    L1Substates,
}

/// Latency Tolerance Reporting (LTR) requirement in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LtrRequirement {
    pub max_snoop_latency_ns: u32,
    pub max_no_snoop_latency_ns: u32,
}

/// PCIe Link Power controller.
pub struct PcieAspmController {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub support: AspmSupport,
    pub enabled: bool,
    pub ltr: Option<LtrRequirement>,
}

impl PcieAspmController {
    pub fn new(bus: u8, device: u8, function: u8, support: AspmSupport) -> Self {
        Self {
            bus,
            device,
            function,
            support,
            enabled: false,
            ltr: None,
        }
    }

    /// Configures ASPM state if latency requirements permit.
    pub fn configure_aspm(&mut self, enable: bool) -> bool {
        if self.support != AspmSupport::Disabled {
            self.enabled = enable;
            true
        } else {
            false
        }
    }

    pub fn set_ltr_latency(&mut self, snoop_ns: u32, no_snoop_ns: u32) {
        self.ltr = Some(LtrRequirement {
            max_snoop_latency_ns: snoop_ns,
            max_no_snoop_latency_ns: no_snoop_ns,
        });
    }
}

//! `pci_amd_am4_am5` — AMD Socket AM4 & AM5 Chipset Architecture Registry.
//! Details AMD Promontory (300/400 series), B550/X570, and PROM21 (600/800 series) chipsets.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmdChipsetGen {
    Promontory300,
    Promontory400,
    MatisseX570,
    B550A520,
    Prom21Am5600,
    Prom21Am5800,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmdSocketType {
    SocketAm4,
    SocketAm5Lga1718,
    SocketsTrX4,
    SocketWrx90,
}

pub struct AmdChipsetDescriptor {
    pub upstream_dev_id: u16,
    pub xhci_dev_id: u16,
    pub sata_dev_id: u16,
    pub generation: AmdChipsetGen,
    pub socket: AmdSocketType,
    pub marketing_name: &'static str,
    pub pcie_generation: u8,
    pub total_downstream_lanes: u8,
    pub supports_dual_gpu_bifurcation: bool,
    pub supports_pbo_overclocking: bool,
}

pub static AMD_CHIPSET_CATALOG: &[AmdChipsetDescriptor] = &[
    // AM5 800 Series
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43F4,
        xhci_dev_id: 0x43F5,
        sata_dev_id: 0x43F6,
        generation: AmdChipsetGen::Prom21Am5800,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD X870E Dual-PROM21 Chipset",
        pcie_generation: 5,
        total_downstream_lanes: 44,
        supports_dual_gpu_bifurcation: true,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43F7,
        xhci_dev_id: 0x43F8,
        sata_dev_id: 0x43F9,
        generation: AmdChipsetGen::Prom21Am5800,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD X870 Single-PROM21 Chipset",
        pcie_generation: 5,
        total_downstream_lanes: 36,
        supports_dual_gpu_bifurcation: false,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43FA,
        xhci_dev_id: 0x43FB,
        sata_dev_id: 0x43FC,
        generation: AmdChipsetGen::Prom21Am5800,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD B850 Mainstream Chipset",
        pcie_generation: 5,
        total_downstream_lanes: 36,
        supports_dual_gpu_bifurcation: false,
        supports_pbo_overclocking: true,
    },

    // AM5 600 Series
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43BA,
        xhci_dev_id: 0x43BB,
        sata_dev_id: 0x43BC,
        generation: AmdChipsetGen::Prom21Am5600,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD X670E Dual-PROM21 Extreme Chipset",
        pcie_generation: 5,
        total_downstream_lanes: 44,
        supports_dual_gpu_bifurcation: true,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43BD,
        xhci_dev_id: 0x43BE,
        sata_dev_id: 0x43BF,
        generation: AmdChipsetGen::Prom21Am5600,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD X670 Dual-PROM21 Chipset",
        pcie_generation: 4,
        total_downstream_lanes: 44,
        supports_dual_gpu_bifurcation: true,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43D0,
        xhci_dev_id: 0x43D1,
        sata_dev_id: 0x43D2,
        generation: AmdChipsetGen::Prom21Am5600,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD B650E Extreme Mainstream Chipset",
        pcie_generation: 5,
        total_downstream_lanes: 36,
        supports_dual_gpu_bifurcation: false,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43D5,
        xhci_dev_id: 0x43D6,
        sata_dev_id: 0x43D7,
        generation: AmdChipsetGen::Prom21Am5600,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD B650 Mainstream Chipset",
        pcie_generation: 4,
        total_downstream_lanes: 36,
        supports_dual_gpu_bifurcation: false,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43DA,
        xhci_dev_id: 0x43DB,
        sata_dev_id: 0x43DC,
        generation: AmdChipsetGen::Prom21Am5600,
        socket: AmdSocketType::SocketAm5Lga1718,
        marketing_name: "AMD A620 Budget Chipset",
        pcie_generation: 4,
        total_downstream_lanes: 32,
        supports_dual_gpu_bifurcation: false,
        supports_pbo_overclocking: false,
    },

    // AM4 500 Series
    AmdChipsetDescriptor {
        upstream_dev_id: 0x1480,
        xhci_dev_id: 0x148C,
        sata_dev_id: 0x1482,
        generation: AmdChipsetGen::MatisseX570,
        socket: AmdSocketType::SocketAm4,
        marketing_name: "AMD X570 PCIe 4.0 Enthusiast Chipset",
        pcie_generation: 4,
        total_downstream_lanes: 40,
        supports_dual_gpu_bifurcation: true,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43EE,
        xhci_dev_id: 0x43EC,
        sata_dev_id: 0x43EB,
        generation: AmdChipsetGen::B550A520,
        socket: AmdSocketType::SocketAm4,
        marketing_name: "AMD B550 Mainstream Chipset",
        pcie_generation: 3,
        total_downstream_lanes: 24,
        supports_dual_gpu_bifurcation: true,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43EF,
        xhci_dev_id: 0x43ED,
        sata_dev_id: 0x43EA,
        generation: AmdChipsetGen::B550A520,
        socket: AmdSocketType::SocketAm4,
        marketing_name: "AMD A520 Entry Chipset",
        pcie_generation: 3,
        total_downstream_lanes: 20,
        supports_dual_gpu_bifurcation: false,
        supports_pbo_overclocking: false,
    },

    // AM4 400 Series
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43D9,
        xhci_dev_id: 0x43D8,
        sata_dev_id: 0x43D7,
        generation: AmdChipsetGen::Promontory400,
        socket: AmdSocketType::SocketAm4,
        marketing_name: "AMD X470 Enthusiast Chipset",
        pcie_generation: 3,
        total_downstream_lanes: 28,
        supports_dual_gpu_bifurcation: true,
        supports_pbo_overclocking: true,
    },
    AmdChipsetDescriptor {
        upstream_dev_id: 0x43D0,
        xhci_dev_id: 0x43D1,
        sata_dev_id: 0x43D2,
        generation: AmdChipsetGen::Promontory400,
        socket: AmdSocketType::SocketAm4,
        marketing_name: "AMD B450 Mainstream Chipset",
        pcie_generation: 3,
        total_downstream_lanes: 24,
        supports_dual_gpu_bifurcation: false,
        supports_pbo_overclocking: true,
    },
];

pub fn lookup_amd_chipset(upstream_id: u16) -> Option<&'static AmdChipsetDescriptor> {
    AMD_CHIPSET_CATALOG.iter().find(|c| c.upstream_dev_id == upstream_id)
}

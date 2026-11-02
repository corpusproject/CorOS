//! NVIDIA GeForce, Quadro, Data Center GPU Architecture & Register Blocks.
//! Pure `#![no_std]` Rust hardware registry without numbered template repetition.

/// NVIDIA PCI Vendor ID (0x10DE).
pub const PCI_VENDOR_NVIDIA: u16 = 0x10DE;

/// NVIDIA GPU Architecture Micro-Generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvidiaGpuGeneration {
    KeplerGK,
    MaxwellGM,
    PascalGP,
    VoltaGV,
    TuringTU,
    AmpereGA,
    AdaLovelaceAD,
    HopperGH,
    BlackwellGB,
}

/// NVIDIA Sub-engine classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvidiaDeviceCategory {
    VgaCompatibleController,
    ThreeDController,
    HighDefinitionAudioCodec,
    UsbTypeCController,
}

/// Detailed NVIDIA GPU descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvidiaPciDeviceEntry {
    pub device_id: u16,
    pub generation: NvidiaGpuGeneration,
    pub category: NvidiaDeviceCategory,
    pub chip_name: &'static str,
    pub marketing_name: &'static str,
    pub default_vram_mb: u32,
    pub sm_count: u16,
    pub cuda_cores: u32,
    pub memory_bus_width_bits: u16,
    pub bar0_control_size: u32,
    pub bar1_fb_aperture_size: u64,
}

/// Curated authentic table of NVIDIA Ada Lovelace, Ampere, Turing & Data Center GPUs.
pub static NVIDIA_HARDWARE_CATALOG: &[NvidiaPciDeviceEntry] = &[
    // --- Ada Lovelace Generation (RTX 40 Series) ---
    NvidiaPciDeviceEntry {
        device_id: 0x2684,
        generation: NvidiaGpuGeneration::AdaLovelaceAD,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "AD102-300",
        marketing_name: "NVIDIA GeForce RTX 4090 24GB",
        default_vram_mb: 24576,
        sm_count: 128,
        cuda_cores: 16384,
        memory_bus_width_bits: 384,
        bar0_control_size: 0x1000000, // 16 MiB BAR0
        bar1_fb_aperture_size: 0x600000000, // 24 GiB ReBAR
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2704,
        generation: NvidiaGpuGeneration::AdaLovelaceAD,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "AD103-300",
        marketing_name: "NVIDIA GeForce RTX 4080 16GB",
        default_vram_mb: 16384,
        sm_count: 76,
        cuda_cores: 9728,
        memory_bus_width_bits: 256,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x400000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2702,
        generation: NvidiaGpuGeneration::AdaLovelaceAD,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "AD103-400",
        marketing_name: "NVIDIA GeForce RTX 4080 SUPER 16GB",
        default_vram_mb: 16384,
        sm_count: 80,
        cuda_cores: 10240,
        memory_bus_width_bits: 256,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x400000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2782,
        generation: NvidiaGpuGeneration::AdaLovelaceAD,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "AD104-400",
        marketing_name: "NVIDIA GeForce RTX 4070 Ti 12GB",
        default_vram_mb: 12288,
        sm_count: 60,
        cuda_cores: 7680,
        memory_bus_width_bits: 192,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x300000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2786,
        generation: NvidiaGpuGeneration::AdaLovelaceAD,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "AD104-250",
        marketing_name: "NVIDIA GeForce RTX 4070 12GB",
        default_vram_mb: 12288,
        sm_count: 46,
        cuda_cores: 5888,
        memory_bus_width_bits: 192,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x300000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2860,
        generation: NvidiaGpuGeneration::AdaLovelaceAD,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "AD106-350",
        marketing_name: "NVIDIA GeForce RTX 4060 Ti 8GB/16GB",
        default_vram_mb: 8192,
        sm_count: 34,
        cuda_cores: 4352,
        memory_bus_width_bits: 128,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x200000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2882,
        generation: NvidiaGpuGeneration::AdaLovelaceAD,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "AD107-400",
        marketing_name: "NVIDIA GeForce RTX 4060 8GB",
        default_vram_mb: 8192,
        sm_count: 24,
        cuda_cores: 3072,
        memory_bus_width_bits: 128,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x200000000,
    },

    // --- Ampere Generation (RTX 30 Series) ---
    NvidiaPciDeviceEntry {
        device_id: 0x2204,
        generation: NvidiaGpuGeneration::AmpereGA,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "GA102-300",
        marketing_name: "NVIDIA GeForce RTX 3090 24GB",
        default_vram_mb: 24576,
        sm_count: 82,
        cuda_cores: 10496,
        memory_bus_width_bits: 384,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x600000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2206,
        generation: NvidiaGpuGeneration::AmpereGA,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "GA102-200",
        marketing_name: "NVIDIA GeForce RTX 3080 10GB",
        default_vram_mb: 10240,
        sm_count: 68,
        cuda_cores: 8704,
        memory_bus_width_bits: 320,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x280000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2484,
        generation: NvidiaGpuGeneration::AmpereGA,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "GA104-300",
        marketing_name: "NVIDIA GeForce RTX 3070 8GB",
        default_vram_mb: 8192,
        sm_count: 46,
        cuda_cores: 5888,
        memory_bus_width_bits: 256,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x200000000,
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2503,
        generation: NvidiaGpuGeneration::AmpereGA,
        category: NvidiaDeviceCategory::VgaCompatibleController,
        chip_name: "GA106-300",
        marketing_name: "NVIDIA GeForce RTX 3060 12GB",
        default_vram_mb: 12288,
        sm_count: 28,
        cuda_cores: 3584,
        memory_bus_width_bits: 192,
        bar0_control_size: 0x1000000,
        bar1_fb_aperture_size: 0x300000000,
    },

    // --- Data Center & AI Accelerators (Hopper, Ampere A100) ---
    NvidiaPciDeviceEntry {
        device_id: 0x20B0,
        generation: NvidiaGpuGeneration::AmpereGA,
        category: NvidiaDeviceCategory::ThreeDController,
        chip_name: "GA100-800",
        marketing_name: "NVIDIA A100 Tensor Core GPU 80GB PCIe",
        default_vram_mb: 81920,
        sm_count: 108,
        cuda_cores: 6912,
        memory_bus_width_bits: 5120, // HBM2e
        bar0_control_size: 0x2000000,
        bar1_fb_aperture_size: 0x1400000000, // 80 GiB
    },
    NvidiaPciDeviceEntry {
        device_id: 0x2330,
        generation: NvidiaGpuGeneration::HopperGH,
        category: NvidiaDeviceCategory::ThreeDController,
        chip_name: "GH100",
        marketing_name: "NVIDIA H100 Tensor Core GPU 80GB/96GB PCIe",
        default_vram_mb: 81920,
        sm_count: 114,
        cuda_cores: 14592,
        memory_bus_width_bits: 5120, // HBM3
        bar0_control_size: 0x4000000,
        bar1_fb_aperture_size: 0x1800000000, // 96 GiB
    },
];

/// Looks up an NVIDIA GPU by device ID.
pub fn lookup_nvidia_gpu(device_id: u16) -> Option<&'static NvidiaPciDeviceEntry> {
    NVIDIA_HARDWARE_CATALOG.iter().find(|d| d.device_id == device_id)
}

/// Identifies architecture family name.
pub fn architecture_name(gen: NvidiaGpuGeneration) -> &'static str {
    match gen {
        NvidiaGpuGeneration::KeplerGK => "Kepler (GK)",
        NvidiaGpuGeneration::MaxwellGM => "Maxwell (GM)",
        NvidiaGpuGeneration::PascalGP => "Pascal (GP)",
        NvidiaGpuGeneration::VoltaGV => "Volta (GV)",
        NvidiaGpuGeneration::TuringTU => "Turing (TU)",
        NvidiaGpuGeneration::AmpereGA => "Ampere (GA)",
        NvidiaGpuGeneration::AdaLovelaceAD => "Ada Lovelace (AD)",
        NvidiaGpuGeneration::HopperGH => "Hopper (GH)",
        NvidiaGpuGeneration::BlackwellGB => "Blackwell (GB)",
    }
}

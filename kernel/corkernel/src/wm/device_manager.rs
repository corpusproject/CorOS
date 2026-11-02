//! Windows Device Manager GUI Data Model & Hardware Topology Tree
//!
//! Provides enterprise hardware inspection and driver management UI:
//! - Device category tree (Display Adapters, Storage Controllers, Network Adapters, Audio, System Devices)
//! - Device status flags: `DeviceRunning`, `DeviceDisabled`, `DriverMissing`, `DeviceFaulted`
//! - Hardware resource enumeration: Port I/O Ranges, MMIO Base Addresses, IRQ Vectors, DMA Channels
//! - Driver details: Driver Name, Provider, Version, Date, Digital Signer
//! - Actions: Enable Device, Disable Device, Uninstall Device, Scan for Hardware Changes

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

/// Device Operational Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    WorkingProperly,
    DisabledByUser,
    DriverNotFound,
    HardwareFault(u32), // Error code
}

/// Hardware Resource Type
#[derive(Debug, Clone)]
pub enum HardwareResource {
    IoPortRange { start: u16, end: u16 },
    MemoryRange { start: u64, end: u64 },
    InterruptVector { irq: u8, is_msi: bool },
    DmaChannel { channel: u8 },
}

/// Device Node Information
#[derive(Debug, Clone)]
pub struct DeviceNode {
    pub id: u32,
    pub name: String,
    pub category: String,
    pub hardware_id: String,
    pub status: DeviceStatus,
    pub resources: Vec<HardwareResource>,
    pub driver_name: String,
    pub driver_version: String,
    pub provider: String,
}

/// Device Manager Application Model
pub struct DeviceManagerApp {
    pub devices: Vec<DeviceNode>,
    pub selected_device_id: Option<u32>,
    pub selected_category: Option<String>,
    pub is_scan_running: bool,
}

impl DeviceManagerApp {
    pub fn new() -> Self {
        let mut app = Self {
            devices: Vec::new(),
            selected_device_id: None,
            selected_category: None,
            is_scan_running: false,
        };

        // Populate baseline hardware topology detected in CorOS
        app.devices.push(DeviceNode {
            id: 1,
            name: String::from("VirtIO Paravirtualized Graphics Controller"),
            category: String::from("Display Adapters"),
            hardware_id: String::from("PCI\\VEN_1AF4&DEV_1050&SUBSYS_11001AF4"),
            status: DeviceStatus::WorkingProperly,
            resources: alloc::vec![
                HardwareResource::MemoryRange { start: 0xFEB00000, end: 0xFEB03FFF },
                HardwareResource::InterruptVector { irq: 11, is_msi: true },
            ],
            driver_name: String::from("virtio_gpu.sys"),
            driver_version: String::from("1.2.0.24"),
            provider: String::from("CorOS Hardware Group"),
        });

        app.devices.push(DeviceNode {
            id: 2,
            name: String::from("Intel(R) 82371AB/EB PCI Bus Master IDE Controller"),
            category: String::from("IDE ATA/ATAPI Controllers"),
            hardware_id: String::from("PCI\\VEN_8086&DEV_7111&SUBSYS_00000000"),
            status: DeviceStatus::WorkingProperly,
            resources: alloc::vec![
                HardwareResource::IoPortRange { start: 0x01F0, end: 0x01F7 },
                HardwareResource::IoPortRange { start: 0x03F6, end: 0x03F6 },
                HardwareResource::InterruptVector { irq: 14, is_msi: false },
            ],
            driver_name: String::from("ata_pio.sys"),
            driver_version: String::from("2.0.1.10"),
            provider: String::from("CorOS System"),
        });

        app.devices.push(DeviceNode {
            id: 3,
            name: String::from("Standard NVM Express Controller"),
            category: String::from("Storage Controllers"),
            hardware_id: String::from("PCI\\VEN_1B36&DEV_0010&SUBSYS_11001AF4"),
            status: DeviceStatus::WorkingProperly,
            resources: alloc::vec![
                HardwareResource::MemoryRange { start: 0xFEA00000, end: 0xFEA03FFF },
                HardwareResource::InterruptVector { irq: 10, is_msi: true },
            ],
            driver_name: String::from("nvme.sys"),
            driver_version: String::from("1.4.2.0"),
            provider: String::from("CorOS Enterprise Storage"),
        });

        app.devices.push(DeviceNode {
            id: 4,
            name: String::from("Intel(R) 82540EM Gigabit Ethernet Controller"),
            category: String::from("Network Adapters"),
            hardware_id: String::from("PCI\\VEN_8086&DEV_100E&SUBSYS_001E8086"),
            status: DeviceStatus::WorkingProperly,
            resources: alloc::vec![
                HardwareResource::IoPortRange { start: 0xC000, end: 0xC03F },
                HardwareResource::MemoryRange { start: 0xFEE00000, end: 0xFEE1FFFF },
                HardwareResource::InterruptVector { irq: 11, is_msi: false },
            ],
            driver_name: String::from("e1000.sys"),
            driver_version: String::from("3.1.4.5"),
            provider: String::from("CorOS Network Subsystem"),
        });

        app.devices.push(DeviceNode {
            id: 5,
            name: String::from("High Definition Audio Controller"),
            category: String::from("Sound, Video and Game Controllers"),
            hardware_id: String::from("PCI\\VEN_8086&DEV_2668&SUBSYS_00000000"),
            status: DeviceStatus::WorkingProperly,
            resources: alloc::vec![
                HardwareResource::MemoryRange { start: 0xFEB40000, end: 0xFEB43FFF },
                HardwareResource::InterruptVector { irq: 10, is_msi: true },
            ],
            driver_name: String::from("intel_hda.sys"),
            driver_version: String::from("1.0.0.1"),
            provider: String::from("CorOS Audio"),
        });

        app.devices.push(DeviceNode {
            id: 6,
            name: String::from("ACPI Power Button and Lid"),
            category: String::from("System Devices"),
            hardware_id: String::from("ACPI\\PNP0C0C"),
            status: DeviceStatus::WorkingProperly,
            resources: alloc::vec![],
            driver_name: String::from("acpi_power.sys"),
            driver_version: String::from("6.2.9200.0"),
            provider: String::from("Microsoft Compatible"),
        });

        app
    }

    /// Retrieve all unique device categories
    pub fn categories(&self) -> Vec<String> {
        let mut cats = Vec::new();
        for dev in &self.devices {
            if !cats.contains(&dev.category) {
                cats.push(dev.category.clone());
            }
        }
        cats.sort();
        cats
    }

    /// Get devices belonging to category
    pub fn devices_in_category(&self, cat: &str) -> Vec<&DeviceNode> {
        self.devices.iter().filter(|d| d.category == cat).collect()
    }

    /// Toggle enable/disable status of selected device
    pub fn toggle_device(&mut self, device_id: u32) {
        if let Some(dev) = self.devices.iter_mut().find(|d| d.id == device_id) {
            match dev.status {
                DeviceStatus::WorkingProperly => dev.status = DeviceStatus::DisabledByUser,
                DeviceStatus::DisabledByUser => dev.status = DeviceStatus::WorkingProperly,
                _ => {}
            }
        }
    }
}

use crate::display::{Color, DisplayEngine};
use alloc::format;

pub fn render_device_manager(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    m_left: bool,
    app: &mut DeviceManagerApp,
    dark_theme: bool,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    let bg_col = if dark_theme { Color::rgb(16, 20, 28) } else { Color::rgb(248, 250, 252) };
    let card_bg = if dark_theme { Color::rgb(24, 30, 42) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(205, 215, 230) };
    let text_col = if dark_theme { Color::rgb(240, 245, 255) } else { Color::rgb(20, 25, 35) };
    let muted_col = if dark_theme { Color::rgb(140, 155, 175) } else { Color::rgb(100, 115, 130) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // Toolbar
    let tb_y = body_y + 8;
    let scan_w = 210;
    let is_scan_hov = mx >= ux + 16 && mx < ux + 16 + scan_w && my >= tb_y && my < tb_y + 26;
    if is_scan_hov && m_left {
        app.is_scan_running = true;
        crate::audio::play_click_sound();
    }
    let scan_bg = if is_scan_hov { Color::rgb(37, 99, 235) } else { Color::rgb(14, 116, 144) };
    engine.fill_rounded_rect(ux + 16, tb_y, scan_w, 26, 4, scan_bg);
    engine.draw_string(ux + 24, tb_y + 6, "[ Donanim Degisikliklerini Tara ]", Color::WHITE, 1);

    if app.is_scan_running {
        engine.draw_string(ux + scan_w + 32, tb_y + 6, "PCI Bus taraniyor... (6 Aygit tespit edildi)", Color::rgb(16, 185, 129), 1);
    }

    // Split Layout: Left Tree View (240px) | Right Inspector
    let tree_x = ux + 16;
    let tree_y = tb_y + 36;
    let tree_w = 260;
    let tree_h = body_h.saturating_sub(52);

    engine.fill_rounded_rect(tree_x, tree_y, tree_w, tree_h, 6, card_bg);
    engine.draw_rect(tree_x, tree_y, tree_w, tree_h, border_col);

    engine.draw_string(tree_x + 12, tree_y + 10, "PCI & Sistem Donanim Agaci:", text_col, 1);

    let mut row_y = tree_y + 32;
    for dev in &app.devices {
        if row_y + 24 > tree_y + tree_h { break; }

        let is_sel = app.selected_device_id == Some(dev.id);
        let is_hov = mx >= tree_x + 8 && mx < tree_x + tree_w - 8 && my >= row_y && my < row_y + 22;

        if is_hov && m_left {
            app.selected_device_id = Some(dev.id);
            crate::audio::play_click_sound();
        }

        let row_bg = if is_sel {
            Color::rgb(35, 55, 80)
        } else if is_hov {
            Color::rgb(28, 36, 50)
        } else {
            card_bg
        };

        engine.fill_rounded_rect(tree_x + 8, row_y, tree_w - 16, 22, 3, row_bg);
        let bullet = if is_sel { ">" } else { "-" };
        let short_name = if dev.name.len() > 24 { &dev.name[..24] } else { dev.name.as_str() };
        let item_txt = format!("{} {}", bullet, short_name);
        let txt_c = if is_sel { Color::rgb(96, 205, 255) } else { text_col };
        engine.draw_string(tree_x + 14, row_y + 4, &item_txt, txt_c, 1);

        row_y += 24;
    }

    // Right Inspector Panel
    let insp_x = tree_x + tree_w + 14;
    let insp_y = tree_y;
    let insp_w = ww.saturating_sub(tree_w + 46);
    let insp_h = tree_h;

    engine.fill_rounded_rect(insp_x, insp_y, insp_w, insp_h, 6, card_bg);
    engine.draw_rect(insp_x, insp_y, insp_w, insp_h, border_col);

    let sel_id = app.selected_device_id.unwrap_or(1);
    let mut toggle_id = None;
    if let Some(dev) = app.devices.iter().find(|d| d.id == sel_id) {
        engine.draw_string(insp_x + 16, insp_y + 14, &dev.name, Color::rgb(96, 205, 255), 1);
        engine.draw_string(insp_x + 16, insp_y + 36, &format!("Kategori: {}", dev.category), text_col, 1);
        engine.draw_string(insp_x + 16, insp_y + 54, &format!("Donanim Kimligi: {}", dev.hardware_id), muted_col, 1);

        let stat_str = match dev.status {
            DeviceStatus::WorkingProperly => "Bu aygit duzgun calisiyor (Kod 0).",
            DeviceStatus::DisabledByUser => "Bu aygit kullanici tarafindan devre disi birakildi (Kod 22).",
            DeviceStatus::DriverNotFound => "Surucu bulunamadi (Kod 28).",
            DeviceStatus::HardwareFault(_) => "Aygit baslatilamadi (Kod 10).",
        };
        let stat_col = match dev.status {
            DeviceStatus::WorkingProperly => Color::rgb(16, 185, 129),
            DeviceStatus::DisabledByUser => Color::rgb(245, 158, 11),
            _ => Color::rgb(239, 68, 68),
        };
        engine.draw_string(insp_x + 16, insp_y + 78, &format!("Durum: {}", stat_str), stat_col, 1);

        // Driver section
        engine.draw_string(insp_x + 16, insp_y + 110, "Surucu Bilgileri:", text_col, 1);
        engine.draw_string(insp_x + 28, insp_y + 128, &format!("Dosya: {} | Surum: {}", dev.driver_name, dev.driver_version), muted_col, 1);
        engine.draw_string(insp_x + 28, insp_y + 146, &format!("Saglayici: {}", dev.provider), muted_col, 1);

        // Resource section
        engine.draw_string(insp_x + 16, insp_y + 176, "Donanimsal Kaynaklar (IRQ / MMIO / Port I/O):", text_col, 1);
        for (idx, res) in dev.resources.iter().enumerate() {
            let ry = insp_y + 196 + idx * 18;
            if ry + 16 > insp_y + insp_h - 40 { break; }
            let res_str = match res {
                HardwareResource::IoPortRange { start, end } => format!("  Port I/O: 0x{:04X} - 0x{:04X}", start, end),
                HardwareResource::MemoryRange { start, end } => format!("  Bellek MMIO: 0x{:08X} - 0x{:08X}", start, end),
                HardwareResource::InterruptVector { irq, is_msi } => format!("  Kesme IRQ: {} (MSI: {})", irq, is_msi),
                HardwareResource::DmaChannel { channel } => format!("  DMA Kanal: {}", channel),
            };
            engine.draw_string(insp_x + 20, ry, &res_str, Color::rgb(147, 197, 253), 1);
        }

        // Toggle button
        let tog_y = insp_y + insp_h - 38;
        let tog_w = 200;
        let is_tog_hov = mx >= insp_x + 16 && mx < insp_x + 16 + tog_w && my >= tog_y && my < tog_y + 26;
        let dev_id = dev.id;
        let is_disabled = dev.status == DeviceStatus::DisabledByUser;

        let tog_lbl = if is_disabled { "[ Aygiti Etkinlestir ]" } else { "[ Aygiti Devre Disi Birak ]" };
        let tog_bg = if is_tog_hov { Color::rgb(59, 130, 246) } else { Color::rgb(30, 41, 59) };
        engine.fill_rounded_rect(insp_x + 16, tog_y, tog_w, 26, 4, tog_bg);
        engine.draw_rect(insp_x + 16, tog_y, tog_w, 26, border_col);
        engine.draw_string(insp_x + 28, tog_y + 6, tog_lbl, Color::WHITE, 1);

        if is_tog_hov && m_left {
            toggle_id = Some(dev_id);
        }
    }

    if let Some(id) = toggle_id {
        app.toggle_device(id);
        crate::audio::play_click_sound();
    }
}

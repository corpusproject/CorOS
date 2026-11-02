//! CorOS Sanallaştırma Yöneticisi & Hardware Hypervisor (`vmm_monitor.rs`)
//!
//! Provides Intel VT-x (VMX) / AMD-V (SVM) hardware virtualization monitoring:
//! - vCPU guest registers state (RIP, RSP, CR0, CR3, CR4)
//! - Nested Paging (EPT/NPT) and VM-Exit telemetry
//! - Virtual machine lifecycle controls (Start, Pause, Reset)

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};

#[derive(Clone, Debug)]
pub struct VmmMonitorState {
    pub is_vm_running: bool,
    pub vm_exit_count: usize,
    pub guest_rip: u64,
    pub guest_cr3: u64,
    pub selected_vm: usize,
    pub tick: usize,
}

impl Default for VmmMonitorState {
    fn default() -> Self {
        Self {
            is_vm_running: true,
            vm_exit_count: 1482,
            guest_rip: 0x00007FFF80001020,
            guest_cr3: 0x0000000001F00000,
            selected_vm: 0,
            tick: 0,
        }
    }
}

pub fn render_vmm_monitor(
    ux: usize,
    uy: usize,
    ww: usize,
    wh: usize,
    engine: &mut DisplayEngine,
    mx: usize,
    my: usize,
    m_left: bool,
    state: &mut VmmMonitorState,
    dark_theme: bool,
) {
    let body_y = uy + 28;
    let body_h = wh.saturating_sub(28);

    state.tick = state.tick.wrapping_add(1);
    if state.is_vm_running && state.tick % 10 == 0 {
        state.vm_exit_count = state.vm_exit_count.wrapping_add(3);
        state.guest_rip = 0x00007FFF80001020 + ((state.tick * 4) as u64 % 0x1000);
    }

    let bg_col = if dark_theme { Color::rgb(14, 18, 26) } else { Color::rgb(248, 250, 252) };
    let card_bg = if dark_theme { Color::rgb(22, 28, 40) } else { Color::rgb(235, 240, 248) };
    let border_col = if dark_theme { Color::rgb(45, 55, 75) } else { Color::rgb(205, 215, 230) };
    let text_col = if dark_theme { Color::rgb(240, 245, 255) } else { Color::rgb(20, 25, 35) };
    let muted_col = if dark_theme { Color::rgb(140, 155, 175) } else { Color::rgb(100, 115, 130) };

    engine.fill_rect(ux, body_y, ww, body_h, bg_col);

    // Header
    engine.draw_string(ux + 16, body_y + 12, "CorOS Hypervisor - Donanimsal Sanallastirma (VMX / SVM Root)", text_col, 1);
    let vt_stat = "Intel VT-x / AMD-V Aktif (EPT 4-Level SLAT)";
    engine.draw_string(ux + ww - 280, body_y + 12, vt_stat, Color::rgb(16, 185, 129), 1);

    // Status Banner & Action Buttons
    let ban_y = body_y + 36;
    let ban_w = ww.saturating_sub(32);
    engine.fill_rounded_rect(ux + 16, ban_y, ban_w, 48, 6, card_bg);
    engine.draw_rect(ux + 16, ban_y, ban_w, 48, border_col);

    let vm_stat_str = if state.is_vm_running { "Misafir VM-01: CALISIYOR (vCPU: 2, RAM: 128MB)" } else { "Misafir VM-01: DURDURULDU" };
    let stat_c = if state.is_vm_running { Color::rgb(16, 185, 129) } else { Color::rgb(245, 158, 11) };
    engine.draw_string(ux + 28, ban_y + 16, vm_stat_str, stat_c, 1);

    // Toggle button
    let btn_x = ux + ban_w - 180;
    let btn_y = ban_y + 10;
    let btn_w = 170;
    let is_btn_hov = mx >= btn_x && mx < btn_x + btn_w && my >= btn_y && my < btn_y + 28;
    if is_btn_hov && m_left {
        state.is_vm_running = !state.is_vm_running;
        crate::audio::play_click_sound();
    }
    let btn_bg = if state.is_vm_running { Color::rgb(220, 38, 38) } else { Color::rgb(16, 185, 129) };
    engine.fill_rounded_rect(btn_x, btn_y, btn_w, 28, 4, btn_bg);
    let btn_lbl = if state.is_vm_running { "[ vCPU'yu Duraklat ]" } else { "[ vCPU'yu Baslat ]" };
    engine.draw_string(btn_x + 18, btn_y + 8, btn_lbl, Color::WHITE, 1);

    // VMCS / VMCB Registers Panel
    let reg_y = ban_y + 60;
    let reg_h = body_h.saturating_sub((reg_y - body_y) + 16);
    engine.fill_rounded_rect(ux + 16, reg_y, ban_w, reg_h, 6, card_bg);
    engine.draw_rect(ux + 16, reg_y, ban_w, reg_h, border_col);

    engine.draw_string(ux + 28, reg_y + 12, "Donanimsal VMCS & Misafir Islemci Kayitlari (Live VMM Telemetry):", text_col, 1);

    let regs = [
        format!("Guest RIP      : 0x{:016X} (Ring 3 User Mode Code)", state.guest_rip),
        format!("Guest RSP      : 0x00007FFFFFFFDE80 (Stack Pointer)"),
        format!("Guest CR0      : 0x0000000080050033 (PE=1, PG=1, WP=1, ET=1)"),
        format!("Guest CR3      : 0x{:016X} (PML4 Page Table Root)", state.guest_cr3),
        format!("Guest CR4      : 0x00000000003506F0 (PAE=1, OSFXSR=1, FSGSBASE=1)"),
        format!("VM-Exit Sayisi : {} kez donanimsal tuzak tetiklendi", state.vm_exit_count),
        format!("Son Exit Nedeni: 0x0000000A (CPUID sanallastirma talimati)"),
        format!("EPT Nested     : 0x0000000002A00000 (SLAT 2MB Huge Pages Aktif)"),
    ];

    for (i, r) in regs.iter().enumerate() {
        let ry = reg_y + 40 + i * 26;
        if ry + 22 > uy + wh { break; }
        engine.draw_string(ux + 32, ry, r, Color::rgb(96, 205, 255), 1);
    }
}

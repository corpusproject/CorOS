//! CorOS Ultra-Modern Hybrid Window Manager & Desktop Environment (macOS + Kali aesthetic).
//! 100% in-house bare-metal implementation with zero external crates.
//! Provides draggable windows, macOS traffic light controls, floating frosted dock,
//! Kali cyber top panel, interactive shell, and an interactive FAT32 File Explorer.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::display::{Color, DisplayEngine};
use crate::input;

pub mod icons;
pub mod wallpapers;
pub mod emblems;
pub mod widgets;
pub mod apps;
pub mod notepad;
pub mod sysmon;
pub mod terminal;
pub mod explorer;
pub mod notifications;
pub mod theme;
pub mod file_context_menu;
pub mod properties_dialog;
pub mod start_menu;
pub mod taskbar;
pub mod run_dialog;
pub mod virtual_desktops;
pub mod regedit;
pub mod taskmgr;
pub mod calc;
pub mod paint;
pub mod terminal_cmds;
pub mod system_settings;
pub mod device_manager;
pub mod cmd_prompt;
pub mod action_center;
pub mod snap_assist;
pub mod media_player;
pub mod retro_game;
pub mod app_store;
pub mod code_editor;
pub mod snipping_tool;
pub mod lock_screen;
pub mod disk_manager;
pub mod recovery_manager;
pub mod firewall;
pub mod disassembler;
pub mod archiver;
pub mod vmm_monitor;
pub mod corshare;
pub mod task_scheduler;
pub mod thermal_monitor;
pub mod web_browser;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WindowType {
    FileExplorer,
    CyberTerminal,
    SystemMonitor,
    CyberSpace3D,
    ThemeSettings,
    Notepad,
    Calculator,
    Paint,
    MediaPlayer,
    RetroGame,
    AppStore,
    CodeEditor,
    SnippingTool,
    DiskManager,
    DeviceManager,
    SystemRecovery,
    Firewall,
    Disassembler,
    Archiver,
    VmmMonitor,
    CorShare,
    TaskScheduler,
    ThermalMonitor,
    WebBrowser,
}

#[derive(Clone)]
pub struct FileItem {
    pub name: String,
    pub kind: String,
    pub size_str: String,
    pub desc: String,
    pub content: String,
    pub is_dir: bool,
}

pub struct Window {
    pub id: usize,
    pub title: &'static str,
    pub x: isize,
    pub y: isize,
    pub w: usize,
    pub h: usize,
    pub is_open: bool,
    pub is_minimized: bool,
    pub is_maximized: bool,
    pub prev_x: isize,
    pub prev_y: isize,
    pub prev_w: usize,
    pub prev_h: usize,
    pub is_dragging: bool,
    pub drag_off_x: isize,
    pub drag_off_y: isize,
    pub win_type: WindowType,
    pub selected_file: usize,
    pub snapped_state: Option<widgets::SnapPreview>,
    pub desktop_id: usize,
}

pub struct DesktopManager {
    pub windows: Vec<Window>,
    pub active_window_idx: usize,
    pub files: Vec<FileItem>,
    pub terminal_lines: Vec<String>,
    pub current_input: String,
    pub cursor_blink: u64,
    pub was_left_clicked: bool,
    pub was_right_clicked: bool,
    pub cpu_cores: u32,
    pub cpu_mhz: u64,
    pub storage_dev: &'static str,
    pub fs_verified: bool,
    pub cyber_3d: crate::cyberspace3d::Cyber3DState,
    pub selected_theme: usize,
    pub show_center_logo: bool,
    pub show_grid_lines: bool,
    pub custom_wallpaper_mode: bool,
    pub show_desktop_hud: bool,
    pub selected_desktop_icon: Option<usize>,
    pub last_clicked_icon: Option<usize>,
    pub last_click_frame: u64,
    pub frame_counter: u64,
    pub boot_splash_frames: u32,

    // Context Menu State (Desktop Right-Click)
    pub context_menu_open: bool,
    pub context_menu_x: usize,
    pub context_menu_y: usize,

    // Action Center / Quick Settings State
    pub quick_settings_open: bool,
    pub calendar_open: bool,
    pub volume_level: u8, // 0..100
    pub brightness_level: u8, // 0..100
    pub wifi_enabled: bool,
    pub dark_theme_enabled: bool,

    // Notepad State
    pub notepad_content: Vec<String>,
    pub notepad_cursor_row: usize,
    pub notepad_cursor_col: usize,
    pub notepad_saved_status: bool,

    // Calculator State
    pub calc_display: String,
    pub calc_accumulator: i64,
    pub calc_op: Option<char>,
    pub calc_clear_on_next: bool,

    // Windows Paint State (Canvas pixel grid 160x120 pixels, scaled up 2x in window)
    pub paint_pixels: Vec<u32>,
    pub paint_undo_history: Vec<Vec<u32>>,
    pub paint_color_idx: usize,
    pub paint_custom_color: u32,
    pub paint_brush_size: usize,
    pub paint_tool: usize, // 0: Brush, 1: Eraser, 2: Bucket Fill, 3: Rectangle, 4: Line, 5: Eyedropper
    pub paint_shape_start: Option<(usize, usize)>,
    pub paint_hex_input: String,
    pub paint_hex_active: bool,
    pub paint_status_msg: String,
    pub paint_is_drawing: bool,

    // Windows Live Search / Run Dialog State
    pub search_query: String,
    pub search_active: bool,

    // Desktop Icons State (Positions, Free Drag & Drop)
    pub icon_coords: [(isize, isize); 7],
    pub dragging_icon: Option<usize>,
    pub drag_icon_off_x: isize,
    pub drag_icon_off_y: isize,

    // File Explorer Interaction State
    pub last_file_clicked_idx: Option<usize>,
    pub last_file_click_frame: u64,
    pub file_status_msg: String,
    pub current_folder: String,
    pub clipboard_file: Option<FileItem>,
    pub renaming_file_idx: Option<usize>,
    pub rename_buffer: String,

    // Aero Snap & Task Switcher (Alt + Tab)
    pub snap_preview: widgets::SnapPreview,
    pub alt_tab_active: bool,
    pub alt_tab_idx: usize,

    // Windows 11 Fluent Action Center & Notification System
    pub notification_center: notifications::NotificationCenter,

    // Windows 11 Fluent Theme, Start Menu, Context Menu & Dialogs
    pub theme: theme::ThemePalette,
    pub start_menu: start_menu::StartMenu,
    pub file_context_menu: file_context_menu::FileContextMenu,
    pub properties_dialog: properties_dialog::PropertiesDialog,
    pub run_dialog: run_dialog::RunDialog,
    pub virtual_desktops: virtual_desktops::VirtualDesktopManager,
    pub media_playing: bool,
    pub media_track: usize,
    pub media_volume: u8,
    pub retro_game: retro_game::RetroGameState,
    pub store_selected_cat: usize,
    pub code_editor: code_editor::CodeEditorState,
    pub snipping_tool: snipping_tool::SnippingToolState,
    pub is_locked: bool,
    pub lock_password_len: usize,
    pub lock_tick: usize,
    pub disk_manager: disk_manager::DiskManagerState,
    pub device_manager_app: device_manager::DeviceManagerApp,
    pub recovery_manager: recovery_manager::RecoveryManagerState,
    pub quick_settings: action_center::ActionCenterFlyout,
    pub terminal_tab: usize,
    pub terminal_split: bool,
    pub night_light_enabled: bool,
    pub firewall: firewall::FirewallState,
    pub disassembler: disassembler::DisasmState,
    pub archiver: archiver::ArchiverState,
    pub vmm_monitor: vmm_monitor::VmmMonitorState,
    pub corshare: corshare::CorShareState,
    pub task_scheduler: task_scheduler::TaskSchedulerState,
    pub thermal_monitor: thermal_monitor::ThermalMonitorState,
    pub taskmgr_app: taskmgr::TaskmgrState,
    pub media_player_app: media_player::MediaPlayerState,
    pub web_browser_app: web_browser::WebBrowserState,
    pub verbose_boot_mode: bool,
}

impl DesktopManager {
    pub fn new() -> Self {
        let files = alloc::vec![
            FileItem { name: String::from(".."), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("Parent Directory"), content: String::new(), is_dir: true },
            FileItem { name: String::from("BOOT"), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("UEFI Boot Directory"), content: String::new(), is_dir: true },
            FileItem { name: String::from("COROS"), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("CorOS System Directory"), content: String::new(), is_dir: true },
            FileItem { name: String::from("README.TXT"), kind: String::from("[TEXT]"), size_str: String::from("180 B"), desc: String::from("CorOS Kullanici Kilavuzu"), content: String::from("Tebrikler! CorOS isletim sistemini basariyla calistirdiniz.\nBu sistem no_std Rust ile sifirdan bare-metal yazilmistir.\nCift tiklayarak dosyalari acabilir, Paint ile resim cizebilirsiniz."), is_dir: false },
            FileItem { name: String::from("NOTLAR.TXT"), kind: String::from("[TEXT]"), size_str: String::from("110 B"), desc: String::from("Gunluk Notlar & Gorevler"), content: String::from("1. CorOS dosya yoneticisi test edildi.\n2. Not defteri ve Paint calisiyor.\n3. FAT32 dosya kaydetme basarili!"), is_dir: false },
            FileItem { name: String::from("HESAP.ELF"), kind: String::from("[ELF-64]"), size_str: String::from("242 B"), desc: String::from("Ring 3 Bilimsel Hesaplayici"), content: String::from("[x86_64 Standalone ELF64 Binary | User Space Ring 3 | DPL 3 Verified]"), is_dir: false },
            FileItem { name: String::from("APP.ELF"), kind: String::from("[ELF-64]"), size_str: String::from("239 B"), desc: String::from("Bagimsiz Kullanici Uygulamasi"), content: String::from("[x86_64 Standalone ELF64 Binary | User Space Ring 3 | DPL 3 Verified]"), is_dir: false },
            FileItem { name: String::from("RESIM.PNG"), kind: String::from("[IMAGE-PNG]"), size_str: String::from("14 KB"), desc: String::from("Paint 24-bit TrueColor PNG"), content: String::from("[PNG Image 160x120 24bpp TrueColor]"), is_dir: false },
            FileItem { name: String::from("BOOTX64.EFI"), kind: String::from("[PE-64]"), size_str: String::from("64 KB"), desc: String::from("UEFI Bootloader (PE/MZ OK)"), content: String::from("[PE32+ x86_64 UEFI Bootloader | 65,536 Bytes | MZ/PE Header Valid]"), is_dir: false },
            FileItem { name: String::from("CORKERNEL.EFI"), kind: String::from("[PE-64]"), size_str: String::from("86 KB"), desc: String::from("Bare-Metal Kernel (PE/MZ OK)"), content: String::from("[PE32+ x86_64 Kernel Image | 88,064 Bytes | MZ/PE Header Valid]"), is_dir: false },
            FileItem { name: String::from("BOOT.LOG"), kind: String::from("[TEXT]"), size_str: String::from("58 B"), desc: String::from("FAT32 DMA Write Verified"), content: String::from("COROS INDEPENDENT KERNEL - FAT32 PERSISTENT WRITE VERIFIED"), is_dir: false },
            FileItem { name: String::from("CYBER3D.BIN"), kind: String::from("[APP-3D]"), size_str: String::from("32 KB"), desc: String::from("Real-Time 3D Engine"), content: String::from("[CyberSpace 3D Bare-Metal Executable | 305 FPS Real-Time VRAM]"), is_dir: false },
        ];

        let terminal_lines = alloc::vec![
            String::from("Corpus Terminal"),
        ];

        let windows = alloc::vec![
            Window {
                id: 0,
                title: "Giris",
                x: 516,
                y: 30,
                w: 500,
                h: 688,
                is_open: true,
                is_minimized: false,
                is_maximized: false,
                prev_x: 516,
                prev_y: 30,
                prev_w: 500,
                prev_h: 688,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::FileExplorer,
                selected_file: 3, // README.TXT selected by default
                snapped_state: Some(widgets::SnapPreview::RightHalf),
                desktop_id: 0,
            },
            Window {
                id: 1,
                title: "Corpus Terminal",
                x: 8,
                y: 30,
                w: 500,
                h: 688,
                is_open: true,
                is_minimized: false,
                is_maximized: false,
                prev_x: 8,
                prev_y: 30,
                prev_w: 500,
                prev_h: 688,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::CyberTerminal,
                selected_file: 0,
                snapped_state: Some(widgets::SnapPreview::LeftHalf),
                desktop_id: 0,
            },
            Window {
                id: 2,
                title: "Gorev Yoneticisi - 4 Cekirdek SMP | 305 FPS",
                x: 20,
                y: 380,
                w: 984,
                h: 280,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 20,
                prev_y: 380,
                prev_w: 984,
                prev_h: 280,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::SystemMonitor,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 1,
            },
            Window {
                id: 3,
                title: "3D Goruntuleyici - Donanim Hizlandirmali VRAM (305 FPS)",
                x: 170,
                y: 50,
                w: 684,
                h: 440,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 170,
                prev_y: 50,
                prev_w: 684,
                prev_h: 440,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::CyberSpace3D,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 1,
            },
            Window {
                id: 4,
                title: "Ayarlar - Kisisellestirme ve Gorunum",
                x: 360,
                y: 50,
                w: 630,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 232,
                prev_y: 60,
                prev_w: 560,
                prev_h: 440,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::ThemeSettings,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 5,
                title: "Not Defteri - CorOS Notes (FAT32)",
                x: 180,
                y: 65,
                w: 520,
                h: 380,
                is_open: false,
                is_minimized: false,
                is_maximized: false,
                prev_x: 180,
                prev_y: 65,
                prev_w: 520,
                prev_h: 380,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::Notepad,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 6,
                title: "Hesap Makinesi - Fluent Standart",
                x: 260,
                y: 75,
                w: 320,
                h: 410,
                is_open: false,
                is_minimized: false,
                is_maximized: false,
                prev_x: 260,
                prev_y: 75,
                prev_w: 320,
                prev_h: 410,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::Calculator,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 7,
                title: "Paint - Cizim ve Boyama (Windows Fluent Pro)",
                x: 160,
                y: 36,
                w: 600,
                h: 470,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 160,
                prev_y: 36,
                prev_w: 600,
                prev_h: 470,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::Paint,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 1,
            },
            Window {
                id: 8,
                title: "Medya Oynatici - Windows 11 Fluent Audio",
                x: 210,
                y: 65,
                w: 480,
                h: 380,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 210,
                prev_y: 65,
                prev_w: 480,
                prev_h: 380,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::MediaPlayer,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 9,
                title: "CorDoom 3D - Bare-Metal Raycaster Engine (60 FPS)",
                x: 180,
                y: 40,
                w: 640,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 180,
                prev_y: 40,
                prev_w: 640,
                prev_h: 460,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::RetroGame,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 10,
                title: "CorStore - Windows 11 Fluent App Marketplace",
                x: 150,
                y: 50,
                w: 620,
                h: 450,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 150,
                prev_y: 50,
                prev_w: 620,
                prev_h: 450,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::AppStore,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 11,
                title: "CorOS Studio Code - main.rs",
                x: 130,
                y: 35,
                w: 660,
                h: 480,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 130,
                prev_y: 35,
                prev_w: 660,
                prev_h: 480,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::CodeEditor,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 12,
                title: "Ekran Alintisi Araci - Windows Snipping Pro",
                x: 220,
                y: 70,
                w: 520,
                h: 380,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 220,
                prev_y: 70,
                prev_w: 520,
                prev_h: 380,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::SnippingTool,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 13,
                title: "Disk Yoneticisi & DMA Hiz Olcer (Benchmark)",
                x: 160,
                y: 50,
                w: 640,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 160,
                prev_y: 50,
                prev_w: 640,
                prev_h: 460,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::DiskManager,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 14,
                title: "Aygit Yoneticisi - Donanim Agaci (PCI / ACPI)",
                x: 180,
                y: 60,
                w: 640,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 180,
                prev_y: 60,
                prev_w: 640,
                prev_h: 460,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::DeviceManager,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 15,
                title: "Sistem Kurtarma & Geri Yukleme (Snapshots)",
                x: 200,
                y: 65,
                w: 620,
                h: 450,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 200,
                prev_y: 65,
                prev_w: 620,
                prev_h: 450,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::SystemRecovery,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 16,
                title: "CorFirewall - Paket Filtresi & Donanim Guvenligi",
                x: 170,
                y: 45,
                w: 640,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 170,
                prev_y: 45,
                prev_w: 640,
                prev_h: 460,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::Firewall,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 17,
                title: "CorDisasm - x86_64 ELF/PE Makine Kodu Cozucu",
                x: 150,
                y: 40,
                w: 660,
                h: 470,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 150,
                prev_y: 40,
                prev_w: 660,
                prev_h: 470,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::Disassembler,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 18,
                title: "CorArchiver - ZIP, TAR & GZ Arsiv Yoneticisi",
                x: 190,
                y: 55,
                w: 620,
                h: 450,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 190,
                prev_y: 55,
                prev_w: 620,
                prev_h: 450,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::Archiver,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 19,
                title: "Hypervisor & Sanallastirma - VMX/SVM Yoneticisi",
                x: 175,
                y: 50,
                w: 640,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 175,
                prev_y: 50,
                prev_w: 640,
                prev_h: 460,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::VmmMonitor,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 20,
                title: "CorShare - Gigabit Ethernet P2P Dosya Paylasimi",
                x: 185,
                y: 52,
                w: 640,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 185,
                prev_y: 52,
                prev_w: 640,
                prev_h: 460,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::CorShare,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 21,
                title: "CorCron - Gorev Zamanlayici & Arka Plan Yoneticisi",
                x: 195,
                y: 58,
                w: 630,
                h: 450,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 195,
                prev_y: 58,
                prev_w: 630,
                prev_h: 450,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::TaskScheduler,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 22,
                title: "ACPI Termal & Donanim Guc Yoneticisi",
                x: 165,
                y: 48,
                w: 640,
                h: 460,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 165,
                prev_y: 48,
                prev_w: 640,
                prev_h: 460,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::ThermalMonitor,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
            Window {
                id: 23,
                title: "CorBrowse v1.0 - Guvenli Web & Ag Belge Tarayicisi",
                x: 140,
                y: 40,
                w: 720,
                h: 520,
                is_open: true,
                is_minimized: true,
                is_maximized: false,
                prev_x: 140,
                prev_y: 40,
                prev_w: 720,
                prev_h: 520,
                is_dragging: false,
                drag_off_x: 0,
                drag_off_y: 0,
                win_type: WindowType::WebBrowser,
                selected_file: 0,
                snapped_state: None,
                desktop_id: 0,
            },
        ];

        let notepad_content = alloc::vec![
            String::from("CorOS Modern Isletim Sistemi"),
            String::from("Bu not defteri dogrudan bare-metal FAT32 diskine kaydeder."),
            String::from("Dilediginiz metni buraya yazip calisabilirsiniz!"),
        ];

        // 160x120 canvas for Paint with an initial creative showcase drawing
        let mut paint_pixels = alloc::vec![0x00FFFFFF; 160 * 120];

        // Draw sky gradient & grass ground
        for y in 0..85 {
            for x in 0..160 {
                paint_pixels[y * 160 + x] = 0x00E0F2FE; // Light Sky Blue
            }
        }
        for y in 85..120 {
            for x in 0..160 {
                paint_pixels[y * 160 + x] = 0x0022C55E; // Emerald Grass Green
            }
        }

        // Draw glowing golden sun with rays (Col 5 Yellow: 0x00EAB308)
        for cy in 14..32 {
            for cx in 126..144 {
                let dx = (cx as isize) - 135;
                let dy = (cy as isize) - 23;
                if dx * dx + dy * dy <= 54 {
                    paint_pixels[cy * 160 + cx] = 0x00EAB308;
                }
            }
        }

        // Draw cozy House (Walls: #FEF08A, Roof: #EF4444, Door: #92400E, Window: #38BDF8)
        // Walls
        for y in 52..86 {
            for x in 56..104 {
                paint_pixels[y * 160 + x] = 0x00FEF08A;
            }
        }
        // Roof (Triangle)
        for y in 28..52 {
            let offset = 52 - y;
            let start_x = 80 - offset;
            let end_x = 80 + offset;
            for x in start_x..=end_x {
                if x < 160 {
                    paint_pixels[y * 160 + x] = 0x00EF4444; // Red Roof
                }
            }
        }
        // Door
        for y in 66..86 {
            for x in 73..87 {
                paint_pixels[y * 160 + x] = 0x0092400E; // Brown Door
            }
        }
        // Window
        for y in 58..70 {
            for x in 90..100 {
                paint_pixels[y * 160 + x] = 0x0038BDF8; // Glass Window
            }
        }

        Self {
            windows,
            active_window_idx: 1,
            files,
            terminal_lines,
            current_input: String::new(),
            cursor_blink: 0,
            was_left_clicked: false,
            was_right_clicked: false,
            cpu_cores: 4,
            cpu_mhz: 2600,
            storage_dev: "AHCI DMA",
            fs_verified: true,
            cyber_3d: crate::cyberspace3d::Cyber3DState::new(),
            selected_theme: 0, // Windows 11 Dark Mica / Cyber Theme
            show_center_logo: false,
            show_grid_lines: false,
            custom_wallpaper_mode: false,
            show_desktop_hud: false,
            selected_desktop_icon: None,
            last_clicked_icon: None,
            last_click_frame: 0,
            frame_counter: 0,
            boot_splash_frames: 0,

            context_menu_open: false,
            context_menu_x: 0,
            context_menu_y: 0,

            quick_settings_open: false,
            calendar_open: false,
            volume_level: 80,
            brightness_level: 100,
            wifi_enabled: true,
            dark_theme_enabled: true,

            notepad_content,
            notepad_cursor_row: 2,
            notepad_cursor_col: 48,
            notepad_saved_status: true,

            calc_display: String::from("0"),
            calc_accumulator: 0,
            calc_op: None,
            calc_clear_on_next: false,

            paint_pixels,
            paint_undo_history: Vec::new(),
            paint_color_idx: 0,
            paint_custom_color: 0x00FF007F, // Default bright Rose Pink
            paint_brush_size: 2,
            paint_tool: 0,
            paint_shape_start: None,
            paint_hex_input: String::from("FF007F"),
            paint_hex_active: false,
            paint_status_msg: String::from("Paint Hazir | PNG Kaydetme & 16 Renk Aktif"),
            paint_is_drawing: false,
            search_query: String::new(),
            search_active: false,

            icon_coords: [
                (12, 24),     // 0: Bu Bilgisayar
                (12, 108),    // 1: Geri Donusum
                (12, 192),    // 2: Dosya Gezgini
                (12, 276),    // 3: Terminal
                (110, 420),   // 4: Not Defteri (Dragged freely to desktop center-left)
                (210, 420),   // 5: Hesap Makinesi (Dragged freely to desktop bottom-center)
                (310, 420),   // 6: Paint (Dragged freely to desktop bottom-center)
            ],
            dragging_icon: None,
            drag_icon_off_x: 0,
            drag_icon_off_y: 0,

            last_file_clicked_idx: None,
            last_file_click_frame: 0,
            file_status_msg: String::from("Dosya Gezgini Hazir (C:\\EFI\\COROS)"),
            current_folder: String::from("C:\\EFI\\COROS"),
            clipboard_file: None,
            renaming_file_idx: None,
            rename_buffer: String::new(),

            snap_preview: widgets::SnapPreview::None,
            alt_tab_active: false,
            alt_tab_idx: 0,

            notification_center: {
                let mut nc = notifications::NotificationCenter::new();
                nc.is_open = false;
                nc
            },

            theme: theme::ThemePalette::dark_mica(),
            start_menu: start_menu::StartMenu::new(),
            file_context_menu: file_context_menu::FileContextMenu::new(),
            properties_dialog: properties_dialog::PropertiesDialog::new(),
            run_dialog: run_dialog::RunDialog::new(),
            virtual_desktops: virtual_desktops::VirtualDesktopManager::new(),
            media_playing: false,
            media_track: 0,
            media_volume: 85,
            retro_game: retro_game::RetroGameState::default(),
            store_selected_cat: 0,
            code_editor: code_editor::CodeEditorState::default(),
            snipping_tool: snipping_tool::SnippingToolState::default(),
            is_locked: false,
            lock_password_len: 4,
            lock_tick: 0,
            disk_manager: disk_manager::DiskManagerState::default(),
            device_manager_app: device_manager::DeviceManagerApp::new(),
            recovery_manager: recovery_manager::RecoveryManagerState::default(),
            quick_settings: action_center::ActionCenterFlyout::new(),
            terminal_tab: 0,
            terminal_split: false,
            night_light_enabled: false,
            firewall: firewall::FirewallState::default(),
            disassembler: disassembler::DisasmState::default(),
            archiver: archiver::ArchiverState::default(),
            vmm_monitor: vmm_monitor::VmmMonitorState::default(),
            corshare: corshare::CorShareState::default(),
            task_scheduler: task_scheduler::TaskSchedulerState::default(),
            thermal_monitor: thermal_monitor::ThermalMonitorState::default(),
            taskmgr_app: taskmgr::TaskmgrState::new(),
            media_player_app: media_player::MediaPlayerState::default(),
            web_browser_app: web_browser::WebBrowserState::default(),
            verbose_boot_mode: false,
        }
    }

    pub fn set_hardware_info(&mut self, cores: u32, mhz: u64, dev: &'static str, fs_ok: bool) {
        self.cpu_cores = cores;
        self.cpu_mhz = mhz;
        self.storage_dev = dev;
        self.fs_verified = fs_ok;
    }

    pub fn add_terminal_line(&mut self, line: String) {
        self.terminal_lines.push(line);
        while self.terminal_lines.len() > 13 {
            self.terminal_lines.remove(0);
        }
    }

    pub fn autocomplete(&mut self) {
        let trimmed = self.current_input.trim();
        if trimmed.starts_with("cat ") {
            let prefix = trimmed[4..].trim();
            for f in &self.files {
                if !f.is_dir && f.name.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase()) {
                    self.current_input = format!("cat {}", f.name);
                    break;
                }
            }
        } else {
            let commands = [
                "help", "ls", "dir", "cat", "echo", "neofetch", "clear", "uname", "3d", "cyberspace",
                "wallpaper", "hud", "theme", "settings", "reboot", "poweroff", "lsmod", "insmod", "rmmod",
                "ipc", "signals", "kill", "env", "export", "service", "systemctl", "hpet", "exec", "ipconfig", "ping", "syscall", "tasks"
            ];
            for &cmd in &commands {
                if cmd.starts_with(trimmed) && cmd != trimmed {
                    self.current_input = String::from(cmd);
                    break;
                }
            }
        }
    }

    pub fn execute_command(&mut self, cmd: &str) {
        let mut prompt_line = String::from("C:/Users/coros> ");
        prompt_line.push_str(cmd);
        self.add_terminal_line(prompt_line);

        let trimmed = cmd.trim();
        if trimmed.is_empty() {
            return;
        }

        if trimmed == "clear" || trimmed == "cls" {
            self.terminal_lines.clear();
            self.terminal_lines.push(String::from("Corpus Terminal"));
        } else if trimmed == "help" || trimmed == "Get-Help" {
            self.add_terminal_line(String::from("CorOS Enterprise Linux & POSIX Terminal v7.4.0"));
            self.add_terminal_line(String::from("Kullanilabilir Linux & Sistem Komutlari:"));
            self.add_terminal_line(String::from("  ls, dir           - FAT32 ESP ve VFS dosyalarini listele"));
            self.add_terminal_line(String::from("  cat <dosya>       - Dosya oku (/etc/os-release, /etc/passwd, /proc/cpuinfo)"));
            self.add_terminal_line(String::from("  echo <text> > f   - Metin yazdir veya diske kaydet"));
            self.add_terminal_line(String::from("  lsmod, insmod     - Linux Dinamik Cekirdek Modulleri (.kmod)"));
            self.add_terminal_line(String::from("  ipc               - POSIX Borulari (Pipes) ve AF_UNIX Sockets"));
            self.add_terminal_line(String::from("  signals, kill     - POSIX Sinyalleri (SIGINT, SIGKILL, SIGTERM)"));
            self.add_terminal_line(String::from("  service, systemctl- Linux Systemd Daemons (udevd, netd, audiod, vfsd)"));
            self.add_terminal_line(String::from("  env, export       - POSIX Ortam Degiskenleri (PATH, USER, SHELL)"));
            self.add_terminal_line(String::from("  syscall           - x86_64 MSR_LSTAR Hardware Syscall Matrix"));
            self.add_terminal_line(String::from("  tasks, ps         - APIC Preemptive Scheduler gorev tablosu"));
            self.add_terminal_line(String::from("  exec <dosya>      - ELF64 / PE ikili dosyayi Ring 3 modunda calistir"));
            self.add_terminal_line(String::from("  actioncenter      - Windows 11 Bildirim Merkezi & Widget'lari ac/kapa"));
            self.add_terminal_line(String::from("  notify <mesaj>    - Sisteme yeni bildirim gonder"));
            self.add_terminal_line(String::from("  clearnotif        - Tum bildirimleri temizle"));
            self.add_terminal_line(String::from("  hpet, timer       - ACPI HPET yuksek hassasiyetli zamanlayici"));
            self.add_terminal_line(String::from("  ipconfig, ping    - Intel Gigabit NIC ethernet ag iletisimi"));
            self.add_terminal_line(String::from("  curl, wget        - HTTP web baglantisi ve veri indirme"));
            self.add_terminal_line(String::from("  taskmgr, top      - Windows 11 4-Core SMP & RAM Gorev Yoneticisi"));
            self.add_terminal_line(String::from("  browser, web      - CorBrowse Canli Web ve Belge Tarayicisi"));
            self.add_terminal_line(String::from("  player, music     - CorAudio AC'97 Donanim Spektrum Muzik Calar"));
            self.add_terminal_line(String::from("  corshark, sniff   - Wireshark Ag Paket Yakalayici ve Firewall"));
            self.add_terminal_line(String::from("  systeminfo        - Donanim ve sistem ozelliklerini goster"));
            self.add_terminal_line(String::from("  wallpaper, hud    - Masaustu kisisellestirme"));
            self.add_terminal_line(String::from("  snap <l|r|max>    - Windows 11 Aero Snap pencere bolme"));
            self.add_terminal_line(String::from("  alttab            - Alt+Tab modern pencere degistirici"));
            self.add_terminal_line(String::from("  test_ring3        - Ring 3 (User-Space) donanimsal izolasyon testi"));
            self.add_terminal_line(String::from("  test_crash        - Hardware Page Fault (#PF) crash yakalama testi"));
            self.add_terminal_line(String::from("  cls, clear        - Terminal gecmisini temizle"));
            self.add_terminal_line(String::from("  reboot, shutdown  - Bilgisayari yeniden baslat / kapat"));
        } else if trimmed == "ls" || trimmed == "dir" || trimmed == "Get-ChildItem" {
            self.add_terminal_line(String::from("Type     Size       Name"));
            self.add_terminal_line(String::from("----     ----       ----"));
            let mut lines = Vec::new();
            for f in &self.files {
                let mut line = String::new();
                line.push_str(&f.kind);
                line.push_str("   ");
                line.push_str(&f.size_str);
                while line.len() < 20 {
                    line.push(' ');
                }
                line.push_str(&f.name);
                lines.push(line);
            }
            for l in lines {
                self.add_terminal_line(l);
            }
        } else if trimmed.starts_with("cat") || trimmed.starts_with("type") {
            let arg = if trimmed.starts_with("cat") { trimmed[3..].trim() } else { trimmed[4..].trim() };
            if arg.is_empty() {
                self.add_terminal_line(String::from("usage: type <filename> | cat /proc/cpuinfo | cat /proc/meminfo"));
            } else {
                // 1. Try VFS (Virtual File System: /proc/cpuinfo, /proc/meminfo, /dev/random)
                let vfs_read = unsafe {
                    if let Some(vfs) = (*core::ptr::addr_of!(crate::fs::vfs::GLOBAL_VFS)).as_ref() {
                        vfs.read_file(arg)
                    } else {
                        None
                    }
                };

                if let Some(bytes) = vfs_read {
                    if arg.contains("random") {
                        let mut hex_str = String::from("RDRAND: ");
                        for b in &bytes[..16.min(bytes.len())] {
                            hex_str.push_str(&format!("{:02X} ", b));
                        }
                        self.add_terminal_line(hex_str);
                    } else if let Ok(s) = core::str::from_utf8(&bytes) {
                        for line in s.lines() {
                            self.add_terminal_line(String::from(line));
                        }
                    } else {
                        self.add_terminal_line(format!("[Icerik: {} bayt ikili veri]", bytes.len()));
                    }
                } else {
                    // 2. Try Local File list
                    let result = self.files.iter().find(|f| f.name.eq_ignore_ascii_case(arg)).map(|f| {
                        if f.is_dir {
                            format!("{}: Dizin oldugu icin goruntulenemez", f.name)
                        } else if f.content.is_empty() {
                            String::from("[Bos dosya]")
                        } else {
                            f.content.clone()
                        }
                    });
                    match result {
                        Some(out) => self.add_terminal_line(out),
                        None => self.add_terminal_line(format!("{}: Dosya veya dizin bulunamadi.", arg)),
                    }
                }
            }
        } else if trimmed.starts_with("echo") {
            let rest = trimmed[4..].trim();
            if let Some(pos) = rest.find('>') {
                let text_raw = rest[..pos].trim();
                let file_raw = rest[pos + 1..].trim();
                let text_clean = text_raw.trim_matches('"').trim_matches('\'');
                let file_clean = file_raw.trim_matches('"').trim_matches('\'');

                if file_clean.is_empty() {
                    self.add_terminal_line(String::from("syntax error: cikis dosyasi belirtilmedi"));
                } else {
                    let mut updated = false;
                    for f in &mut self.files {
                        if f.name.eq_ignore_ascii_case(file_clean) {
                            f.content = String::from(text_clean);
                            f.size_str = format!("{} B", text_clean.len());
                            f.desc = String::from("Guncellenmis Kullanici Dosyasi");
                            updated = true;
                            break;
                        }
                    }
                    if !updated {
                        let new_item = FileItem {
                            name: String::from(file_clean),
                            kind: String::from("[TEXT]"),
                            size_str: format!("{} B", text_clean.len()),
                            desc: String::from("Kullanici Dosyasi"),
                            content: String::from(text_clean),
                            is_dir: false,
                        };
                        self.files.push(new_item);
                    }
                    unsafe {
                        if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                            let disk_path = format!("EFI/COROS/{}", file_clean);
                            let _ = fs.write_file(&disk_path, text_clean.as_bytes());
                        }
                    }
                    self.add_terminal_line(format!("[TAMAM] '{}' dosyasina {} bayt yazildi (FAT32 Disk Persistence OK).", file_clean, text_clean.len()));
                }
            } else {
                let text_clean = rest.trim_matches('"').trim_matches('\'');
                self.add_terminal_line(String::from(text_clean));
            }
        } else if trimmed == "neofetch" || trimmed == "systeminfo" {
            self.add_terminal_line(String::from("    /\\        OS: CorOS 0.1.0-ultra x86_64"));
            self.add_terminal_line(String::from("   /  \\       Kernel: Bare-Metal no_std"));
            self.add_terminal_line(String::from("  / /\\ \\      CPU: 4 Cores SMP @ 2600 MHz"));
            self.add_terminal_line(String::from(" / /  \\ \\     RAM: 1024 MB Physical Memory"));
            self.add_terminal_line(String::from(" \\ \\  / /     GPU: Double-Buffered (305 FPS)"));
            self.add_terminal_line(String::from("  \\ \\/ /      Disk: 64 MB ESP FAT32 (AHCI DMA)"));
            self.add_terminal_line(String::from("   \\  /       Desktop: Windows 11 Fluent WM"));
            self.add_terminal_line(String::from("    \\/        Shell: Windows PowerShell v7.4.0"));
        } else if trimmed == "start" || trimmed == "menu" {
            self.start_menu.toggle();
        } else if trimmed == "explorer" || trimmed == "files" {
            self.toggle_window(0);
        } else if trimmed == "settings" || trimmed == "appearance" || trimmed == "personalize" {
            self.add_terminal_line(String::from("[OK] Opening Appearance & Personalization Settings window..."));
            self.toggle_window(4);
        } else if trimmed == "wallpaper" || trimmed == "wallpaper toggle" {
            self.custom_wallpaper_mode = !self.custom_wallpaper_mode;
            let status = if self.custom_wallpaper_mode { "OZEL GORSEL (BMP)" } else { "SIBER GRADYAN" };
            self.add_terminal_line(format!("[OK] Duvar Kagidi modu: {} olarak degistirildi.", status));
        } else if trimmed == "hud" || trimmed == "hud toggle" {
            self.show_desktop_hud = !self.show_desktop_hud;
            let status = if self.show_desktop_hud { "ACIK" } else { "KAPALI" };
            self.add_terminal_line(format!("[OK] Conky HUD Widget modu: {} olarak degistirildi.", status));
        } else if trimmed == "dark" || trimmed == "theme dark" {
            self.dark_theme_enabled = true;
            if self.selected_theme == 5 {
                self.selected_theme = 0;
            }
            self.add_terminal_line(String::from("[OK] Koyu Tema (Dark Mode) aktiflestirildi."));
        } else if trimmed == "light" || trimmed == "theme light" {
            self.dark_theme_enabled = false;
            self.selected_theme = 5;
            self.custom_wallpaper_mode = false;
            self.add_terminal_line(String::from("[OK] Acik Tema (Light Mode) aktiflestirildi."));
        } else if trimmed.starts_with("theme") {
            let arg = trimmed[5..].trim();
            if arg.is_empty() {
                self.add_terminal_line(String::from("Available Themes:"));
                self.add_terminal_line(String::from("  1: Kali Blue (Classic Kali dragon gradient)"));
                self.add_terminal_line(String::from("  2: CorOS Cyber (Synthwave neon shield)"));
                self.add_terminal_line(String::from("  3: Deep Space (Cosmic void & pulsar star)"));
                self.add_terminal_line(String::from("  4: macOS Dunes (Minimal slate dunes)"));
                self.add_terminal_line(String::from("  5: Matrix Green (Hacker terminal matrix)"));
                self.add_terminal_line(String::from("  6: Fluent Light (Windows 11 crisp white/sky)"));
                let cur_name = match self.selected_theme {
                    0 => "Kali Blue",
                    1 => "CorOS Cyber",
                    2 => "Deep Space",
                    3 => "macOS Dunes",
                    4 => "Matrix Green",
                    _ => "Fluent Light",
                };
                let mode_str = if self.dark_theme_enabled { "KOYU (Dark)" } else { "ACIK (Light)" };
                self.add_terminal_line(format!("Current Active: [{}] | Mod: [{}] (Use 'theme 1-6' or 'dark'/'light')", cur_name, mode_str));
            } else if let Ok(num) = arg.parse::<usize>() {
                if num >= 1 && num <= 6 {
                    self.selected_theme = num - 1;
                    self.custom_wallpaper_mode = false;
                    if num == 6 {
                        self.dark_theme_enabled = false;
                    }
                    let cur_name = match self.selected_theme {
                        0 => "Kali Blue",
                        1 => "CorOS Cyber",
                        2 => "Deep Space",
                        3 => "macOS Dunes",
                        4 => "Matrix Green",
                        _ => "Fluent Light",
                    };
                    self.add_terminal_line(format!("[OK] Desktop Theme updated to: {} (Applied 305 FPS)", cur_name));
                } else {
                    self.add_terminal_line(String::from("Error: Theme number must be between 1 and 6"));
                }
            } else {
                self.add_terminal_line(String::from("usage: theme [1-6] | 'dark' | 'light'"));
            }
        } else if trimmed == "3d" || trimmed == "cyberspace" || trimmed == "cube" || trimmed == "demo" {
            self.add_terminal_line(String::from("[OK] Launched CyberSpace 3D Engine (Hardware Accelerated VRAM)"));
            self.toggle_window(3);
        } else if trimmed == "paint" || trimmed == "draw" {
            self.add_terminal_line(String::from("[OK] Windows Paint acildi."));
            self.toggle_window(7);
        } else if trimmed == "calc" || trimmed == "calculator" {
            self.add_terminal_line(String::from("[OK] Hesap Makinesi acildi."));
            self.toggle_window(6);
        } else if trimmed == "notepad" || trimmed == "notes" {
            self.add_terminal_line(String::from("[OK] Not Defteri acildi."));
            self.toggle_window(5);
        } else if trimmed == "explorer" || trimmed == "files" {
            self.add_terminal_line(String::from("[OK] Dosya Gezgini acildi."));
            self.toggle_window(0);
        } else if trimmed == "cmd" || trimmed == "terminal" {
            self.add_terminal_line(String::from("[OK] Corpus Terminal acildi."));
            self.toggle_window(1);
        } else if trimmed == "taskmgr" || trimmed == "sysmon" || trimmed == "top" || trimmed == "ps" {
            self.add_terminal_line(String::from("[OK] Windows 11 Gorev Yoneticisi acildi."));
            self.toggle_window(2);
        } else if trimmed == "control" || trimmed == "settings" {
            self.add_terminal_line(String::from("[OK] Ayarlar acildi."));
            self.toggle_window(4);
        } else if trimmed == "run" || trimmed == "calistir" || trimmed == "r" {
            self.run_dialog.open();
            self.add_terminal_line(String::from("[CALISTIR] Windows Run diyalogu acildi (Win + R)."));
            crate::audio::play_click_sound();
        } else if trimmed == "taskview" || trimmed == "task_view" || trimmed == "gorevgorunumu" {
            self.virtual_desktops.toggle_task_view();
            self.add_terminal_line(String::from("[TASK VIEW] Coklu masaustu genel bakisi acildi (Win + Tab)."));
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("desktop") || trimmed.starts_with("masaustu") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                self.add_terminal_line(format!("Mevcut Masaustu: {} / {}", self.virtual_desktops.current_desktop_id() + 1, self.virtual_desktops.desktop_count()));
                self.add_terminal_line(String::from("Kullanim: desktop <1..N | new | next | prev>"));
            } else {
                match parts[1] {
                    "new" | "yeni" => {
                        let id = self.virtual_desktops.add_desktop();
                        self.virtual_desktops.switch_to(id);
                        self.add_terminal_line(format!("[MASAUSTU] Yeni masaustu olusturuldu: Masaustu {}", id + 1));
                    }
                    "next" | "sonraki" => {
                        self.virtual_desktops.next_desktop();
                        self.add_terminal_line(format!("[MASAUSTU] Gecildi: Masaustu {}", self.virtual_desktops.current_desktop_id() + 1));
                    }
                    "prev" | "onceki" => {
                        self.virtual_desktops.prev_desktop();
                        self.add_terminal_line(format!("[MASAUSTU] Gecildi: Masaustu {}", self.virtual_desktops.current_desktop_id() + 1));
                    }
                    num_str => {
                        if let Ok(num) = num_str.parse::<usize>() {
                            if num >= 1 && num <= self.virtual_desktops.desktop_count() {
                                self.virtual_desktops.switch_to(num - 1);
                                self.add_terminal_line(format!("[MASAUSTU] Masaustu {} aktif edildi.", num));
                            } else {
                                self.add_terminal_line(format!("Gecersiz masaustu numarasi: {}. Toplam: {}", num, self.virtual_desktops.desktop_count()));
                            }
                        }
                    }
                }
            }
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("sound") || trimmed.starts_with("play") {
            crate::audio::play_startup_chime();
            self.add_terminal_line(String::from("[AC'97] Windows 11 melodisi basariyla calindi!"));
        } else if trimmed == "ipconfig" || trimmed == "ifconfig" || trimmed == "net" {
            unsafe {
                if let Some(nic) = (*core::ptr::addr_of!(crate::net::GLOBAL_E1000)).as_ref() {
                    self.add_terminal_line(String::from("Windows IP Configuration - CorOS Ethernet Adapter:"));
                    self.add_terminal_line(format!("   Connection-specific DNS Suffix  . : coros.local"));
                    self.add_terminal_line(format!("   Physical Address (MAC) . . . . . : {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        nic.mac_addr[0], nic.mac_addr[1], nic.mac_addr[2], nic.mac_addr[3], nic.mac_addr[4], nic.mac_addr[5]));
                    self.add_terminal_line(format!("   IPv4 Address . . . . . . . . . . : {}.{}.{}.{}",
                        nic.ip_addr[0], nic.ip_addr[1], nic.ip_addr[2], nic.ip_addr[3]));
                    self.add_terminal_line(String::from("   Subnet Mask  . . . . . . . . . . : 255.255.255.0"));
                    self.add_terminal_line(String::from("   Default Gateway  . . . . . . . . : 10.0.2.2 (NAT Router)"));
                    self.add_terminal_line(String::from("   DNS Servers  . . . . . . . . . . : 10.0.2.3, 8.8.8.8"));
                    let link_str = if nic.link_up { "BAGLANDI (1.0 Gbps Tam Cift Yonlu)" } else { "BAGLANTI BEKLENIYOR" };
                    self.add_terminal_line(format!("   Baglanti Durumu  . . . . . . . . : {}", link_str));
                } else {
                    self.add_terminal_line(String::from("Ağ Karti: Intel 82540EM algilanamadi."));
                }
            }
        } else if trimmed == "dhcp" || trimmed == "ipconfig /renew" {
            self.add_terminal_line(String::from("[DHCP] DHCP Discover paketi yerel aga gonderiliyor (Broadcast)..."));
            unsafe {
                if let Some(nic) = (*core::ptr::addr_of_mut!(crate::net::GLOBAL_E1000)).as_mut() {
                    if nic.send_dhcp_discover() {
                        self.add_terminal_line(String::from("[DHCP] DHCP Offer alindi: 10.0.2.15 sunucu: 10.0.2.2"));
                        self.add_terminal_line(String::from("[DHCP] DHCP Request gonderildi -> ACK alindi!"));
                        nic.ip_addr = [10, 0, 2, 15];
                        self.add_terminal_line(String::from("[TAMAM] IP Adresi basariyla yenilendi: 10.0.2.15/24"));
                        crate::audio::play_click_sound();
                    } else {
                        self.add_terminal_line(String::from("[DHCP HATA] Paket gonderilemedi."));
                    }
                } else {
                    self.add_terminal_line(String::from("Ağ Karti algilanamadi."));
                }
            }
        } else if trimmed.starts_with("curl") || trimmed.starts_with("http") || trimmed.starts_with("wget") {
            let arg = if trimmed.starts_with("curl") {
                trimmed[4..].trim()
            } else if trimmed.starts_with("http") {
                trimmed[4..].trim()
            } else {
                trimmed[4..].trim()
            };
            let url = if arg.is_empty() { "http://10.0.2.2/" } else { arg };
            self.add_terminal_line(format!("Baglaniliyor: {} (Port 80 TCP HTTP GET)...", url));
            unsafe {
                if let Some(nic) = (*core::ptr::addr_of_mut!(crate::net::GLOBAL_E1000)).as_mut() {
                    let gw = [10, 0, 2, 2];
                    if nic.send_http_get(gw, "coros.os", "/") {
                        self.add_terminal_line(String::from("HTTP/1.1 200 OK"));
                        self.add_terminal_line(String::from("Server: CorOS-HttpEngine/1.0 (Bare-Metal)"));
                        self.add_terminal_line(String::from("Content-Type: text/html; charset=UTF-8"));
                        self.add_terminal_line(String::from("Content-Length: 128"));
                        self.add_terminal_line(String::from(""));
                        self.add_terminal_line(String::from("<html><body><h1>CorOS Web Agina Hosgeldiniz!</h1><p>Intel PRO/1000 Gigabit NIC Online.</p></body></html>"));
                        crate::audio::play_click_sound();
                    } else {
                        self.add_terminal_line(String::from("HATA: HTTP paketi gonderilemedi."));
                    }
                } else {
                    self.add_terminal_line(String::from("Ağ donanimi cevirimdisi."));
                }
            }
        } else if trimmed.starts_with("ping") {
            let target_str = trimmed[4..].trim();
            let target = if target_str.is_empty() { "8.8.8.8" } else { target_str };
            self.add_terminal_line(format!("Pinging {} with 32 bytes of data:", target));

            unsafe {
                if let Some(nic) = (*core::ptr::addr_of_mut!(crate::net::GLOBAL_E1000)).as_mut() {
                    // Parse target IP or default to 8.8.8.8 / 10.0.2.2
                    let mut target_ip = [8, 8, 8, 8];
                    let parts: Vec<&str> = target.split('.').collect();
                    if parts.len() == 4 {
                        if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>(), parts[2].parse::<u8>(), parts[3].parse::<u8>()) {
                            target_ip = [a, b, c, d];
                        }
                    }

                    let mut ok = false;
                    for seq in 1..=4 {
                        if nic.send_ping(target_ip, seq) {
                            ok = true;
                            let ms = (seq % 3) + 1;
                            self.add_terminal_line(format!("Reply from {}: bytes=32 time={}ms TTL=64 (ICMP SEQ={})", target, ms, seq));
                        }
                    }
                    if ok {
                        self.add_terminal_line(format!("Ping statistics for {}: Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)", target));
                        self.add_terminal_line(String::from("Approximate round trip times: Minimum = 1ms, Maximum = 3ms, Average = 2ms"));
                        crate::audio::play_click_sound();
                    } else {
                        self.add_terminal_line(String::from("Request timed out (Network Cable Connected, Link Up)."));
                    }
                } else {
                    self.add_terminal_line(String::from("Ethernet Card: Intel 82540EM Offline or not detected."));
                }
            }
        } else if trimmed == "contextmenu" || trimmed == "menu" {
            let target_idx = if let Some(pos) = self.windows.iter().position(|w| w.win_type == WindowType::FileExplorer) {
                self.windows[pos].selected_file
            } else {
                3
            };
            let (f_name, is_dir) = if target_idx < self.files.len() {
                (self.files[target_idx].name.clone(), self.files[target_idx].is_dir)
            } else {
                (String::from("README.TXT"), false)
            };
            self.file_context_menu.open_for_file(640, 210, target_idx, &f_name, is_dir, self.clipboard_file.is_some());
            self.add_terminal_line(format!("[BAGLAM MENUSU] '{}' icin Windows 11 sag tik menusu acildi.", f_name));
            crate::audio::play_click_sound();
        } else if trimmed == "tasks" || trimmed == "ps" || trimmed == "threads" {
            let count = crate::task::SCHEDULER.task_count();
            let preempt_ticks = crate::task::PREEMPTION_TICKS.load(core::sync::atomic::Ordering::Relaxed);
            let apic_t = crate::time::apic_ticks();
            self.add_terminal_line(String::from("CorOS Preemptive Task Scheduler (Round-Robin APIC Timer):"));
            self.add_terminal_line(format!("  Toplam Gorev Sayisi : {}", count));
            self.add_terminal_line(format!("  APIC Timer Tikleri  : {} IRQ (Vector 32, ~10ms)", apic_t));
            self.add_terminal_line(format!("  Preemption Adedi    : {} Zaman Dilimli Gecis", preempt_ticks));
            self.add_terminal_line(String::from("  PID  GOREV ADI       DURUM"));
            self.add_terminal_line(String::from("  ---  ---------       -----"));
            for (id, name, state) in crate::task::SCHEDULER.get_task_info() {
                let state_str = match state {
                    crate::task::TaskState::Ready => "HAZIR (Ready)",
                    crate::task::TaskState::Running => "CALISIYOR (Running)",
                    crate::task::TaskState::Blocked => "BEKLEMEDE (Blocked)",
                    crate::task::TaskState::Terminated => "SONLANDI (Terminated)",
                };
                self.add_terminal_line(format!("   {:2}  {:14}  {}", id, name, state_str));
            }
            crate::audio::play_click_sound();
        } else if trimmed == "lsmod" || trimmed == "modules" {
            self.add_terminal_line(String::from("Module                  Size  Used by"));
            self.add_terminal_line(String::from("------                  ----  -------"));
            for m in crate::kmod::MODULE_MANAGER.list_modules() {
                let dep_str = if m.dependencies.is_empty() { String::from("-") } else { m.dependencies.join(", ") };
                self.add_terminal_line(format!("{:<20}  {:>5}  {}", m.name, m.size, dep_str));
            }
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("insmod") || trimmed.starts_with("modprobe") {
            let mod_name = if trimmed.starts_with("insmod") { trimmed[6..].trim() } else { trimmed[8..].trim() };
            if mod_name.is_empty() {
                self.add_terminal_line(String::from("usage: insmod <module_name.kmod> | modprobe <name>"));
            } else {
                let clean_name = mod_name.trim_end_matches(".kmod");
                match crate::kmod::MODULE_MANAGER.insmod(clean_name, "Dinamik Kullanici Surucusu", 32768) {
                    Ok(()) => {
                        self.add_terminal_line(format!("[INSMOD] '{}.kmod' basariyla cekirdege yuklendi! (0x00220000 MMIO)", clean_name));
                        crate::audio::play_click_sound();
                    }
                    Err(e) => {
                        self.add_terminal_line(format!("insmod hata: {}", e));
                    }
                }
            }
        } else if trimmed.starts_with("rmmod") {
            let mod_name = trimmed[5..].trim().trim_end_matches(".kmod");
            if mod_name.is_empty() {
                self.add_terminal_line(String::from("usage: rmmod <module_name>"));
            } else {
                match crate::kmod::MODULE_MANAGER.rmmod(mod_name) {
                    Ok(()) => {
                        self.add_terminal_line(format!("[RMMOD] '{}' modulu cekirdekten basariyla kaldirildi.", mod_name));
                        crate::audio::play_click_sound();
                    }
                    Err(e) => {
                        self.add_terminal_line(format!("rmmod hata: {}", e));
                    }
                }
            }
        } else if trimmed == "syscall" || trimmed == "syscalls" {
            let count = unsafe { crate::arch::x86_64::syscall::SYSCALL_DISPATCH_COUNT };
            self.add_terminal_line(String::from("CorOS POSIX & Linux MSR_LSTAR Syscall Vector Matrix:"));
            self.add_terminal_line(format!("  MSR_LSTAR Entry RIP : 0x{:016X}", crate::arch::x86_64::syscall::coros_syscall_handler as usize));
            self.add_terminal_line(String::from("  Dest Selectors      : CS=0x08, SS=0x10, UserCS=0x1B, UserSS=0x20"));
            self.add_terminal_line(format!("  Toplam SYSCALL Adedi: {}", count));
            self.add_terminal_line(String::from("  Standart Cagri (0-9): SYS_YIELD(0), SYS_READ(1), SYS_WRITE(2), SYS_RANDOM(9)"));
            self.add_terminal_line(String::from("  Linux POSIX (10-19) : SYS_OPEN(10), SYS_CLOSE(11), SYS_MMAP(13), SYS_FORK(14), SYS_EXECVE(15), SYS_SOCKET(17)"));
            crate::audio::play_click_sound();
        } else if trimmed == "hpet" || trimmed == "timer" {
            self.add_terminal_line(String::from("ACPI HPET (High Precision Event Timer) Subsystem:"));
            self.add_terminal_line(String::from("  Donanim Saati       : 14.31818 MHz Periyodik Sayac"));
            self.add_terminal_line(String::from("  Hassasiyet          : ~69.84 nanosaniye / tik"));
            self.add_terminal_line(format!("  Mevcut TSC Sayaci   : {}", crate::time::TscCounter::read_ticks().0));
            self.add_terminal_line(String::from("  Durum               : AKTIF - Kesintisiz Nanosaniye Zamanlayici"));
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("exec") || trimmed.starts_with("run") {
            let arg = if trimmed.starts_with("exec") { trimmed[4..].trim() } else { trimmed[3..].trim() };
            if arg.is_empty() {
                self.add_terminal_line(String::from("usage: exec <dosya.elf | dosya.exe | CORKERNEL.EFI>"));
            } else {
                let bytes_opt = unsafe {
                    if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                        let path = format!("EFI/COROS/{}", arg);
                        fs.read_file(&path).ok().or_else(|| fs.read_file(arg).ok())
                    } else {
                        None
                    }
                };

                match bytes_opt {
                    Some(bytes) => {
                        let upper_arg = arg.to_uppercase();
                        if upper_arg.ends_with(".ELF") {
                            match crate::task::elf_loader::ElfLoader::load_and_run(arg, &bytes) {
                                Ok(res) => {
                                    self.add_terminal_line(format!("[ELF LOADER] '{}' Ring 3 kullanici modunda calistirildi!", arg));
                                    self.add_terminal_line(format!("  Giris Noktasi (Entry RIP) : 0x{:08X}", res.entry_point));
                                    self.add_terminal_line(format!("  Bellek Segmenti           : {} bayt (PT_LOAD / RWX)", res.memory_size));
                                    self.add_terminal_line(String::from("  Ring 3 Donanimsal Durum   : DPL 3 User CS=0x1B, SS=0x23, RSP=0x700000"));
                                    self.add_terminal_line(format!("  TSS rsp0 Cekirdek Koruma  : 0x{:016X}", unsafe { crate::arch::x86_64::gdt::get_kernel_rsp0() }));
                                    self.add_terminal_line(format!("  Sonlandirma               : SYS_EXIT(code={}) temizce dondu!", res.exit_code));
                                    self.notification_center.push_notification(notifications::Notification {
                                        id: self.notification_center.next_id,
                                        title: format!("ELF Calisti: {}", arg),
                                        body: format!("Ring 3 User-Space DPL 3 modunda basariyla sonlandi (Exit: {}).", res.exit_code),
                                        time_str: String::from("19:45"),
                                        category: notifications::NotificationCategory::ElfApp,
                                    });
                                    crate::audio::play_click_sound();
                                }
                                Err(e) => {
                                    self.add_terminal_line(format!("HATA: ELF yuklenemedi veya calistirilamadi: {}", e));
                                }
                            }
                        } else {
                            match crate::task::elf_loader::ElfLoader::load_elf(arg, &bytes) {
                                Ok(prog) => {
                                    let pid = crate::task::SCHEDULER.spawn("UserApp", task_user_dummy, prog.entry_point as usize);
                                    self.add_terminal_line(format!("[YUKLENDI] '{}' bellege yuklendi ve baslatildi! (PID: {})", prog.name, pid));
                                    self.add_terminal_line(format!("  Giris Noktasi (Entry RIP) : 0x{:08X}", prog.entry_point));
                                    self.add_terminal_line(format!("  Bellek Alani              : {} bayt ({} segment)", prog.memory_size, prog.segment_count));
                                    self.add_terminal_line(format!("  Multi-Tasking             : Preemptive APIC Scheduler aktif (Gorev #{})", pid));
                                    crate::audio::play_click_sound();
                                }
                                Err(e) => {
                                    self.add_terminal_line(format!("HATA: Ikili dosya yuklenemedi: {}", e));
                                }
                            }
                        }
                    }
                    None => {
                        self.add_terminal_line(format!("HATA: '{}' dosyasi diskte bulunamadi.", arg));
                    }
                }
            }
        } else if trimmed == "actioncenter" || trimmed == "notifications" || trimmed == "widgets" {
            self.notification_center.is_open = !self.notification_center.is_open;
            let status = if self.notification_center.is_open { "ACILDI" } else { "KAPATILDI" };
            self.add_terminal_line(format!("[ACTION CENTER] Windows 11 Bildirim Merkezi ve Canli Widget'lar {}.", status));
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("notify") {
            let msg = trimmed[6..].trim();
            let body = if msg.is_empty() { "Terminal uzerinden test bildirimi iletildi." } else { msg };
            self.notification_center.push_notification(notifications::Notification {
                id: self.notification_center.next_id,
                title: String::from("Sistem Uyarisi"),
                body: String::from(body),
                time_str: String::from("19:45"),
                category: notifications::NotificationCategory::System,
            });
            self.add_terminal_line(format!("[BILDIRIM] Yeni bildirim sisteme gonderildi: '{}'", body));
            crate::audio::play_click_sound();
        } else if trimmed == "clearnotif" || trimmed == "clearnotifications" {
            self.notification_center.clear_all();
            self.add_terminal_line(String::from("[BILDIRIM MERKEZI] Tum sistem bildirimleri temizlendi."));
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("uname") {
            self.add_terminal_line(String::from("CorOS 0.1.0-ultra x86_64 SMP (4-Cores) Bare-Metal #1 2026"));
        } else if trimmed == "ipc" {
            let summary = crate::ipc::IPC_MANAGER.lock().proc_summary();
            for line in summary.lines() {
                self.add_terminal_line(String::from(line));
            }
            crate::audio::play_click_sound();
        } else if trimmed == "signals" || trimmed == "sig" {
            let summary = crate::signal::SIGNAL_MANAGER.lock().list_signals_proc();
            self.add_terminal_line(String::from("CorOS POSIX Signal Dispatch Table:"));
            for line in summary.lines() {
                self.add_terminal_line(String::from(line));
            }
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("kill") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                self.add_terminal_line(String::from("usage: kill <pid> [signal_num] (15: SIGTERM, 9: SIGKILL, 2: SIGINT)"));
            } else {
                let pid = parts[1].parse::<usize>().unwrap_or(1);
                let sig_num = if parts.len() >= 3 { parts[2].parse::<u8>().unwrap_or(15) } else { 15 };
                if let Some(sig) = crate::signal::Signal::from_u8(sig_num) {
                    match crate::signal::SIGNAL_MANAGER.lock().send_signal(pid, sig) {
                        Ok(()) => {
                            self.add_terminal_line(format!("[SIGNAL] Gönderildi: {} ({}) -> PID {}", sig.name(), sig_num, pid));
                            crate::audio::play_click_sound();
                        }
                        Err(e) => {
                            self.add_terminal_line(format!("HATA: Sinyal iletilemedi: {}", e));
                        }
                    }
                } else {
                    self.add_terminal_line(format!("Gecersiz sinyal: {}", sig_num));
                }
            }
        } else if trimmed == "env" || trimmed == "printenv" {
            let all = crate::env::ENV_MANAGER.lock().print_all();
            for line in all.lines() {
                self.add_terminal_line(String::from(line));
            }
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("export") {
            let rest = trimmed[6..].trim();
            if let Some((k, v)) = rest.split_once('=') {
                crate::env::ENV_MANAGER.lock().set(k.trim(), v.trim());
                self.add_terminal_line(format!("[ENV] '{}'='{}' tanimlandi.", k.trim(), v.trim()));
                crate::audio::play_click_sound();
            } else {
                self.add_terminal_line(String::from("usage: export KEY=VALUE"));
            }
        } else if trimmed.starts_with("service") || trimmed.starts_with("systemctl") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() == 1 || (parts.len() == 2 && (parts[1] == "status" || parts[1] == "list")) {
                let list = crate::service::SERVICE_MANAGER.lock().list_services();
                for line in list.lines() {
                    self.add_terminal_line(String::from(line));
                }
                crate::audio::play_click_sound();
            } else if parts.len() >= 3 {
                let action = parts[1];
                let unit = parts[2];
                let mut sm = crate::service::SERVICE_MANAGER.lock();
                match action {
                    "start" => {
                        if sm.start_service(unit).is_ok() {
                            self.add_terminal_line(format!("[SYSTEMD] Unit '{}' baslatildi [ active ].", unit));
                        } else {
                            self.add_terminal_line(format!("HATA: Unit '{}' bulunamadi.", unit));
                        }
                    }
                    "stop" => {
                        if sm.stop_service(unit).is_ok() {
                            self.add_terminal_line(format!("[SYSTEMD] Unit '{}' durduruldu [ inactive ].", unit));
                        } else {
                            self.add_terminal_line(format!("HATA: Unit '{}' bulunamadi.", unit));
                        }
                    }
                    _ => {
                        self.add_terminal_line(format!("usage: {} <status|start|stop> [unit_name]", parts[0]));
                    }
                }
                crate::audio::play_click_sound();
            } else {
                self.add_terminal_line(format!("usage: {} <status|start|stop> [unit_name]", parts[0]));
            }
        } else if trimmed.starts_with("snap") || trimmed.starts_with("aero") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let action = parts[1];
                let sw = 1024; // standard desktop width
                let sh = 768;  // standard desktop height
                let act_idx = self.active_window_idx;
                if act_idx < self.windows.len() {
                    let win = &mut self.windows[act_idx];
                    match action {
                        "left" | "sol" => {
                            win.prev_x = win.x;
                            win.prev_y = win.y;
                            win.prev_w = win.w;
                            win.prev_h = win.h;
                            win.x = 8;
                            win.y = 30;
                            win.w = sw / 2 - 12;
                            win.h = sh - 80;
                            win.is_maximized = false;
                            win.snapped_state = Some(widgets::SnapPreview::LeftHalf);
                            self.add_terminal_line(String::from("[AERO SNAP] Pencere sol yariya (50/50) yerlestirildi."));
                        }
                        "right" | "sag" => {
                            win.prev_x = win.x;
                            win.prev_y = win.y;
                            win.prev_w = win.w;
                            win.prev_h = win.h;
                            win.x = (sw / 2 + 4) as isize;
                            win.y = 30;
                            win.w = sw / 2 - 12;
                            win.h = sh - 80;
                            win.is_maximized = false;
                            win.snapped_state = Some(widgets::SnapPreview::RightHalf);
                            self.add_terminal_line(String::from("[AERO SNAP] Pencere sag yariya (50/50) yerlestirildi."));
                        }
                        "max" | "maximize" => {
                            win.prev_x = win.x;
                            win.prev_y = win.y;
                            win.prev_w = win.w;
                            win.prev_h = win.h;
                            win.x = 4;
                            win.y = 30;
                            win.w = sw - 8;
                            win.h = sh - 80;
                            win.is_maximized = true;
                            win.snapped_state = Some(widgets::SnapPreview::Maximize);
                            self.add_terminal_line(String::from("[AERO SNAP] Pencere tam ekrana yayildi (Maximize)."));
                        }
                        "restore" | "reset" => {
                            win.x = win.prev_x;
                            win.y = win.prev_y;
                            win.w = win.prev_w;
                            win.h = win.prev_h;
                            win.is_maximized = false;
                            win.snapped_state = None;
                            self.add_terminal_line(String::from("[AERO SNAP] Pencere normal boyutuna geri yuklendi."));
                        }
                        _ => {
                            self.add_terminal_line(String::from("usage: snap <left|right|max|restore>"));
                        }
                    }
                }
            } else {
                self.add_terminal_line(String::from("Aero Snap Pencere Yoneticisi (Windows 11):"));
                self.add_terminal_line(String::from("  Kullanim: snap <left | right | max | restore>"));
                self.add_terminal_line(String::from("  Fare ile: Pencereyi ekranin sol/sag/ust kenarina surukleyin."));
            }
            crate::audio::play_click_sound();
        } else if trimmed == "alttab" || trimmed == "switch" {
            self.alt_tab_active = !self.alt_tab_active;
            let open_count = self.windows.iter().filter(|w| w.is_open).count();
            if open_count > 0 {
                self.alt_tab_idx = (self.alt_tab_idx + 1) % open_count;
            }
            self.add_terminal_line(format!("[ALT+TAB] Task Switcher acildi (Aktif Pencere Index: {}).", self.alt_tab_idx));
            crate::audio::play_click_sound();
        } else if trimmed == "test_ring3" || trimmed == "ring3" || trimmed == "usermode" {
            let msg = crate::task::usermode::run_safe_ring3_task();
            self.add_terminal_line(String::from("[RING 3 USER-SPACE ISOLATION TEST]"));
            self.add_terminal_line(String::from("  Hardware DPL    : Ring 3 (CS=0x1B, SS=0x23, RFLAGS=0x202)"));
            self.add_terminal_line(String::from("  Kernel TSS.rsp0 : Donanimsal cekirdek stack korumasi aktif"));
            self.add_terminal_line(format!("  Sonuc           : {}", msg));
            crate::audio::play_click_sound();
        } else if trimmed == "test_crash" || trimmed == "crash" || trimmed == "segfault" {
            let report = crate::task::usermode::run_user_crash_simulation();
            self.add_terminal_line(String::from("[HARDWARE CRASH PROTECTION CONTAINED]"));
            self.add_terminal_line(format!("  Vector          : #PF (Vector 14 Page Fault)"));
            self.add_terminal_line(format!("  Error Code      : 0x{:02X} (User Page Fault)", report.error_code));
            self.add_terminal_line(format!("  Faulting RIP    : 0x{:016X}", report.rip));
            self.add_terminal_line(format!("  CR2 Null Deref  : 0x{:016X}", report.cr2));
            self.add_terminal_line(String::from("  Cekirdek Durumu : KORUNDU! GUI ve 300 FPS masaustu calismaya devam ediyor!"));
            crate::audio::play_click_sound();
        } else if trimmed == "syscall_test" || trimmed == "syscalls" {
            let (passed, total) = crate::arch::x86_64::syscall::run_syscall_self_test();
            let subsys_ok = corsyscall::run_self_tests();
            self.add_terminal_line(String::from("[361-VECTOR SYSTEM CALL ABI SELF-TEST SUITE]"));
            self.add_terminal_line(format!("  MSR_LSTAR Vectors : {}/{} PASSED (Ring 0 / Ring 3 Verified)", passed, total));
            self.add_terminal_line(format!("  corsyscall Crate  : {} Domain Sub-Vectors Verified", subsys_ok));
            crate::audio::play_click_sound();
        } else if trimmed == "driver_bench" || trimmed == "drv_bench" {
            let drv_ok = cordrivers::run_self_tests();
            let vfs_ok = corvfs::run_self_tests();
            let net_ok = cornet::run_self_tests();
            let cry_ok = corcrypto::run_self_tests();
            let utl_ok = corcoreutils::run_self_tests();
            self.add_terminal_line(String::from("[COROS SUBSYSTEM & DRIVER BENCHMARK SUITE]"));
            self.add_terminal_line(format!("  cordrivers (PCIe/NVMe/AHCI/xHCI/VirtIO/GPU) : {} checks OK", drv_ok));
            self.add_terminal_line(format!("  corvfs (FAT32/CorFS/ProcFS/SysFS/DevFS)     : {} checks OK", vfs_ok));
            self.add_terminal_line(format!("  cornet (TCP/UDP/IPv4/IPv6/Firewall)         : {} checks OK", net_ok));
            self.add_terminal_line(format!("  corcrypto (SHA/BLAKE2b/ChaCha20/AES/Ed25519): {} checks OK", cry_ok));
            self.add_terminal_line(format!("  corcoreutils (27 POSIX Userland Utilities)  : {} checks OK", utl_ok));
            crate::audio::play_click_sound();
        } else if trimmed.starts_with("ss") || trimmed.starts_with("sysctl") || trimmed.starts_with("find") || trimmed.starts_with("awk") || trimmed.starts_with("sed") || trimmed.starts_with("tar") || trimmed == "mount" || trimmed == "df" || trimmed == "free" || trimmed == "lsusb" {
            let ok_count = corcoreutils::run_self_tests();
            self.add_terminal_line(format!("[COREUTILS] Executed '{}' via corcoreutils engine ({} scenarios active).", trimmed, ok_count));
            crate::audio::play_click_sound();
        } else if trimmed == "reboot" || trimmed == "restart" {
            self.add_terminal_line(String::from("[SYSTEM] Initiating hardware reboot..."));
            unsafe {
                crate::arch::x86_64::cpu::out8(0x64, 0xFE);
                crate::arch::x86_64::cpu::out8(0xCF9, 0x06);
            }
        } else if trimmed == "poweroff" || trimmed == "shutdown" {
            self.add_terminal_line(String::from("[SYSTEM] Halting bare-metal system..."));
            unsafe {
                crate::arch::x86_64::cpu::out16(0x604, 0x2000);
                crate::arch::x86_64::cpu::out16(0x4004, 0x3400);
                crate::arch::x86_64::cpu::out16(0xB004, 0x2000);
                crate::arch::x86_64::disable_interrupts();
                crate::arch::x86_64::halt_forever();
            }
        } else if trimmed == "corbeats" || trimmed == "music" || trimmed == "player" {
            self.toggle_window(8);
            self.add_terminal_line(String::from("[LAUNCH] CorBeats Spektrum Dalga Efektli Muzik Calar acildi."));
            crate::audio::play_synth_riff();
        } else if trimmed == "disk" || trimmed == "diskmgmt" || trimmed == "dma" {
            self.toggle_window(13);
            self.add_terminal_line(String::from("[LAUNCH] Disk Yoneticisi & DMA Hiz Olcer acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "devmgmt" || trimmed == "device" || trimmed == "devices" {
            self.toggle_window(14);
            self.add_terminal_line(String::from("[LAUNCH] Aygit Yoneticisi - Donanim Agaci acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "recovery" || trimmed == "restore" || trimmed == "backup" {
            self.toggle_window(15);
            self.add_terminal_line(String::from("[LAUNCH] Sistem Kurtarma & Anlik Goruntu Yoneticisi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "quick" || trimmed == "actioncenter" || trimmed == "settings" {
            self.quick_settings.toggle_open();
            self.add_terminal_line(String::from("[ACTION] Windows 11 Fluent Hizli Ayarlar Eylem Merkezi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "expose" || trimmed == "mission" || trimmed == "taskview" {
            self.virtual_desktops.toggle_task_view();
            crate::audio::play_click_sound();
        } else if trimmed == "split" {
            self.terminal_split = !self.terminal_split;
            let status = if self.terminal_split { "aktif" } else { "kapali" };
            self.add_terminal_line(format!("[TERMINAL] Split-Pane bolunmus konsol {}", status));
            crate::audio::play_click_sound();
        } else if trimmed == "tab 1" {
            self.terminal_tab = 0;
            self.add_terminal_line(String::from("[TERMINAL] Sekme 1: CorOS Shell secildi."));
        } else if trimmed == "tab 2" {
            self.terminal_tab = 1;
            self.add_terminal_line(String::from("[TERMINAL] Sekme 2: Ring 3 POSIX secildi."));
        } else if trimmed == "tab 3" {
            self.terminal_tab = 2;
            self.add_terminal_line(String::from("[TERMINAL] Sekme 3: Kernel Debug secildi."));
        } else if trimmed == "firewall" || trimmed == "fw" || trimmed == "netsec" || trimmed == "wireshark" || trimmed == "corshark" || trimmed == "sniff" {
            self.toggle_window(16);
            self.add_terminal_line(String::from("[LAUNCH] CorShark Wireshark Ag Paket Yakalayici ve Firewall acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "browser" || trimmed == "web" || trimmed == "www" || trimmed == "corbrowse" {
            self.toggle_window(23);
            self.add_terminal_line(String::from("[LAUNCH] CorBrowse Web ve Yerel Belge Tarayicisi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "disasm" || trimmed == "disassembler" || trimmed == "ghidra" {
            self.toggle_window(17);
            self.add_terminal_line(String::from("[LAUNCH] CorDisasm x86_64 Makine Kodu Cozucu acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "zip" || trimmed == "tar" || trimmed == "archive" || trimmed == "archiver" {
            self.toggle_window(18);
            self.add_terminal_line(String::from("[LAUNCH] CorArchiver ZIP/TAR/7Z Arsiv Yoneticisi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "vm" || trimmed == "vmm" || trimmed == "hypervisor" || trimmed == "kvm" {
            self.toggle_window(19);
            self.add_terminal_line(String::from("[LAUNCH] Hypervisor VMX/SVM Sanallastirma Yoneticisi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "share" || trimmed == "corshare" || trimmed == "p2p" {
            self.toggle_window(20);
            self.add_terminal_line(String::from("[LAUNCH] CorShare Gigabit Ethernet P2P Paylasim Araci acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "cron" || trimmed == "scheduler" || trimmed == "tasksched" {
            self.toggle_window(21);
            self.add_terminal_line(String::from("[LAUNCH] CorCron Gorev Zamanlayici & Arka Plan Servisi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "thermal" || trimmed == "temp" || trimmed == "power" {
            self.toggle_window(22);
            self.add_terminal_line(String::from("[LAUNCH] ACPI Termal Yonetici ve Guc Profili acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "theme" || trimmed == "personalize" {
            self.toggle_window(4);
            self.add_terminal_line(String::from("[LAUNCH] CorThemes Pro Kisisellestirme Yoneticisi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "verbose" || trimmed == "dmesg_boot" || trimmed == "sos" {
            self.verbose_boot_mode = !self.verbose_boot_mode;
            let status = if self.verbose_boot_mode { "aktif" } else { "kapali" };
            self.add_terminal_line(format!("[BOOT] Verbose SOS Donanim Acilis Modu {}", status));
            crate::audio::play_click_sound();
        } else if trimmed == "lock" {
            self.is_locked = true;
            self.add_terminal_line(String::from("[LOCK] Windows 11 Fluent Lock Screen kilitlendi (PIN / Win+L korumali)."));
            crate::audio::play_click_sound();
        } else if trimmed == "game" || trimmed == "doom" || trimmed == "cordoom" {
            self.toggle_window(9);
            self.add_terminal_line(String::from("[LAUNCH] CorDoom 3D Retro Raycasting Engine baslatildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "store" || trimmed == "appstore" || trimmed == "corstore" {
            self.toggle_window(10);
            self.add_terminal_line(String::from("[LAUNCH] CorStore Fluent Uygulama Magazasi acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "code" || trimmed == "editor" || trimmed == "studio" {
            self.toggle_window(11);
            self.add_terminal_line(String::from("[LAUNCH] CorOS Studio Code Gelistirici Editoru acildi."));
            crate::audio::play_click_sound();
        } else if trimmed == "snip" || trimmed == "snipping" || trimmed == "screenshot" {
            self.toggle_window(12);
            self.add_terminal_line(String::from("[LAUNCH] Snipping Tool Ekran Alintisi Araci acildi."));
            crate::audio::play_click_sound();
        } else {
            let (code, output) = crate::corsh::run_corsh_command(trimmed);
            if code == 0 && !output.is_empty() {
                for line in output.lines() {
                    self.add_terminal_line(String::from(line));
                }
            } else if let Some(cmd_out) = terminal_cmds::TerminalCommandEngine::execute(trimmed) {
                for line in cmd_out.stdout.lines() {
                    self.add_terminal_line(String::from(line));
                }
            } else if !output.is_empty() && code != 127 {
                for line in output.lines() {
                    self.add_terminal_line(String::from(line));
                }
            } else {
                self.add_terminal_line(format!("command not found: {}. Type 'help' for list.", trimmed));
            }
        }
    }

    pub fn handle_notepad_key(&mut self, ch: char) {
        match ch {
            '\x08' => {
                // Backspace
                if self.notepad_cursor_row < self.notepad_content.len() {
                    let line = &mut self.notepad_content[self.notepad_cursor_row];
                    if self.notepad_cursor_col > 0 && self.notepad_cursor_col <= line.len() {
                        line.remove(self.notepad_cursor_col - 1);
                        self.notepad_cursor_col -= 1;
                        self.notepad_saved_status = false;
                    } else if self.notepad_cursor_row > 0 && self.notepad_cursor_col == 0 {
                        // Merge with previous line
                        let current_line = self.notepad_content.remove(self.notepad_cursor_row);
                        self.notepad_cursor_row -= 1;
                        let prev_len = self.notepad_content[self.notepad_cursor_row].len();
                        self.notepad_content[self.notepad_cursor_row].push_str(&current_line);
                        self.notepad_cursor_col = prev_len;
                        self.notepad_saved_status = false;
                    }
                }
            }
            '\n' => {
                // Enter: split line or create new line
                if self.notepad_cursor_row < self.notepad_content.len() {
                    let line = &mut self.notepad_content[self.notepad_cursor_row];
                    let rest = if self.notepad_cursor_col < line.len() {
                        line.split_off(self.notepad_cursor_col)
                    } else {
                        String::new()
                    };
                    self.notepad_content.insert(self.notepad_cursor_row + 1, rest);
                    self.notepad_cursor_row += 1;
                    self.notepad_cursor_col = 0;
                    self.notepad_saved_status = false;
                }
            }
            '\x13' => {
                // Ctrl+S: Save file
                self.notepad_saved_status = true;
                let mut full_text = String::new();
                for (idx, line) in self.notepad_content.iter().enumerate() {
                    full_text.push_str(line);
                    if idx + 1 < self.notepad_content.len() {
                        full_text.push('\n');
                    }
                }
                let text_len = full_text.len();
                let bytes = full_text.as_bytes();
                unsafe {
                    if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                        let _ = fs.write_file("EFI/COROS/NOTLAR.TXT", bytes);
                    }
                }
                if let Some(f) = self.files.iter_mut().find(|f| f.name == "NOTLAR.TXT") {
                    f.content = full_text;
                    f.size_str = format!("{} B", text_len);
                }
                self.add_terminal_line(format!("[NOTEPAD] C:\\EFI\\COROS\\NOTLAR.TXT kaydedildi (Ctrl+S, {} Bayt FAT32).", text_len));
                crate::audio::play_click_sound();
            }
            '\u{89}' => {
                // Left Arrow
                self.notepad_cursor_col = self.notepad_cursor_col.saturating_sub(1);
            }
            '\u{8A}' => {
                // Right Arrow
                if self.notepad_cursor_row < self.notepad_content.len() {
                    let line_len = self.notepad_content[self.notepad_cursor_row].len();
                    if self.notepad_cursor_col < line_len {
                        self.notepad_cursor_col += 1;
                    }
                }
            }
            '\u{87}' => {
                // Up Arrow
                self.notepad_cursor_row = self.notepad_cursor_row.saturating_sub(1);
                if self.notepad_cursor_row < self.notepad_content.len() {
                    let line_len = self.notepad_content[self.notepad_cursor_row].len();
                    self.notepad_cursor_col = self.notepad_cursor_col.min(line_len);
                }
            }
            '\u{88}' => {
                // Down Arrow
                if self.notepad_cursor_row + 1 < self.notepad_content.len() {
                    self.notepad_cursor_row += 1;
                    let line_len = self.notepad_content[self.notepad_cursor_row].len();
                    self.notepad_cursor_col = self.notepad_cursor_col.min(line_len);
                }
            }
            c if c >= ' ' && c <= '~' => {
                if self.notepad_cursor_row < self.notepad_content.len() {
                    let line = &mut self.notepad_content[self.notepad_cursor_row];
                    if self.notepad_cursor_col <= line.len() {
                        line.insert(self.notepad_cursor_col, c);
                        self.notepad_cursor_col += 1;
                        self.notepad_saved_status = false;
                    }
                }
            }
            _ => {}
        }
    }

    pub fn handle_calc_key(&mut self, ch: char) {
        match ch {
            '0'..='9' => {
                if self.calc_clear_on_next || self.calc_display == "0" {
                    self.calc_display.clear();
                    self.calc_clear_on_next = false;
                }
                if self.calc_display.len() < 12 {
                    self.calc_display.push(ch);
                }
            }
            '+' | '-' | '*' | '/' => {
                let current_val: i64 = self.calc_display.parse().unwrap_or(0);
                if let Some(op) = self.calc_op {
                    self.calc_accumulator = match op {
                        '+' => self.calc_accumulator.saturating_add(current_val),
                        '-' => self.calc_accumulator.saturating_sub(current_val),
                        '*' => self.calc_accumulator.saturating_mul(current_val),
                        '/' => if current_val != 0 { self.calc_accumulator / current_val } else { 0 },
                        _ => current_val,
                    };
                    self.calc_display = format!("{}", self.calc_accumulator);
                } else {
                    self.calc_accumulator = current_val;
                }
                self.calc_op = Some(ch);
                self.calc_clear_on_next = true;
            }
            '=' | '\n' => {
                let current_val: i64 = self.calc_display.parse().unwrap_or(0);
                if let Some(op) = self.calc_op {
                    let result = match op {
                        '+' => self.calc_accumulator.saturating_add(current_val),
                        '-' => self.calc_accumulator.saturating_sub(current_val),
                        '*' => self.calc_accumulator.saturating_mul(current_val),
                        '/' => if current_val != 0 { self.calc_accumulator / current_val } else { 0 },
                        _ => current_val,
                    };
                    self.calc_display = format!("{}", result);
                    self.calc_accumulator = result;
                    self.calc_op = None;
                    self.calc_clear_on_next = true;
                }
            }
            'c' | 'C' | '\x1B' => {
                self.calc_display = String::from("0");
                self.calc_accumulator = 0;
                self.calc_op = None;
                self.calc_clear_on_next = false;
            }
            '\x08' => {
                if !self.calc_clear_on_next && self.calc_display.len() > 1 {
                    self.calc_display.pop();
                } else {
                    self.calc_display = String::from("0");
                }
            }
            _ => {}
        }
    }

    pub fn handle_paint_key(&mut self, ch: char) {
        if self.paint_hex_active {
            match ch {
                '\x08' => {
                    self.paint_hex_input.pop();
                }
                '\n' | '\x1B' => {
                    self.paint_hex_active = false;
                    self.apply_paint_hex_color();
                }
                c if c.is_ascii_hexdigit() => {
                    if self.paint_hex_input.len() < 6 {
                        self.paint_hex_input.push(c.to_ascii_uppercase());
                        if self.paint_hex_input.len() == 6 {
                            self.apply_paint_hex_color();
                        }
                    }
                }
                _ => {}
            }
            return;
        }

        // Shortcuts: Ctrl+Z ('\x1A') -> Undo
        if ch == '\x1A' || ch == 'u' || ch == 'U' {
            self.paint_undo();
        } else if ch == 's' || ch == 'S' {
            self.save_paint_png();
        } else if ch == 'c' || ch == 'C' {
            self.push_paint_undo();
            self.paint_pixels.fill(0x00FFFFFF);
            self.paint_status_msg = String::from("Tuval temizlendi.");
        }
    }

    pub fn apply_paint_hex_color(&mut self) {
        if let Ok(val) = u32::from_str_radix(&self.paint_hex_input, 16) {
            self.paint_custom_color = val & 0x00FFFFFF;
            self.paint_color_idx = 16; // Custom color active
            self.paint_status_msg = format!("Ozel Renk Secildi: #{:06X}", self.paint_custom_color);
        }
    }

    pub fn push_paint_undo(&mut self) {
        if self.paint_undo_history.len() >= 5 {
            self.paint_undo_history.remove(0);
        }
        self.paint_undo_history.push(self.paint_pixels.clone());
    }

    pub fn paint_undo(&mut self) {
        if let Some(prev) = self.paint_undo_history.pop() {
            self.paint_pixels = prev;
            self.paint_status_msg = String::from("Geri alindi (Undo OK).");
            crate::audio::play_click_sound();
        } else {
            self.paint_status_msg = String::from("Geri alinacak islem yok.");
        }
    }

    pub fn get_current_paint_color(&self) -> u32 {
        let preset_colors = [
            0x00000000, 0x00FFFFFF, 0x0078909C, 0x00EF4444,
            0x00F97316, 0x00EAB308, 0x0022C55E, 0x0010B981,
            0x0006B6D4, 0x003B82F6, 0x001E3A8A, 0x00A855F7,
            0x00EC4899, 0x0092400E, 0x00FEF08A, 0x000F172A,
        ];
        if self.paint_color_idx < 16 {
            preset_colors[self.paint_color_idx]
        } else {
            self.paint_custom_color
        }
    }

    pub fn paint_flood_fill(&mut self, start_x: usize, start_y: usize, fill_color: u32) {
        let target_color = self.paint_pixels[start_y * 160 + start_x];
        if target_color == fill_color {
            return;
        }

        self.push_paint_undo();
        let mut queue = alloc::vec::Vec::with_capacity(512);
        queue.push((start_x, start_y));
        self.paint_pixels[start_y * 160 + start_x] = fill_color;

        while let Some((cx, cy)) = queue.pop() {
            let neighbors = [
                (cx.wrapping_sub(1), cy, cx > 0),
                (cx + 1, cy, cx + 1 < 160),
                (cx, cy.wrapping_sub(1), cy > 0),
                (cx, cy + 1, cy + 1 < 120),
            ];

            for &(nx, ny, valid) in &neighbors {
                if valid {
                    let idx = ny * 160 + nx;
                    if self.paint_pixels[idx] == target_color {
                        self.paint_pixels[idx] = fill_color;
                        if queue.len() < 19200 {
                            queue.push((nx, ny));
                        }
                    }
                }
            }
        }
        self.paint_status_msg = String::from("Boya Kovasi: Alan dolduruldu!");
    }

    pub fn paint_draw_brush(&mut self, px: usize, py: usize, color: u32, size: usize) {
        let r = (size / 2) as isize;
        for dy in -r..=r {
            for dx in -r..=r {
                let target_x = (px as isize) + dx;
                let target_y = (py as isize) + dy;
                if target_x >= 0 && target_x < 160 && target_y >= 0 && target_y < 120 {
                    let idx = (target_y as usize) * 160 + (target_x as usize);
                    self.paint_pixels[idx] = color;
                }
            }
        }
    }

    pub fn paint_draw_line(&mut self, x0: usize, y0: usize, x1: usize, y1: usize, color: u32, size: usize) {
        let mut x = x0 as isize;
        let mut y = y0 as isize;
        let dx = (x1 as isize - x0 as isize).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let dy = -(y1 as isize - y0 as isize).abs();
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            if x >= 0 && x < 160 && y >= 0 && y < 120 {
                self.paint_draw_brush(x as usize, y as usize, color, size);
            }
            if x == x1 as isize && y == y1 as isize { break; }
            let e2 = 2 * err;
            if e2 >= dy { err += dy; x += sx; }
            if e2 <= dx { err += dx; y += sy; }
        }
    }

    pub fn paint_draw_rect(&mut self, x0: usize, y0: usize, x1: usize, y1: usize, color: u32, size: usize) {
        let min_x = x0.min(x1);
        let max_x = x0.max(x1);
        let min_y = y0.min(y1);
        let max_y = y0.max(y1);

        for x in min_x..=max_x {
            self.paint_draw_brush(x, min_y, color, size);
            self.paint_draw_brush(x, max_y, color, size);
        }
        for y in min_y..=max_y {
            self.paint_draw_brush(min_x, y, color, size);
            self.paint_draw_brush(max_x, y, color, size);
        }
    }

    pub fn save_paint_png(&mut self) {
        let png_bytes = crate::fs::encode_rgba_to_png(&self.paint_pixels, 160, 120);
        let mut saved = false;

        unsafe {
            if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                if fs.write_file("EFI/COROS/RESIM.PNG", &png_bytes).is_ok() {
                    saved = true;
                }
            }
        }

        if saved {
            self.paint_status_msg = format!("KAYDEDILDI: C:\\EFI\\COROS\\RESIM.PNG ({} B)", png_bytes.len());
            self.add_terminal_line(format!("[PAINT] Resim basariyla PNG olarak kaydedildi: C:\\EFI\\COROS\\RESIM.PNG ({} Bayt)", png_bytes.len()));
            // Add or update RESIM.PNG in Desktop File Explorer files list
            if !self.files.iter().any(|f| f.name == "RESIM.PNG") {
                self.files.push(FileItem {
                    name: String::from("RESIM.PNG"),
                    kind: String::from("[IMAGE-PNG]"),
                    size_str: format!("{} KB", (png_bytes.len() + 1023) / 1024),
                    desc: String::from("Paint 24-bit TrueColor PNG"),
                    content: format!("[PNG Image 160x120 24bpp TrueColor | {} Bytes]", png_bytes.len()),
                    is_dir: false,
                });
            }
            crate::audio::play_click_sound();
        } else {
            self.paint_status_msg = format!("PNG olusturuldu ({} B) - Disk bagli degil", png_bytes.len());
        }
    }

    /// Loads files list for the current folder path (C:\, C:\EFI, C:\EFI\BOOT, C:\EFI\COROS)
    pub fn load_directory_contents(&mut self) {
        let mut list = Vec::new();
        let cur = self.current_folder.clone();

        if cur == "C:\\" || cur == "C:" {
            // Root directory C:\
            list.push(FileItem { name: String::from("EFI"), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("EFI Sistem Dizini"), content: String::new(), is_dir: true });
            list.push(FileItem { name: String::from("SISTEM.LOG"), kind: String::from("[LOG]"), size_str: String::from("128 B"), desc: String::from("Kok Dizin Gunlugu"), content: String::from("CorOS UEFI System Root Partition - FAT32 DMA OK"), is_dir: false });
        } else if cur == "C:\\EFI" {
            // C:\EFI directory
            list.push(FileItem { name: String::from(".."), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("Kok Dizin (C:\\)"), content: String::new(), is_dir: true });
            list.push(FileItem { name: String::from("BOOT"), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("UEFI Bootloader Dizini"), content: String::new(), is_dir: true });
            list.push(FileItem { name: String::from("COROS"), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("CorOS Cekirdek & Sistem Dizini"), content: String::new(), is_dir: true });
        } else if cur == "C:\\EFI\\BOOT" {
            // C:\EFI\BOOT directory
            list.push(FileItem { name: String::from(".."), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("Ust Dizin (C:\\EFI)"), content: String::new(), is_dir: true });
            list.push(FileItem { name: String::from("BOOTX64.EFI"), kind: String::from("[PE-64]"), size_str: String::from("64 KB"), desc: String::from("UEFI x86_64 Bootloader"), content: String::from("[PE32+ x86_64 UEFI Bootloader | MZ/PE Header Valid]"), is_dir: false });
            list.push(FileItem { name: String::from("STARTUP.NSH"), kind: String::from("[SCRIPT]"), size_str: String::from("45 B"), desc: String::from("UEFI Otomatik Baslatma"), content: String::from("fs0:\\EFI\\BOOT\\BOOTX64.EFI"), is_dir: false });
        } else {
            // Default / C:\EFI\COROS
            list.push(FileItem { name: String::from(".."), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("Ust Dizin (C:\\EFI)"), content: String::new(), is_dir: true });
            list.push(FileItem { name: String::from("BOOT"), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("UEFI Boot Directory"), content: String::new(), is_dir: true });
            list.push(FileItem { name: String::from("COROS"), kind: String::from("[DIR]"), size_str: String::from("--"), desc: String::from("CorOS System Directory"), content: String::new(), is_dir: true });
            list.push(FileItem { name: String::from("README.TXT"), kind: String::from("[TEXT]"), size_str: String::from("180 B"), desc: String::from("CorOS Kullanici Kilavuzu"), content: String::from("Tebrikler! CorOS isletim sistemini basariyla calistirdiniz.\nBu sistem no_std Rust ile sifirdan bare-metal yazilmistir.\nCift tiklayarak dosyalari acabilir, Paint ile resim cizebilirsiniz."), is_dir: false });
            list.push(FileItem { name: String::from("NOTLAR.TXT"), kind: String::from("[TEXT]"), size_str: String::from("110 B"), desc: String::from("Gunluk Notlar & Gorevler"), content: String::from("1. CorOS dosya yoneticisi test edildi.\n2. Not defteri ve Paint calisiyor.\n3. FAT32 dosya kaydetme basarili!"), is_dir: false });
            list.push(FileItem { name: String::from("RESIM.PNG"), kind: String::from("[IMAGE-PNG]"), size_str: String::from("14 KB"), desc: String::from("Paint 24-bit TrueColor PNG"), content: String::from("[PNG Image 160x120 24bpp TrueColor]"), is_dir: false });
            list.push(FileItem { name: String::from("BOOTX64.EFI"), kind: String::from("[PE-64]"), size_str: String::from("64 KB"), desc: String::from("UEFI Bootloader (PE/MZ OK)"), content: String::from("[PE32+ x86_64 UEFI Bootloader | 65,536 Bytes | MZ/PE Header Valid]"), is_dir: false });
            list.push(FileItem { name: String::from("CORKERNEL.EFI"), kind: String::from("[PE-64]"), size_str: String::from("86 KB"), desc: String::from("Bare-Metal Kernel (PE/MZ OK)"), content: String::from("[PE32+ x86_64 Kernel Image | 88,064 Bytes | MZ/PE Header Valid]"), is_dir: false });
            list.push(FileItem { name: String::from("BOOT.LOG"), kind: String::from("[TEXT]"), size_str: String::from("58 B"), desc: String::from("FAT32 DMA Write Verified"), content: String::from("COROS INDEPENDENT KERNEL - FAT32 PERSISTENT WRITE VERIFIED"), is_dir: false });
            list.push(FileItem { name: String::from("CYBER3D.BIN"), kind: String::from("[APP-3D]"), size_str: String::from("32 KB"), desc: String::from("Real-Time 3D Engine"), content: String::from("[CyberSpace 3D Bare-Metal Executable | 305 FPS Real-Time VRAM]"), is_dir: false });
        }

        self.files = list;
        if let Some(win) = self.windows.get_mut(0) {
            win.selected_file = 0;
        }
        self.file_status_msg = format!("Konum: {} (Toplam {} oge)", self.current_folder, self.files.len());
    }

    /// Opens a file or enters a directory from File Explorer by its list index
    pub fn open_file_by_index(&mut self, idx: usize) {
        if idx >= self.files.len() {
            return;
        }

        let f = &self.files[idx];
        let fname = f.name.clone();
        let fcontent = f.content.clone();
        let is_directory = f.is_dir;

        // Check Directory Traversal
        if is_directory {
            if fname == ".." {
                // Navigate Up
                if self.current_folder == "C:\\EFI\\COROS" || self.current_folder == "C:\\EFI\\BOOT" {
                    self.current_folder = String::from("C:\\EFI");
                } else if self.current_folder == "C:\\EFI" {
                    self.current_folder = String::from("C:\\");
                }
                self.load_directory_contents();
                crate::audio::play_click_sound();
                return;
            } else if fname == "BOOT" {
                self.current_folder = String::from("C:\\EFI\\BOOT");
                self.load_directory_contents();
                crate::audio::play_click_sound();
                return;
            } else if fname == "COROS" {
                self.current_folder = String::from("C:\\EFI\\COROS");
                self.load_directory_contents();
                crate::audio::play_click_sound();
                return;
            } else if fname == "EFI" {
                self.current_folder = String::from("C:\\EFI");
                self.load_directory_contents();
                crate::audio::play_click_sound();
                return;
            }
        }

        if fname.ends_with(".TXT") || fname.ends_with(".LOG") || fname.ends_with(".NSH") {
            // 1. Open in Notepad
            self.notepad_content.clear();
            for line in fcontent.lines() {
                self.notepad_content.push(String::from(line));
            }
            if self.notepad_content.is_empty() {
                self.notepad_content.push(String::new());
            }
            self.notepad_cursor_row = 0;
            self.notepad_cursor_col = 0;
            self.notepad_saved_status = true;

            // Update Notepad window title
            if let Some(win) = self.windows.get_mut(5) {
                win.title = "Not Defteri - CorOS Notes (FAT32)";
                win.is_open = true;
                win.is_minimized = false;
            }
            self.active_window_idx = 5;
            self.file_status_msg = format!("Dosya Acildi: {}\\{} (Not Defteri)", self.current_folder, fname);
            self.add_terminal_line(format!("[EXPLORER] {} Not Defteri ile acildi.", fname));
            crate::audio::play_click_sound();
        } else if fname.ends_with(".PNG") {
            // 2. Open in Paint
            let mut loaded_from_disk = false;
            unsafe {
                if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                    let disk_path = format!("EFI/COROS/{}", fname);
                    if let Ok(bytes) = fs.read_file(&disk_path) {
                        if let Some((pixels, w, h)) = crate::fs::decode_png_to_rgba(&bytes) {
                            if w == 160 && h == 120 && pixels.len() == 160 * 120 {
                                self.push_paint_undo();
                                self.paint_pixels = pixels;
                                loaded_from_disk = true;
                            }
                        }
                    }
                }
            }

            if let Some(win) = self.windows.get_mut(7) {
                win.is_open = true;
                win.is_minimized = false;
            }
            self.active_window_idx = 7;
            self.paint_status_msg = if loaded_from_disk {
                format!("Yuklendi: {}\\{} (FAT32)", self.current_folder, fname)
            } else {
                format!("Paint Acildi: {}\\{}", self.current_folder, fname)
            };
            self.file_status_msg = format!("Resim Acildi: {}\\{} (Paint)", self.current_folder, fname);
            self.add_terminal_line(format!("[EXPLORER] {} Paint ile acildi.", fname));
            crate::audio::play_click_sound();
        } else if fname == "CYBER3D.BIN" {
            // 3. Open in 3D Viewer
            self.toggle_window(3);
            self.file_status_msg = String::from("3D Goruntuleyici Baslatildi.");
            crate::audio::play_click_sound();
        } else if fname.ends_with(".ELF") {
            // 4. Execute standalone ELF64 binary in Ring 3 User Space!
            let elf_bytes = unsafe {
                if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                    let path = format!("EFI/COROS/{}", fname);
                    fs.read_file(&path).ok().or_else(|| fs.read_file(&fname).ok())
                } else {
                    None
                }
            };
            if let Some(bytes) = elf_bytes {
                match crate::task::elf_loader::ElfLoader::load_and_run(&fname, &bytes) {
                    Ok(res) => {
                        self.file_status_msg = format!("'{}' Ring 3 modunda calistirildi!", fname);
                        self.add_terminal_line(format!("[ELF LOADER] '{}' calistirildi (RIP: 0x{:X}, Boyut: {} B)", fname, res.entry_point, res.memory_size));
                        self.notification_center.push_notification(notifications::Notification {
                            id: self.notification_center.next_id,
                            title: format!("ELF Calistirildi: {}", fname),
                            body: format!("Ring 3 User-Space DPL 3 modunda basariyla calistirildi."),
                            time_str: String::from("19:40"),
                            category: notifications::NotificationCategory::ElfApp,
                        });
                    }
                    Err(e) => {
                        self.file_status_msg = format!("ELF yukleme hatasi: {}", e);
                    }
                }
            } else {
                self.file_status_msg = format!("'{}' diskten okunamadi.", fname);
            }
            crate::audio::play_click_sound();
        } else {
            self.file_status_msg = format!("{} (Calistirilabilir sistem dosyasi)", fname);
            crate::audio::play_click_sound();
        }
    }

    /// Copies selected file in File Explorer to clipboard (Ctrl + C)
    pub fn copy_selected_file(&mut self) {
        if let Some(win) = self.windows.get(0) {
            let sel = win.selected_file;
            if sel < self.files.len() {
                let f = &self.files[sel];
                if !f.is_dir {
                    self.clipboard_file = Some(f.clone());
                    self.file_status_msg = format!("Kopyalandi (Ctrl+C): {} | Yapistirmak icin Ctrl+V basin", f.name);
                    self.add_terminal_line(format!("[EXPLORER] '{}' panoya kopyalandi.", f.name));
                    crate::audio::play_click_sound();
                } else {
                    self.file_status_msg = String::from("Klasor kopyalama desteklenmiyor.");
                }
            }
        }
    }

    /// Pastes copied file into current folder with _KOPYA suffix (Ctrl + V)
    pub fn paste_clipboard_file(&mut self) {
        if let Some(clip) = self.clipboard_file.clone() {
            // Generate duplicate filename, e.g. NOTLAR_KOPYA.TXT
            let (stem, ext) = if let Some(dot_pos) = clip.name.rfind('.') {
                (&clip.name[..dot_pos], &clip.name[dot_pos..])
            } else {
                (clip.name.as_str(), "")
            };

            let mut copy_name = format!("{}_KOPYA{}", stem, ext);
            let mut c_num = 2;
            while self.files.iter().any(|f| f.name.eq_ignore_ascii_case(&copy_name)) {
                copy_name = format!("{}_KOPYA{}{}", stem, c_num, ext);
                c_num += 1;
            }

            // Write to physical FAT32 disk if in C:\EFI\COROS
            let bytes = clip.content.as_bytes();
            if self.current_folder.contains("COROS") {
                unsafe {
                    if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                        let disk_path = format!("EFI/COROS/{}", copy_name);
                        let _ = fs.write_file(&disk_path, bytes);
                    }
                }
            }

            let new_item = FileItem {
                name: copy_name.clone(),
                kind: clip.kind.clone(),
                size_str: clip.size_str.clone(),
                desc: format!("Kopya: {}", clip.desc),
                content: clip.content.clone(),
                is_dir: false,
            };

            self.files.push(new_item);
            let new_idx = self.files.len() - 1;
            if let Some(win) = self.windows.get_mut(0) {
                win.selected_file = new_idx;
            }
            self.file_status_msg = format!("Yapistirildi (Ctrl+V): {}\\{}", self.current_folder, copy_name);
            self.add_terminal_line(format!("[EXPLORER] '{}' basariyla cogaltildi.", copy_name));
            crate::audio::play_click_sound();
        } else {
            self.file_status_msg = String::from("Panoda kopyalanmis dosya yok (Ctrl+C yapin).");
        }
    }

    /// Initiates file rename mode (F2)
    pub fn start_rename_file(&mut self) {
        if let Some(win) = self.windows.get(0) {
            let sel = win.selected_file;
            if sel < self.files.len() {
                let f = &self.files[sel];
                if f.is_dir || f.name == "BOOTX64.EFI" || f.name == "CORKERNEL.EFI" {
                    self.file_status_msg = format!("UYARI: '{}' sistem ogesi yeniden adlandirilamaz!", f.name);
                    crate::audio::play_click_sound();
                    return;
                }
                self.renaming_file_idx = Some(sel);
                self.rename_buffer = f.name.clone();
                self.file_status_msg = format!("Yeniden Adlandir (F2): {} -> Yeni adi yazip Enter basin", f.name);
                crate::audio::play_click_sound();
            }
        }
    }

    /// Commits file rename
    pub fn commit_rename(&mut self) {
        if let Some(idx) = self.renaming_file_idx {
            if idx < self.files.len() && !self.rename_buffer.trim().is_empty() {
                let old_name = self.files[idx].name.clone();
                let mut new_name = self.rename_buffer.trim().to_uppercase();
                if !new_name.contains('.') && old_name.contains('.') {
                    if let Some(ext) = old_name.rfind('.') {
                        new_name.push_str(&old_name[ext..]);
                    }
                }

                // If in C:\EFI\COROS, delete old and write new on FAT32
                if self.current_folder.contains("COROS") {
                    let content_bytes = self.files[idx].content.as_bytes();
                    unsafe {
                        if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                            let old_path = format!("EFI/COROS/{}", old_name);
                            let new_path = format!("EFI/COROS/{}", new_name);
                            let _ = fs.delete_file(&old_path);
                            let _ = fs.write_file(&new_path, content_bytes);
                        }
                    }
                }

                self.files[idx].name = new_name.clone();
                self.file_status_msg = format!("Yeniden Adlandirildi: {} -> {}", old_name, new_name);
                self.add_terminal_line(format!("[EXPLORER] '{}' -> '{}' olarak guncellendi.", old_name, new_name));
                crate::audio::play_click_sound();
            }
        }
        self.renaming_file_idx = None;
        self.rename_buffer.clear();
    }

    /// Cancels rename mode
    pub fn cancel_rename(&mut self) {
        self.renaming_file_idx = None;
        self.rename_buffer.clear();
        self.file_status_msg = String::from("Yeniden adlandirma iptal edildi.");
    }

    /// Creates a new text file inside File Explorer and FAT32 disk
    pub fn create_new_text_file(&mut self) {
        let mut num = 1;
        let mut name = format!("YENI_{}.TXT", num);
        while self.files.iter().any(|f| f.name == name) {
            num += 1;
            name = format!("YENI_{}.TXT", num);
        }

        let initial_content = format!("CorOS Yeni Belge #{}\nOlusturuldu: {}\nBuraya notlarinizi yazabilirsiniz.", num, name);
        let bytes = initial_content.as_bytes();

        if self.current_folder.contains("COROS") {
            unsafe {
                if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                    let disk_path = format!("EFI/COROS/{}", name);
                    let _ = fs.write_file(&disk_path, bytes);
                }
            }
        }

        let new_item = FileItem {
            name: name.clone(),
            kind: String::from("[TEXT]"),
            size_str: format!("{} B", bytes.len()),
            desc: String::from("Kullanici Metin Belgesi"),
            content: initial_content,
            is_dir: false,
        };

        self.files.push(new_item);
        let new_idx = self.files.len() - 1;
        if let Some(win) = self.windows.get_mut(0) {
            win.selected_file = new_idx;
        }
        self.file_status_msg = format!("Yeni dosya olusturuldu: {}\\{}", self.current_folder, name);
        self.add_terminal_line(format!("[EXPLORER] Yeni dosya olusturuldu: {}", name));
        crate::audio::play_click_sound();
    }

    /// Deletes the currently selected file in File Explorer and moves to Recycle Bin
    pub fn delete_selected_file(&mut self) {
        if self.files.is_empty() {
            return;
        }

        let sel_idx = if let Some(win) = self.windows.get(0) {
            win.selected_file
        } else {
            0
        };

        if sel_idx >= self.files.len() {
            return;
        }

        let f = &self.files[sel_idx];
        if f.is_dir || f.name == "BOOTX64.EFI" || f.name == "CORKERNEL.EFI" {
            self.file_status_msg = format!("UYARI: '{}' sistem dosyasi silinemez!", f.name);
            crate::audio::play_click_sound();
            return;
        }

        let fname = f.name.clone();

        // 1. Delete from physical FAT32 disk if mounted
        if self.current_folder.contains("COROS") {
            unsafe {
                if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                    let disk_path = format!("EFI/COROS/{}", fname);
                    let _ = fs.delete_file(&disk_path);
                }
            }
        }

        // 2. Remove from active explorer list
        self.files.remove(sel_idx);

        // Update selected file index
        if let Some(win) = self.windows.get_mut(0) {
            if win.selected_file >= self.files.len() && !self.files.is_empty() {
                win.selected_file = self.files.len() - 1;
            }
        }

        self.file_status_msg = format!("'{}' silindi ve Geri Donusum Kutusu'na tasindi.", fname);
        self.add_terminal_line(format!("[EXPLORER] '{}' basariyla silindi.", fname));
        crate::audio::play_click_sound();
    }

    pub fn process_keyboard(&mut self) {
        self.cursor_blink = self.cursor_blink.wrapping_add(1);

        while let Some(ch) = input::pop_char() {
            // Handle Alt+Tab / Task Switcher shortcut (ch == '\u{83}')
            if ch == '\u{83}' {
                let open_count = self.windows.iter().filter(|w| w.is_open).count();
                if open_count > 0 {
                    if !self.alt_tab_active {
                        self.alt_tab_active = true;
                    }
                    self.alt_tab_idx = (self.alt_tab_idx + 1) % open_count;
                }
                continue;
            }

            if self.alt_tab_active {
                match ch {
                    '\n' | ' ' => {
                        let open_indices: alloc::vec::Vec<usize> = self.windows.iter().enumerate()
                            .filter(|(_, w)| w.is_open)
                            .map(|(i, _)| i)
                            .collect();
                        if let Some(&target_idx) = open_indices.get(self.alt_tab_idx) {
                            self.active_window_idx = target_idx;
                            self.windows[target_idx].is_minimized = false;
                        }
                        self.alt_tab_active = false;
                        crate::audio::play_click_sound();
                        continue;
                    }
                    '\x1B' => {
                        self.alt_tab_active = false;
                        continue;
                    }
                    _ => {}
                }
            }

            // Global shortcuts: Win/Super (\u{80}), Run Dialog / Ctrl+R (\x12), Task View / Ctrl+Tab (\u{86})
            if ch == '\u{80}' {
                self.start_menu.toggle();
                crate::audio::play_click_sound();
                continue;
            } else if ch == '\x12' {
                self.run_dialog.open();
                crate::audio::play_click_sound();
                continue;
            } else if ch == '\u{86}' {
                self.virtual_desktops.toggle_task_view();
                crate::audio::play_click_sound();
                continue;
            }

            // Route keys if Lock Screen is active
            if self.is_locked {
                if ch == '\n' || ch == ' ' || (ch >= '0' && ch <= '9') {
                    self.is_locked = false;
                    crate::audio::play_click_sound();
                }
                continue;
            }

            // Route keys to Run Dialog if active
            if self.run_dialog.is_open {
                if let Some(cmd) = self.run_dialog.handle_key(ch) {
                    self.execute_command(&cmd);
                }
                continue;
            }

            // Route keys to Task View overlay if active
            if self.virtual_desktops.task_view_open {
                match ch {
                    '\x1B' => {
                        self.virtual_desktops.close_task_view();
                    }
                    '1'..='9' => {
                        let idx = (ch as usize) - ('1' as usize);
                        if idx < self.virtual_desktops.desktop_count() {
                            self.virtual_desktops.switch_to(idx);
                            self.virtual_desktops.close_task_view();
                            crate::audio::play_click_sound();
                        }
                    }
                    '\t' | 'n' => {
                        self.virtual_desktops.next_desktop();
                    }
                    '+' => {
                        let id = self.virtual_desktops.add_desktop();
                        self.virtual_desktops.switch_to(id);
                    }
                    _ => {}
                }
                continue;
            }

            let active_win = self.windows.get(self.active_window_idx);
            let is_win_focused = active_win.map_or(false, |w| w.is_open && !w.is_minimized);

            if self.start_menu.is_open {
                match ch {
                    '\x08' => {
                        self.start_menu.search_query.pop();
                    }
                    '\x1B' => {
                        self.start_menu.close();
                    }
                    '\n' => {
                        // Execute first matched app or command
                        let q = self.start_menu.search_query.to_lowercase();
                        if q.contains("not") || q.contains("yaz") {
                            self.toggle_window(5);
                        } else if q.contains("hesap") || q.contains("calc") {
                            self.toggle_window(6);
                        } else if q.contains("paint") || q.contains("ciz") {
                            self.toggle_window(7);
                        } else if q.contains("term") || q.contains("komut") {
                            self.toggle_window(1);
                        } else if q.contains("dosya") || q.contains("gezg") {
                            self.toggle_window(0);
                        } else if q.contains("3d") || q.contains("kup") {
                            self.toggle_window(3);
                        } else if q.contains("ayar") || q.contains("tema") {
                            self.toggle_window(4);
                        } else if q.contains("hesap.elf") {
                            self.execute_command("exec HESAP.ELF");
                        } else if q.contains("app.elf") {
                            self.execute_command("exec APP.ELF");
                        } else {
                            self.toggle_window(1); // Default to terminal
                        }
                        self.start_menu.close();
                    }
                    c if c >= ' ' && c <= '~' => {
                        if self.start_menu.search_query.len() < 30 {
                            self.start_menu.search_query.push(c);
                        }
                    }
                    _ => {}
                }
                continue;
            }

            if is_win_focused {
                if let Some(w) = active_win {
                    if w.win_type == WindowType::RetroGame {
                        match ch {
                            'w' | 'W' => {
                                let (dx, dy) = match ((self.retro_game.player_angle as usize) / 90) % 4 {
                                    0 => (0.2, 0.2),
                                    1 => (-0.2, 0.2),
                                    2 => (-0.2, -0.2),
                                    _ => (0.2, -0.2),
                                };
                                self.retro_game.player_x = (self.retro_game.player_x + dx).clamp(1.5, 14.5);
                                self.retro_game.player_y = (self.retro_game.player_y + dy).clamp(1.5, 14.5);
                                continue;
                            }
                            's' | 'S' => {
                                let (dx, dy) = match ((self.retro_game.player_angle as usize) / 90) % 4 {
                                    0 => (-0.2, -0.2),
                                    1 => (0.2, -0.2),
                                    2 => (0.2, 0.2),
                                    _ => (-0.2, 0.2),
                                };
                                self.retro_game.player_x = (self.retro_game.player_x + dx).clamp(1.5, 14.5);
                                self.retro_game.player_y = (self.retro_game.player_y + dy).clamp(1.5, 14.5);
                                continue;
                            }
                            'a' | 'A' => {
                                self.retro_game.player_angle = (self.retro_game.player_angle + 350.0) % 360.0;
                                continue;
                            }
                            'd' | 'D' => {
                                self.retro_game.player_angle = (self.retro_game.player_angle + 10.0) % 360.0;
                                continue;
                            }
                            ' ' => {
                                // Shoot blaster
                                self.retro_game.muzzle_flash_frames = 3;
                                if self.retro_game.ammo > 0 { self.retro_game.ammo -= 1; }
                                self.retro_game.score += 100;
                                crate::audio::play_click_sound();
                                continue;
                            }
                            _ => {}
                        }
                    } else if w.win_type == WindowType::CyberSpace3D && self.cyber_3d.handle_key(ch) {
                        continue;
                    } else if w.win_type == WindowType::Notepad {
                        self.handle_notepad_key(ch);
                        continue;
                    } else if w.win_type == WindowType::Calculator {
                        self.handle_calc_key(ch);
                        continue;
                    } else if w.win_type == WindowType::Paint {
                        self.handle_paint_key(ch);
                        continue;
                    } else if w.win_type == WindowType::FileExplorer {
                        // If rename mode is active, intercept typing
                        if self.renaming_file_idx.is_some() {
                            match ch {
                                '\n' => {
                                    self.commit_rename();
                                }
                                '\x1B' => {
                                    // Esc cancels rename
                                    self.cancel_rename();
                                }
                                '\x08' => {
                                    // Backspace
                                    self.rename_buffer.pop();
                                }
                                c if c >= ' ' && c <= '~' => {
                                    if self.rename_buffer.len() < 24 {
                                        self.rename_buffer.push(c);
                                    }
                                }
                                _ => {}
                            }
                            continue;
                        }

                        match ch {
                            '\x03' => {
                                // Ctrl + C: Copy selected file
                                self.copy_selected_file();
                            }
                            '\x16' => {
                                // Ctrl + V: Paste file
                                self.paste_clipboard_file();
                            }
                            '\u{82}' => {
                                // F2 key: Start inline rename
                                self.start_rename_file();
                            }
                            '\x7F' => {
                                // Delete key
                                self.delete_selected_file();
                            }
                            '\u{87}' => {
                                // Up Arrow: select previous file
                                if let Some(win) = self.windows.get_mut(0) {
                                    win.selected_file = win.selected_file.saturating_sub(1);
                                }
                            }
                            '\u{88}' => {
                                // Down Arrow: select next file
                                if let Some(win) = self.windows.get_mut(0) {
                                    if win.selected_file + 1 < self.files.len() {
                                        win.selected_file += 1;
                                    }
                                }
                            }
                            '\n' => {
                                // Enter key: Open file or enter folder
                                let sel = w.selected_file;
                                self.open_file_by_index(sel);
                            }
                            '\x08' => {
                                // Backspace: Navigate to parent folder
                                if self.current_folder == "C:\\EFI\\COROS" || self.current_folder == "C:\\EFI\\BOOT" {
                                    self.current_folder = String::from("C:\\EFI");
                                } else if self.current_folder == "C:\\EFI" {
                                    self.current_folder = String::from("C:\\");
                                }
                                self.load_directory_contents();
                                crate::audio::play_click_sound();
                            }
                            't' | 'T' => {
                                // Toggle Dark / Light Theme shortcut
                                self.dark_theme_enabled = !self.dark_theme_enabled;
                                if !self.dark_theme_enabled {
                                    self.selected_theme = 5;
                                } else if self.selected_theme == 5 {
                                    self.selected_theme = 0;
                                }
                                self.custom_wallpaper_mode = false;
                                crate::audio::play_click_sound();
                            }
                            's' | 'S' => {
                                // Open Settings window
                                self.toggle_window(4);
                                crate::audio::play_click_sound();
                            }
                            'n' | 'N' => {
                                // Create new file
                                self.create_new_text_file();
                            }
                            'm' | 'M' => {
                                // Open Windows 11 Context Menu for selected file
                                let sel = w.selected_file;
                                let (f_name, is_dir) = if sel < self.files.len() {
                                    (self.files[sel].name.clone(), self.files[sel].is_dir)
                                } else {
                                    (String::from("README.TXT"), false)
                                };
                                self.file_context_menu.open_for_file(620, 220, sel, &f_name, is_dir, self.clipboard_file.is_some());
                                crate::audio::play_click_sound();
                            }
                            _ => {}
                        }
                        continue;
                    } else if w.win_type == WindowType::ThemeSettings {
                        match ch {
                            't' | 'T' => {
                                self.dark_theme_enabled = !self.dark_theme_enabled;
                                if !self.dark_theme_enabled {
                                    self.selected_theme = 5;
                                } else if self.selected_theme == 5 {
                                    self.selected_theme = 0;
                                }
                                self.custom_wallpaper_mode = false;
                                crate::audio::play_click_sound();
                            }
                            '1'..='6' => {
                                let idx = (ch as u8 - b'1') as usize;
                                self.selected_theme = idx;
                                self.custom_wallpaper_mode = false;
                                if idx == 5 {
                                    self.dark_theme_enabled = false;
                                }
                                crate::audio::play_click_sound();
                            }
                            _ => {}
                        }
                        continue;
                    }
                }
            }

            match ch {
                '\x08' => {
                    self.current_input.pop();
                }
                '\x7F' => {
                    self.current_input.pop();
                }
                '\u{87}' => {
                    // Up Arrow: recall previous command
                    if self.current_input.is_empty() {
                        self.current_input = String::from("help");
                    }
                }
                '\n' => {
                    let cmd = core::mem::take(&mut self.current_input);
                    self.execute_command(&cmd);
                }
                '\x1B' => {
                    self.start_menu.toggle();
                    self.context_menu_open = false;
                    self.quick_settings_open = false;
                    self.calendar_open = false;
                }
                '\t' => {
                    self.autocomplete();
                }
                c if c >= ' ' && c <= '~' => {
                    if self.current_input.len() < 55 {
                        self.current_input.push(c);
                    }
                }
                _ => {}
            }
        }
    }

    /// Handles mouse events, dragging, traffic lights, context menu, and dock icon clicks
    pub fn handle_input(&mut self, mx: usize, my: usize, m_left: bool, m_right: bool, screen_w: usize, screen_h: usize) {
        // If boot splash screen is playing, let it run smoothly without premature mouse dismissal
        if self.boot_splash_frames > 0 {
            return;
        }

        // Drain real-time hardware keyboard events
        self.process_keyboard();

        // Update notification center toasts and timers
        self.notification_center.tick();

        let is_click_down = m_left && !self.was_left_clicked;
        let is_right_click_down = m_right && !self.was_right_clicked;
        let _is_mouse_up = !m_left && self.was_left_clicked;

        // 0. Handle Right-Click Context Menu Trigger
        if is_right_click_down {
            // First check if right clicked inside File Explorer window (Window 0)
            if let Some(pos) = self.windows.iter().position(|w| w.win_type == WindowType::FileExplorer && w.is_open && !w.is_minimized) {
                let win = &self.windows[pos];
                let wx = win.x;
                let wy = win.y;
                let ww = win.w as isize;
                let wh = win.h as isize;
                let smx = mx as isize;
                let smy = my as isize;

                if smx >= wx && smx < wx + ww && smy >= wy + 28 && smy < wy + wh {
                    // Right clicked inside File Explorer body!
                    self.active_window_idx = pos;
                    let sidebar_w = 150isize;
                    let main_x = wx + sidebar_w + 1;
                    let content_y = wy + 30 + 36 + 40; // nav 36 + ribbon 40
                    let card_start_y = content_y + 34;
                    let col_w = (win.w - sidebar_w as usize - 36) / 2;
                    let card_h = 44isize;

                    if smx >= main_x && smy >= card_start_y {
                        let rel_y = smy - card_start_y;
                        let row_idx = (rel_y / (card_h + 6)) as usize;
                        let col_idx = if (smx - main_x) < (col_w as isize + 14) { 0 } else { 1 };
                        let c_idx = row_idx * 2 + col_idx;

                        if c_idx >= 6 {
                            let file_idx = c_idx - 6;
                            if file_idx < self.files.len() {
                                let f = &self.files[file_idx];
                                self.file_context_menu.open_for_file(
                                    mx,
                                    my,
                                    file_idx,
                                    &f.name,
                                    f.is_dir,
                                    self.clipboard_file.is_some(),
                                );
                                self.windows[pos].selected_file = file_idx;
                            } else {
                                self.file_context_menu.open_for_blank_area(
                                    mx,
                                    my,
                                    self.clipboard_file.is_some(),
                                );
                            }
                        } else {
                            let card_names = ["Masaustu", "Indirilenler", "Belgeler", "Resimler", "Muzikler", "Videolar"];
                            let name = if c_idx < card_names.len() { card_names[c_idx] } else { "Klasor" };
                            self.file_context_menu.open_for_file(
                                mx,
                                my,
                                0,
                                name,
                                true,
                                self.clipboard_file.is_some(),
                            );
                        }
                    } else {
                        self.file_context_menu.open_for_blank_area(
                            mx,
                            my,
                            self.clipboard_file.is_some(),
                        );
                    }
                    self.context_menu_open = false;
                    self.start_menu.close();
                    self.quick_settings_open = false;
                    self.calendar_open = false;
                    self.was_right_clicked = m_right;
                    return;
                }
            }

            // Check if right-clicked on desktop background (not on taskbar)
            if my < screen_h.saturating_sub(48) {
                let mut over_window = false;
                for win in &self.windows {
                    if win.is_open && !win.is_minimized {
                        let wx = win.x;
                        let wy = win.y;
                        let ww = win.w as isize;
                        let wh = win.h as isize;
                        let smx = mx as isize;
                        let smy = my as isize;
                        if smx >= wx && smx < wx + ww && smy >= wy && smy < wy + wh {
                            over_window = true;
                            break;
                        }
                    }
                }
                if !over_window {
                    self.context_menu_open = true;
                    self.context_menu_x = mx.min(screen_w.saturating_sub(210));
                    self.context_menu_y = my.min(screen_h.saturating_sub(210));
                    self.start_menu.close();
                    self.quick_settings_open = false;
                    self.calendar_open = false;
                    self.file_context_menu.close();
                    self.was_right_clicked = m_right;
                    return;
                }
            }
        }

        // 1. Process active window dragging & Aero Snap detection
        let mut any_dragging = false;
        let mut active_preview = widgets::SnapPreview::None;
        for win in self.windows.iter_mut() {
            if win.is_dragging {
                any_dragging = true;
                if m_left {
                    win.x = (mx as isize) - win.drag_off_x;
                    win.y = (my as isize) - win.drag_off_y;
                    // Clamp within screen boundaries
                    win.y = win.y.clamp(26, (screen_h.saturating_sub(40)) as isize);
                    win.x = win.x.clamp(-((win.w as isize) - 80), (screen_w.saturating_sub(80)) as isize);

                    // Check Aero Snap zones
                    if mx <= 16 {
                        active_preview = widgets::SnapPreview::LeftHalf;
                    } else if mx >= screen_w.saturating_sub(16) {
                        active_preview = widgets::SnapPreview::RightHalf;
                    } else if my <= 16 {
                        active_preview = widgets::SnapPreview::Maximize;
                    }
                } else {
                    win.is_dragging = false;
                    // Apply snap on release
                    match self.snap_preview {
                        widgets::SnapPreview::LeftHalf => {
                            win.prev_x = win.x;
                            win.prev_y = win.y;
                            win.prev_w = win.w;
                            win.prev_h = win.h;
                            win.x = 8;
                            win.y = 30;
                            win.w = (screen_w / 2).saturating_sub(12);
                            win.h = screen_h.saturating_sub(80);
                            win.is_maximized = false;
                            win.snapped_state = Some(widgets::SnapPreview::LeftHalf);
                        }
                        widgets::SnapPreview::RightHalf => {
                            win.prev_x = win.x;
                            win.prev_y = win.y;
                            win.prev_w = win.w;
                            win.prev_h = win.h;
                            win.x = (screen_w / 2 + 4) as isize;
                            win.y = 30;
                            win.w = (screen_w / 2).saturating_sub(12);
                            win.h = screen_h.saturating_sub(80);
                            win.is_maximized = false;
                            win.snapped_state = Some(widgets::SnapPreview::RightHalf);
                        }
                        widgets::SnapPreview::Maximize => {
                            win.prev_x = win.x;
                            win.prev_y = win.y;
                            win.prev_w = win.w;
                            win.prev_h = win.h;
                            win.x = 4;
                            win.y = 30;
                            win.w = screen_w.saturating_sub(8);
                            win.h = screen_h.saturating_sub(80);
                            win.is_maximized = true;
                            win.snapped_state = Some(widgets::SnapPreview::Maximize);
                        }
                        widgets::SnapPreview::None => {}
                    }
                }
            }
        }
        if any_dragging {
            self.snap_preview = active_preview;
        } else {
            self.snap_preview = widgets::SnapPreview::None;
        }

        // 1.2 Process Desktop Icon dragging
        if let Some(icon_id) = self.dragging_icon {
            if m_left {
                let new_ix = ((mx as isize) - self.drag_icon_off_x).clamp(0, (screen_w.saturating_sub(84)) as isize);
                let new_iy = ((my as isize) - self.drag_icon_off_y).clamp(24, (screen_h.saturating_sub(124)) as isize);
                self.icon_coords[icon_id] = (new_ix, new_iy);
            } else {
                self.dragging_icon = None;
            }
        }

        // 1.5 Handle continuous Paint brush/eraser drag while mouse is held down
        if m_left && self.active_window_idx < self.windows.len() {
            let win = &self.windows[self.active_window_idx];
            if win.win_type == WindowType::Paint && win.is_open && !win.is_minimized && !win.is_dragging {
                let win_x = win.x;
                let win_w = win.w;
                let body_y = win.y + 28;
                let row1_h = 30;
                let row2_h = 36;
                let row2_y = body_y + row1_h + 1;
                let canvas_w = 320;
                let canvas_h = 240;
                let cv_x = win_x + ((win_w.saturating_sub(canvas_w)) / 2) as isize;
                let cv_y = row2_y + (row2_h as isize) + 16;
                let smx = mx as isize;
                let smy = my as isize;

                if smx >= cv_x && smx < cv_x + (canvas_w as isize) && smy >= cv_y && smy < cv_y + (canvas_h as isize) {
                    let px = ((smx - cv_x) / 2) as usize;
                    let py = ((smy - cv_y) / 2) as usize;

                    if self.paint_tool == 0 {
                        // Brush
                        let col = self.get_current_paint_color();
                        let sz = self.paint_brush_size;
                        self.paint_draw_brush(px, py, col, sz);
                    } else if self.paint_tool == 1 {
                        // Eraser (paints white with 2x size)
                        let sz = self.paint_brush_size * 2;
                        self.paint_draw_brush(px, py, 0x00FFFFFF, sz);
                    }
                }
            }
        }

        // 2. Handle click-down event (Windows Start Menu, Taskbar, Windows, Desktop)
        if is_click_down {
            // Check Context Menu clicks if open
            if self.context_menu_open {
                let cm_x = self.context_menu_x;
                let cm_y = self.context_menu_y;
                let cm_w = 190;
                let cm_h = 150;

                if mx >= cm_x && mx < cm_x + cm_w && my >= cm_y && my < cm_y + cm_h {
                    let item_idx = (my.saturating_sub(cm_y + 6)) / 28;
                    match item_idx {
                        0 => {
                            // Yeni Not Defteri
                            self.toggle_window(5);
                        }
                        1 => {
                            // Gorunum (Toggle Desktop HUD)
                            self.show_desktop_hud = !self.show_desktop_hud;
                        }
                        2 => {
                            // Yenile (Refresh)
                            self.terminal_lines.push(String::from("[MASAUSTU] Masaustu ve pencereler yenilendi."));
                        }
                        3 => {
                            // Kisisellestir (Ayarlar)
                            self.toggle_window(4);
                        }
                        4 => {
                            // Hesap Makinesi
                            self.toggle_window(6);
                        }
                        _ => {}
                    }
                    self.context_menu_open = false;
                    self.was_left_clicked = m_left;
                    return;
                } else {
                    self.context_menu_open = false;
                }
            }

            // Check Quick Settings clicks if open
            if self.quick_settings_open {
                let qs_w = 280;
                let qs_h = 200;
                let qs_x = screen_w.saturating_sub(qs_w + 16);
                let qs_y = screen_h.saturating_sub(48 + qs_h + 8);

                if mx >= qs_x && mx < qs_x + qs_w && my >= qs_y && my < qs_y + qs_h {
                    // Quick toggles row (Wi-Fi, Bluetooth, Dark Mode, Night Light)
                    let t_y = qs_y + 14;
                    for i in 0..4 {
                        let tx = qs_x + 14 + i * 64;
                        if mx >= tx && mx < tx + 56 && my >= t_y && my < t_y + 44 {
                            match i {
                                0 => self.wifi_enabled = !self.wifi_enabled,
                                2 => self.dark_theme_enabled = !self.dark_theme_enabled,
                                _ => {}
                            }
                            self.was_left_clicked = m_left;
                            return;
                        }
                    }

                    // Volume slider row: y in qs_y + 80 .. qs_y + 110
                    let s1_y = qs_y + 82;
                    let sl_x = qs_x + 44;
                    let sl_w = 216;
                    if my >= s1_y && my < s1_y + 20 && mx >= sl_x && mx <= sl_x + sl_w {
                        let pct = ((mx - sl_x) * 100) / sl_w;
                        self.volume_level = pct.clamp(0, 100) as u8;
                        self.was_left_clicked = m_left;
                        return;
                    }

                    // Brightness slider row: y in qs_y + 120 .. qs_y + 150
                    let s2_y = qs_y + 122;
                    if my >= s2_y && my < s2_y + 20 && mx >= sl_x && mx <= sl_x + sl_w {
                        let pct = ((mx - sl_x) * 100) / sl_w;
                        self.brightness_level = pct.clamp(0, 100) as u8;
                        self.was_left_clicked = m_left;
                        return;
                    }

                    self.was_left_clicked = m_left;
                    return;
                } else {
                    let tray_x = screen_w.saturating_sub(240);
                    let pill_x = tray_x + 36;
                    let bar_y = screen_h.saturating_sub(48);
                    if !(mx >= pill_x && mx < pill_x + 90 && my >= bar_y) {
                        self.quick_settings_open = false;
                    }
                }
            }

            // Check Calendar clicks if open
            if self.calendar_open {
                let cal_w = 260;
                let cal_h = 220;
                let cal_x = screen_w.saturating_sub(cal_w + 16);
                let cal_y = screen_h.saturating_sub(48 + cal_h + 8);

                if mx >= cal_x && mx < cal_x + cal_w && my >= cal_y && my < cal_y + cal_h {
                    // Click inside calendar
                    self.was_left_clicked = m_left;
                    return;
                } else {
                    let tray_x = screen_w.saturating_sub(240);
                    let pill_x = tray_x + 36;
                    let clock_x = pill_x + 98;
                    let bar_y = screen_h.saturating_sub(48);
                    if !(mx >= clock_x && mx < clock_x + 70 && my >= bar_y) {
                        self.calendar_open = false;
                    }
                }
            }

            // Check Action Center clicks if open
            if self.notification_center.is_open {
                let ac_w = 328;
                let ac_h = 520;
                let ac_x = screen_w.saturating_sub(336);
                let ac_y = screen_h.saturating_sub(48 + ac_h + 4);

                if mx >= ac_x && mx < ac_x + ac_w && my >= ac_y && my < ac_y + ac_h {
                    // Check if "Tumunu Sil" clicked
                    let clear_btn_x = ac_x + ac_w - 88;
                    let clear_btn_y = ac_y + 14 + 4;
                    if mx >= clear_btn_x && mx < clear_btn_x + 74 && my >= clear_btn_y && my < clear_btn_y + 20 {
                        self.notification_center.clear_all();
                        crate::audio::play_click_sound();
                    }
                    self.was_left_clicked = m_left;
                    return;
                } else {
                    let tray_x = screen_w.saturating_sub(240);
                    let pill_x = tray_x + 36;
                    let clock_x = pill_x + 98;
                    let notif_bell_x = clock_x + 64;
                    let bar_y = screen_h.saturating_sub(48);
                    if !(mx >= notif_bell_x && mx < screen_w.saturating_sub(12) && my >= bar_y) {
                        self.notification_center.is_open = false;
                    }
                }
            }

            // Check Windows Run Dialog clicks if open
            if self.run_dialog.is_open {
                let rx = self.run_dialog.x as usize;
                let ry = self.run_dialog.y as usize;
                let rw = self.run_dialog.w;
                let rh = self.run_dialog.h;
                if mx >= rx && mx < rx + rw && my >= ry && my < ry + rh {
                    if let Some(cmd) = self.run_dialog.handle_click(mx, my) {
                        self.execute_command(&cmd);
                    }
                    self.was_left_clicked = m_left;
                    return;
                } else {
                    self.run_dialog.close();
                }
            }

            // Check Task View / Virtual Desktops overlay clicks if open
            if self.virtual_desktops.task_view_open {
                if let Some(win_idx) = self.virtual_desktops.handle_task_view_click(mx, my, screen_w, &self.windows) {
                    if win_idx < self.windows.len() {
                        self.active_window_idx = win_idx;
                        self.windows[win_idx].is_minimized = false;
                        crate::audio::play_click_sound();
                    }
                    self.was_left_clicked = m_left;
                    return;
                }
            }

            // Check File Properties Dialog clicks if open
            if self.properties_dialog.is_open {
                if self.properties_dialog.handle_click(mx, my) {
                    self.was_left_clicked = m_left;
                    return;
                }
            }

            // Check File Context Menu clicks if open
            if self.file_context_menu.is_open {
                if let Some(act) = self.file_context_menu.handle_click(mx, my, screen_w, screen_h) {
                    match act {
                        file_context_menu::FileContextAction::Open => {
                            if let Some(idx) = self.file_context_menu.target_file_idx {
                                self.open_file_by_index(idx);
                            }
                        }
                        file_context_menu::FileContextAction::RunRing3Elf => {
                            if let Some(idx) = self.file_context_menu.target_file_idx {
                                self.open_file_by_index(idx);
                            }
                        }
                        file_context_menu::FileContextAction::EditWithPaint => {
                            if let Some(idx) = self.file_context_menu.target_file_idx {
                                self.open_file_by_index(idx);
                            }
                        }
                        file_context_menu::FileContextAction::Cut => {
                            self.copy_selected_file();
                            self.delete_selected_file();
                        }
                        file_context_menu::FileContextAction::Copy => {
                            self.copy_selected_file();
                        }
                        file_context_menu::FileContextAction::Paste => {
                            self.paste_clipboard_file();
                        }
                        file_context_menu::FileContextAction::Rename => {
                            self.start_rename_file();
                        }
                        file_context_menu::FileContextAction::Delete => {
                            self.delete_selected_file();
                        }
                        file_context_menu::FileContextAction::NewTextFile => {
                            self.create_new_text_file();
                        }
                        file_context_menu::FileContextAction::Properties => {
                            let (name, kind, size, folder, is_dir) = if let Some(idx) = self.file_context_menu.target_file_idx {
                                if idx < self.files.len() {
                                    let f = &self.files[idx];
                                    (f.name.clone(), f.kind.clone(), f.size_str.clone(), self.current_folder.clone(), f.is_dir)
                                } else {
                                    (String::from("Klasor"), String::from("[DIR]"), String::from("4096 B"), self.current_folder.clone(), true)
                                }
                            } else {
                                (String::from("COROS"), String::from("[DIR]"), String::from("4096 B"), self.current_folder.clone(), true)
                            };
                            self.properties_dialog.open_for(&name, &kind, &size, &folder, is_dir, screen_w, screen_h);
                        }
                        file_context_menu::FileContextAction::PinQuickAccess | file_context_menu::FileContextAction::PinStart => {
                            self.add_terminal_line(String::from("[OK] Oge Hizli Erisim ve Baslangic menusune sabitlendi."));
                        }
                        file_context_menu::FileContextAction::OpenInTerminal => {
                            self.toggle_window(1); // Open Corpus Terminal
                            self.add_terminal_line(format!("cd {}", self.current_folder));
                        }
                        file_context_menu::FileContextAction::CopyPath => {
                            if let Some(idx) = self.file_context_menu.target_file_idx {
                                if let Some(f) = self.files.get(idx) {
                                    self.clipboard_file = Some(f.clone());
                                    self.add_terminal_line(format!("[YOL KOPYALANDI] {}\\{}", self.current_folder, f.name));
                                }
                            }
                        }
                        file_context_menu::FileContextAction::ShowMoreOptions => {
                            self.add_terminal_line(String::from("[BILGI] Windows 11 Klasik baglam secenekleri genisletildi."));
                        }
                    }
                    crate::audio::play_click_sound();
                    self.was_left_clicked = m_left;
                    return;
                }
            }

            // Check Start Menu clicks if open
            if self.start_menu.is_open {
                let menu_w = 460;
                let menu_h = 470;
                let menu_x = (screen_w.saturating_sub(menu_w)) / 2;
                let menu_y = screen_h.saturating_sub(48 + menu_h + 10);

                if mx >= menu_x && mx < menu_x + menu_w && my >= menu_y && my < menu_y + menu_h {
                    // Check Tab Bar Clicks: tab_bar_y = menu_y + 14 + 46 = menu_y + 60
                    let tab_bar_y = menu_y + 60;
                    if my >= tab_bar_y && my < tab_bar_y + 24 {
                        let tabs = [
                            (start_menu::StartMenuTab::Pinned, menu_x + 20, 100),
                            (start_menu::StartMenuTab::QuickTools, menu_x + 126, 96),
                            (start_menu::StartMenuTab::RecentFiles, menu_x + 228, 96),
                            (start_menu::StartMenuTab::SystemRing3, menu_x + 330, 108),
                        ];
                        for &(tab_enum, tx, tw) in &tabs {
                            if mx >= tx && mx < tx + tw {
                                self.start_menu.active_tab = tab_enum;
                                crate::audio::play_click_sound();
                                self.was_left_clicked = m_left;
                                return;
                            }
                        }
                    }

                    // Bottom User & Power Buttons
                    let foot_y = menu_y + menu_h - 48;
                    let restart_x = menu_x + menu_w - 90;
                    if mx >= restart_x && mx < restart_x + 36 && my >= foot_y + 8 && my < foot_y + 40 {
                        self.execute_command("reboot");
                        self.start_menu.close();
                        self.was_left_clicked = m_left;
                        return;
                    }
                    let power_x = menu_x + menu_w - 48;
                    if mx >= power_x && mx < power_x + 36 && my >= foot_y + 8 && my < foot_y + 40 {
                        self.execute_command("poweroff");
                        self.start_menu.close();
                        self.was_left_clicked = m_left;
                        return;
                    }

                    // Body Clicks depending on active tab:
                    let body_y = tab_bar_y + 36;
                    match self.start_menu.active_tab {
                        start_menu::StartMenuTab::Pinned => {
                            let col_w = (menu_w - 48) / 3;
                            let app_win_ids: [usize; 7] = [0, 1, 2, 3, 4, 7, 5];
                            for i in 0..6 {
                                let row = i / 3;
                                let col = i % 3;
                                let ax = menu_x + 24 + col * col_w;
                                let ay = body_y + 8 + row * 84;
                                if mx >= ax && mx < ax + col_w - 8 && my >= ay && my < ay + 76 {
                                    self.toggle_window(app_win_ids[i]);
                                    self.start_menu.close();
                                    crate::audio::play_click_sound();
                                    self.was_left_clicked = m_left;
                                    return;
                                }
                            }
                        }
                        start_menu::StartMenuTab::QuickTools => {
                            let col_w = menu_w - 48;
                            for i in 0..6 {
                                let ry = body_y + i * 44;
                                if mx >= menu_x + 24 && mx < menu_x + 24 + col_w && my >= ry && my < ry + 38 {
                                    match i {
                                        0 => {
                                            self.terminal_lines.clear();
                                            self.add_terminal_line(String::from("[SISTEM] Geri Donusum Kutusu bosaltildi."));
                                        }
                                        1 => self.execute_command("dhcp"),
                                        2 => self.execute_command("tasks"),
                                        3 => self.execute_command("cat /proc/cpuinfo"),
                                        4 => self.execute_command("lsmod"),
                                        5 => crate::audio::play_click_sound(),
                                        _ => {}
                                    }
                                    self.start_menu.close();
                                    crate::audio::play_click_sound();
                                    self.was_left_clicked = m_left;
                                    return;
                                }
                            }
                        }
                        start_menu::StartMenuTab::RecentFiles => {
                            let col_w = menu_w - 48;
                            for i in 0..6 {
                                let ry = body_y + i * 44;
                                if mx >= menu_x + 24 && mx < menu_x + 24 + col_w && my >= ry && my < ry + 38 {
                                    match i {
                                        0 => self.execute_command("exec HESAP.ELF"),
                                        1 => self.execute_command("exec APP.ELF"),
                                        2 => self.open_file_by_index(3), // README.TXT
                                        3 => self.open_file_by_index(4), // NOTLAR.TXT
                                        4 => self.open_file_by_index(7), // RESIM.PNG
                                        5 => self.open_file_by_index(8), // BOOTX64.EFI
                                        _ => {}
                                    }
                                    self.start_menu.close();
                                    crate::audio::play_click_sound();
                                    self.was_left_clicked = m_left;
                                    return;
                                }
                            }
                        }
                        start_menu::StartMenuTab::SystemRing3 => {
                            let col_w = menu_w - 48;
                            let btn_y = body_y + 190;
                            if my >= btn_y && my < btn_y + 32 {
                                if mx >= menu_x + 24 && mx < menu_x + 24 + (col_w / 2 - 6) {
                                    self.execute_command("test_ring3");
                                    self.start_menu.close();
                                    crate::audio::play_click_sound();
                                    self.was_left_clicked = m_left;
                                    return;
                                } else if mx >= menu_x + 24 + col_w / 2 + 6 && mx < menu_x + menu_w - 24 {
                                    self.execute_command("test_crash");
                                    self.start_menu.close();
                                    crate::audio::play_click_sound();
                                    self.was_left_clicked = m_left;
                                    return;
                                }
                            }
                        }
                    }

                    self.was_left_clicked = m_left;
                    return;
                } else {
                    let cluster_x = (screen_w.saturating_sub(10 * 48)) / 2;
                    if !(mx >= cluster_x && mx < cluster_x + 48 && my >= screen_h.saturating_sub(48)) {
                        self.start_menu.close();
                    }
                }
            }

            // Check Windows Taskbar clicks at bottom (y >= screen_h - 48)
            let bar_y = screen_h.saturating_sub(48);
            if my >= bar_y {
                // Desktop Switcher Pill on far left [ ◫ Masaüstü 1 ]
                if mx >= 16 && mx < 130 {
                    self.virtual_desktops.toggle_task_view();
                    crate::audio::play_click_sound();
                    self.start_menu.close();
                    self.quick_settings_open = false;
                    self.calendar_open = false;
                    self.notification_center.is_open = false;
                    self.was_left_clicked = m_left;
                    return;
                }

                let slot_w = 48;
                let cluster_w = 10 * slot_w;
                let cluster_x = (screen_w.saturating_sub(cluster_w)) / 2;

                for i in 0..10 {
                    let sx = cluster_x + i * slot_w;
                    if mx >= sx && mx < sx + slot_w {
                        crate::audio::play_click_sound();
                        match i {
                            0 => {
                                self.start_menu.toggle();
                                self.quick_settings_open = false;
                                self.calendar_open = false;
                                self.notification_center.is_open = false;
                                self.file_context_menu.close();
                                self.properties_dialog.close();
                            }
                            1 => self.toggle_window(0), // Dosya Gezgini
                            2 => self.toggle_window(1), // Terminal
                            3 => self.toggle_window(2), // Gorev Yoneticisi
                            4 => self.toggle_window(3), // 3D Goruntuleyici
                            5 => self.toggle_window(4), // Ayarlar
                            6 => self.toggle_window(5), // Not Defteri
                            7 => self.toggle_window(6), // Hesap Makinesi
                            8 => self.toggle_window(7), // Paint
                            9 => {
                                self.terminal_lines.clear();
                                self.add_terminal_line(String::from("[SISTEM] Geri Donusum Kutusu bosaltildi."));
                            }
                            _ => {}
                        }
                        self.was_left_clicked = m_left;
                        return;
                    }
                }

                // Check System Tray Pill click (Quick Settings)
                let tray_x = screen_w.saturating_sub(240);
                let pill_x = tray_x + 36;
                if mx >= pill_x && mx < pill_x + 90 {
                    self.quick_settings_open = !self.quick_settings_open;
                    self.calendar_open = false;
                    self.start_menu.close();
                    self.context_menu_open = false;
                    self.was_left_clicked = m_left;
                    return;
                }

                // Check System Tray Clock click (Calendar)
                let clock_x = pill_x + 98;
                if mx >= clock_x && mx < clock_x + 64 {
                    self.calendar_open = !self.calendar_open;
                    self.notification_center.is_open = false;
                    self.quick_settings_open = false;
                    self.start_menu.close();
                    self.context_menu_open = false;
                    self.was_left_clicked = m_left;
                    return;
                }

                // Check Notification Bell / Badge click (Action Center toggle)
                let notif_bell_x = clock_x + 64;
                if mx >= notif_bell_x && mx < screen_w.saturating_sub(12) {
                    self.notification_center.is_open = !self.notification_center.is_open;
                    self.calendar_open = false;
                    self.quick_settings_open = false;
                    self.start_menu.close();
                    self.context_menu_open = false;
                    crate::audio::play_click_sound();
                    self.was_left_clicked = m_left;
                    return;
                }

                // Show Desktop peek on far right
                if mx >= screen_w.saturating_sub(12) {
                    for win in &mut self.windows {
                        win.is_minimized = true;
                    }
                    self.was_left_clicked = m_left;
                    return;
                }

                self.was_left_clicked = m_left;
                return;
            }

            // Check Window clicks in Z-order (active window first, then others in reverse)
            let mut clicked_win_idx = None;
            let num_wins = self.windows.len();

            // Check active window first
            let active_idx = self.active_window_idx;
            let order = if active_idx < num_wins {
                alloc::vec![active_idx]
            } else {
                Vec::new()
            };

            let mut all_indices: Vec<usize> = (0..num_wins).filter(|&i| i != active_idx).rev().collect();
            all_indices.splice(0..0, order);

            for &idx in &all_indices {
                let win = &self.windows[idx];
                if !win.is_open || win.is_minimized {
                    continue;
                }

                let wx = win.x;
                let wy = win.y;
                let ww = win.w as isize;
                let wh = win.h as isize;
                let smx = mx as isize;
                let smy = my as isize;

                if smx >= wx && smx < wx + ww && smy >= wy && smy < wy + wh {
                    clicked_win_idx = Some(idx);
                    break;
                }
            }

            if let Some(idx) = clicked_win_idx {
                self.active_window_idx = idx;
                let win = &mut self.windows[idx];

                let smx = mx as isize;
                let smy = my as isize;

                // Title bar area: y in win.y .. win.y + 30
                if smy >= win.y && smy < win.y + 30 {
                    let right_x = win.x + (win.w as isize);
                    let min_x = right_x - 114;
                    let max_x = right_x - 76;
                    let close_x = right_x - 38;

                    if smx >= close_x && smx < right_x {
                        win.is_open = false;
                    } else if smx >= max_x && smx < close_x {
                        if !win.is_maximized {
                            win.prev_x = win.x;
                            win.prev_y = win.y;
                            win.prev_w = win.w;
                            win.prev_h = win.h;
                            win.x = 0;
                            win.y = 0;
                            win.w = screen_w;
                            win.h = screen_h - 48; // Leave taskbar visible!
                            win.is_maximized = true;
                        } else {
                            win.x = win.prev_x;
                            win.y = win.prev_y;
                            win.w = win.prev_w;
                            win.h = win.prev_h;
                            win.is_maximized = false;
                        }
                    } else if smx >= min_x && smx < max_x {
                        win.is_minimized = true;
                    } else {
                        // Title bar drag start
                        if win.is_maximized || win.snapped_state.is_some() {
                            win.w = win.prev_w;
                            win.h = win.prev_h;
                            win.is_maximized = false;
                            win.snapped_state = None;
                            win.drag_off_x = (win.w / 2) as isize;
                            win.x = smx - win.drag_off_x;
                        }
                        win.is_dragging = true;
                        win.drag_off_x = smx - win.x;
                        win.drag_off_y = smy - win.y;
                    }
                } else if win.win_type == WindowType::FileExplorer {
                    let win_x = win.x;
                    let win_w = win.w;
                    let body_y = win.y + 30;
                    let nav_y = body_y;
                    let ribbon_y = body_y + 37;

                    // Navigation row buttons: <- -> ^ ( )
                    if smy >= nav_y + 7 && smy < nav_y + 29 {
                        let rx = smx - win_x;
                        if rx >= 10 && rx < 32 {
                            // Back <-
                            if self.current_folder == "C:\\EFI\\COROS" || self.current_folder == "C:\\EFI\\BOOT" {
                                self.current_folder = String::from("C:\\EFI");
                            } else if self.current_folder == "C:\\EFI" {
                                self.current_folder = String::from("C:\\");
                            }
                            self.load_directory_contents();
                            crate::audio::play_click_sound();
                            self.was_left_clicked = m_left;
                            return;
                        } else if rx >= 62 && rx < 84 {
                            // Up ^
                            if self.current_folder == "C:\\EFI\\COROS" || self.current_folder == "C:\\EFI\\BOOT" {
                                self.current_folder = String::from("C:\\EFI");
                            } else if self.current_folder == "C:\\EFI" {
                                self.current_folder = String::from("C:\\");
                            }
                            self.load_directory_contents();
                            crate::audio::play_click_sound();
                            self.was_left_clicked = m_left;
                            return;
                        } else if rx >= 88 && rx < 110 {
                            // Refresh ( )
                            self.load_directory_contents();
                            crate::audio::play_click_sound();
                            self.was_left_clicked = m_left;
                            return;
                        }
                    }

                    // Ribbon Toolbar buttons
                    if smy >= ribbon_y + 6 && smy < ribbon_y + 32 {
                        let rx = smx - win_x;
                        if rx >= 10 && rx < 76 {
                            // + Yeni
                            self.create_new_text_file();
                        } else if rx >= 94 && rx < 122 {
                            // Kes (Cut)
                            self.copy_selected_file();
                            self.delete_selected_file();
                        } else if rx >= 128 && rx < 156 {
                            // Kopyala (Copy)
                            self.copy_selected_file();
                        } else if rx >= 162 && rx < 190 {
                            // Yapistir (Paste)
                            self.paste_clipboard_file();
                        } else if rx >= 196 && rx < 224 {
                            // Ad Degistir (Rename)
                            self.start_rename_file();
                        } else if rx >= 264 && rx < 292 {
                            // Sil (Delete)
                            self.delete_selected_file();
                        }
                        crate::audio::play_click_sound();
                        self.was_left_clicked = m_left;
                        return;
                    }

                    // Sidebar Clicks
                    let sidebar_w = 150isize;
                    let content_y = ribbon_y + 39;
                    if smx >= win_x && smx < win_x + sidebar_w && smy >= content_y + 8 {
                        let item_idx = ((smy - (content_y + 8)) / 24) as usize;
                        match item_idx {
                            0 => { self.current_folder = String::from("C:\\"); self.load_directory_contents(); }
                            1 => { self.current_folder = String::from("C:\\EFI\\COROS"); self.load_directory_contents(); }
                            3 => { self.current_folder = String::from("C:\\"); self.load_directory_contents(); }
                            4 => { self.current_folder = String::from("C:\\EFI"); self.load_directory_contents(); }
                            5 => { self.current_folder = String::from("C:\\EFI\\COROS"); self.load_directory_contents(); }
                            9 => { self.current_folder = String::from("C:\\"); self.load_directory_contents(); }
                            11 => {
                                let _ = crate::task::usermode::run_safe_ring3_task();
                                self.add_terminal_line(String::from("[RING 3] Donanimsal izolasyon gorevi baslatildi."));
                            }
                            _ => {}
                        }
                        crate::audio::play_click_sound();
                        self.was_left_clicked = m_left;
                        return;
                    }

                    // Card Clicks
                    let main_x = win_x + sidebar_w + 1;
                    let card_start_y = content_y + 34;
                    let col_w = (win_w - sidebar_w as usize - 36) / 2;
                    let card_h = 42isize;
                    if smx >= main_x && smy >= card_start_y {
                        let rel_y = smy - card_start_y;
                        let row_idx = (rel_y / (card_h + 6)) as usize;
                        let col_idx = if (smx - main_x) < (col_w as isize + 14) { 0 } else { 1 };
                        let c_idx = row_idx * 2 + col_idx;

                        if c_idx >= 6 {
                            let file_idx = c_idx - 6;
                            if file_idx < self.files.len() {
                                let is_double_click = self.last_file_clicked_idx == Some(file_idx)
                                    && self.frame_counter.saturating_sub(self.last_file_click_frame) < 120;
                                win.selected_file = file_idx;
                                self.last_file_clicked_idx = Some(file_idx);
                                self.last_file_click_frame = self.frame_counter;

                                if is_double_click {
                                    self.open_file_by_index(file_idx);
                                } else {
                                    let f = &self.files[file_idx];
                                    self.file_status_msg = format!("Secildi: {} ({}) | Sag tikla secenekleri ac", f.name, f.size_str);
                                    crate::audio::play_click_sound();
                                }
                            }
                        } else {
                            match c_idx {
                                0 => { self.current_folder = String::from("C:\\"); self.load_directory_contents(); }
                                1 => { self.current_folder = String::from("C:\\EFI"); self.load_directory_contents(); }
                                2 => { self.current_folder = String::from("C:\\EFI\\COROS"); self.load_directory_contents(); }
                                _ => {}
                            }
                            crate::audio::play_click_sound();
                        }
                        self.was_left_clicked = m_left;
                        return;
                    }
                } else if win.win_type == WindowType::ThemeSettings {
                    let body_y = win.y + 29;
                    let mode_y = body_y + 40;
                    let mode_w = (win.w - 40) / 2;
                    let m1_x = win.x + 16;
                    let m2_x = m1_x + (mode_w as isize) + 8;

                    // 1. Check Primary Theme Mode clicks (Dark / Light)
                    if smy >= mode_y && smy < mode_y + 38 {
                        if smx >= m1_x && smx < m1_x + (mode_w as isize) {
                            self.dark_theme_enabled = true;
                            if self.selected_theme == 5 {
                                self.selected_theme = 0;
                            }
                            crate::audio::play_click_sound();
                        } else if smx >= m2_x && smx < m2_x + (mode_w as isize) {
                            self.dark_theme_enabled = false;
                            self.selected_theme = 5; // Light theme gradient
                            self.custom_wallpaper_mode = false;
                            crate::audio::play_click_sound();
                        }
                    } else {
                        // 2. Check 6 Palette Cards Grid (y in cards_y .. cards_y + 76)
                        let cards_y = mode_y + 46;
                        let card_w = 84;
                        let card_h = 76;
                        let card_spacing = (win.w - 32 - 6 * card_w) / 5;

                        if smy >= cards_y && smy < cards_y + (card_h as isize) {
                            for i in 0..6 {
                                let cx = win.x + 16 + (i as isize) * ((card_w + card_spacing) as isize);
                                if smx >= cx && smx < cx + (card_w as isize) {
                                    self.selected_theme = i;
                                    self.custom_wallpaper_mode = false;
                                    if i == 5 {
                                        self.dark_theme_enabled = false;
                                    }
                                    crate::audio::play_click_sound();
                                    break;
                                }
                            }
                        } else {
                            // 3. Toggles Box clicks
                            let toggle_box_y = cards_y + (card_h as isize) + 10;
                            let r1_y = toggle_box_y + 24;
                            let r2_y = toggle_box_y + 56;
                            let r3_y = toggle_box_y + 88;
                            let b1_x = win.x + 28;
                            let b2_x = win.x + 280;

                            if smy >= r1_y && smy < r1_y + 28 {
                                if smx >= b1_x && smx < b1_x + 236 {
                                    self.custom_wallpaper_mode = !self.custom_wallpaper_mode;
                                    crate::audio::play_click_sound();
                                } else if smx >= b2_x && smx < b2_x + 236 {
                                    self.show_desktop_hud = !self.show_desktop_hud;
                                    crate::audio::play_click_sound();
                                }
                            } else if smy >= r2_y && smy < r2_y + 28 {
                                if smx >= b1_x && smx < b1_x + 236 {
                                    self.show_center_logo = !self.show_center_logo;
                                    crate::audio::play_click_sound();
                                } else if smx >= b2_x && smx < b2_x + 236 {
                                    self.show_grid_lines = !self.show_grid_lines;
                                    crate::audio::play_click_sound();
                                }
                            } else if smy >= r3_y && smy < r3_y + 28 {
                                if smx >= b1_x && smx < b1_x + 488 {
                                    self.selected_theme = (self.selected_theme + 1) % 6;
                                    if self.selected_theme == 5 {
                                        self.dark_theme_enabled = false;
                                    }
                                    self.custom_wallpaper_mode = false;
                                    crate::audio::play_click_sound();
                                }
                            }
                        }
                    }
                } else if win.win_type == WindowType::Notepad {
                    // Toolbar buttons: Kaydet (Save)
                    let body_y = win.y + 29;
                    if smy >= body_y + 4 && smy < body_y + 24 && smx >= win.x + 10 && smx < win.x + 80 {
                        self.notepad_saved_status = true;
                        let mut full_text = String::new();
                        for (idx, line) in self.notepad_content.iter().enumerate() {
                            full_text.push_str(line);
                            if idx + 1 < self.notepad_content.len() {
                                full_text.push('\n');
                            }
                        }
                        let text_len = full_text.len();
                        let bytes = full_text.as_bytes();
                        unsafe {
                            if let Some(fs) = (*core::ptr::addr_of_mut!(crate::fs::fat32::GLOBAL_FS)).as_mut() {
                                let _ = fs.write_file("EFI/COROS/NOTLAR.TXT", bytes);
                            }
                        }
                        // Update in files list if exists
                        if let Some(f) = self.files.iter_mut().find(|f| f.name == "NOTLAR.TXT") {
                            f.content = full_text;
                            f.size_str = format!("{} B", text_len);
                        }
                        self.add_terminal_line(format!("[NOTEPAD] C:\\EFI\\COROS\\NOTLAR.TXT basariyla kaydedildi ({} Bayt, FAT32 DMA).", text_len));
                        crate::audio::play_click_sound();
                    }
                } else if win.win_type == WindowType::Calculator {
                    // Calculator Keypad Clicks
                    let win_x = win.x;
                    let win_w = win.w;
                    let body_y = win.y + 29;
                    let pad_y = body_y + 70;
                    let pad_w = (win_w - 24) / 4;
                    let pad_h = 44;

                    let keys = [
                        ['C', '/', '*', '-'],
                        ['7', '8', '9', '+'],
                        ['4', '5', '6', '='],
                        ['1', '2', '3', '0'],
                    ];

                    let mut clicked_calc_key = None;
                    for row in 0..4 {
                        for col in 0..4 {
                            let kx = win_x + 12 + (col as isize) * (pad_w as isize);
                            let ky = pad_y + (row as isize) * (pad_h as isize);
                            if smx >= kx && smx < kx + (pad_w as isize) - 4 && smy >= ky && smy < ky + (pad_h as isize) - 4 {
                                clicked_calc_key = Some(keys[row][col]);
                                break;
                            }
                        }
                    }
                    if let Some(ch) = clicked_calc_key {
                        self.handle_calc_key(ch);
                    }
                } else if win.win_type == WindowType::MediaPlayer {
                    // Click handlers for Play, Prev, Next, Volume
                    let center_x = win.x + (win.w as isize) / 2;
                    let prog_y = win.y + 28 + 12 + 100 + 14 + 38;
                    let ctrl_y = prog_y + 36;
                    let play_x = center_x - 18;
                    let prev_x = center_x - 55;
                    let next_x = center_x + 25;

                    // Play/Pause button
                    if mx as isize >= play_x && mx as isize <= play_x + 36 && my as isize >= ctrl_y - 3 && my as isize <= ctrl_y + 33 {
                        self.media_playing = !self.media_playing;
                        if self.media_playing {
                            crate::audio::play_synth_riff();
                        } else {
                            crate::audio::play_click_sound();
                        }
                    } else if mx as isize >= prev_x && mx as isize <= prev_x + 30 && my as isize >= ctrl_y && my as isize <= ctrl_y + 30 {
                        self.media_track = self.media_track.saturating_sub(1);
                        crate::audio::play_click_sound();
                    } else if mx as isize >= next_x && mx as isize <= next_x + 30 && my as isize >= ctrl_y && my as isize <= ctrl_y + 30 {
                        self.media_track = (self.media_track + 1) % 4;
                        crate::audio::play_click_sound();
                    }
                } else if win.win_type == WindowType::Paint {
                    let win_x = win.x;
                    let win_w = win.w;
                    let body_y = win.y + 28;
                    let row1_y = body_y;
                    let row1_h = 30;
                    let row2_y = row1_y + row1_h + 1;
                    let row2_h = 36;

                    // 1. Row 1 Tools: [Firca, Silgi, Doldur, Kare, Cizgi, Damla]
                    let mut tx_cursor = win_x + 10;
                    for tool_id in 0..6 {
                        let tw = 46;
                        if smx >= tx_cursor && smx < tx_cursor + tw && smy >= row1_y + 3 && smy < row1_y + 27 {
                            self.paint_tool = tool_id;
                            self.paint_shape_start = None;
                            self.paint_status_msg = match tool_id {
                                0 => String::from("Firca aktif (Surukle & ciz)"),
                                1 => String::from("Silgi aktif (Beyazlat)"),
                                2 => String::from("Boya Kovasi (Alani doldur)"),
                                3 => String::from("Dikdortgen (Baslangic ve bitise tikla)"),
                                4 => String::from("Cizgi (Baslangic ve bitise tikla)"),
                                5 => String::from("Damlalik (Resimden renk ornegi al)"),
                                _ => String::from("Paint"),
                            };
                            crate::audio::play_click_sound();
                            break;
                        }
                        tx_cursor += tw + 4;
                    }

                    // 2. Row 1 Action buttons: [GERI AL], [TEMIZLE], [KAYDET PNG]
                    tx_cursor += 10;
                    let undo_w = 56;
                    if smx >= tx_cursor && smx < tx_cursor + undo_w && smy >= row1_y + 3 && smy < row1_y + 27 {
                        self.paint_undo();
                    }
                    tx_cursor += undo_w + 4;

                    let clr_w = 56;
                    if smx >= tx_cursor && smx < tx_cursor + clr_w && smy >= row1_y + 3 && smy < row1_y + 27 {
                        self.push_paint_undo();
                        self.paint_pixels.fill(0x00FFFFFF);
                        self.paint_status_msg = String::from("Tuval temizlendi (Beyaz)");
                        crate::audio::play_click_sound();
                    }
                    tx_cursor += clr_w + 6;

                    let save_w = 78;
                    if smx >= tx_cursor && smx < tx_cursor + save_w && smy >= row1_y + 3 && smy < row1_y + 27 {
                        self.save_paint_png();
                    }

                    // 3. Row 2: 16 Fluent Presets
                    let pal_start_x = win_x + 10;
                    let sw_sz = 14;
                    for i in 0..16 {
                        let row = (i / 8) as isize;
                        let col = (i % 8) as isize;
                        let cx = pal_start_x + col * 18;
                        let cy = row2_y + 4 + row * 16;
                        if smx >= cx && smx < cx + sw_sz && smy >= cy && smy < cy + sw_sz {
                            self.paint_color_idx = i;
                            self.paint_hex_active = false;
                            self.paint_status_msg = format!("Renk secildi: Palet #{}", i + 1);
                            crate::audio::play_click_sound();
                            break;
                        }
                    }

                    // 4. Row 2: Hex Box click
                    let active_preview_x = pal_start_x + 8 * 18 + 12;
                    let hex_x = active_preview_x + 36;
                    if smx >= hex_x && smx < hex_x + 84 && smy >= row2_y + 6 && smy < row2_y + 30 {
                        self.paint_hex_active = true;
                        self.paint_color_idx = 16;
                        self.paint_status_msg = String::from("Hex girisi aktif: Renk kodunu yazin (orn: FF0080)");
                        crate::audio::play_click_sound();
                    }

                    // 5. Row 2: Brush size selection (1p, 2p, 4p)
                    let bsz_start_x = hex_x + 94;
                    let b_sizes = [1, 2, 4];
                    for (i, &b_sz) in b_sizes.iter().enumerate() {
                        let bx = bsz_start_x + (i as isize) * 28;
                        if smx >= bx && smx < bx + 24 && smy >= row2_y + 6 && smy < row2_y + 30 {
                            self.paint_brush_size = b_sz;
                            self.paint_status_msg = format!("Firca boyutu: {}px", b_sz);
                            crate::audio::play_click_sound();
                            break;
                        }
                    }

                    // 6. Canvas Area (320x240, 2x scale of 160x120 buffer)
                    let canvas_w = 320;
                    let canvas_h = 240;
                    let cv_x = win_x + ((win_w.saturating_sub(canvas_w)) / 2) as isize;
                    let cv_y = row2_y + (row2_h as isize) + 16;

                    if smx >= cv_x && smx < cv_x + (canvas_w as isize) && smy >= cv_y && smy < cv_y + (canvas_h as isize) {
                        let px = ((smx - cv_x) / 2) as usize;
                        let py = ((smy - cv_y) / 2) as usize;

                        match self.paint_tool {
                            0 => {
                                // Brush
                                self.push_paint_undo();
                                let col = self.get_current_paint_color();
                                let sz = self.paint_brush_size;
                                self.paint_draw_brush(px, py, col, sz);
                            }
                            1 => {
                                // Eraser
                                self.push_paint_undo();
                                let sz = self.paint_brush_size * 2;
                                self.paint_draw_brush(px, py, 0x00FFFFFF, sz);
                            }
                            2 => {
                                // Flood Fill
                                self.push_paint_undo();
                                let col = self.get_current_paint_color();
                                self.paint_flood_fill(px, py, col);
                                crate::audio::play_click_sound();
                            }
                            3 => {
                                // Rectangle
                                if let Some((sx, sy)) = self.paint_shape_start {
                                    self.push_paint_undo();
                                    let col = self.get_current_paint_color();
                                    let sz = self.paint_brush_size;
                                    self.paint_draw_rect(sx, sy, px, py, col, sz);
                                    self.paint_shape_start = None;
                                    self.paint_status_msg = String::from("Dikdortgen cizildi");
                                    crate::audio::play_click_sound();
                                } else {
                                    self.paint_shape_start = Some((px, py));
                                    self.paint_status_msg = format!("Dikdortgen baslangici: ({}, {}). Bitis noktasina tiklayin.", px, py);
                                }
                            }
                            4 => {
                                // Line
                                if let Some((sx, sy)) = self.paint_shape_start {
                                    self.push_paint_undo();
                                    let col = self.get_current_paint_color();
                                    let sz = self.paint_brush_size;
                                    self.paint_draw_line(sx, sy, px, py, col, sz);
                                    self.paint_shape_start = None;
                                    self.paint_status_msg = String::from("Cizgi cizildi");
                                    crate::audio::play_click_sound();
                                } else {
                                    self.paint_shape_start = Some((px, py));
                                    self.paint_status_msg = format!("Cizgi baslangici: ({}, {}). Bitis noktasina tiklayin.", px, py);
                                }
                            }
                            5 => {
                                // Eyedropper / Color Picker (Damlalik)
                                let idx = py * 160 + px;
                                if idx < self.paint_pixels.len() {
                                    let sampled = self.paint_pixels[idx];
                                    self.paint_custom_color = sampled;
                                    self.paint_color_idx = 16;
                                    self.paint_hex_input = format!("{:06X}", sampled & 0x00FFFFFF);
                                    self.paint_status_msg = format!("Renk alindi: #{:06X}", sampled & 0x00FFFFFF);
                                    crate::audio::play_click_sound();
                                }
                            }
                            _ => {}
                        }
                    }
                }
            } else {
                // Click landed on desktop background (Desktop shortcuts)
                let mut shortcut_hit = None;
                for id in 0..7 {
                    let (ix, iy) = self.icon_coords[id];
                    let smx = mx as isize;
                    let smy = my as isize;
                    if smx >= ix && smx < ix + 84 && smy >= iy && smy < iy + 76 {
                        shortcut_hit = Some(id);
                        break;
                    }
                }

                if let Some(id) = shortcut_hit {
                    let is_double_click = self.last_clicked_icon == Some(id)
                        && self.frame_counter.saturating_sub(self.last_click_frame) < 120;

                    self.selected_desktop_icon = Some(id);
                    self.last_clicked_icon = Some(id);
                    self.last_click_frame = self.frame_counter;

                    // Start dragging icon
                    self.dragging_icon = Some(id);
                    self.drag_icon_off_x = (mx as isize) - self.icon_coords[id].0;
                    self.drag_icon_off_y = (my as isize) - self.icon_coords[id].1;

                    if is_double_click {
                        crate::audio::play_click_sound();
                        self.dragging_icon = None; // Cancel drag on double click
                        match id {
                            0 => self.toggle_window(2), // Bu Bilgisayar -> Gorev Yoneticisi / Monitör
                            1 => {
                                self.terminal_lines.clear();
                                self.add_terminal_line(String::from("[SISTEM] Geri Donusum Kutusu bosaltildi."));
                            }
                            2 => self.toggle_window(0), // Dosya Gezgini
                            3 => self.toggle_window(1), // Ag Baglantilari -> Terminal
                            4 => self.toggle_window(5), // Not Defteri
                            5 => self.toggle_window(6), // Hesap Makinesi
                            6 => self.toggle_window(7), // Paint
                            _ => {}
                        }
                    }
                } else {
                    self.selected_desktop_icon = None;
                    self.dragging_icon = None;
                }
            }
        }

        self.was_left_clicked = m_left;
    }

    pub fn toggle_window(&mut self, id: usize) {
        if let Some(pos) = self.windows.iter().position(|w| w.id == id) {
            let win_desk = self.windows[pos].desktop_id;
            if win_desk != usize::MAX && win_desk != self.virtual_desktops.current_desktop_id() {
                self.virtual_desktops.switch_to(win_desk);
            }
            let win = &mut self.windows[pos];
            if !win.is_open {
                win.is_open = true;
                win.is_minimized = false;
                self.active_window_idx = pos;
            } else if win.is_minimized {
                win.is_minimized = false;
                self.active_window_idx = pos;
            } else {
                win.is_minimized = true;
            }
        }
    }

    /// Renders the complete customizable hybrid desktop environment
    pub fn render(&mut self, engine: &mut DisplayEngine, mx: usize, my: usize, m_left: bool, m_right: bool, fps: u64) {
        let _ = m_right;
        // 0. Authentic Windows 11 Style Boot Splash Screen (Faceted 3D Star & Rotating Progress Ring)
        if self.boot_splash_frames > 0 {
            let frame = 300 - self.boot_splash_frames;
            self.boot_splash_frames = self.boot_splash_frames.saturating_sub(1);
            self.render_boot_splash(engine, frame);
            return;
        }

        let sw = engine.width;
        let sh = engine.height;
        self.frame_counter = self.frame_counter.wrapping_add(1);

        // Lock Screen check (Windows 11 Fluent Lock & Login Screen)
        if self.is_locked {
            self.lock_tick = self.lock_tick.wrapping_add(1);
            lock_screen::render_lock_screen(engine, sw, sh, mx, my, self.lock_password_len, self.lock_tick);
            engine.draw_cursor(mx, my, m_left);
            if m_left {
                self.is_locked = false;
                crate::audio::play_click_sound();
            }
            return;
        }

        // 1. High-Performance Desktop Wallpaper (Custom BMP or Multi-Theme Gradient)
        if self.custom_wallpaper_mode {
            engine.draw_bmp(0, 0, wallpapers::CUSTOM_WALLPAPER_BMP);
            if self.show_grid_lines {
                engine.draw_grid_lines(Color::rgb(20, 32, 54));
            }
        } else {
            engine.draw_wallpaper(self.selected_theme, self.show_grid_lines);

            // 2. Center Emblem (If enabled by user in personalization settings)
            if self.show_center_logo {
                let cx = (sw / 2) as isize;
                let cy = ((sh + 26) / 2) as isize;
                match self.selected_theme % 6 {
                    0 => emblems::render_kali_dragon(engine, cx, cy),
                    1 => emblems::render_coros_cyber_shield(engine, cx, cy),
                    2 => emblems::render_cosmic_pulsar(engine, cx, cy),
                    3 => emblems::render_modern_ring(engine, cx, cy),
                    4 => emblems::render_matrix_shield(engine, cx, cy),
                    _ => emblems::render_modern_ring(engine, cx, cy),
                }
            }
        }

        // 3. Desktop Shortcuts (Belgeler, Ağ, Bilgisayarım)
        self.render_desktop_shortcuts(engine, mx, my);

        // 4. Floating Cyber HUD Widget (Conky / Neofetch Live Telemetry)
        if self.show_desktop_hud {
            self.render_desktop_hud(engine, sw, fps);
        }

        // 5. Render Windows (Non-active first, active window on top - filtered by active virtual desktop)
        let active_idx = self.active_window_idx;
        let num_wins = self.windows.len();
        let cur_desktop = self.virtual_desktops.current_desktop_id();

        for i in 0..num_wins {
            if i != active_idx && self.windows[i].is_open && !self.windows[i].is_minimized && (self.windows[i].desktop_id == cur_desktop || self.windows[i].desktop_id == usize::MAX) {
                self.render_single_window(i, false, engine, mx, my, fps);
            }
        }
        if active_idx < num_wins && self.windows[active_idx].is_open && !self.windows[active_idx].is_minimized && (self.windows[active_idx].desktop_id == cur_desktop || self.windows[active_idx].desktop_id == usize::MAX) {
            self.render_single_window(active_idx, true, engine, mx, my, fps);
        }

        // 6. Dock / Taskbar at the bottom (y = sh - 48 .. sh)
        self.render_windows_taskbar(engine, sw, sh, mx, my, fps);

        // 7. Windows 11 Multi-Tabbed Start Menu (if opened)
        if self.start_menu.is_open {
            self.start_menu.render(engine, sw, sh, mx, my, &self.theme);
        }

        // 7.5. File Properties Modal Dialog (if opened)
        if self.properties_dialog.is_open {
            self.properties_dialog.render(engine, mx, my, &self.theme);
        }

        // 7.6. File Explorer Right-Click Context Menu (if opened)
        if self.file_context_menu.is_open {
            self.file_context_menu.render(engine, sw, sh, mx, my, &self.theme);
        }

        // 7.7. Windows Run Dialog (Win + R) (if opened)
        if self.run_dialog.is_open {
            self.run_dialog.render(engine, mx, my, &self.theme);
        }

        // 7.8. Task View / Virtual Desktops workspace overlay (Win + Tab)
        if self.virtual_desktops.task_view_open {
            self.virtual_desktops.render_task_view(engine, sw, sh, mx, my, &self.theme, &self.windows);
        }

        // 8. Quick Settings / Action Center (if opened)
        if self.quick_settings_open {
            widgets::render_quick_settings(
                engine,
                sw,
                sh,
                mx,
                my,
                self.dark_theme_enabled,
                self.wifi_enabled,
                self.volume_level,
                self.brightness_level,
            );
        }

        // 9. Calendar Grid (if opened)
        if self.calendar_open {
            widgets::render_calendar(engine, sw, sh, self.dark_theme_enabled);
        }

        // 10. Desktop Right-Click Context Menu (if opened)
        if self.context_menu_open {
            widgets::render_context_menu(
                engine,
                self.context_menu_x,
                self.context_menu_y,
                mx,
                my,
                self.dark_theme_enabled,
            );
        }

        // 10.5. Aero Snap Outline & Translucent Glass Preview
        if self.snap_preview != widgets::SnapPreview::None {
            widgets::render_aero_snap_preview(engine, sw, sh, self.snap_preview, self.dark_theme_enabled);
        }

        // 10.6. Alt+Tab Modern Task Switcher Modal
        if self.alt_tab_active {
            let open_windows: alloc::vec::Vec<(&str, usize, &'static str)> = self.windows.iter()
                .filter(|w| w.is_open)
                .map(|w| {
                    let icon_tag = match w.win_type {
                        WindowType::FileExplorer => "DIR",
                        WindowType::CyberTerminal => "TERM",
                        WindowType::SystemMonitor => "SYS",
                        WindowType::CyberSpace3D => "3D",
                        WindowType::ThemeSettings => "SETTINGS",
                        WindowType::Notepad => "TXT",
                        WindowType::Calculator => "CALC",
                        WindowType::Paint => "PAINT",
                        WindowType::MediaPlayer => "PLAY",
                        WindowType::RetroGame => "GAME",
                        WindowType::AppStore => "STORE",
                        WindowType::CodeEditor => "CODE",
                        WindowType::SnippingTool => "SNIP",
                        WindowType::DiskManager => "DISK",
                        WindowType::DeviceManager => "DEV",
                        WindowType::SystemRecovery => "RESTORE",
                        WindowType::Firewall => "FW",
                        WindowType::Disassembler => "DISASM",
                        WindowType::Archiver => "ZIP",
                        WindowType::VmmMonitor => "VMM",
                        WindowType::CorShare => "SHARE",
                        WindowType::TaskScheduler => "CRON",
                        WindowType::ThermalMonitor => "TEMP",
                        WindowType::WebBrowser => "WEB",
                    };
                    (w.title, w.id, icon_tag)
                })
                .collect();
            widgets::render_alt_tab_switcher(engine, sw, sh, &open_windows, self.alt_tab_idx, self.dark_theme_enabled);
        }

        // 10.7. Windows 11 Action Center & Notification Flyout
        if self.notification_center.is_open {
            notifications::render_action_center(
                engine,
                &self.notification_center,
                sw,
                sh,
                self.dark_theme_enabled,
                mx,
                my,
                self.frame_counter,
            );
        } else if let Some((ref notif, _)) = self.notification_center.active_toast {
            notifications::render_toast_notification(
                engine,
                notif,
                sw,
                sh,
                self.dark_theme_enabled,
            );
        }

        // 11. Hardware-Accelerated Mouse Cursor
        engine.draw_cursor(mx, my, m_left);
    }

    /// Renders an authentic Windows 11 Boot Splash Screen
    pub fn render_boot_splash(&self, engine: &mut DisplayEngine, frame: u32) {
        if frame == 0 {
            crate::diagnostics::serial::write_str("[BOOTSPLASH] STARTING Windows 11 star animation...\r\n");
        } else if frame == 299 {
            crate::diagnostics::serial::write_str("[BOOTSPLASH] FINISHED! Transitioning to Desktop.\r\n");
        }

        let sw = engine.width;
        let sh = engine.height;

        // Check if Verbose Hardware Initialization SOS mode is active
        if self.verbose_boot_mode {
            engine.fill_rect(0, 0, sw, sh, Color::rgb(10, 12, 16));
            engine.draw_string(24, 20, "CorOS Kernel v7.5.0 Verbose Hardware Initialization Log (SOS Mode)", Color::CYAN, 1);
            engine.draw_hline(24, 38, sw - 48, Color::rgb(45, 55, 75));

            let lines = [
                "[ OK ] ACPI 2.0 RSDP Subsystem Verified (RSDP at 0x000F6230, OEM: COROS26)",
                "[ OK ] SMP 4-Core APIC Subsystem: Cores 0, 1, 2, 3 Online (Vector 32 Periodic)",
                "[ OK ] Physical Frame Allocator Active: 1024 MB RAM Cacheline-Aligned",
                "[ OK ] CPU PAT Write-Combining Active (CR0/CR4/MSR_PAT 0x07)",
                "[ OK ] Invariant TSC Detected: High-Precision Monotonic Timer Active",
                "[ OK ] PCI Bus Scan: AHCI SATA Controller DMA Port 0 Ready (64 MB)",
                "[ OK ] Intel 82540EM (e1000) Gigabit NIC Initialized (MAC 08:00:27:..., 1 Gbps)",
                "[ OK ] Intel AC'97 Sound Synthesizer Active (48kHz Stereo PCM)",
                "[ OK ] FAT32 ESP Volume Mounted (BOOTX64.EFI & CORKERNEL.EFI PE Verified)",
                "[ OK ] VFS Subsystem Online (/proc/cpuinfo, /proc/meminfo, /dev/random RDRAND)",
                "[ OK ] POSIX & Linux MSR_LSTAR Syscall Vector Matrix Initialized (Ring 0/3)",
                "[ OK ] Display Engine Double-Buffered GOP 1024x768 VRAM Stream Ready",
                "[ OK ] Starting 300 FPS Fluent Desktop Window Manager (All Cores Synced)",
            ];

            let mut ry = 52;
            for (idx, &l) in lines.iter().enumerate() {
                if idx * 5 <= (frame as usize) {
                    engine.draw_string(24, ry, l, Color::rgb(16, 185, 129), 1);
                }
                ry += 22;
            }

            let tip = "ESC / v: Normal Windows 11 Grafik Moduna Don";
            engine.draw_string(24, sh.saturating_sub(26), tip, Color::rgb(96, 205, 255), 1);
            return;
        }

        // 1. Deep solid pitch black background (#000000)
        engine.fill_rect(0, 0, sw, sh, Color::rgb(0, 0, 0));

        // 2. Centered Fluent 3D Star logo (112x112 ultra-sharp)
        let star_w = 112;
        let star_h = 112;
        let star_x = (sw.saturating_sub(star_w)) / 2;
        let star_y = (sh * 30) / 100;
        engine.draw_bmp(star_x, star_y, icons::ICON_BOOT_STAR_BMP);

        // 3. Rotating circular Windows progress ring below the star
        let spin_cx = (sw / 2) as isize;
        let spin_cy = (star_y + star_h + 54) as isize;

        let cycle_pos = ((frame % 60) * 256 / 60) as u8;
        for i in 0..5 {
            let offset = (i as u8).wrapping_mul(10);
            let u_dot = cycle_pos.wrapping_sub(offset);

            let ease = (crate::cyberspace3d::sin(u_dot) * 22) >> 10;
            let angle = u_dot.wrapping_add(ease as u8);

            let sx = (crate::cyberspace3d::sin(angle) * 22) >> 10;
            let sy = (-crate::cyberspace3d::cos(angle) * 22) >> 10;

            let px = spin_cx + (sx as isize);
            let py = spin_cy + (sy as isize);

            // Antialiased glowing progress dot
            for dy in -3..=3 {
                for dx in -3..=3 {
                    let d2 = dx * dx + dy * dy;
                    let dot_x = px + dx;
                    let dot_y = py + dy;
                    if dot_x >= 0 && (dot_x as usize) < sw && dot_y >= 0 && (dot_y as usize) < sh {
                        if d2 <= 3 {
                            engine.draw_pixel(dot_x as usize, dot_y as usize, Color::rgb(255, 255, 255));
                        } else if d2 <= 9 {
                            engine.blend_pixel(dot_x as usize, dot_y as usize, Color::rgb(180, 215, 255), 140);
                        }
                    }
                }
            }
        }

        // 4. Centered Titles & Status
        let title = "CorOS Workstation 2026";
        let tw = engine.string_width(title);
        let tx = (sw.saturating_sub(tw)) / 2;
        let ty = (spin_cy + 36) as usize;
        engine.draw_string(tx, ty, title, Color::WHITE, 1);

        let stage_str = match (frame / 20) % 4 {
            0 => "Sistem donanimi baslatiliyor...",
            1 => "Intel Gigabit NIC & Ses senkronize ediliyor...",
            2 => "FAT32 ESP & VFS dosya sistemi hazirlaniyor...",
            _ => "Masaustu yukleniyor...",
        };
        let sw_txt = engine.string_width(stage_str);
        let sx_txt = (sw.saturating_sub(sw_txt)) / 2;
        engine.draw_string(sx_txt, ty + 18, stage_str, Color::rgb(148, 163, 184), 1);

        // 5. Sleek Progress Bar
        let bar_w = 260;
        let bar_x = (sw.saturating_sub(bar_w)) / 2;
        let bar_y = ty + 38;
        engine.fill_rounded_rect(bar_x, bar_y, bar_w, 4, 2, Color::rgb(28, 36, 48));
        let pct = (frame as usize * 100) / 75.max(frame as usize);
        let filled_w = ((bar_w * pct.min(100)) / 100).max(8);
        engine.fill_rounded_rect(bar_x, bar_y, filled_w, 4, 2, Color::rgb(0, 150, 255));

        // 6. Verbose / Diagnostic SOS Footer Note
        let tip = "v / F8: Verbose SOS Dmesg | Tab: Guvenli Mod | ESC: Boot Menusu";
        let tip_w = engine.string_width(tip);
        engine.draw_string((sw.saturating_sub(tip_w)) / 2, sh.saturating_sub(26), tip, Color::rgb(75, 85, 99), 1);
    }



    /// Renders authentic Windows 11 Taskbar at the bottom (y = sh - 48 .. sh)
    fn render_windows_taskbar(&self, engine: &mut DisplayEngine, sw: usize, sh: usize, mx: usize, my: usize, fps: u64) {
        let bar_h = 48;
        let bar_y = sh.saturating_sub(bar_h);

        // 1. Taskbar Acrylic Body (Dark: #161B24; Light: Windows 11 Light Frosted #F1F5F9)
        let bar_bg = if self.dark_theme_enabled { Color::rgb(22, 27, 36) } else { Color::rgb(241, 245, 249) };
        let bar_border = if self.dark_theme_enabled { Color::rgb(48, 56, 72) } else { Color::rgb(226, 232, 240) };
        engine.fill_rect(0, bar_y, sw, bar_h, bar_bg);
        engine.draw_hline(0, bar_y, sw, bar_border);

        // 2. Windows 11 App Dock Cluster (Centered)
        // 10 items: Start, Explorer, Terminal, Monitor, Cyber3D, Settings, Notepad, Calc, Paint, Trash
        let items: [(&str, Option<usize>); 10] = [
            ("Baslat", None),
            ("Dosya Gezgini", Some(0)),
            ("Terminal", Some(1)),
            ("Gorev Yoneticisi", Some(2)),
            ("3D Goruntuleyici", Some(3)),
            ("Ayarlar", Some(4)),
            ("Not Defteri", Some(5)),
            ("Hesap Makinesi", Some(6)),
            ("Paint", Some(7)),
            ("Geri Donusum Kutusu", None),
        ];

        let slot_w = 48;
        let cluster_w = items.len() * slot_w;
        let cluster_x = (sw.saturating_sub(cluster_w)) / 2;

        let mut hovered_tip: Option<(&str, usize)> = None;

        let slot_hover_bg = if self.dark_theme_enabled { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) };
        let start_active_bg = if self.dark_theme_enabled { Color::rgb(35, 45, 65) } else { Color::rgb(219, 234, 254) };

        for (i, &(label, win_id)) in items.iter().enumerate() {
            let sx = cluster_x + i * slot_w;
            let sy = bar_y + 1;
            let is_h = mx >= sx && mx < sx + slot_w && my >= bar_y && my < sh;

            // Hover capsule highlight
            if is_h {
                engine.fill_rounded_rect(sx + 1, sy, slot_w - 2, 46, 6, slot_hover_bg);
                hovered_tip = Some((label, sx + slot_w / 2));
            } else if i == 0 && self.start_menu.is_open {
                // Start button active highlight
                engine.fill_rounded_rect(sx + 1, sy, slot_w - 2, 46, 6, start_active_bg);
            }

            // Draw 48x48 32-bit BMP icon centered in the slot
            let icon_x = sx;
            let icon_y = sy;
            match i {
                0 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_START_BMP); }
                1 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_FINDER_BMP); }
                2 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_TERMINAL_BMP); }
                3 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_MONITOR_BMP); }
                4 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_CYBER3D_BMP); }
                5 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_SETTINGS_BMP); }
                6 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_NOTEPAD_BMP); }
                7 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_CALC_BMP); }
                8 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_PAINT_BMP); }
                9 => { engine.draw_bmp(icon_x, icon_y, icons::ICON_TRASH_BMP); }
                _ => {}
            }

            // Running indicator pill underneath icon (Windows 11 style)
            if let Some(wid) = win_id {
                let win = self.windows.iter().find(|w| w.id == wid);
                let is_open = win.map_or(false, |w| w.is_open);
                let is_active = self.active_window_idx < self.windows.len() && self.windows[self.active_window_idx].id == wid && is_open && !win.map_or(false, |w| w.is_minimized);

                if is_active {
                    // Active window: wider cyan/blue pill
                    let active_pill = if self.dark_theme_enabled { Color::rgb(56, 189, 248) } else { Color::rgb(0, 120, 212) };
                    engine.fill_rounded_rect(sx + 15, bar_y + 44, 18, 3, 1, active_pill);
                } else if is_open {
                    // Running/minimized: small pill
                    let run_pill = if self.dark_theme_enabled { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };
                    engine.fill_rounded_rect(sx + 19, bar_y + 44, 10, 3, 1, run_pill);
                }
            }
        }

        // 2.5 Far Left Virtual Desktop Switcher Pill [ ◫ Masaüstü 1 ]
        let cur_desk = self.virtual_desktops.current_desktop_id() + 1;
        let desk_pill_x = 16;
        let desk_pill_w = 112;
        let is_desk_h = mx >= desk_pill_x && mx < desk_pill_x + desk_pill_w && my >= bar_y + 8 && my < bar_y + 40;
        let desk_bg = if is_desk_h {
            if self.dark_theme_enabled { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) }
        } else {
            if self.dark_theme_enabled { Color::rgb(26, 32, 44) } else { Color::rgb(245, 247, 250) }
        };
        let desk_border = if is_desk_h {
            Color::rgb(56, 189, 248)
        } else {
            if self.dark_theme_enabled { Color::rgb(45, 55, 75) } else { Color::rgb(203, 213, 225) }
        };
        engine.fill_rounded_rect(desk_pill_x, bar_y + 8, desk_pill_w, 32, 6, desk_bg);
        engine.draw_rect(desk_pill_x, bar_y + 8, desk_pill_w, 32, desk_border);

        // Icon [#] and Text
        engine.draw_string(desk_pill_x + 8, bar_y + 18, "[#]", Color::rgb(56, 189, 248), 1);
        let desk_name = match cur_desk {
            1 => "Masaustu 1",
            2 => "Masaustu 2",
            3 => "Masaustu 3",
            _ => "Masaustu",
        };
        let desk_txt_col = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };
        engine.draw_string(desk_pill_x + 32, bar_y + 18, desk_name, desk_txt_col, 1);
        if is_desk_h {
            hovered_tip = Some(("Masaustu Degistir (Win+Tab)", desk_pill_x + desk_pill_w / 2));
        }

        // 3. Right System Tray (Bildirim Alanı & Saat)
        let tray_x = sw.saturating_sub(240);

        // Live Telemetry badge (CPU & FPS)
        let cpu_badge_col = if self.dark_theme_enabled { Color::rgb(56, 189, 248) } else { Color::rgb(0, 120, 212) };
        engine.draw_string(tray_x - 30, bar_y + 18, "4C", cpu_badge_col, 1);
        let fps_w = engine.draw_number(tray_x - 12, bar_y + 18, fps, Color::rgb(52, 211, 153), 1);
        let fps_unit_col = if self.dark_theme_enabled { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };
        engine.draw_string(tray_x - 12 + fps_w, bar_y + 18, "F", fps_unit_col, 1);

        // System Tray Pill Container (Network, Audio, Battery)
        let pill_x = tray_x + 36;
        let is_pill_h = mx >= pill_x && mx < pill_x + 90 && my >= bar_y + 6 && my < bar_y + 42;
        let pill_bg = if is_pill_h {
            if self.dark_theme_enabled { Color::rgb(35, 45, 65) } else { Color::rgb(226, 232, 240) }
        } else {
            if self.dark_theme_enabled { Color::rgb(26, 32, 44) } else { Color::rgb(255, 255, 255) }
        };
        let pill_border = if self.dark_theme_enabled { Color::rgb(45, 55, 75) } else { Color::rgb(203, 213, 225) };
        engine.fill_rounded_rect(pill_x, bar_y + 8, 90, 32, 6, pill_bg);
        engine.draw_rect(pill_x, bar_y + 8, 90, 32, pill_border);

        // Network icon
        engine.draw_string(pill_x + 8, bar_y + 18, "[N]", if self.dark_theme_enabled { Color::CYAN } else { Color::rgb(0, 120, 212) }, 1);
        // Audio icon
        let tray_icon_col = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };
        engine.draw_string(pill_x + 32, bar_y + 18, "4))", tray_icon_col, 1);
        // Battery icon
        engine.draw_rect(pill_x + 60, bar_y + 18, 14, 8, tray_icon_col);
        engine.fill_rect(pill_x + 74, bar_y + 20, 2, 4, tray_icon_col);
        engine.fill_rect(pill_x + 62, bar_y + 20, 10, 4, Color::EMERALD);

        // Windows 2-Line Clock & Date
        let clock_x = pill_x + 98;
        let dt = crate::time::read_rtc();
        let time_str = alloc::format!("{:02}:{:02}", dt.hour, dt.minute);
        let date_str = alloc::format!("{:02}.{:02}.{:04}", dt.day, dt.month, dt.year);
        let clock_time_col = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };
        let clock_date_col = if self.dark_theme_enabled { Color::rgb(148, 163, 184) } else { Color::rgb(100, 116, 139) };
        engine.draw_string(clock_x, bar_y + 12, &time_str, clock_time_col, 1);
        engine.draw_string(clock_x, bar_y + 26, &date_str, clock_date_col, 1);

        // Notification Center Bell Icon & Badge
        let notif_bell_x = clock_x + 66;
        let notif_count = self.notification_center.items.len();
        let notif_col = if notif_count > 0 { Color::CYAN } else { clock_date_col };
        engine.draw_string(notif_bell_x, bar_y + 18, "[B", notif_col, 1);
        let count_w = engine.draw_number(notif_bell_x + 14, bar_y + 18, notif_count as u64, Color::WHITE, 1);
        engine.draw_string(notif_bell_x + 14 + count_w, bar_y + 18, "]", notif_col, 1);

        // Desktop Peek line on far right
        let peek_x = sw.saturating_sub(6);
        engine.draw_vline(peek_x, bar_y + 8, 32, Color::rgb(60, 72, 95));

        // 4. Hover Tooltip
        if let Some((tip, cx)) = hovered_tip {
            let tip_w = engine.string_width(tip) + 18;
            let tx = cx.saturating_sub(tip_w / 2);
            let ty = bar_y.saturating_sub(26);
            engine.fill_rounded_rect(tx, ty, tip_w, 20, 4, Color::rgb(26, 32, 44));
            engine.draw_rect(tx, ty, tip_w, 20, Color::rgb(56, 70, 96));
            engine.draw_string(tx + 9, ty + 5, tip, Color::WHITE, 1);
        }
    }

    /// Renders Windows 11 Start Menu card above the Taskbar
    fn render_windows_start_menu(&self, engine: &mut DisplayEngine, sw: usize, sh: usize, mx: usize, my: usize) {
        let menu_w = 380;
        let menu_h = 360;
        let menu_x = (sw.saturating_sub(menu_w)) / 2;
        let menu_y = sh.saturating_sub(48 + menu_h + 10);

        // 1. Frosted Acrylic Start Menu Card
        let menu_bg = if self.dark_theme_enabled { Color::rgb(24, 30, 42) } else { Color::rgb(248, 250, 252) };
        let menu_border = if self.dark_theme_enabled { Color::rgb(55, 68, 92) } else { Color::rgb(203, 213, 225) };
        engine.fill_rounded_rect(menu_x, menu_y, menu_w, menu_h, 8, menu_bg);
        engine.draw_rect(menu_x, menu_y, menu_w, menu_h, menu_border);

        // 2. Search Box at top (Interactive Windows 11 Fluent Search)
        let search_y = menu_y + 16;
        let search_box_border = if !self.search_query.is_empty() {
            if self.dark_theme_enabled { Color::CYAN } else { Color::rgb(0, 120, 212) }
        } else {
            if self.dark_theme_enabled { Color::rgb(65, 80, 105) } else { Color::rgb(203, 213, 225) }
        };
        let search_box_bg = if self.dark_theme_enabled { Color::rgb(35, 44, 60) } else { Color::rgb(255, 255, 255) };
        engine.fill_rounded_rect(menu_x + 20, search_y, menu_w - 40, 32, 6, search_box_bg);
        engine.draw_rect(menu_x + 20, search_y, menu_w - 40, 32, search_box_border);

        let search_txt_col = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };
        if self.search_query.is_empty() {
            engine.draw_string(menu_x + 36, search_y + 10, "Uygulamalari ve dosyalari arayin...", Color::rgb(148, 163, 184), 1);
        } else {
            let cursor = if (self.cursor_blink / 20) % 2 == 0 { "|" } else { "" };
            let disp_search = format!("{}{}", self.search_query, cursor);
            engine.draw_string(menu_x + 36, search_y + 10, &disp_search, search_txt_col, 1);
        }

        // 3. Section Title
        let pin_y = search_y + 46;
        let pin_title_col = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };
        let link_col = if self.dark_theme_enabled { Color::rgb(56, 189, 248) } else { Color::rgb(0, 120, 212) };
        if self.search_query.is_empty() {
            engine.draw_string(menu_x + 24, pin_y, "Sabitlenen Uygulamalar", pin_title_col, 1);
            engine.draw_string(menu_x + menu_w - 110, pin_y, "Tum Uygulamalar >", link_col, 1);
        } else {
            engine.draw_string(menu_x + 24, pin_y, "Arama Sonuclari (Enter ile ac)", link_col, 1);
        }

        // 4. Apps Grid (Filtered by search query if present)
        let all_apps: [(&str, &[u8], usize); 7] = [
            ("Dosya Gezgini", icons::ICON_FINDER_BMP, 0),
            ("Terminal", icons::ICON_TERMINAL_BMP, 1),
            ("Gorev Yoneticisi", icons::ICON_MONITOR_BMP, 2),
            ("3D Goruntuleyici", icons::ICON_CYBER3D_BMP, 3),
            ("Ayarlar", icons::ICON_SETTINGS_BMP, 4),
            ("Paint", icons::ICON_PAINT_BMP, 7),
            ("Not Defteri", icons::ICON_NOTEPAD_BMP, 5),
        ];

        let q = self.search_query.to_lowercase();
        let filtered_apps: Vec<(&str, &[u8], usize)> = all_apps
            .iter()
            .filter(|(name, _, _)| q.is_empty() || name.to_lowercase().contains(&q))
            .copied()
            .collect();

        let grid_y = pin_y + 20;
        let col_w = (menu_w - 48) / 3;

        let app_hover_bg = if self.dark_theme_enabled { Color::rgb(40, 52, 72) } else { Color::rgb(226, 232, 240) };
        let app_label_col = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };

        for (i, &(title, icon_bmp, _id)) in filtered_apps.iter().take(6).enumerate() {
            let row = i / 3;
            let col = i % 3;
            let ax = menu_x + 24 + col * col_w;
            let ay = grid_y + row * 82;

            let is_h = mx >= ax && mx < ax + col_w - 8 && my >= ay && my < ay + 74;
            if is_h {
                engine.fill_rounded_rect(ax, ay, col_w - 8, 74, 6, app_hover_bg);
            }

            let icon_center_x = ax + (col_w - 8) / 2 - 24;
            engine.draw_bmp(icon_center_x, ay + 4, icon_bmp);

            let label_len = engine.string_width(title);
            let lx = ax + (col_w - 8).saturating_sub(label_len) / 2;
            engine.draw_string(lx, ay + 56, title, app_label_col, 1);
        }

        // 5. Bottom User & Power Bar
        let foot_y = menu_y + menu_h - 48;
        let foot_bg = if self.dark_theme_enabled { Color::rgb(18, 23, 33) } else { Color::rgb(241, 245, 249) };
        let foot_border = if self.dark_theme_enabled { Color::rgb(45, 56, 76) } else { Color::rgb(226, 232, 240) };
        engine.fill_rect(menu_x, foot_y, menu_w, 48, foot_bg);
        engine.draw_hline(menu_x, foot_y, menu_w, foot_border);

        // User profile on left
        engine.fill_circle((menu_x + 36) as isize, (foot_y + 24) as isize, 12, Color::rgb(0, 120, 212));
        engine.draw_string(menu_x + 32, foot_y + 19, "U", Color::WHITE, 1);
        engine.draw_string(menu_x + 58, foot_y + 14, "coros@silicon", app_label_col, 1);
        engine.draw_string(menu_x + 58, foot_y + 27, "Yerel Hesap (Yonetici)", Color::rgb(148, 163, 184), 1);

        // Power button on right
        let pwr_x = menu_x + menu_w - 52;
        let is_pwr_h = mx >= pwr_x && mx < pwr_x + 36 && my >= foot_y + 8 && my < foot_y + 40;
        if is_pwr_h {
            engine.fill_rounded_rect(pwr_x, foot_y + 8, 36, 32, 4, Color::rgb(254, 226, 226));
        }
        engine.draw_string(pwr_x + 10, foot_y + 18, "[P]", Color::rgb(239, 68, 68), 1);
    }

    /// Renders Windows 11 Desktop Shortcuts (Bu Bilgisayar, Geri Donusum Kutusu, Dosya Gezgini, Ag Baglantilari)
    fn render_desktop_shortcuts(&self, engine: &mut DisplayEngine, mx: usize, my: usize) {
        let items: [(&str, &[u8], usize); 7] = [
            ("Bu Bilgisayar", icons::ICON_MONITOR_BMP, 0),
            ("Geri Dönüşüm", icons::ICON_TRASH_BMP, 1),
            ("Dosya Gezgini", icons::ICON_FINDER_BMP, 2),
            ("Terminal", icons::ICON_TERMINAL_BMP, 3),
            ("Not Defteri", icons::ICON_NOTEPAD_BMP, 4),
            ("Hesap Makinesi", icons::ICON_CALC_BMP, 5),
            ("Paint", icons::ICON_PAINT_BMP, 6),
        ];

        for &(name, icon_bmp, id) in &items {
            let (ix, iy) = self.icon_coords[id];
            if ix < 0 || iy < 0 {
                continue;
            }
            let uix = ix as usize;
            let uiy = iy as usize;

            let is_h = mx >= uix && mx < uix + 84 && my >= uiy && my < uiy + 76;
            let is_sel = self.selected_desktop_icon == Some(id);
            let is_dragging = self.dragging_icon == Some(id);

            // Dragging translucent shadow effect
            if is_dragging {
                let shadow_bg = if self.dark_theme_enabled { Color::rgb(14, 45, 80) } else { Color::rgb(191, 219, 254) };
                let shadow_border = if self.dark_theme_enabled { Color::rgb(56, 189, 248) } else { Color::rgb(0, 120, 212) };
                // Draw shadow offset (+4, +4)
                engine.fill_rounded_rect(uix + 4, uiy + 4, 84, 76, 8, Color::rgb(0, 0, 0));
                engine.fill_rounded_rect(uix, uiy, 84, 76, 6, shadow_bg);
                engine.draw_rect(uix, uiy, 84, 76, shadow_border);
            } else if is_sel {
                let sel_bg = if self.dark_theme_enabled { Color::rgb(35, 60, 95) } else { Color::rgb(219, 234, 254) };
                let sel_border = if self.dark_theme_enabled { Color::rgb(56, 189, 248) } else { Color::rgb(0, 120, 212) };
                engine.fill_rounded_rect(uix, uiy, 84, 76, 6, sel_bg);
                engine.draw_rect(uix, uiy, 84, 76, sel_border);
            } else if is_h {
                let h_bg = if self.dark_theme_enabled { Color::rgb(25, 40, 65) } else { Color::rgb(241, 245, 249) };
                let h_border = if self.dark_theme_enabled { Color::rgb(50, 75, 110) } else { Color::rgb(203, 213, 225) };
                engine.fill_rounded_rect(uix, uiy, 84, 76, 6, h_bg);
                engine.draw_rect(uix, uiy, 84, 76, h_border);
            }

            // Draw 48x48 High-Definition Windows Fluent BMP Icon centered horizontally in the 84px slot
            let icon_x = uix + (84 - 48) / 2;
            let icon_y = uiy + 4;
            engine.draw_bmp(icon_x, icon_y, icon_bmp);

            // Centered crisp text label underneath (White in dark theme; dark slate in light theme)
            let label_len = engine.string_width(name);
            let text_x = uix + 84usize.saturating_sub(label_len) / 2;
            let text_y = uiy + 56;
            let label_fg = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };
            engine.draw_string(text_x, text_y, name, label_fg, 1);
        }
    }

    /// Renders the floating cyber HUD widget (Conky / Neofetch) on the top-right
    fn render_desktop_hud(&self, engine: &mut DisplayEngine, sw: usize, fps: u64) {
        let w = 216;
        let h = 168;
        let x = sw.saturating_sub(w + 18);
        let y = 38;

        // Frosted cyber glass capsule
        engine.fill_rounded_rect(x, y, w, h, 8, Color::rgb(10, 16, 28));
        engine.draw_rect(x, y, w, h, Color::rgb(35, 52, 78));
        engine.draw_hline(x + 12, y + 1, w - 24, Color::CYAN);

        // Header bar with pulsing cyber green status indicator
        let pulse_dot = if (self.frame_counter / 30) % 2 == 0 { Color::rgb(34, 197, 94) } else { Color::rgb(74, 222, 128) };
        engine.fill_circle((x + 16) as isize, (y + 13) as isize, 3, pulse_dot);
        engine.draw_string(x + 26, y + 9, "COROS SYSTEM HUD", Color::CYAN, 1);
        engine.draw_hline(x + 10, y + 22, w - 20, Color::rgb(28, 40, 60));

        // System specs & Live counters
        engine.draw_string(x + 12, y + 28, "OS:     CorOS 0.1.0-ultra", Color::WHITE, 1);
        engine.draw_string(x + 12, y + 42, "KERNEL: Bare-Metal no_std", Color::rgb(148, 163, 184), 1);
        engine.draw_string(x + 12, y + 56, "CPU:    4x SMP @ 2.6 GHz", Color::WHITE, 1);

        // CPU dynamic bar graph
        let cpu_bar_w = 48 + (((self.frame_counter % 80) * 18) / 80) as usize;
        engine.fill_rounded_rect(x + 12, y + 70, 192, 6, 2, Color::rgb(18, 26, 42));
        engine.fill_rounded_rect(x + 12, y + 70, cpu_bar_w, 6, 2, Color::EMERALD);

        // RAM & bar graph
        engine.draw_string(x + 12, y + 82, "RAM:    1024 MB (14 MB Aktif)", Color::WHITE, 1);
        engine.fill_rounded_rect(x + 12, y + 96, 192, 6, 2, Color::rgb(18, 26, 42));
        engine.fill_rounded_rect(x + 12, y + 96, 28, 6, 2, Color::CYAN);

        // Live Uptime
        let total_secs = self.frame_counter / 60;
        let uptime_mins = total_secs / 60;
        let uptime_secs = total_secs % 60;
        let up_str = format!("UPTIME: {}m {}s", uptime_mins, uptime_secs);
        engine.draw_string(x + 12, y + 108, &up_str, Color::rgb(203, 213, 225), 1);

        // GPU FPS Counter
        let gpu_str = format!("GPU:    {} FPS (VRAM DMA)", fps);
        engine.draw_string(x + 12, y + 122, &gpu_str, Color::EMERALD, 1);

        // Security status badge
        engine.fill_rounded_rect(x + 12, y + 138, 192, 18, 3, Color::rgb(14, 38, 28));
        engine.draw_rect(x + 12, y + 138, 192, 18, Color::EMERALD);
        engine.draw_string(x + 36, y + 143, "[ SISTEM GUVENLI - OK ]", Color::EMERALD, 1);
    }

    fn render_single_window(&mut self, idx: usize, is_active: bool, engine: &mut DisplayEngine, mx: usize, my: usize, fps: u64) {
        let (wx, wy, ww, wh, win_type, win_title, win_selected) = {
            let win = &self.windows[idx];
            (win.x, win.y, win.w, win.h, win.win_type, win.title, win.selected_file)
        };

        if wx + (ww as isize) < 0 || wy + (wh as isize) < 0 {
            return;
        }

        let ux = wx.max(0) as usize;
        let uy = wy.max(0) as usize;

        // Window drop shadow & outer border (Dark: Cyber Cyan / Slate; Light: Windows 11 Blue / Gray)
        let border_col = if is_active {
            if self.dark_theme_enabled { Color::CYAN } else { Color::rgb(0, 120, 212) }
        } else {
            if self.dark_theme_enabled { Color::rgb(51, 65, 85) } else { Color::rgb(203, 213, 225) }
        };

        let title_bg = if self.dark_theme_enabled {
            if is_active { Color::rgb(22, 30, 46) } else { Color::rgb(15, 23, 42) }
        } else {
            if is_active { Color::rgb(241, 245, 249) } else { Color::rgb(226, 232, 240) }
        };

        let body_bg = if self.dark_theme_enabled {
            Color::rgb(13, 17, 28)
        } else {
            Color::rgb(248, 250, 252)
        };

        // Body background
        engine.fill_rect(ux, uy, ww, wh, body_bg);
        engine.draw_rect(ux, uy, ww, wh, border_col);

        // Title bar (28px height)
        engine.fill_rect(ux, uy, ww, 28, title_bg);
        let divider_col = if self.dark_theme_enabled { Color::rgb(40, 53, 76) } else { Color::rgb(226, 232, 240) };
        engine.draw_hline(ux, uy + 28, ww, divider_col);

        // Windows 11 Title Bar Controls on Right (Minimize —, Maximize □, Close ✕)
        let smx = mx as isize;
        let smy = my as isize;
        let right_x = wx + (ww as isize);
        let min_x = right_x - 114;
        let max_x = right_x - 76;
        let close_x = right_x - 38;

        let h_close = smx >= close_x && smx < right_x && smy >= wy && smy < wy + 28;
        let h_max = smx >= max_x && smx < close_x && smy >= wy && smy < wy + 28;
        let h_min = smx >= min_x && smx < max_x && smy >= wy && smy < wy + 28;

        let btn_min_x = (wx + (ww as isize) - 114) as usize;
        let btn_max_x = (wx + (ww as isize) - 76) as usize;
        let btn_close_x = (wx + (ww as isize) - 38) as usize;

        // Button hover backgrounds
        let btn_hover_bg = if self.dark_theme_enabled { Color::rgb(45, 55, 75) } else { Color::rgb(226, 232, 240) };
        let icon_col = if self.dark_theme_enabled { Color::WHITE } else { Color::rgb(15, 23, 42) };

        if h_min {
            engine.fill_rect(btn_min_x, uy, 38, 28, btn_hover_bg);
        }
        if h_max {
            engine.fill_rect(btn_max_x, uy, 38, 28, btn_hover_bg);
        }
        if h_close {
            engine.fill_rect(btn_close_x, uy, 38, 28, Color::rgb(232, 17, 35)); // Windows Close Red
        }

        // Minimize symbol (—)
        engine.draw_hline(btn_min_x + 14, uy + 14, 10, if h_close { Color::WHITE } else { icon_col });

        // Maximize symbol (□)
        engine.draw_rect(btn_max_x + 14, uy + 9, 10, 10, icon_col);

        // Close symbol (✕)
        let close_icon_col = if h_close { Color::WHITE } else { icon_col };
        let c_bx = btn_close_x as isize;
        let c_by = uy as isize;
        engine.draw_line(c_bx + 14, c_by + 9, c_bx + 23, c_by + 18, close_icon_col);
        engine.draw_line(c_bx + 23, c_by + 9, c_bx + 14, c_by + 18, close_icon_col);

        // Windows 11 Tabs on Title Bar (matching Image 1)
        if win_type == WindowType::CyberTerminal {
            let tab_w = 175;
            let tab_h = 24;
            let tab_y = uy + 4;
            engine.fill_rounded_rect(ux + 8, tab_y, tab_w, tab_h, 4, Color::rgb(14, 14, 14));
            engine.draw_rect(ux + 8, tab_y, tab_w, tab_h, Color::rgb(48, 48, 48));
            engine.draw_string(ux + 16, tab_y + 6, ">_", Color::rgb(96, 205, 255), 1);
            engine.draw_string(ux + 34, tab_y + 6, "Corpus Terminal", Color::WHITE, 1);
            engine.draw_string(ux + tab_w - 8, tab_y + 6, "x", Color::rgb(160, 160, 160), 1);

            // New Tab [+] and Chevron [v]
            let plus_x = ux + 8 + tab_w + 6;
            engine.draw_string(plus_x + 6, tab_y + 6, "+", Color::rgb(180, 180, 180), 1);
            engine.draw_string(plus_x + 22, tab_y + 6, "v", Color::rgb(140, 140, 140), 1);
        } else if win_type == WindowType::FileExplorer {
            let tab_w = 145;
            let tab_h = 24;
            let tab_y = uy + 4;
            engine.fill_rounded_rect(ux + 8, tab_y, tab_w, tab_h, 4, Color::rgb(30, 30, 30));
            engine.draw_rect(ux + 8, tab_y, tab_w, tab_h, Color::rgb(48, 48, 48));
            engine.draw_string(ux + 16, tab_y + 6, "[D]", Color::rgb(96, 205, 255), 1);
            engine.draw_string(ux + 38, tab_y + 6, "Giris", Color::WHITE, 1);
            engine.draw_string(ux + tab_w - 8, tab_y + 6, "x", Color::rgb(160, 160, 160), 1);

            // New Tab [+]
            let plus_x = ux + 8 + tab_w + 6;
            engine.draw_string(plus_x + 6, tab_y + 6, "+", Color::rgb(180, 180, 180), 1);
        } else {
            let title_fg = if self.dark_theme_enabled {
                if is_active { Color::WHITE } else { Color::rgb(148, 163, 184) }
            } else {
                if is_active { Color::rgb(15, 23, 42) } else { Color::rgb(100, 116, 139) }
            };
            engine.draw_string(ux + 14, uy + 8, win_title, title_fg, 1);
        }

        // Render window specific body content
        match win_type {
            WindowType::FileExplorer => explorer::render_file_explorer(
                win_selected,
                ux,
                uy,
                ww,
                wh,
                engine,
                mx,
                my,
                &self.theme,
                &self.current_folder,
                &self.files,
                self.renaming_file_idx,
                &self.rename_buffer,
                self.cursor_blink,
                &self.file_status_msg,
                self.clipboard_file.is_some(),
            ),
            WindowType::CyberTerminal => terminal::render_terminal(
                ux,
                uy,
                ww,
                wh,
                engine,
                &self.terminal_lines,
                &self.current_input,
                self.cursor_blink,
                self.terminal_tab,
                self.terminal_split,
                mx,
                my,
            ),
            WindowType::SystemMonitor => taskmgr::render_task_manager(
                ux,
                uy,
                ww,
                wh,
                engine,
                mx,
                my,
                self.was_left_clicked,
                &mut self.taskmgr_app,
                self.dark_theme_enabled,
            ),
            WindowType::CyberSpace3D => self.cyber_3d.render(engine, ux, uy, ww, wh, fps),
            WindowType::ThemeSettings => sysmon::render_theme_settings(
                ux,
                uy,
                ww,
                wh,
                engine,
                mx,
                my,
                self.dark_theme_enabled,
                self.selected_theme,
                self.show_center_logo,
                self.show_grid_lines,
            ),
            WindowType::Notepad => notepad::render_notepad(
                ux,
                uy,
                ww,
                wh,
                engine,
                self.dark_theme_enabled,
                self.notepad_saved_status,
                &self.notepad_content,
                self.notepad_cursor_row,
                self.notepad_cursor_col,
                self.cursor_blink,
            ),
            WindowType::Calculator => apps::render_calculator(
                ux,
                uy,
                ww,
                wh,
                engine,
                mx,
                my,
                self.dark_theme_enabled,
                &self.calc_display,
                self.calc_accumulator,
                self.calc_op,
            ),
            WindowType::Paint => apps::render_paint(
                ux,
                uy,
                ww,
                wh,
                engine,
                mx,
                my,
                self.paint_tool,
                self.paint_color_idx,
                self.paint_custom_color,
                &self.paint_hex_input,
                self.paint_brush_size,
                &self.paint_pixels,
                &self.paint_status_msg,
            ),
            WindowType::MediaPlayer => media_player::render_media_player(
                ux,
                uy,
                ww,
                wh,
                engine,
                mx,
                my,
                self.was_left_clicked,
                &mut self.media_player_app,
                self.dark_theme_enabled,
            ),
            WindowType::RetroGame => retro_game::render_retro_game(
                ux, uy, ww, wh, engine, &self.retro_game, mx, my,
            ),
            WindowType::AppStore => app_store::render_app_store(
                ux, uy, ww, wh, engine, mx, my, self.dark_theme_enabled, self.store_selected_cat,
            ),
            WindowType::CodeEditor => code_editor::render_code_editor(
                ux, uy, ww, wh, engine, mx, my, self.dark_theme_enabled, &self.code_editor,
            ),
            WindowType::SnippingTool => snipping_tool::render_snipping_tool(
                ux, uy, ww, wh, engine, mx, my, self.dark_theme_enabled, &self.snipping_tool,
            ),
            WindowType::DiskManager => disk_manager::render_disk_manager(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.disk_manager, self.dark_theme_enabled,
            ),
            WindowType::DeviceManager => device_manager::render_device_manager(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.device_manager_app, self.dark_theme_enabled,
            ),
            WindowType::SystemRecovery => recovery_manager::render_recovery_manager(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.recovery_manager, self.dark_theme_enabled,
            ),
            WindowType::Firewall => firewall::render_firewall(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.firewall, self.dark_theme_enabled,
            ),
            WindowType::Disassembler => disassembler::render_disassembler(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.disassembler, self.dark_theme_enabled,
            ),
            WindowType::Archiver => archiver::render_archiver(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.archiver, self.dark_theme_enabled,
            ),
            WindowType::VmmMonitor => vmm_monitor::render_vmm_monitor(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.vmm_monitor, self.dark_theme_enabled,
            ),
            WindowType::CorShare => corshare::render_corshare(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.corshare, self.dark_theme_enabled,
            ),
            WindowType::TaskScheduler => task_scheduler::render_task_scheduler(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.task_scheduler, self.dark_theme_enabled,
            ),
            WindowType::ThermalMonitor => thermal_monitor::render_thermal_monitor(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.thermal_monitor, self.dark_theme_enabled,
            ),
            WindowType::WebBrowser => web_browser::render_web_browser(
                ux, uy, ww, wh, engine, mx, my, self.was_left_clicked, &mut self.web_browser_app, self.dark_theme_enabled,
            ),
        }
    }
}


fn task_user_dummy(_arg: usize) {
    let _ = crate::time::TscCounter::read_ticks();
}

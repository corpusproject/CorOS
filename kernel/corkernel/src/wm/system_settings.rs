//! CorOS Windows 11 Fluent Settings App Data Model & Controller (`system_settings.rs`)
//!
//! Provides the backend configuration tree for the Modern Settings Application:
//! - Navigation Categories:
//!   - System: Display, Sound, Notifications, Power & Battery, Storage, About
//!   - Bluetooth & Devices: Mouse, Keyboard, Printers & Scanners, USB
//!   - Network & Internet: Wi-Fi, Ethernet, VPN, Proxy
//!   - Personalization: Background wallpaper, Colors (Dark/Light mode), Themes, Taskbar
//!   - Apps: Installed apps, Default apps, Startup apps
//!   - Accounts: Your info, Sign-in options, Other users
//!   - Time & Language: Date & time, Language & region, Keyboard layout
//!   - Windows Update: Check for updates, Update history, Advanced options

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsCategory {
    System,
    BluetoothDevices,
    NetworkInternet,
    Personalization,
    Apps,
    Accounts,
    TimeLanguage,
    WindowsUpdate,
}

impl SettingsCategory {
    pub fn title(&self) -> &'static str {
        match self {
            Self::System => "System",
            Self::BluetoothDevices => "Bluetooth & devices",
            Self::NetworkInternet => "Network & internet",
            Self::Personalization => "Personalization",
            Self::Apps => "Apps",
            Self::Accounts => "Accounts",
            Self::TimeLanguage => "Time & language",
            Self::WindowsUpdate => "CorOS Update",
        }
    }

    pub fn icon_char(&self) -> char {
        match self {
            Self::System => 'S',
            Self::BluetoothDevices => 'B',
            Self::NetworkInternet => 'N',
            Self::Personalization => 'P',
            Self::Apps => 'A',
            Self::Accounts => 'U',
            Self::TimeLanguage => 'T',
            Self::WindowsUpdate => 'W',
        }
    }
}

/// A setting item card in the Settings app
#[derive(Debug, Clone)]
pub struct SettingItem {
    pub key: String,
    pub title: String,
    pub description: String,
    pub current_value: String,
    pub is_toggle: bool,
    pub toggle_state: bool,
}

/// Settings Application State
pub struct SystemSettingsManager {
    pub active_category: SettingsCategory,
    pub dark_mode: bool,
    pub resolution_text: String,
    pub volume_percent: u8,
    pub taskbar_centered: bool,
    pub auto_update: bool,
}

impl SystemSettingsManager {
    pub fn new() -> Self {
        Self {
            active_category: SettingsCategory::System,
            dark_mode: true,
            resolution_text: String::from("1024 x 768"),
            volume_percent: 75,
            taskbar_centered: true,
            auto_update: true,
        }
    }

    /// Retrieve items for the currently selected category
    pub fn get_category_items(&self, cat: SettingsCategory) -> Vec<SettingItem> {
        match cat {
            SettingsCategory::System => alloc::vec![
                SettingItem {
                    key: String::from("display_res"),
                    title: String::from("Display resolution"),
                    description: String::from("Adjust the resolution of the connected monitor"),
                    current_value: self.resolution_text.clone(),
                    is_toggle: false,
                    toggle_state: false,
                },
                SettingItem {
                    key: String::from("sound_vol"),
                    title: String::from("Volume"),
                    description: String::from("Master output audio volume"),
                    current_value: alloc::format!("{}%", self.volume_percent),
                    is_toggle: false,
                    toggle_state: false,
                },
                SettingItem {
                    key: String::from("notifications"),
                    title: String::from("Notifications"),
                    description: String::from("Get notifications from apps and senders"),
                    current_value: String::from("On"),
                    is_toggle: true,
                    toggle_state: true,
                },
                SettingItem {
                    key: String::from("power_mode"),
                    title: String::from("Power mode"),
                    description: String::from("Optimize your device for performance or battery life"),
                    current_value: String::from("Balanced (Recommended)"),
                    is_toggle: false,
                    toggle_state: false,
                },
                SettingItem {
                    key: String::from("about"),
                    title: String::from("About CorOS"),
                    description: String::from("Device name: COROS-PC | Edition: CorOS Enterprise 2026"),
                    current_value: String::from("Build 50000"),
                    is_toggle: false,
                    toggle_state: false,
                },
            ],
            SettingsCategory::Personalization => alloc::vec![
                SettingItem {
                    key: String::from("theme_mode"),
                    title: String::from("Choose your mode"),
                    description: String::from("Select Light or Dark Windows appearance"),
                    current_value: if self.dark_mode { String::from("Dark") } else { String::from("Light") },
                    is_toggle: true,
                    toggle_state: self.dark_mode,
                },
                SettingItem {
                    key: String::from("accent_color"),
                    title: String::from("Accent color"),
                    description: String::from("Choose an accent color for taskbar and title bars"),
                    current_value: String::from("CorOS Blue (#0078D7)"),
                    is_toggle: false,
                    toggle_state: false,
                },
                SettingItem {
                    key: String::from("taskbar_alignment"),
                    title: String::from("Taskbar alignment"),
                    description: String::from("Align icons to Center or Left"),
                    current_value: if self.taskbar_centered { String::from("Center") } else { String::from("Left") },
                    is_toggle: true,
                    toggle_state: self.taskbar_centered,
                },
                SettingItem {
                    key: String::from("transparency"),
                    title: String::from("Transparency effects"),
                    description: String::from("Windows and surfaces appear translucent (Mica/Acrylic)"),
                    current_value: String::from("On"),
                    is_toggle: true,
                    toggle_state: true,
                },
            ],
            SettingsCategory::NetworkInternet => alloc::vec![
                SettingItem {
                    key: String::from("net_status"),
                    title: String::from("Ethernet"),
                    description: String::from("Connected | Intel PRO/1000 MT Desktop Adapter"),
                    current_value: String::from("192.168.1.150"),
                    is_toggle: false,
                    toggle_state: false,
                },
                SettingItem {
                    key: String::from("dns_settings"),
                    title: String::from("DNS server assignment"),
                    description: String::from("Encrypted DNS over TLS / HTTPS"),
                    current_value: String::from("Automatic (DHCP)"),
                    is_toggle: false,
                    toggle_state: false,
                },
            ],
            SettingsCategory::WindowsUpdate => alloc::vec![
                SettingItem {
                    key: String::from("update_status"),
                    title: String::from("You're up to date"),
                    description: String::from("Last checked: Today, 14:28"),
                    current_value: String::from("CorOS 2026 Update Ready"),
                    is_toggle: false,
                    toggle_state: false,
                },
                SettingItem {
                    key: String::from("auto_update"),
                    title: String::from("Get the latest updates as soon as they're available"),
                    description: String::from("Be among the first to get the latest non-security updates"),
                    current_value: if self.auto_update { String::from("On") } else { String::from("Off") },
                    is_toggle: true,
                    toggle_state: self.auto_update,
                },
            ],
            _ => alloc::vec![
                SettingItem {
                    key: String::from("placeholder"),
                    title: alloc::format!("{} Settings", cat.title()),
                    description: String::from("Configurable parameters for this hardware profile"),
                    current_value: String::from("Standard"),
                    is_toggle: false,
                    toggle_state: false,
                }
            ],
        }
    }
}

//! CorOS Custom Wallpaper Resource
//! Provides user-customizable 1024x768 24-bit wallpaper BMP.

pub static CUSTOM_WALLPAPER_BMP: &[u8] = include_bytes!("../../../../assets/wallpapers/wallpaper.bmp");

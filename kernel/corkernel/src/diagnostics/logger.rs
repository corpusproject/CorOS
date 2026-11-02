use crate::diagnostics::serial;
use corboot_info::BootInfo;
use core::fmt::{self, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel { Trace, Debug, Info, Warn, Error, Panic }
impl LogLevel { fn label(self) -> &'static str { match self { Self::Trace=>"TRACE",Self::Debug=>"DEBUG",Self::Info=>"INFO",Self::Warn=>"WARN",Self::Error=>"ERROR",Self::Panic=>"PANIC" } } }

/// Allocation-free early logger.
/// # Safety
/// Any supplied BootInfo and its memory-map range must be validated, readable, and live.
pub unsafe fn log(info: Option<&BootInfo>, level: LogLevel, message: &str) {
    let label = level.label();
    serial::write_str("[COROS "); serial::write_str(label); serial::write_str("] "); serial::write_str(message); serial::write_str("\r\n");
    let _ = info;
}

pub fn log_info(message: &str) {
    unsafe { log(None, LogLevel::Info, message); }
}

struct SerialWriter;
impl Write for SerialWriter {
    fn write_str(&mut self, text: &str) -> fmt::Result { serial::write_str(text); Ok(()) }
}

/// # Safety
/// Any supplied BootInfo and its memory-map range must be validated, readable, and live.
pub unsafe fn log_panic(info: Option<&BootInfo>, panic: &core::panic::PanicInfo<'_>) {
    serial::write_str("[COROS PANIC] COROS KERNEL PANIC");
    if let Some(location) = panic.location() {
        let _ = write!(SerialWriter, " at {}:{}:{}", location.file(), location.line(), location.column());
    }
    serial::write_str("\r\n");
    let _ = info;
    serial::write_str("COROS KERNEL HALTED\r\n");
}

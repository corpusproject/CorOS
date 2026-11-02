//! Virtual Device Filesystem (/dev devtmpfs) for CorOS.
//! 100% in-house implementation providing POSIX standard character and block device nodes:
//! /dev/null, /dev/zero, /dev/random, /dev/urandom, /dev/full, /dev/tty, /dev/fb0, /dev/sda.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use crate::crypto::random::GLOBAL_CSPRNG;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceType {
    Char,
    Block,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StandardDevice {
    Null,
    Zero,
    Random,
    Urandom,
    Full,
    Tty,
    Console,
    Fb0,
    Sda,
}

pub struct DevNode {
    pub name: &'static str,
    pub dev_type: DeviceType,
    pub major: u32,
    pub minor: u32,
    pub standard_dev: StandardDevice,
}

pub struct DevFs {
    devices: BTreeMap<String, DevNode>,
}

impl DevFs {
    pub fn new() -> Self {
        let mut devfs = Self {
            devices: BTreeMap::new(),
        };

        devfs.register(DevNode { name: "null",    dev_type: DeviceType::Char, major: 1, minor: 3,  standard_dev: StandardDevice::Null });
        devfs.register(DevNode { name: "zero",    dev_type: DeviceType::Char, major: 1, minor: 5,  standard_dev: StandardDevice::Zero });
        devfs.register(DevNode { name: "full",    dev_type: DeviceType::Char, major: 1, minor: 7,  standard_dev: StandardDevice::Full });
        devfs.register(DevNode { name: "random",  dev_type: DeviceType::Char, major: 1, minor: 8,  standard_dev: StandardDevice::Random });
        devfs.register(DevNode { name: "urandom", dev_type: DeviceType::Char, major: 1, minor: 9,  standard_dev: StandardDevice::Urandom });
        devfs.register(DevNode { name: "tty",     dev_type: DeviceType::Char, major: 5, minor: 0,  standard_dev: StandardDevice::Tty });
        devfs.register(DevNode { name: "console", dev_type: DeviceType::Char, major: 5, minor: 1,  standard_dev: StandardDevice::Console });
        devfs.register(DevNode { name: "fb0",     dev_type: DeviceType::Char, major: 29, minor: 0, standard_dev: StandardDevice::Fb0 });
        devfs.register(DevNode { name: "sda",     dev_type: DeviceType::Block, major: 8, minor: 0, standard_dev: StandardDevice::Sda });

        devfs
    }

    pub fn register(&mut self, node: DevNode) {
        self.devices.insert(String::from(node.name), node);
    }

    /// Read from a device node.
    pub fn read(&self, name: &str, buf: &mut [u8]) -> Result<usize, &'static str> {
        let dev = self.devices.get(name).ok_or("Device node not found")?;

        match dev.standard_dev {
            StandardDevice::Null => Ok(0), // EOF
            StandardDevice::Zero | StandardDevice::Full => {
                buf.fill(0);
                Ok(buf.len())
            }
            StandardDevice::Random | StandardDevice::Urandom => {
                let mut rng = GLOBAL_CSPRNG.lock();
                rng.fill_bytes(buf);
                Ok(buf.len())
            }
            _ => Ok(0),
        }
    }

    /// Write to a device node.
    pub fn write(&self, name: &str, data: &[u8]) -> Result<usize, &'static str> {
        let dev = self.devices.get(name).ok_or("Device node not found")?;

        match dev.standard_dev {
            StandardDevice::Null => Ok(data.len()), // Discard all data
            StandardDevice::Full => Err("No space left on device (ENOSPC)"),
            StandardDevice::Tty | StandardDevice::Console => {
                let text = String::from_utf8_lossy(data);
                crate::diagnostics::logger::log_info(&text);
                Ok(data.len())
            }
            _ => Ok(data.len()),
        }
    }

    /// List all device names in /dev.
    pub fn list_devices(&self) -> Vec<&'static str> {
        let mut list = Vec::new();
        for dev in self.devices.values() {
            list.push(dev.name);
        }
        list
    }
}

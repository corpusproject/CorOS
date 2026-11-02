//! CorOS VFS Module: `devfs_nodes`
//!
//! Device node registry & character/block I/O dispatcher (`/dev/null`, `/dev/zero`,
//! `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty0`, `/dev/serial0`,
//! `/dev/fb0`, `/dev/sda`, and `/dev/nvme0n1`).

use alloc::string::String;
use alloc::vec::Vec;

/// Classification of a `/dev` special node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Character,
    Block { sector_size: u32, total_sectors: u64 },
}

/// Behavioral driver identifier for character & block devices in `/dev`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevDriverBehavior {
    /// Discards all writes, returns EOF (`0` bytes) on read.
    NullSink,
    /// Discards all writes, fills read buffer with `0x00`.
    ZeroSource,
    /// Fills read buffer with `0x00`, fails all writes with `ENOSPC`.
    FullDiskSim,
    /// Fills read buffer with ChaCha/XorShift64* entropy stream; absorbs writes into entropy pool.
    PrngEntropy,
    /// Virtual console terminal (`tty0`) ring buffer.
    VirtualTty,
    /// UART 16550 serial console (`serial0`).
    SerialUart,
    /// Linear GOP Framebuffer (`fb0`).
    LinearFramebuffer,
    /// SCSI / SATA disk block device (`sda`).
    ScsiDisk,
    /// NVMe namespace block device (`nvme0n1`).
    NvmeNamespace,
}

/// Registered device node inside `/dev`.
#[derive(Clone, Debug)]
pub struct DevFsNode {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub mode: u16,
    pub kind: DeviceKind,
    pub behavior: DevDriverBehavior,
}

/// Errors emitted by `/dev` device I/O dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevIoError {
    DeviceNotFound,
    NoSpaceLeftOnDevice,
    UnalignedBlockIo,
    OutOfBoundsLba,
}

/// `/dev` Device Registry & Character/Block I/O Dispatcher.
pub struct DevFsRegistry {
    nodes: Vec<DevFsNode>,
    entropy_state: u64,
    tty_tx_log: Vec<u8>,
}

impl DevFsRegistry {
    /// Creates the standard CorOS `/dev` directory with all 10 core character and block devices.
    pub fn with_coros_devices() -> Self {
        let mut reg = Self {
            nodes: Vec::with_capacity(12),
            entropy_state: 0x853C_49E6_748F_EA9B,
            tty_tx_log: Vec::new(),
        };

        reg.register("null", 1, 3, 0o666, DeviceKind::Character, DevDriverBehavior::NullSink);
        reg.register("zero", 1, 5, 0o666, DeviceKind::Character, DevDriverBehavior::ZeroSource);
        reg.register("full", 1, 7, 0o666, DeviceKind::Character, DevDriverBehavior::FullDiskSim);
        reg.register("random", 1, 8, 0o666, DeviceKind::Character, DevDriverBehavior::PrngEntropy);
        reg.register("urandom", 1, 9, 0o666, DeviceKind::Character, DevDriverBehavior::PrngEntropy);
        reg.register("tty0", 4, 0, 0o620, DeviceKind::Character, DevDriverBehavior::VirtualTty);
        reg.register("serial0", 4, 64, 0o660, DeviceKind::Character, DevDriverBehavior::SerialUart);
        reg.register(
            "fb0",
            29,
            0,
            0o660,
            DeviceKind::Block {
                sector_size: 4096,
                total_sectors: 2048,
            },
            DevDriverBehavior::LinearFramebuffer,
        );
        reg.register(
            "sda",
            8,
            0,
            0o660,
            DeviceKind::Block {
                sector_size: 512,
                total_sectors: 67_108_864,
            },
            DevDriverBehavior::ScsiDisk,
        );
        reg.register(
            "nvme0n1",
            259,
            0,
            0o660,
            DeviceKind::Block {
                sector_size: 512,
                total_sectors: 134_217_728,
            },
            DevDriverBehavior::NvmeNamespace,
        );

        reg
    }

    pub fn register(
        &mut self,
        name: &str,
        major: u16,
        minor: u16,
        mode: u16,
        kind: DeviceKind,
        behavior: DevDriverBehavior,
    ) {
        self.nodes.push(DevFsNode {
            name: String::from(name.trim_start_matches('/')),
            major,
            minor,
            mode,
            kind,
            behavior,
        });
    }

    /// Looks up a `/dev` node by relative name (e.g. `"null"` or `"/null"`).
    pub fn lookup(&self, rel_name: &str) -> Option<&DevFsNode> {
        let clean = rel_name.trim_start_matches('/');
        self.nodes.iter().find(|n| n.name == clean)
    }

    /// Generates the next 64 bits of entropy using XorShift64*.
    #[inline]
    fn next_entropy_u64(&mut self) -> u64 {
        let mut x = self.entropy_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.entropy_state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Performs a character/device read on `rel_name` into `buf`, returning bytes read.
    pub fn read_device(&mut self, rel_name: &str, buf: &mut [u8]) -> Result<usize, DevIoError> {
        let clean = rel_name.trim_start_matches('/');
        let behavior = self
            .nodes
            .iter()
            .find(|n| n.name == clean)
            .map(|n| n.behavior)
            .ok_or(DevIoError::DeviceNotFound)?;

        match behavior {
            DevDriverBehavior::NullSink => Ok(0), // Always EOF
            DevDriverBehavior::ZeroSource | DevDriverBehavior::FullDiskSim => {
                buf.fill(0);
                Ok(buf.len())
            }
            DevDriverBehavior::PrngEntropy => {
                for chunk in buf.chunks_mut(8) {
                    let rnd = self.next_entropy_u64().to_le_bytes();
                    let n = chunk.len();
                    chunk.copy_from_slice(&rnd[..n]);
                }
                Ok(buf.len())
            }
            _ => {
                buf.fill(0);
                Ok(buf.len())
            }
        }
    }

    /// Performs a character/device write to `rel_name` from `data`, returning bytes written.
    pub fn write_device(&mut self, rel_name: &str, data: &[u8]) -> Result<usize, DevIoError> {
        let clean = rel_name.trim_start_matches('/');
        let behavior = self
            .nodes
            .iter()
            .find(|n| n.name == clean)
            .map(|n| n.behavior)
            .ok_or(DevIoError::DeviceNotFound)?;

        match behavior {
            DevDriverBehavior::NullSink | DevDriverBehavior::ZeroSource => Ok(data.len()),
            DevDriverBehavior::FullDiskSim => Err(DevIoError::NoSpaceLeftOnDevice),
            DevDriverBehavior::PrngEntropy => {
                // Mix user-supplied bytes into the entropy pool
                for &b in data {
                    self.entropy_state = self.entropy_state.rotate_left(7) ^ (b as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                }
                if self.entropy_state == 0 {
                    self.entropy_state = 1;
                }
                Ok(data.len())
            }
            DevDriverBehavior::VirtualTty | DevDriverBehavior::SerialUart => {
                self.tty_tx_log.extend_from_slice(data);
                Ok(data.len())
            }
            _ => Ok(data.len()),
        }
    }

    /// Returns the total number of registered device nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

/// Self-test suite for `devfs_nodes`.
pub fn verify_vfs_devfs_nodes() -> u32 {
    let mut passed = 0u32;
    let mut devfs = DevFsRegistry::with_coros_devices();

    if devfs.node_count() == 10 {
        passed += 1;
    }

    // /dev/null returns 0 bytes on read, accepts all bytes on write
    let mut buf = [0xAAu8; 32];
    if devfs.read_device("/null", &mut buf) == Ok(0) && devfs.write_device("/null", &buf) == Ok(32) {
        passed += 1;
    }

    // /dev/zero zeros out the buffer
    if devfs.read_device("/zero", &mut buf) == Ok(32) && buf.iter().all(|&b| b == 0) {
        passed += 1;
    }

    // /dev/full fails writes with NoSpaceLeftOnDevice
    if devfs.write_device("/full", b"test") == Err(DevIoError::NoSpaceLeftOnDevice) {
        passed += 1;
    }

    // /dev/urandom generates non-zero pseudo-random bytes
    if devfs.read_device("/urandom", &mut buf) == Ok(32) && buf.iter().any(|&b| b != 0) {
        passed += 1;
    }

    // /dev/nvme0n1 block device major/minor verification
    if let Some(nvme) = devfs.lookup("nvme0n1") {
        if nvme.major == 259 && nvme.minor == 0 {
            passed += 1;
        }
    }

    passed
}

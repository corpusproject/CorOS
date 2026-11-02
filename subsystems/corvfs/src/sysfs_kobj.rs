//! CorOS VFS Module: `sysfs_kobj`
//!
//! Hierarchical `/sys` kernel object (`kobject`) attribute tree supporting
//! `/sys/bus/pci/devices`, `/sys/class/net`, `/sys/class/block`,
//! `/sys/devices/system/cpu`, and `/sys/firmware/acpi/tables`.

use alloc::string::String;
use alloc::vec::Vec;

/// Attribute node attached to a `KObject` in `/sys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SysFsAttribute {
    pub name: String,
    pub value: String,
    pub writable: bool,
}

/// Kernel Object (`kobject`) directory node within the `/sys` hierarchy.
#[derive(Clone, Debug)]
pub struct KObjectNode {
    pub path: String,
    pub subsystem: &'static str,
    pub attributes: Vec<SysFsAttribute>,
}

/// `/sys` Hierarchical KObject Registry & Attribute Store.
pub struct SysFsKObjTree {
    nodes: Vec<KObjectNode>,
}

impl SysFsKObjTree {
    pub const fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Populates the standard CorOS hardware topology under `/sys`.
    pub fn with_coros_topology() -> Self {
        let mut tree = Self::new();

        // /sys/bus/pci/devices/0000:00:02.0 (VirtIO / Bochs / Gop GPU)
        tree.register_kobject(
            "/bus/pci/devices/0000:00:02.0",
            "pci",
            &[
                ("vendor", "0x1234", false),
                ("device", "0x1111", false),
                ("class", "0x030000", false),
                ("irq", "11", false),
                ("enable", "1", true),
            ],
        );

        // /sys/bus/pci/devices/0000:00:04.0 (NVMe Controller)
        tree.register_kobject(
            "/bus/pci/devices/0000:00:04.0",
            "pci",
            &[
                ("vendor", "0x1b36", false),
                ("device", "0x0010", false),
                ("class", "0x010802", false),
                ("irq", "48", false),
                ("numa_node", "0", false),
            ],
        );

        // /sys/class/net/eth0
        tree.register_kobject(
            "/class/net/eth0",
            "net",
            &[
                ("address", "52:54:00:12:34:56", false),
                ("mtu", "1500", true),
                ("operstate", "up", false),
                ("speed", "10000", false),
                ("tx_queue_len", "1000", true),
            ],
        );

        // /sys/class/block/nvme0n1
        tree.register_kobject(
            "/class/block/nvme0n1",
            "block",
            &[
                ("size", "134217728", false), // 64 GiB in 512B sectors
                ("ro", "0", false),
                ("removable", "0", false),
                ("dev", "259:0", false),
            ],
        );

        // /sys/devices/system/cpu/cpu0
        tree.register_kobject(
            "/devices/system/cpu/cpu0",
            "cpu",
            &[
                ("online", "1", false),
                ("topology_core_id", "0", false),
                ("cpufreq_scaling_governor", "performance", true),
            ],
        );

        // /sys/firmware/acpi/tables
        tree.register_kobject(
            "/firmware/acpi/tables",
            "acpi",
            &[
                ("APIC", "MADT_v4_LAPIC_IOAPIC", false),
                ("FACP", "FADT_v6_PM_PROFILE_WORKSTATION", false),
                ("MCFG", "PCIE_ECAM_0xE0000000", false),
                ("HPET", "HPET_0xFED00000", false),
            ],
        );

        tree
    }

    /// Registers a `KObjectNode` and its attributes at `kobj_rel_path` (relative to `/sys`).
    pub fn register_kobject(&mut self, kobj_rel_path: &str, subsystem: &'static str, attrs: &[(&str, &str, bool)]) {
        let clean_path = kobj_rel_path.trim_end_matches('/');
        let mut attributes = Vec::with_capacity(attrs.len());
        for &(name, val, writable) in attrs {
            attributes.push(SysFsAttribute {
                name: String::from(name),
                value: String::from(val),
                writable,
            });
        }

        self.nodes.push(KObjectNode {
            path: String::from(clean_path),
            subsystem,
            attributes,
        });
    }

    ///Splits a `/sys`-relative attribute path `"/class/net/eth0/mtu"` into `("/class/net/eth0", "mtu")`.
    fn split_kobj_attr(rel_path: &str) -> Option<(&str, &str)> {
        let trimmed = rel_path.trim_end_matches('/');
        let slash_idx = trimmed.rfind('/')?;
        if slash_idx == 0 {
            return None;
        }
        Some((&trimmed[..slash_idx], &trimmed[slash_idx + 1..]))
    }

    /// Reads an attribute value from `/sys` by its `/sys`-relative path.
    pub fn read_attribute(&self, rel_path: &str) -> Option<&str> {
        let (kobj_path, attr_name) = Self::split_kobj_attr(rel_path)?;
        let node = self.nodes.iter().find(|n| n.path == kobj_path)?;
        let attr = node.attributes.iter().find(|a| a.name == attr_name)?;
        Some(attr.value.as_str())
    }

    /// Writes a new value to a writable `/sys` attribute (e.g., changing `/class/net/eth0/mtu`).
    pub fn write_attribute(&mut self, rel_path: &str, new_val: &str) -> Result<(), &'static str> {
        let (kobj_path, attr_name) = Self::split_kobj_attr(rel_path).ok_or("Invalid sysfs attribute path")?;
        let node = self
            .nodes
            .iter_mut()
            .find(|n| n.path == kobj_path)
            .ok_or("KObject not found")?;
        let attr = node
            .attributes
            .iter_mut()
            .find(|a| a.name == attr_name)
            .ok_or("Sysfs attribute not found")?;

        if !attr.writable {
            return Err("Sysfs attribute is read-only");
        }
        attr.value = String::from(new_val);
        Ok(())
    }

    /// Lists all attribute names inside a `kobject` directory.
    pub fn list_attributes(&self, kobj_rel_path: &str) -> Option<Vec<&str>> {
        let clean = kobj_rel_path.trim_end_matches('/');
        let node = self.nodes.iter().find(|n| n.path == clean)?;
        Some(node.attributes.iter().map(|a| a.name.as_str()).collect())
    }
}

/// Self-test suite for `sysfs_kobj`.
pub fn verify_vfs_sysfs_kobj() -> u32 {
    let mut passed = 0u32;
    let mut sysfs = SysFsKObjTree::with_coros_topology();

    if sysfs.read_attribute("/bus/pci/devices/0000:00:04.0/vendor") == Some("0x1b36") {
        passed += 1;
    }

    if sysfs.read_attribute("/class/block/nvme0n1/dev") == Some("259:0") {
        passed += 1;
    }

    // Attempt to write a read-only attribute (must fail)
    if sysfs.write_attribute("/class/net/eth0/address", "00:11:22:33:44:55").is_err() {
        passed += 1;
    }

    // Write a writable attribute (MTU -> 9000 jumbo frames) and verify readback
    if sysfs.write_attribute("/class/net/eth0/mtu", "9000").is_ok()
        && sysfs.read_attribute("/class/net/eth0/mtu") == Some("9000")
    {
        passed += 1;
    }

    if let Some(acpi_tables) = sysfs.list_attributes("/firmware/acpi/tables") {
        if acpi_tables.len() == 4 && acpi_tables.contains(&"MCFG") {
            passed += 1;
        }
    }

    passed
}

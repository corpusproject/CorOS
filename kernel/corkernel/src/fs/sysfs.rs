//! Pure Bare-Metal SysFS (Virtual /sys Device Hierarchy) for CorOS.
//! 100% in-house implementation representing kernel device hierarchy,
//! bus topology, device drivers, power states, and system attributes.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct SysfsAttribute {
    pub name: String,
    pub value: String,
    pub writable: bool,
}

#[derive(Clone, Debug)]
pub struct SysfsNode {
    pub name: String,
    pub is_dir: bool,
    pub children: BTreeMap<String, SysfsNode>,
    pub attributes: BTreeMap<String, SysfsAttribute>,
}

impl SysfsNode {
    pub fn new_dir(name: &str) -> Self {
        Self {
            name: String::from(name),
            is_dir: true,
            children: BTreeMap::new(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn add_attribute(&mut self, name: &str, value: &str, writable: bool) {
        self.attributes.insert(String::from(name), SysfsAttribute {
            name: String::from(name),
            value: String::from(value),
            writable,
        });
    }

    pub fn get_or_create_child(&mut self, name: &str) -> &mut SysfsNode {
        if !self.children.contains_key(name) {
            self.children.insert(String::from(name), SysfsNode::new_dir(name));
        }
        self.children.get_mut(name).unwrap()
    }
}

pub struct SysFs {
    root: SysfsNode,
}

impl SysFs {
    pub fn new() -> Self {
        let mut root = SysfsNode::new_dir("sys");

        // 1. /sys/block/
        {
            let block = root.get_or_create_child("block");
            let sda = block.get_or_create_child("sda");
            sda.add_attribute("size", "20971520", false); // 10 GB
            sda.add_attribute("removable", "0", false);
            sda.add_attribute("ro", "0", false);
            sda.add_attribute("model", "CorOS Virtual Block Device", false);

            let nvme0n1 = block.get_or_create_child("nvme0n1");
            nvme0n1.add_attribute("size", "104857600", false); // 50 GB
            nvme0n1.add_attribute("removable", "0", false);
            nvme0n1.add_attribute("model", "Samsung NVMe SSD 980 Pro", false);
        }

        // 2. /sys/bus/
        {
            let bus = root.get_or_create_child("bus");
            let pci = bus.get_or_create_child("pci");
            let pci_devs = pci.get_or_create_child("devices");

            // Host Bridge
            let dev0 = pci_devs.get_or_create_child("0000:00:00.0");
            dev0.add_attribute("vendor", "0x8086", false);
            dev0.add_attribute("device", "0x1237", false);
            dev0.add_attribute("class", "0x060000", false);

            // VGA Controller
            let dev2 = pci_devs.get_or_create_child("0000:00:02.0");
            dev2.add_attribute("vendor", "0x1234", false);
            dev2.add_attribute("device", "0x1111", false);
            dev2.add_attribute("class", "0x030000", false);

            // Intel E1000 NIC
            let dev3 = pci_devs.get_or_create_child("0000:00:03.0");
            dev3.add_attribute("vendor", "0x8086", false);
            dev3.add_attribute("device", "0x100e", false);
            dev3.add_attribute("class", "0x020000", false);

            // AHCI SATA Controller
            let dev31 = pci_devs.get_or_create_child("0000:00:1f.2");
            dev31.add_attribute("vendor", "0x8086", false);
            dev31.add_attribute("device", "0x2829", false);
            dev31.add_attribute("class", "0x010601", false);
        }

        // 3. /sys/class/
        {
            let class = root.get_or_create_child("class");
            let net = class.get_or_create_child("net");

            let eth0 = net.get_or_create_child("eth0");
            eth0.add_attribute("address", "08:00:27:12:34:56", false);
            eth0.add_attribute("operstate", "up", false);
            eth0.add_attribute("mtu", "1500", true);
            eth0.add_attribute("speed", "1000", false);
            eth0.add_attribute("duplex", "full", false);

            let lo = net.get_or_create_child("lo");
            lo.add_attribute("address", "00:00:00:00:00:00", false);
            lo.add_attribute("operstate", "up", false);
            lo.add_attribute("mtu", "65536", false);
        }

        // 4. /sys/kernel/
        {
            let kernel = root.get_or_create_child("kernel");
            let mm = kernel.get_or_create_child("mm");
            mm.add_attribute("transparent_hugepage", "always", true);

            let sec = kernel.get_or_create_child("security");
            sec.add_attribute("secure_boot", "1", false);
            sec.add_attribute("lsm", "cor_srm", false);
        }

        Self { root }
    }

    /// Read attribute value from sysfs path e.g. `/sys/class/net/eth0/operstate`.
    pub fn read_file(&self, path: &str) -> Option<String> {
        let clean = path.trim_start_matches("/sys/").trim_start_matches('/');
        let mut cur = &self.root;

        let parts: Vec<&str> = clean.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return None;
        }

        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Last part: could be attribute
                if let Some(attr) = cur.attributes.get(*part) {
                    let mut val = attr.value.clone();
                    val.push('\n');
                    return Some(val);
                }
            }

            if let Some(child) = cur.children.get(*part) {
                cur = child;
            } else {
                return None;
            }
        }

        None
    }

    /// List directory contents in sysfs.
    pub fn list_dir(&self, path: &str) -> Option<Vec<String>> {
        let clean = path.trim_start_matches("/sys/").trim_start_matches('/');
        let mut cur = &self.root;

        if !clean.is_empty() {
            for part in clean.split('/').filter(|p| !p.is_empty()) {
                if let Some(child) = cur.children.get(part) {
                    cur = child;
                } else {
                    return None;
                }
            }
        }

        let mut entries = Vec::new();
        for child_name in cur.children.keys() {
            entries.push(child_name.clone());
        }
        for attr_name in cur.attributes.keys() {
            entries.push(attr_name.clone());
        }

        Some(entries)
    }
}

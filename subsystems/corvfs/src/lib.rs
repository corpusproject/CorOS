#![no_std]
//! `corvfs` — CorOS Multi-Filesystem Virtual File System (VFS) & Storage Stack.

extern crate alloc;

pub mod mount_table;
pub mod inode_cache;
pub mod fd_table;
pub mod fat32_esp;
pub mod corfs_extent;
pub mod procfs_tree;
pub mod sysfs_kobj;
pub mod devfs_nodes;
pub mod tmpfs_ram;
pub mod initramfs_cpio;
pub mod page_cache;
pub mod vfs_permissions;
pub mod elf64_loader;
pub mod fs_journal;
pub mod quota_tracker;
pub mod mime_registry;
pub mod traits;

pub use traits::{DirEntry, FileSystem, FsError, Inode};

/// Runs VFS self-tests across all 16 filesystem modules.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;
    passed += mount_table::verify_vfs_mount_table();
    passed += inode_cache::verify_vfs_inode_cache();
    passed += fd_table::verify_vfs_fd_table();
    passed += fat32_esp::verify_vfs_fat32_esp();
    passed += corfs_extent::verify_vfs_corfs_extent();
    passed += procfs_tree::verify_vfs_procfs_tree();
    passed += sysfs_kobj::verify_vfs_sysfs_kobj();
    passed += devfs_nodes::verify_vfs_devfs_nodes();
    passed += tmpfs_ram::verify_vfs_tmpfs_ram();
    passed += initramfs_cpio::verify_vfs_initramfs_cpio();
    passed += page_cache::verify_vfs_page_cache();
    passed += vfs_permissions::verify_vfs_vfs_permissions();
    passed += elf64_loader::verify_vfs_elf64_loader();
    passed += fs_journal::verify_vfs_fs_journal();
    passed += quota_tracker::verify_vfs_quota_tracker();
    passed += mime_registry::verify_vfs_mime_registry();
    passed += traits::verify_vfs_traits();
    passed
}

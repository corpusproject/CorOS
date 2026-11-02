#![no_std]
//! `corfsdb` — CorOS Filesystem Signatures, Binary Superblock Layouts & Inode Structures.
//! Pure `#![no_std]` Rust filesystem format registry without numbered template repetition.

extern crate alloc;

pub mod ext4_layout;
pub mod btrfs_xfs_layout;
pub mod ntfs_layout;
pub mod iso9660_udf;
pub mod f2fs_layout;
pub mod zfs_uberblock;

/// Runs self-tests verifying filesystem magic numbers, endian conversions and structural alignments.
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. Ext4 superblock verification
    let ext4_sb = ext4_layout::Ext4Superblock {
        s_inodes_count: 1000,
        s_blocks_count_lo: 4000,
        s_r_blocks_count_lo: 200,
        s_free_blocks_count_lo: 3500,
        s_free_inodes_count: 900,
        s_first_data_block: 0,
        s_log_block_size: 2, // 1024 << 2 = 4096 bytes
        s_log_cluster_size: 2,
        s_blocks_per_group: 32768,
        s_clusters_per_group: 32768,
        s_inodes_per_group: 8192,
        s_mtime: 0,
        s_wtime: 0,
        s_mnt_count: 1,
        s_max_mnt_count: 30,
        s_magic: ext4_layout::EXT4_SUPERBLOCK_MAGIC,
        s_state: 1,
        s_errors: 1,
        s_minor_rev_level: 0,
        s_lastcheck: 0,
        s_checkinterval: 0,
        s_creator_os: 0,
        s_rev_level: 1,
        s_def_resuid: 0,
        s_def_resgid: 0,
        s_first_ino: 11,
        s_inode_size: 256,
        s_block_group_nr: 0,
        s_feature_compat: 0,
        s_feature_incompat: ext4_layout::ext4_feature_incompat::INCOMPAT_EXTENTS,
        s_feature_ro_compat: 0,
        s_uuid: [0u8; 16],
        s_volume_name: [0u8; 16],
    };
    if ext4_sb.is_valid() && ext4_sb.block_size_bytes() == 4096 && ext4_sb.has_extents() {
        passed += 1;
    }

    // 2. Btrfs superblock validation
    let btrfs_sb = btrfs_xfs_layout::BtrfsSuperblock {
        csum: [0u8; 32],
        fsid: [0u8; 16],
        bytenr: 0x10000,
        flags: 0,
        magic: btrfs_xfs_layout::BTRFS_MAGIC,
        generation: 1,
        root: 0,
        chunk_root: 0,
        log_root: 0,
        log_root_transid: 0,
        total_bytes: 1_000_000_000,
        bytes_used: 100_000,
        root_dir_objectid: 6,
        num_devices: 1,
        sectorsize: 4096,
        nodesize: 16384,
        stripesize: 4096,
        sys_chunk_array_size: 0,
        chunk_root_generation: 1,
        compat_flags: 0,
        compat_ro_flags: 0,
        incompat_flags: 0,
        csum_type: 0,
        root_level: 0,
        chunk_root_level: 0,
        log_root_level: 0,
    };
    if btrfs_sb.is_valid() {
        passed += 1;
    }

    // 3. NTFS Boot Sector validation
    let ntfs_bs = ntfs_layout::NtfsBootSector {
        jump_instruction: [0xEB, 0x52, 0x90],
        oem_id: ntfs_layout::NTFS_OEM_ID,
        bytes_per_sector: 512,
        sectors_per_cluster: 8, // 4096 cluster
        reserved_sectors: 0,
        unused_zero0: [0; 3],
        unused_zero1: 0,
        media_descriptor: 0xF8,
        unused_zero2: 0,
        sectors_per_track: 63,
        number_of_heads: 255,
        hidden_sectors: 2048,
        unused_zero3: 0,
        total_sectors: 1_000_000,
        mft_cluster_lcn: 4,
        mft_mirror_cluster_lcn: 2,
        clusters_per_mft_record: -10, // 2^10 = 1024 bytes
        unused_zero4: [0; 3],
        clusters_per_index_buffer: -12,
        unused_zero5: [0; 3],
        volume_serial_number: 0x1234_5678_9ABC_DEF0,
        checksum: 0,
    };
    if ntfs_bs.is_valid() && ntfs_bs.cluster_size_bytes() == 4096 && ntfs_bs.mft_record_size_bytes() == 1024 {
        passed += 1;
    }

    // 4. ISO9660 PVD validation
    let pvd = iso9660_udf::Iso9660PrimaryVolumeDescriptor {
        type_code: 1,
        standard_id: iso9660_udf::ISO9660_STANDARD_ID,
        version: 1,
        unused0: 0,
        system_id: [0; 32],
        volume_id: [0; 32],
        unused1: [0; 8],
        volume_space_size_le: 1000,
        volume_space_size_be: 1000,
        unused2: [0; 32],
        volume_set_size_le: 1,
        volume_set_size_be: 1,
        volume_sequence_number_le: 1,
        volume_sequence_number_be: 1,
        logical_block_size_le: 2048,
        logical_block_size_be: 2048,
        path_table_size_le: 0,
        path_table_size_be: 0,
        type_l_path_table_loc: 0,
        opt_type_l_path_table_loc: 0,
        type_m_path_table_loc: 0,
        opt_type_m_path_table_loc: 0,
        root_directory_record: [0; 34],
        volume_set_id: [0; 128],
        publisher_id: [0; 128],
        data_preparer_id: [0; 128],
        application_id: [0; 128],
    };
    if pvd.is_valid() && pvd.block_size() == 2048 {
        passed += 1;
    }

    // 5. F2FS Superblock validation
    let f2fs_sb = f2fs_layout::F2fsSuperblock {
        magic: f2fs_layout::F2FS_SUPER_MAGIC,
        major_ver: 1,
        minor_ver: 16,
        log_sectorsize: 9, // 512 bytes
        log_sectors_per_block: 3, // 8 sectors = 4096 bytes
        log_blocksize: 12, // 4096 bytes
        log_blocks_per_seg: 9,
        segs_per_sec: 1,
        secs_per_zone: 1,
        checksum_offset: 0,
        block_count: 102400,
        section_count: 200,
        total_node_count: 4000,
        node_ino: 1,
        meta_ino: 2,
        root_ino: 3,
        active_logs: 6,
        cp_payload: 1,
        sit_nat_version_bitmap: [0; 64],
        extension_count: 0,
        extension_list: [[0; 8]; f2fs_layout::F2FS_MAX_EXTENSION],
    };
    if f2fs_sb.is_valid() && f2fs_sb.block_size() == 4096 && f2fs_sb.sector_size() == 512 {
        passed += 1;
    }

    // 6. ZFS Uberblock validation
    let zfs_ub = zfs_uberblock::ZfsUberblock {
        ub_magic: zfs_uberblock::UBERBLOCK_MAGIC,
        ub_version: 5000,
        ub_txg: 1024,
        ub_guid_sum: 0xDEADBEEF,
        ub_timestamp: 1600000000,
        ub_rootbp: zfs_uberblock::ZfsBlkPtr {
            dva: [zfs_uberblock::ZfsDva { vdev: 0, offset: 0 }; 3],
            prop: 0,
            pad: [0; 2],
            birth_txg: 1024,
            fill_count: 1,
            checksum: [0; 4],
        },
        ub_software_version: 5000,
        ub_mmp_magic: 0,
        ub_mmp_delay: 0,
        ub_mmp_seq: 0,
        ub_checkpoint_txg: 0,
    };
    if zfs_ub.is_valid() && zfs_ub.txg() == 1024 && !zfs_ub.is_big_endian() {
        passed += 1;
    }

    passed
}

#![no_std]
//! `corblock` — CorOS Block Layer (`bio`), Multi-Queue (`blk-mq`), I/O Schedulers, GPT/MBR, RAID & `dm-crypt` Subsystem.

extern crate alloc;

pub mod bio;
pub mod blk_mq;
pub mod io_scheduler;
pub mod gpt_partition;
pub mod software_raid;
pub mod dm_crypt;
pub mod thin_provision;
pub mod bcache;
pub mod loopback_blk;
pub mod smart_telemetry;

use alloc::vec;
use alloc::vec::Vec;

use bio::{Bio, BioOp, BioFlags, BioStatus, SECTOR_SIZE};
use blk_mq::{BlkMqController, BlkMqHctx};
use io_scheduler::{DeadlineScheduler, BfqScheduler, IoScheduler, SchedRequest, IoPriorityClass};
use gpt_partition::{crc32, Guid, GptHeader, GptPartitionEntry, GptDisk};
use software_raid::{SoftwareRaidArray, VirtualDisk, RaidLevel, RaidState};
use dm_crypt::{Aes128Cipher, XtsEngine, Luks2Header, DmCryptDevice, gf128_mul_x};
use thin_provision::ThinProvisioningManager;
use bcache::{BcacheDevice, CacheMode};
use loopback_blk::{LoopController, LoopConfig};
use smart_telemetry::{SmartAttribute, PredictiveFailureAnalyzer, DriveHealthStatus, NvmeSmartLog, ata_attr_id};

/// Executes comprehensive self-tests across all 10 `corblock` modules and returns
/// the total count of verified subsystems (10 when all pass).
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    if test_bio() {
        passed += 1;
    }
    if test_blk_mq() {
        passed += 1;
    }
    if test_io_scheduler() {
        passed += 1;
    }
    if test_gpt_partition() {
        passed += 1;
    }
    if test_software_raid() {
        passed += 1;
    }
    if test_dm_crypt() {
        passed += 1;
    }
    if test_thin_provision() {
        passed += 1;
    }
    if test_bcache() {
        passed += 1;
    }
    if test_loopback_blk() {
        passed += 1;
    }
    if test_smart_telemetry() {
        passed += 1;
    }

    passed
}

fn test_bio() -> bool {
    let mut bio = Bio::with_flags(BioOp::Write, 100, BioFlags::SYNC);
    let seg1 = vec![0xAAu8; SECTOR_SIZE];
    let seg2 = vec![0xBBu8; SECTOR_SIZE];

    bio.add_buffer(&seg1);
    bio.add_buffer(&seg2);

    if bio.sector_count() != 2 || !bio.is_write() || bio.bi_size != 1024 {
        return false;
    }

    // Split bio into two 512-byte sub-bios
    let Ok((mut first, second)) = bio.split(SECTOR_SIZE) else {
        return false;
    };

    if first.bi_sector != 100 || first.bi_size != SECTOR_SIZE {
        return false;
    }
    if second.bi_sector != 101 || second.bi_size != SECTOR_SIZE {
        return false;
    }

    // Test merging: merge second back into first
    if !first.can_merge(&second) {
        return false;
    }
    if first.merge(second).is_err() || first.bi_size != 1024 {
        return false;
    }

    // Test segment iterator advancement
    if !first.advance(256) || first.bi_iter.bytes_remaining != 768 {
        return false;
    }

    first.complete(BioStatus::Success);
    first.is_complete() && first.bi_status == BioStatus::Success
}

fn test_blk_mq() -> bool {
    let mut ctl = BlkMqController::new(4, 16);
    if ctl.hctx_count() != 4 {
        return false;
    }

    // Submit bios across 4 hardware queues
    let mut tags = Vec::new();
    for cpu in 0..4 {
        let mut b = Bio::new(BioOp::Read, 200 + (cpu as u64 * 8));
        b.add_buffer(&vec![0u8; 512]);
        let Ok((hctx_idx, tag)) = ctl.submit(cpu, b, 1_000_000, 50_000_000) else {
            return false;
        };
        tags.push((hctx_idx, tag));
    }

    // Dispatch batch on hctx 0
    let hctx0 = ctl.hctx_for_cpu(0);
    let dispatched = hctx0.dispatch_batch(8);
    if dispatched.is_empty() {
        return false;
    }

    // Complete all submitted requests
    for &(hctx_idx, tag) in &tags {
        if ctl.complete(hctx_idx, tag, BioStatus::Success).is_err() {
            return false;
        }
    }

    // Verify completion ring drainage
    let hctx0 = ctl.hctx_for_cpu(0);
    let completions = hctx0.poll_completions();
    if completions.is_empty() {
        return false;
    }

    // Test tag saturation and queue full handling
    let mut single_hctx = BlkMqHctx::new(0, 0, 4);
    for _ in 0..4 {
        let b = Bio::new(BioOp::Write, 50);
        if single_hctx.submit_bio(b, 100, 1000).is_err() {
            return false;
        }
    }
    let overflow_bio = Bio::new(BioOp::Write, 60);
    single_hctx.submit_bio(overflow_bio, 100, 1000).is_err() && single_hctx.busy_count() == 4
}

fn test_io_scheduler() -> bool {
    // 1. Deadline Scheduler verification
    let mut deadline = DeadlineScheduler::new(2);
    let req_read1 = SchedRequest::new(1, 1000, 8, false, 10_000);
    let req_read2 = SchedRequest::new(2, 200, 8, false, 10_000);
    let mut req_expired = SchedRequest::new(3, 5000, 8, false, 10_000);
    req_expired.deadline_ns = 15_000;

    deadline.insert_request(req_read1);
    deadline.insert_request(req_read2);
    deadline.insert_request(req_expired);

    // At tick 20_000, request 3 is expired -> must be dispatched first despite high sector LBA
    let first_out = deadline.dispatch_next(20_000);
    if first_out.map(|r| r.id) != Some(3) {
        return false;
    }

    // Next request dispatched follows elevator ordering: sector 200 before sector 1000
    let second_out = deadline.dispatch_next(20_000);
    if second_out.map(|r| r.id) != Some(2) {
        return false;
    }

    // 2. BFQ Scheduler verification
    let mut bfq = BfqScheduler::new(100);
    let req_rt = SchedRequest::new(10, 100, 8, false, 1000)
        .with_priority(IoPriorityClass::RealTime, 200)
        .with_entity(1);
    let req_be = SchedRequest::new(20, 200, 8, false, 1000)
        .with_priority(IoPriorityClass::BestEffort, 50)
        .with_entity(2);

    bfq.insert_request(req_be);
    bfq.insert_request(req_rt);

    // RealTime entity receives priority dispatch
    let bfq_first = bfq.dispatch_next(1000);
    bfq_first.map(|r| r.id) == Some(10)
}

fn test_gpt_partition() -> bool {
    // 1. Test standard IEEE 802.3 CRC32 vector
    if crc32(b"123456789") != 0xCBF4_3926 {
        return false;
    }

    // 2. Build a synthetic GPT disk image
    const SECTOR_SZ: usize = 512;
    let mut disk_data = vec![0u8; SECTOR_SZ * 40];

    // LBA 0: Protective MBR
    disk_data[510] = 0x55;
    disk_data[511] = 0xAA;
    disk_data[446 + 4] = 0xEE; // Partition type 0xEE

    // LBA 2..33: Partition Entries Array
    let mut part1 = GptPartitionEntry {
        type_guid: Guid::EFI_SYSTEM,
        unique_guid: Guid([1u8; 16]),
        starting_lba: 2048,
        ending_lba: 4095,
        attributes: GptPartitionEntry::ATTR_SYSTEM_PARTITION,
        name: [0u16; 36],
    };
    part1.name[0] = 'E' as u16;
    part1.name[1] = 'S' as u16;
    part1.name[2] = 'P' as u16;

    let mut part2 = GptPartitionEntry {
        type_guid: Guid::COROS_ROOT,
        unique_guid: Guid([2u8; 16]),
        starting_lba: 4096,
        ending_lba: 8191,
        attributes: 0,
        name: [0u16; 36],
    };
    let root_str = "CorOS";
    for (i, c) in root_str.chars().enumerate() {
        part2.name[i] = c as u16;
    }

    let mut entries_bytes = vec![0u8; 128 * 128];
    entries_bytes[0..128].copy_from_slice(&part1.serialize());
    entries_bytes[128..256].copy_from_slice(&part2.serialize());
    let entries_crc = crc32(&entries_bytes);

    // Place entries at LBA 2
    disk_data[SECTOR_SZ * 2..SECTOR_SZ * 2 + entries_bytes.len()].copy_from_slice(&entries_bytes);

    // LBA 1: GPT Header
    let header = GptHeader {
        signature: *b"EFI PART",
        revision: 0x0001_0000,
        header_size: 92,
        header_crc32: 0,
        reserved: 0,
        current_lba: 1,
        backup_lba: 39,
        first_usable_lba: 34,
        last_usable_lba: 38,
        disk_guid: Guid([0x42; 16]),
        partition_entry_lba: 2,
        num_partition_entries: 128,
        partition_entry_size: 128,
        partition_array_crc32: entries_crc,
    };
    let header_serialized = header.serialize();
    disk_data[SECTOR_SZ..SECTOR_SZ + header_serialized.len()].copy_from_slice(&header_serialized);

    // Parse and verify GPT disk
    let Ok(parsed_disk) = GptDisk::parse(&disk_data, SECTOR_SZ) else {
        return false;
    };

    if parsed_disk.partitions.len() != 2 {
        return false;
    }

    let Some(esp) = parsed_disk.find_partition_by_name("ESP") else {
        return false;
    };
    if esp.sector_count() != 2048 || !esp.is_system_partition() {
        return false;
    }

    let Some(root) = parsed_disk.find_partition_by_name("CorOS") else {
        return false;
    };
    root.starting_lba == 4096 && root.type_guid == Guid::COROS_ROOT
}

fn test_software_raid() -> bool {
    // 1. RAID 0 (Striping)
    let d0 = VirtualDisk::new(256);
    let d1 = VirtualDisk::new(256);
    let mut raid0 = SoftwareRaidArray::new(RaidLevel::Raid0, 4, vec![d0, d1]).unwrap();

    let write_buf = [0x5Au8; SECTOR_SIZE];
    if raid0.write_sector(5, &write_buf).is_err() {
        return false;
    }
    let mut read_buf = [0u8; SECTOR_SIZE];
    if raid0.read_sector(5, &mut read_buf).is_err() || read_buf != write_buf {
        return false;
    }

    // 2. RAID 1 (Mirroring & Rebuild)
    let m0 = VirtualDisk::new(128);
    let m1 = VirtualDisk::new(128);
    let mut raid1 = SoftwareRaidArray::new(RaidLevel::Raid1, 4, vec![m0, m1]).unwrap();

    let r1_data = [0xA5u8; SECTOR_SIZE];
    if raid1.write_sector(10, &r1_data).is_err() {
        return false;
    }

    // Fail disk 0 -> degraded read must succeed from disk 1
    if raid1.fail_disk(0).is_err() || raid1.state != RaidState::Degraded {
        return false;
    }
    read_buf.fill(0);
    if raid1.read_sector(10, &mut read_buf).is_err() || read_buf != r1_data {
        return false;
    }

    // Rebuild disk 0 -> returns to Optimal
    if raid1.rebuild_disk(0).is_err() || raid1.state != RaidState::Optimal {
        return false;
    }

    // 3. RAID 5 (Distributed Parity & Degraded XOR Rebuild)
    let p0 = VirtualDisk::new(128);
    let p1 = VirtualDisk::new(128);
    let p2 = VirtualDisk::new(128);
    let mut raid5 = SoftwareRaidArray::new(RaidLevel::Raid5, 4, vec![p0, p1, p2]).unwrap();

    let r5_data = [0x7Eu8; SECTOR_SIZE];
    if raid5.write_sector(2, &r5_data).is_err() {
        return false;
    }

    // Fail disk 1 -> degraded XOR read must reconstruct original data
    if raid5.fail_disk(1).is_err() || raid5.state != RaidState::Degraded {
        return false;
    }
    read_buf.fill(0);
    if raid5.read_sector(2, &mut read_buf).is_err() || read_buf != r5_data {
        return false;
    }

    // Rebuild disk 1
    raid5.rebuild_disk(1).is_ok() && raid5.state == RaidState::Optimal
}

fn test_dm_crypt() -> bool {
    // 1. Test AES-128 core cipher roundtrip
    let key = [0x2bu8, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let cipher = Aes128Cipher::new(&key);
    let pt = [0x6bu8, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
    let ct = cipher.encrypt_block(&pt);
    let decrypted = cipher.decrypt_block(&ct);
    if decrypted != pt {
        return false;
    }

    // 2. Test GF(2^128) tweak update
    let mut tweak = [0x80u8; 16];
    gf128_mul_x(&mut tweak);
    // MSB carry should XOR 0x87 into lowest byte
    if (tweak[0] & 0x87) == 0 {
        return false;
    }

    // 3. Test XTS 512-byte sector encryption & decryption
    let master_key = [0x55u8; 32];
    let xts = XtsEngine::new(&master_key);
    let mut sector_data = [0u8; SECTOR_SIZE];
    for (i, b) in sector_data.iter_mut().enumerate() {
        *b = (i & 0xFF) as u8;
    }

    let mut cipher_sector = [0u8; SECTOR_SIZE];
    if xts.encrypt_sector(42, &sector_data, &mut cipher_sector).is_err() {
        return false;
    }
    if cipher_sector == sector_data {
        return false;
    }

    let mut recovered = [0u8; SECTOR_SIZE];
    if xts.decrypt_sector(42, &cipher_sector, &mut recovered).is_err() || recovered != sector_data {
        return false;
    }

    // 4. Test LUKS2 Header serialization & parsing
    let hdr = Luks2Header::new(512, "c001-cafe-beef-4242");
    let serialized = hdr.serialize();
    let Ok(parsed_hdr) = Luks2Header::parse(&serialized) else {
        return false;
    };
    if parsed_hdr.version != 2 || parsed_hdr.sector_size != 512 {
        return false;
    }

    // 5. Test DmCryptDevice
    let mut dev = DmCryptDevice::new(hdr, 64);
    dev.unlock(&master_key);
    if !dev.is_unlocked() {
        return false;
    }
    if dev.write_sector(1, &sector_data).is_err() {
        return false;
    }
    recovered.fill(0);
    dev.read_sector(1, &mut recovered).is_ok() && recovered == sector_data
}

fn test_thin_provision() -> bool {
    let mut mgr = ThinProvisioningManager::new(16, 4096).unwrap();
    let vol1 = mgr.create_volume(1024 * 1024); // 1 MiB virtual capacity

    let write_chunk0 = [0xCCu8; 4096];
    if mgr.write(vol1, 0, &write_chunk0).is_err() {
        return false;
    }

    // Read back written chunk
    let mut read_buf = [0u8; 4096];
    if mgr.read(vol1, 0, &mut read_buf).is_err() || read_buf != write_chunk0 {
        return false;
    }

    // Reading unallocated logical address returns zeroes
    read_buf.fill(0xFF);
    if mgr.read(vol1, 8192, &mut read_buf).is_err() || read_buf.iter().any(|&b| b != 0) {
        return false;
    }

    // Create Copy-On-Write snapshot
    let Ok(snap_vol) = mgr.create_snapshot(vol1) else {
        return false;
    };

    // Snapshot initially has identical content
    read_buf.fill(0);
    if mgr.read(snap_vol, 0, &mut read_buf).is_err() || read_buf != write_chunk0 {
        return false;
    }

    // Write new data to volume 1 chunk 0 -> triggers COW
    let write_new = [0xDDu8; 4096];
    if mgr.write(vol1, 0, &write_new).is_err() {
        return false;
    }

    // Verify origin has new data and snapshot retains original data
    let mut origin_buf = [0u8; 4096];
    let mut snap_buf = [0u8; 4096];
    if mgr.read(vol1, 0, &mut origin_buf).is_err() || origin_buf != write_new {
        return false;
    }
    if mgr.read(snap_vol, 0, &mut snap_buf).is_err() || snap_buf != write_chunk0 {
        return false;
    }

    // Discard chunk on snapshot
    mgr.discard_chunk(snap_vol, 0).is_ok()
}

fn test_bcache() -> bool {
    let mut bcache = BcacheDevice::new(128, 4, CacheMode::WriteBack);
    let test_data = [0x42u8; SECTOR_SIZE];

    // Write-back: writes to cache and marks dirty
    if bcache.write_sector(10, &test_data).is_err() {
        return false;
    }

    // Direct backing read should NOT have the data before flush
    let mut backing_raw = [0u8; SECTOR_SIZE];
    if bcache.read_backing_direct(10, &mut backing_raw).is_err() || backing_raw == test_data {
        return false;
    }

    // Explicit flush synchronizes dirty buckets to backing store
    if bcache.flush() == 0 {
        return false;
    }
    if bcache.read_backing_direct(10, &mut backing_raw).is_err() || backing_raw != test_data {
        return false;
    }

    // Read through cache yields cache hit
    let mut cache_read = [0u8; SECTOR_SIZE];
    if bcache.read_sector(10, &mut cache_read).is_err() || cache_read != test_data {
        return false;
    }
    if bcache.stats().read_hits == 0 {
        return false;
    }

    // Test WriteThrough mode
    bcache.set_mode(CacheMode::WriteThrough);
    let wt_data = [0x77u8; SECTOR_SIZE];
    if bcache.write_sector(20, &wt_data).is_err() {
        return false;
    }
    backing_raw.fill(0);
    bcache.read_backing_direct(20, &mut backing_raw).is_ok() && backing_raw == wt_data
}

fn test_loopback_blk() -> bool {
    let mut controller = LoopController::new(4);
    let free_id = controller.find_free_device().unwrap();

    let image_data = vec![0x11u8; 16 * 1024]; // 16 KiB image
    let config = LoopConfig::new("/dev/shm/virtual_disk.raw")
        .with_sector_size(512)
        .unwrap();

    if controller.attach(free_id, config, image_data).is_err() {
        return false;
    }

    let dev = controller.get_device_mut(free_id).unwrap();
    if dev.total_sectors() != 32 {
        return false;
    }

    // Dispatch Bio Read request
    let mut read_bio = Bio::new(BioOp::Read, 2);
    read_bio.add_buffer(&vec![0u8; 512]);
    if dev.submit_bio(&mut read_bio).is_err() || !read_bio.is_complete() {
        return false;
    }
    if read_bio.flatten_data() != vec![0x11u8; 512] {
        return false;
    }

    // Dispatch Bio Write request
    let mut write_bio = Bio::new(BioOp::Write, 2);
    write_bio.add_buffer(&vec![0x99u8; 512]);
    if dev.submit_bio(&mut write_bio).is_err() || !write_bio.is_complete() {
        return false;
    }

    // Read back written sector
    let mut check_bio = Bio::new(BioOp::Read, 2);
    check_bio.add_buffer(&vec![0u8; 512]);
    if dev.submit_bio(&mut check_bio).is_err() || check_bio.flatten_data() != vec![0x99u8; 512] {
        return false;
    }

    // Detach device
    controller.detach(free_id).is_ok()
}

fn test_smart_telemetry() -> bool {
    let analyzer = PredictiveFailureAnalyzer::new();

    // 1. ATA SMART evaluation: healthy drive
    let healthy_attrs = vec![
        SmartAttribute::new(ata_attr_id::REALLOCATED_SECTOR_COUNT, "Reallocated Sectors", 100, 100, 36, 0, true),
        SmartAttribute::new(ata_attr_id::POWER_ON_HOURS, "Power-On Hours", 98, 98, 0, 1200, false),
        SmartAttribute::new(ata_attr_id::TEMPERATURE_CELSIUS, "Temperature", 65, 50, 0, 35, false),
        SmartAttribute::new(ata_attr_id::SSD_LIFE_REMAINING, "SSD Life Left", 98, 98, 10, 0, true),
    ];
    let rep_healthy = analyzer.evaluate_ata_attributes(&healthy_attrs);
    if rep_healthy.status != DriveHealthStatus::Healthy {
        return false;
    }

    // 2. ATA SMART evaluation: failing drive with reallocated sectors surge
    let failing_attrs = vec![
        SmartAttribute::new(ata_attr_id::REALLOCATED_SECTOR_COUNT, "Reallocated Sectors", 30, 30, 36, 180, true),
        SmartAttribute::new(ata_attr_id::CURRENT_PENDING_SECTOR_COUNT, "Pending Sectors", 50, 50, 0, 45, true),
    ];
    let rep_failing = analyzer.evaluate_ata_attributes(&failing_attrs);
    if rep_failing.status != DriveHealthStatus::PredictiveFailure {
        return false;
    }

    // 3. NVMe SMART log parsing & evaluation
    let mut nvme_buf = vec![0u8; 512];
    nvme_buf[0] = 0; // No critical warnings
    nvme_buf[1] = 0x3E; // 318 Kelvin = 45 Celsius
    nvme_buf[2] = 0x01;
    nvme_buf[3] = 100; // Available spare 100%
    nvme_buf[4] = 10;  // Threshold 10%
    nvme_buf[5] = 2;   // 2% used

    let Some(nvme_log) = NvmeSmartLog::parse(&nvme_buf) else {
        return false;
    };
    if nvme_log.temperature_celsius() != 45 {
        return false;
    }
    let rep_nvme = analyzer.evaluate_nvme_health(&nvme_log);
    if rep_nvme.status != DriveHealthStatus::Healthy {
        return false;
    }

    // Critical warning: Spare below threshold
    let mut nvme_bad_buf = nvme_buf.clone();
    nvme_bad_buf[0] = NvmeSmartLog::CRITICAL_WARN_SPARE_BELOW_THRESHOLD;
    let nvme_bad_log = NvmeSmartLog::parse(&nvme_bad_buf).unwrap();
    let rep_bad = analyzer.evaluate_nvme_health(&nvme_bad_log);

    rep_bad.status == DriveHealthStatus::PredictiveFailure
}

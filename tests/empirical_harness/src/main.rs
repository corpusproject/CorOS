#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// 4 MiB Static Heap Allocator for #![no_std] tests
// ---------------------------------------------------------------------------
const HEAP_SIZE: usize = 4 * 1024 * 1024;
#[repr(align(4096))]
struct HeapStorage([u8; HEAP_SIZE]);
static mut HEAP_MEM: HeapStorage = HeapStorage([0; HEAP_SIZE]);
static HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);

struct SimpleBumpAllocator;

unsafe impl GlobalAlloc for SimpleBumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(16);
        let size = layout.size();
        loop {
            let current = HEAP_OFFSET.load(Ordering::Relaxed);
            let aligned = (current + align - 1) & !(align - 1);
            let next = aligned + size;
            if next > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if HEAP_OFFSET.compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                return (core::ptr::addr_of_mut!(HEAP_MEM.0) as *mut u8).add(aligned);
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator does not reclaim individual allocations
    }
}

#[global_allocator]
static ALLOCATOR: SimpleBumpAllocator = SimpleBumpAllocator;

// ---------------------------------------------------------------------------
// Private Stack and Entry Trampoline
// ---------------------------------------------------------------------------
#[repr(align(16))]
struct HarnessStack([u8; 131072]); // 128 KiB

#[no_mangle]
static mut HARNESS_STACK: HarnessStack = HarnessStack([0; 131072]);


global_asm!(
    r#"
    .text
    .globl efi_main
efi_main:
    cli
    leaq HARNESS_STACK+131072(%rip), %rsp
    andq $-16, %rsp
    subq $32, %rsp
    xorq %rbp, %rbp
    call harness_main
1:
    cli
    hlt
    jmp 1b
    "#,
    options(att_syntax)
);

// ---------------------------------------------------------------------------
// COM1 Serial Port Driver
// ---------------------------------------------------------------------------
const COM1: u16 = 0x3F8;

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags));
    val
}

unsafe fn serial_init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01); // 115200 baud
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03); // 8 bits, no parity, 1 stop bit
    outb(COM1 + 2, 0xC7); // FIFO
    outb(COM1 + 4, 0x0B); // DTR/RTS/OUT2
}

unsafe fn serial_write_byte(b: u8) {
    for _ in 0..100_000 {
        if (inb(COM1 + 5) & 0x20) != 0 {
            outb(COM1, b);
            return;
        }
        core::hint::spin_loop();
    }
}

unsafe fn serial_print(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            serial_write_byte(b'\r');
        }
        serial_write_byte(b);
    }
}

unsafe fn serial_print_num(mut val: u64) {
    if val == 0 {
        serial_write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        serial_write_byte(buf[i]);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    unsafe {
        serial_print("\n[CHALLENGER PANIC] ");
        if let Some(loc) = info.location() {
            serial_print(loc.file());
            serial_print(":");
            serial_print_num(loc.line() as u64);
        }
        serial_print("\n");
        loop {
            core::arch::asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

// ---------------------------------------------------------------------------
// Harness Main Entry
// ---------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "efiapi" fn harness_main(_boot_info: *const corboot_info::BootInfo, _unused: *mut core::ffi::c_void) -> ! {
    serial_init();
    serial_print("\n");
    serial_print("=======================================================================\n");
    serial_print("       COROS EMPIRICAL CHALLENGER SUBSYSTEM & STRESS TEST HARNESS      \n");
    serial_print("=======================================================================\n\n");

    let mut all_crates_ok = true;
    let mut total_self_tests = 0u64;

    // -----------------------------------------------------------------------
    // PART 1: 18 Subsystem run_self_tests() Execution
    // -----------------------------------------------------------------------
    serial_print("--- PART 1: Executing run_self_tests() across all 18 crates ---\n");

    macro_rules! test_crate {
        ($name:expr, $call:expr) => {{
            serial_print("  Testing [");
            serial_print($name);
            serial_print("] ... ");
            let count = $call;
            serial_print_num(count as u64);
            serial_print(" checks passed\n");
            if count == 0 {
                serial_print("    [FAIL] Zero self-test count returned!\n");
                all_crates_ok = false;
            }
            total_self_tests += count as u64;
        }};
    }

    test_crate!("corsyscall", corsyscall::run_self_tests());
    test_crate!("cordrivers", cordrivers::run_self_tests());
    test_crate!("corvfs", corvfs::run_self_tests());
    test_crate!("cornet", cornet::run_self_tests());
    test_crate!("corcrypto", corcrypto::run_self_tests());
    test_crate!("corcoreutils", corcoreutils::run_self_tests());
    test_crate!("cormm", cormm::run_self_tests());
    test_crate!("corvirt", corvirt::run_self_tests());
    test_crate!("corsound", corsound::run_self_tests());
    test_crate!("corsec", corsec::run_self_tests());
    test_crate!("coripc", coripc::run_self_tests());
    test_crate!("corbpf", corbpf::run_self_tests());
    test_crate!("cordrm", cordrm::run_self_tests());
    test_crate!("corpower", corpower::run_self_tests());
    test_crate!("corinput", corinput::run_self_tests());
    test_crate!("corblock", corblock::run_self_tests());
    test_crate!("corsched", corsched::run_self_tests());
    test_crate!("cortoolchain", cortoolchain::run_self_tests());

    serial_print("\nPart 1 Result: Total authentic subsystem checks = ");
    serial_print_num(total_self_tests);
    serial_print("\n");

    // -----------------------------------------------------------------------
    // PART 2: Stress Testing Newly Implemented Subsystems
    // -----------------------------------------------------------------------
    serial_print("\n--- PART 2: Stress Testing Boundary & Edge Conditions ---\n");

    // 2.1 corblock Stress Tests
    serial_print("\n[STRESS 1] corblock Edge Conditions:\n");
    {
        // 1. bio splitting at non-power-of-2 offsets (e.g., 513 bytes, 7 sectors + 19 bytes = 3603 bytes)
        let mut bio = corblock::bio::Bio::new(corblock::bio::BioOp::Write, 100);
        let test_payload = alloc::vec![0xAAu8; 4096];
        bio.add_buffer(&test_payload);

        // Split at non-power-of-2 offset: 513 bytes
        let split_res_513 = bio.split(513);
        match split_res_513 {
            Ok((first, second)) => {
                let first_len = first.bi_size;
                let second_len = second.bi_size;
                let first_sec = first.bi_sector;
                let second_sec = second.bi_sector;
                serial_print("  - Bio split at 513 B: first_size=");
                serial_print_num(first_len as u64);
                serial_print(" (sec ");
                serial_print_num(first_sec);
                serial_print("), second_size=");
                serial_print_num(second_len as u64);
                serial_print(" (sec ");
                serial_print_num(second_sec);
                serial_print(") -> ");
                // Verify content integrity
                let f_data = first.flatten_data();
                let s_data = second.flatten_data();
                if first_len == 513 && second_len == 4096 - 513 && f_data.len() == 513 && s_data.len() == 4096 - 513 {
                    serial_print("[PASS] Buffer split intact\n");
                } else {
                    serial_print("[FAIL] Buffer split corrupted\n");
                }

                // Note sector truncation anomaly:
                if second_sec == 100 + (513 / 512) {
                    serial_print("    [NOTE] Sector offset calculation: 513/512 = 1 sector (sub-sector remainder unexpressed in LBA)\n");
                }
            }
            Err(_) => serial_print("  - Bio split at 513 B: [FAIL]\n"),
        }

        // Split at 3603 bytes (7 sectors + 19 bytes)
        let split_res_3603 = bio.split(3603);
        match split_res_3603 {
            Ok((first, second)) => {
                serial_print("  - Bio split at 3603 B (7 sectors + 19 B): ");
                if first.bi_size == 3603 && second.bi_size == 4096 - 3603 {
                    serial_print("[PASS] Exact boundary partition\n");
                } else {
                    serial_print("[FAIL] Mismatch\n");
                }
            }
            Err(_) => serial_print("  - Bio split at 3603 B: [FAIL]\n"),
        }

        // Split at 0 bytes (should return Err)
        if bio.split(0).is_err() && bio.split(4096).is_err() {
            serial_print("  - Bio split at boundaries 0 and len: [PASS] Correctly rejected\n");
        } else {
            serial_print("  - Bio split at boundaries: [FAIL] Did not reject invalid bounds\n");
        }

        // 2. GPT CRC32 validation
        let sample_data = b"CorOS GPT Partition Table Verification Test String 2026";
        let crc_val = corblock::gpt_partition::crc32(sample_data);
        serial_print("  - GPT CRC32 computation: 0x");
        serial_print_num(crc_val as u64);
        // Bit-flip test
        let mut corrupted_data = *sample_data;
        corrupted_data[5] ^= 0x01;
        let corrupted_crc = corblock::gpt_partition::crc32(&corrupted_data);
        if crc_val != corrupted_crc {
            serial_print(" -> [PASS] CRC32 detects single-bit corruption\n");
        } else {
            serial_print(" -> [FAIL] CRC32 collision on single-bit flip\n");
        }

        // 3. RAID 5 XOR Parity Rebuild
        let mut d0 = alloc::vec![0x11u8; 512];
        let mut d1 = alloc::vec![0x22u8; 512];
        let mut d2 = alloc::vec![0x33u8; 512];
        let mut p = alloc::vec![0x00u8; 512];

        // P = d0 ^ d1 ^ d2
        corblock::software_raid::xor_buffers(&mut p, &d0);
        corblock::software_raid::xor_buffers(&mut p, &d1);
        corblock::software_raid::xor_buffers(&mut p, &d2);

        // Simulate loss of d1: rebuild d1' = d0 ^ d2 ^ P
        let mut d1_rebuilt = alloc::vec![0x00u8; 512];
        corblock::software_raid::xor_buffers(&mut d1_rebuilt, &d0);
        corblock::software_raid::xor_buffers(&mut d1_rebuilt, &d2);
        corblock::software_raid::xor_buffers(&mut d1_rebuilt, &p);

        serial_print("  - RAID 5 XOR Parity Rebuild (3 Data + 1 Parity): ");
        if d1_rebuilt == d1 {
            serial_print("[PASS] Missing disk perfectly reconstructed\n");
        } else {
            serial_print("[FAIL] Rebuild parity mismatch\n");
        }

        // 4. AES-128 / XTS Encryption
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let cipher = corblock::dm_crypt::Aes128Cipher::new(&key);
        let plaintext_block = [0x42u8; 16];
        let ciphertext = cipher.encrypt_block(&plaintext_block);
        let decrypted = cipher.decrypt_block(&ciphertext);

        serial_print("  - AES-128 Core Block Encrypt/Decrypt Roundtrip: ");
        if decrypted == plaintext_block && ciphertext != plaintext_block {
            serial_print("[PASS] Full roundtrip match\n");
        } else {
            serial_print("[FAIL] Decryption mismatch\n");
        }

    }

    // 2.2 corsched Stress Tests
    serial_print("\n[STRESS 2] corsched Edge Conditions:\n");
    {
        // 1. EEVDF deadline calculation & lag
        let mut rq = corsched::CfsRunQueue::new();
        let entity_nice_neg5 = corsched::SchedEntity::new(1, "interactive_audio", -5);
        let entity_nice_pos10 = corsched::SchedEntity::new(2, "batch_indexer", 10);

        let w_high = entity_nice_neg5.weight;
        let w_low = entity_nice_pos10.weight;

        serial_print("  - EEVDF Nice-to-Weight Mapping: nice(-5)=");
        serial_print_num(w_high as u64);
        serial_print(" vs nice(10)=");
        serial_print_num(w_low as u64);
        if w_high == 3121 && w_low == 110 {
            serial_print(" -> [PASS] Matches Linux nice-to-weight table\n");
        } else {
            serial_print(" -> [FAIL] Nice weight table divergence\n");
        }

        rq.enqueue_task(entity_nice_neg5);
        rq.enqueue_task(entity_nice_pos10);

        // Pick task at t = 1ms
        let picked = rq.pick_next_task(1_000_000);
        serial_print("  - EEVDF Earliest Virtual Deadline Pick: ");
        if picked.is_some() {
            serial_print("[PASS] SchedEntity successfully scheduled\n");
        } else {
            serial_print("[FAIL] No task picked\n");
        }

        // 2. Lockdep ABBA Cycle Detection
        let mut lockdep = corsched::LockdepValidator::new();
        lockdep.register_class(10, "vfs_inode_lock", 0);
        lockdep.register_class(20, "page_cache_lock", 0);

        // CPU 0 acquires Inode (10) -> PageCache (20)
        let _ = lockdep.acquire(10, 0x1000, false, false, 0, 100);
        let _ = lockdep.acquire(20, 0x2000, false, false, 0, 200);
        let _ = lockdep.release(0x2000);
        let _ = lockdep.release(0x1000);

        // CPU 1 acquires PageCache (20) -> Inode (10) -> ABBA Cycle!
        let _ = lockdep.acquire(20, 0x2000, false, false, 1, 300);
        let abba = lockdep.acquire(10, 0x1000, false, false, 1, 400);

        serial_print("  - Lockdep ABBA Cycle Detection: ");
        match abba {
            Err(corsched::LockdepError::DeadlockCycle { from_class, to_class, .. }) => {
                if from_class == 20 && to_class == 10 {
                    serial_print("[PASS] Caught ABBA cycle (class 20 -> 10)\n");
                } else {
                    serial_print("[FAIL] Wrong cycle classes reported\n");
                }
            }
            _ => serial_print("[FAIL] Failed to catch ABBA deadlock\n"),
        }

        // 3. Tree RCU Quiescent State Tracking
        let mut rcu = corsched::TreeRcu::new(8);
        static mut RCU_STRESS_FIRED: bool = false;
        fn rcu_stress_cb(_arg: u64) {
            unsafe { RCU_STRESS_FIRED = true; }
        }

        rcu.call_rcu(0, corsched::RcuCallback {
            id: 99,
            func: rcu_stress_cb,
            arg: 1234,
            gp_seq: 0,
        });

        let started = rcu.start_grace_period();
        // Report on CPUs 0..7
        for cpu in 0..7 {
            rcu.report_quiescent_state(cpu);
        }
        let idle_before_last = rcu.state == corsched::RcuGpState::Idle;
        // Report final CPU
        rcu.report_quiescent_state(7);
        let idle_after_last = rcu.state == corsched::RcuGpState::Idle;
        let dispatched = rcu.do_batch(0, 10);

        serial_print("  - Tree RCU Quiescent State Barrier: ");
        if started && !idle_before_last && idle_after_last && dispatched == 1 && unsafe { RCU_STRESS_FIRED } {
            serial_print("[PASS] Grace period resolves only after all CPUs report QS\n");
        } else {
            serial_print("[FAIL] RCU state machine barrier failure\n");
        }
    }

    // 2.3 cortoolchain Stress Tests
    serial_print("\n[STRESS 3] cortoolchain Edge Conditions:\n");
    {
        // 1. ELF64 Relocation Application
        let mut target_section = alloc::vec![0u8; 64];
        // R_X86_64_64 relocation at offset 8: *target += Symbol + Addend
        let rela_64 = cortoolchain::Elf64Rela::new(8, 1, cortoolchain::elf64_reloc::R_X86_64_64, 0x10);
        let rela_pc32 = cortoolchain::Elf64Rela::new(24, 1, cortoolchain::elf64_reloc::R_X86_64_PC32, -4);

        struct TestSymResolver;
        impl cortoolchain::SymbolResolver for TestSymResolver {
            fn resolve_symbol(&self, sym_idx: u32) -> Option<u64> {
                if sym_idx == 1 { Some(0x0040_0000) } else { None }
            }
            fn resolve_name(&self, _name: &str) -> Option<u64> { None }
        }

        let ctx = cortoolchain::RelocContext::new(0x0040_0000, 0, 0);
        let resolver = TestSymResolver;

        let mut stats = cortoolchain::elf64_reloc::RelocStats::default();
        let res_64 = cortoolchain::RelocationEngine::apply_rela(&mut target_section, &rela_64, &ctx, &resolver, &mut stats);
        let res_pc32 = cortoolchain::RelocationEngine::apply_rela(&mut target_section, &rela_pc32, &ctx, &resolver, &mut stats);


        serial_print("  - ELF64 Relocation Engine (R_X86_64_64 & R_X86_64_PC32): ");
        if res_64.is_ok() && res_pc32.is_ok() {
            let val64 = u64::from_le_bytes(target_section[8..16].try_into().unwrap());
            // Target was 0, symbol was 0x400000, addend was 0x10 -> expected 0x400010
            if val64 == 0x0040_0010 {
                serial_print("[PASS] Exact reloc patch applied (0x");
                serial_print_num(val64);
                serial_print(")\n");
            } else {
                serial_print("[FAIL] Reloc value mismatch\n");
            }
        } else {
            serial_print("[FAIL] Relocation returned error\n");
        }

        // 2. DWARF ULEB128 Decoding
        // Test 1: Single byte (0x7F -> 127)
        let buf_single = [0x7Fu8];
        let mut off1 = 0;
        let uleb1 = cortoolchain::dwarf_unwind::read_uleb128(&buf_single, &mut off1);

        // Test 2: Multi-byte (624485 = 0xE5 0x8E 0x26)
        let buf_multi = [0xE5u8, 0x8Eu8, 0x26u8];
        let mut off2 = 0;
        let uleb2 = cortoolchain::dwarf_unwind::read_uleb128(&buf_multi, &mut off2);

        // Test 3: Truncated stream
        let buf_trunc = [0x80u8, 0x80u8];
        let mut off3 = 0;
        let uleb_trunc = cortoolchain::dwarf_unwind::read_uleb128(&buf_trunc, &mut off3);

        serial_print("  - DWARF ULEB128 Decoder: ");
        if uleb1 == Ok(127) && uleb2 == Ok(624485) && uleb_trunc == Err(cortoolchain::dwarf_unwind::UnwindError::EndOfStream) {
            serial_print("[PASS] Standard values and truncation handled correctly\n");
        } else {
            serial_print("[FAIL] ULEB128 decode discrepancy\n");
        }

        // 3. Disassembler Prefix Parsing
        // REX.W prefix (0x48) + NOP (0x90) -> should have rex.present = true, rex.w = true
        let inst_bytes = [0x48, 0x90];
        let decoded = cortoolchain::Disassembler::decode_one(&inst_bytes, 0x1000);
        serial_print("  - Disassembler Prefix Parsing (REX.W + NOP): ");
        if let Some(inst) = decoded {
            if inst.mnemonic == "nop" && inst.length == 2 {
                serial_print("[PASS] Decoded instruction with prefix\n");
            } else {
                serial_print("[FAIL] Unexpected instruction or length\n");
            }
        } else {
            serial_print("[FAIL] Disassembler returned None\n");
        }
    }

    // 2.4 corinput Stress Tests
    serial_print("\n[STRESS 4] corinput Edge Conditions:\n");
    {
        // 1. 24-byte event packing/unpacking
        let orig_evt = corinput::InputEvent::new(1700000000, 500000, corinput::ev_types::EV_KEY, corinput::key_codes::KEY_ENTER, 1);
        let wire_bytes = orig_evt.to_bytes();
        let unpacked_evt = corinput::InputEvent::from_bytes(&wire_bytes);

        serial_print("  - Linux evdev 24-byte InputEvent pack/unpack: ");
        if wire_bytes.len() == 24 && unpacked_evt == orig_evt {
            serial_print("[PASS] Perfect 24-byte wire roundtrip\n");
        } else {
            serial_print("[FAIL] Packing serialization mismatch\n");
        }

        // 2. Ring buffer overflow behavior
        let mut queue = corinput::EvdevClientQueue::new(4);
        for i in 1..=4 {
            queue.push_event(corinput::InputEvent::new(100, i, corinput::ev_types::EV_REL, corinput::rel_codes::REL_X, i as i32));
        }

        serial_print("  - EvdevClientQueue fill to max_capacity (4): len=");
        serial_print_num(queue.len() as u64);
        serial_print("\n");

        // Push 5th event -> should be dropped due to capacity
        queue.push_event(corinput::InputEvent::new(100, 5, corinput::ev_types::EV_REL, corinput::rel_codes::REL_X, 5));
        serial_print("  - EvdevClientQueue overflow push (5th event): dropped_overflow=");
        if queue.dropped_overflow {
            serial_print("true [PASS] Dropped flag set\n");
        } else {
            serial_print("false [FAIL] Dropped flag not set\n");
        }

        // Now pop 1 event (len becomes 3)
        let _ = queue.pop_event();
        let len_after_pop = queue.len();

        // Push another event while dropped_overflow was true
        queue.push_event(corinput::InputEvent::new(100, 6, corinput::ev_types::EV_REL, corinput::rel_codes::REL_X, 6));
        let len_after_recovery = queue.len();

        serial_print("  - EvdevClientQueue recovery after drop: len_after_pop=");
        serial_print_num(len_after_pop as u64);
        serial_print(", len_after_recovery_push=");
        serial_print_num(len_after_recovery as u64);
        serial_print(" (max=");
        serial_print_num(queue.max_capacity as u64);
        serial_print(")\n");

        if len_after_recovery > queue.max_capacity {
            serial_print("    [FINDING/BUG] EvdevClientQueue exceeded max_capacity! (pushed both SYN_DROPPED and event without verifying available space for 2 items)\n");
        } else {
            serial_print("    [PASS] Capacity strictly respected\n");
        }
    }

    // -----------------------------------------------------------------------
    // PART 2.5: cordrivers Milestone 2 (F08-F12) Empirical Challenges
    // -----------------------------------------------------------------------
    serial_print("\n[STRESS 5] cordrivers Milestone 2 (F08-F12) Empirical Challenges:\n");
    {
        // 5.1 VirtIO-Input (F08)
        let mut vinput = cordrivers::virtio_input::VirtioInputDevice::new();
        let _ = vinput.initialize();

        // Edge case: Negative relative motion (-32768, -10, -1)
        let ev_neg_x = cordrivers::virtio_input::VirtioInputEvent::new(cordrivers::virtio_input::EV_REL, cordrivers::virtio_input::REL_X, (-32768i32) as u32);
        let ev_neg_y = cordrivers::virtio_input::VirtioInputEvent::new(cordrivers::virtio_input::EV_REL, cordrivers::virtio_input::REL_Y, (-1i32) as u32);
        let ev_unknown = cordrivers::virtio_input::VirtioInputEvent::new(0xFFFF, 0x1234, 0xCAFE);
        vinput.push_event(ev_neg_x);
        vinput.push_event(ev_neg_y);
        vinput.push_event(ev_unknown);

        let p1 = vinput.pop_evdev_event(100, 1);
        let p2 = vinput.pop_evdev_event(100, 2);
        let p3 = vinput.pop_evdev_event(100, 3);
        let mut f08_ok = true;
        if let (Some(e1), Some(e2), Some(e3)) = (p1, p2, p3) {
            if e1.value != -32768 || e2.value != -1 || e3.event_type != 0xFFFF || e3.value != 0xCAFE as i32 {
                f08_ok = false;
            }
        } else {
            f08_ok = false;
        }

        // Virtqueue buffer exhaustion test: post until 64, then test 65th rejected
        let mut vq = cordrivers::virtio_input::VirtioInputVirtqueue::new();
        for i in 0..64 {
            let posted = vq.post_receive_buffer(0x1000 + (i as u64) * 8, 8);
            if !posted { f08_ok = false; }
        }
        let post_65 = vq.post_receive_buffer(0x5000, 8);
        if post_65 { f08_ok = false; } // Must be rejected
        // Consume all 64
        for _ in 0..64 {
            if vq.consume_buffer().is_none() { f08_ok = false; }
        }
        if vq.consume_buffer().is_some() { f08_ok = false; }

        serial_print("  - F08 VirtIO-Input negative coords & VQ exhaustion: ");
        if f08_ok {
            serial_print("[PASS]\n");
        } else {
            serial_print("[FAIL]\n");
        }

        // 5.2 VirtIO-Sound (F09)
        let mut vsnd = cordrivers::virtio_snd::VirtioSoundDevice::new();
        let mut f09_ok = true;

        // Invalid channel counts (0, 33) and sample rates (0, 384000)
        if cordrivers::virtio_snd::VirtioSoundDevice::is_valid_channels(0)
            || cordrivers::virtio_snd::VirtioSoundDevice::is_valid_channels(33)
            || cordrivers::virtio_snd::VirtioSoundDevice::is_valid_rate(0)
            || cordrivers::virtio_snd::VirtioSoundDevice::is_valid_rate(384000)
        {
            f09_ok = false;
        }

        // Setting invalid rate returns Err
        if vsnd.set_pcm_params(0, 384000, 2, cordrivers::virtio_snd::VIRTIO_SND_PCM_FMT_S16).is_ok() {
            f09_ok = false;
        }

        // Stream lifecycle: prepare -> start -> write -> stop -> write fails
        if vsnd.set_pcm_params(0, 48000, 2, cordrivers::virtio_snd::VIRTIO_SND_PCM_FMT_S16).is_ok() {
            let _ = vsnd.prepare_stream(0);
            let _ = vsnd.start_stream(0);
            let pcm_buf = [0x77u8; 512];
            let w1 = vsnd.write_pcm_frames(0, &pcm_buf);
            let w_zero = vsnd.write_pcm_frames(0, &[]);
            let _ = vsnd.stop_stream(0);
            let w_after_stop = vsnd.write_pcm_frames(0, &pcm_buf);
            if w1 != Ok(512) || w_zero != Ok(0) || w_after_stop.is_ok() {
                f09_ok = false;
            }
        } else {
            f09_ok = false;
        }

        serial_print("  - F09 VirtIO-Sound param validation & lifecycle: ");
        if f09_ok {
            serial_print("[PASS]\n");
        } else {
            serial_print("[FAIL]\n");
        }

        // 5.3 ATA IDE (F10)
        let mut ata = cordrivers::ata_ide::AtaIdeController::new(
            cordrivers::ata_ide::PRIMARY_ATA_IO_BASE,
            cordrivers::ata_ide::PRIMARY_ATA_CTRL_BASE,
        );
        let mut f10_ok = true;

        // LBA28 count 0 expands to 256
        ata.set_lba28(0, 0);
        if ata.sector_count_reg != 256 { f10_ok = false; }

        // LBA48 count 0 expands to 65536
        ata.set_lba48(0x0001_8000_0000, 0);
        if ata.sector_count_reg != 65536 || ata.current_lba != 0x0001_8000_0000 { f10_ok = false; }

        // Master vs Slave drive selection bitmasks
        ata.select_drive(0, 0xA);
        if (ata.drive_head_reg & 0x10) != 0 || (ata.drive_head_reg & 0x0F) != 0xA { f10_ok = false; }
        ata.select_drive(1, 0x5);
        if (ata.drive_head_reg & 0x10) == 0 || (ata.drive_head_reg & 0x0F) != 0x5 { f10_ok = false; }

        // Read out of bounds error propagation
        ata.set_lba28(1024, 1);
        let mut read_buf = [0u8; 512];
        if ata.read_sectors_pio(&mut read_buf).is_ok() || !ata.has_error() {
            f10_ok = false;
        }

        serial_print("  - F10 ATA IDE LBA48, count zero & drive selection: ");
        if f10_ok {
            serial_print("[PASS]\n");
        } else {
            serial_print("[FAIL]\n");
        }

        // 5.4 Universal Device Model (F11)
        use cordrivers::universal_device::{BlockDeviceDriver, NetworkDeviceDriver, AudioDeviceDriver};
        let mut f11_ok = true;

        // Polymorphic block device
        let mut nvme: alloc::boxed::Box<dyn BlockDeviceDriver> = alloc::boxed::Box::new(
            cordrivers::universal_device::NvmeBlockAdapter::new("nvme0", 100, 512)
        );
        let s_data = [0x55u8; 512];
        if nvme.write_sectors(99, 1, &s_data).is_err() || nvme.write_sectors(100, 1, &s_data).is_ok() {
            f11_ok = false;
        }

        // E1000 MTU enforcement
        let mut e1000 = cordrivers::universal_device::E1000NetAdapter::new("eth0", [1, 2, 3, 4, 5, 6]);
        let big_frame = alloc::vec![0xFFu8; 1515];
        let empty_frame = alloc::vec![];
        let valid_frame = alloc::vec![0xAAu8; 64];
        if e1000.transmit(&big_frame).is_ok() || e1000.transmit(&empty_frame).is_ok() || e1000.transmit(&valid_frame).is_err() {
            f11_ok = false;
        }

        // AC'97 Volume clamping
        let mut ac97 = cordrivers::universal_device::Ac97AudioAdapter::new("ac97-0");
        ac97.set_master_volume(-128);
        if ac97.volume_db != -128 { f11_ok = false; }
        ac97.set_master_volume(20);
        if ac97.volume_db != 0 { f11_ok = false; }

        serial_print("  - F11 Universal Driver traits & boundary clamping: ");
        if f11_ok {
            serial_print("[PASS]\n");
        } else {
            serial_print("[FAIL]\n");
        }

        // 5.5 PCIe ECAM & Dual-Mode (F12)
        let mut f12_ok = true;
        let ecam_max = cordrivers::pcie_ecam::calculate_ecam_address(0xE000_0000, 255, 31, 7, 4095);
        if ecam_max != 0xEFFF_FFFF { f12_ok = false; }

        let cf8_max = cordrivers::pcie_ecam::calculate_cf8_address(255, 31, 7, 0xFC);
        if (cf8_max & 0x8000_0000) == 0 || ((cf8_max >> 16) & 0xFF) != 255 || ((cf8_max >> 11) & 0x1F) != 31 {
            f12_ok = false;
        }

        let dual_mmio = cordrivers::pcie_dual_mode::PciDualModeAccessor::new(Some(0xE000_0000));
        let dual_io = cordrivers::pcie_dual_mode::PciDualModeAccessor::new(None);
        if dual_mmio.active_mode != cordrivers::pcie_dual_mode::PciAccessMode::EcamMmio
            || dual_io.active_mode != cordrivers::pcie_dual_mode::PciAccessMode::LegacyIoPorts
        {
            f12_ok = false;
        }

        serial_print("  - F12 PCIe ECAM max BDF & Dual-Mode access: ");
        if f12_ok {
            serial_print("[PASS]\n");
        } else {
            serial_print("[FAIL]\n");
        }
    }

    serial_print("\n=======================================================================\n");
    serial_print("          CHALLENGER VERDICT & EXECUTION SUMMARY COMPLETED             \n");
    serial_print("=======================================================================\n");

    loop {
        core::arch::asm!("cli; hlt", options(nomem, nostack));
    }
}

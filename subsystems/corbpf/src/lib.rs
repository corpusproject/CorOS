#![no_std]
//! `corbpf` — CorOS Extended BPF (`eBPF`) Verifier, 64-bit VM, x86_64 Native JIT,
//! Maps, RingBuf, LPM Radix Trie, XDP Packet Pipeline, Dynamic Kprobes & BTF Subsystem.

extern crate alloc;

pub mod bpf_insn;
pub mod bpf_jit_x86;
pub mod bpf_lpm_trie;
pub mod bpf_maps;
pub mod bpf_ringbuf;
pub mod bpf_verifier;
pub mod bpf_vm;
pub mod btf_typeinfo;
pub mod kprobe_trace;
pub mod xdp_pipeline;

use bpf_insn::{BpfInsn, BpfProgramBuilder, BPF_DW, BPF_W};
use bpf_jit_x86::X86JitCompiler;
use bpf_lpm_trie::BpfLpmTrie;
use bpf_maps::{BpfArrayMap, BpfHashMap, BPF_ANY, BPF_NOEXIST};
use bpf_ringbuf::BpfRingBuf;
use bpf_verifier::{BpfVerifier, VerifyError};
use bpf_vm::{BpfVm, BPF_FUNC_KTIME_GET_NS};
use btf_typeinfo::{BtfBlobBuilder, BtfKind, BtfParser, BTF_INT_SIGNED, BTF_MAGIC};
use kprobe_trace::{KprobeManager, PerfEventRing, TracepointRegistry, X86_INT3_OPCODE};
use xdp_pipeline::{XdpAction, XdpContext, XdpPipeline};

/// Execute comprehensive self-tests across all 10 `corbpf` modules.
/// Returns the number of passed subsystem self-tests (`10` when all pass).
pub fn run_self_tests() -> u32 {
    let mut passed = 0u32;

    // 1. Test `bpf_insn`: 64-bit instruction encoding, serialization, and builder.
    let mut builder = BpfProgramBuilder::new();
    builder
        .push(BpfInsn::mov64_imm(0, 40))
        .push(BpfInsn::add64_imm(0, 2))
        .push(BpfInsn::st_mem(BPF_DW, 10, -8, 99))
        .push(BpfInsn::ldx_mem(BPF_DW, 2, 10, -8))
        .push(BpfInsn::add64_reg(0, 2))
        .push(BpfInsn::exit_insn());
    let prog = builder.build();
    let roundtrip = BpfInsn::from_le_bytes(prog[0].to_le_bytes());
    if prog.len() == 6 && roundtrip == prog[0] && prog[2].mem_byte_width() == 8 {
        passed += 1;
    }

    // 2. Test `bpf_verifier`: accept valid program and reject division-by-zero & R10 writes.
    let verifier = BpfVerifier::new(64);
    let ok_report = verifier.verify(&prog);
    let bad_div_zero = [
        BpfInsn::mov64_imm(0, 10),
        BpfInsn::div64_imm(0, 0),
        BpfInsn::exit_insn(),
    ];
    let bad_r10_write = [BpfInsn::mov64_imm(10, 0), BpfInsn::exit_insn()];
    if let Ok(rep) = ok_report {
        if rep.max_stack_depth == 8
            && verifier.verify(&bad_div_zero) == Err(VerifyError::DivisionByZero(1))
            && verifier.verify(&bad_r10_write) == Err(VerifyError::WriteToReadOnlyFramePointer(0))
        {
            passed += 1;
        }
    }

    // 3. Test `bpf_vm`: execute verified program + helper call (`bpf_ktime_get_ns`).
    let mut vm = BpfVm::new();
    let mut ctx_buf = [0u8; 32];
    let res_val = vm.execute(&prog, &mut ctx_buf);
    let helper_prog = [
        BpfInsn::call_helper(BPF_FUNC_KTIME_GET_NS),
        BpfInsn::exit_insn(),
    ];
    let ktime_val = vm.execute(&helper_prog, &mut ctx_buf).unwrap_or(0);
    if res_val == Ok(141) && ktime_val > 1_000_000_000 {
        passed += 1;
    }

    // 4. Test `bpf_jit_x86`: compile eBPF program to native x86_64 machine code with prologue & epilogue.
    if let Ok(jit_buf) = X86JitCompiler::compile(&prog) {
        let code = &jit_buf.code;
        // Prologue starts with `push rbp` (0x55), `mov rbp, rsp` (0x48 0x89 0xE5) and ends with `leave; ret` (0xC9 0xC3).
        if code.len() > 24
            && code[0] == 0x55
            && code[1..4] == [0x48, 0x89, 0xE5]
            && code[code.len() - 2..] == [0xC9, 0xC3]
        {
            passed += 1;
        }
    }

    // 5. Test `bpf_maps`: `BpfArrayMap` and `BpfHashMap` (`LRU_HASH` eviction + `BPF_NOEXIST`).
    let mut arr = BpfArrayMap::new(8, 4);
    let idx_one = 1u32.to_le_bytes();
    let val_bytes = 0xCAFE_BABE_1234_5678u64.to_le_bytes();
    let _ = arr.update_elem(&idx_one, &val_bytes, BPF_ANY);

    let mut lru = BpfHashMap::new_lru(4, 4, 2);
    let _ = lru.update_elem(&1u32.to_le_bytes(), &100u32.to_le_bytes(), BPF_NOEXIST);
    let _ = lru.update_elem(&2u32.to_le_bytes(), &200u32.to_le_bytes(), BPF_NOEXIST);
    // Touch key 1 so key 2 becomes LRU victim when key 3 is inserted.
    let _ = lru.lookup_elem(&1u32.to_le_bytes());
    let _ = lru.update_elem(&3u32.to_le_bytes(), &300u32.to_le_bytes(), BPF_ANY);
    if arr.lookup_elem(&idx_one) == Some(&val_bytes[..])
        && lru.lookup_elem(&1u32.to_le_bytes()).is_some()
        && lru.lookup_elem(&2u32.to_le_bytes()).is_none()
        && lru.lookup_elem(&3u32.to_le_bytes()) == Some(&300u32.to_le_bytes()[..])
    {
        passed += 1;
    }

    // 6. Test `bpf_ringbuf`: variable-length reserve, submit, discard, and consume_all.
    if let Ok(mut ring) = BpfRingBuf::new(256) {
        if let (Ok(r1), Ok(r2)) = (ring.reserve(6), ring.reserve(4)) {
            let _ = ring.write_reservation(r1, b"corbpf");
            let _ = ring.submit(r1);
            let _ = ring.discard(r2);
            let mut sum_bytes = 0usize;
            let delivered = ring.consume_all(|rec| {
                sum_bytes += rec.len();
            });
            if delivered == 1 && sum_bytes == 6 && ring.pending_bytes() == 0 {
                passed += 1;
            }
        }
    }

    // 7. Test `bpf_lpm_trie`: IPv4 longest-prefix match (`/8`, `/16`, `/24`) and prefix deletion.
    let mut trie = BpfLpmTrie::new(4, 4, 32);
    let _ = trie.update_prefix(8, &[10, 0, 0, 0], &1u32.to_le_bytes());
    let _ = trie.update_prefix(16, &[10, 20, 0, 0], &2u32.to_le_bytes());
    let _ = trie.update_prefix(24, &[10, 20, 30, 0], &3u32.to_le_bytes());
    let match_24 = trie
        .lookup_lpm(&[10, 20, 30, 99])
        .ok()
        .flatten()
        .map(|(plen, v)| (plen, u32::from_le_bytes([v[0], v[1], v[2], v[3]])));
    let _ = trie.delete_prefix(24, &[10, 20, 30, 0]);
    let match_16 = trie
        .lookup_lpm(&[10, 20, 30, 99])
        .ok()
        .flatten()
        .map(|(plen, v)| (plen, u32::from_le_bytes([v[0], v[1], v[2], v[3]])));
    if match_24 == Some((24, 3)) && match_16 == Some((16, 2)) {
        passed += 1;
    }

    // 8. Test `xdp_pipeline`: VLAN push via `bpf_xdp_adjust_head` and XDP verdict filtering.
    let xdp_prog = alloc::vec![
        BpfInsn::ldx_mem(BPF_W, 2, 1, 12),
        BpfInsn::mov64_imm(0, XdpAction::Pass as i32),
        BpfInsn::exit_insn(),
    ];
    let mut pipeline = XdpPipeline::new(xdp_prog);
    let mut pkt = [0xAAu8; 64];
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    let mut xdp_ctx = XdpContext::from_packet(&pkt, 2, 0);
    if xdp_ctx.push_vlan_tag(100).is_ok()
        && xdp_ctx.packet_len() == 68
        && pipeline.process_packet(&mut xdp_ctx) == Ok(XdpAction::Pass)
        && pipeline.stats.passed_pkts == 1
    {
        passed += 1;
    }

    // 9. Test `kprobe_trace`: `INT3` (`0xCC`) breakpoint patching, firing, and original opcode restoration.
    let mut kprobes = KprobeManager::new();
    let mut tracepoints = TracepointRegistry::new();
    let mut perf_ring = PerfEventRing::new(16);
    let mut kernel_text = [0x55u8, 0x48, 0x89, 0xE5];
    let probe_prog = alloc::vec![BpfInsn::mov64_imm(0, 77), BpfInsn::exit_insn()];
    if let Ok(pid) = kprobes.attach_kprobe(
        "sys_execve",
        0xffff_8000_0010_0000,
        &mut kernel_text,
        probe_prog.clone(),
    ) {
        let patched_ok = kernel_text[0] == X86_INT3_OPCODE;
        let mut regs_ctx = [0u8; 16];
        let trap_ret = kprobes.handle_breakpoint_trap(
            0xffff_8000_0010_0000,
            &mut regs_ctx,
            &mut perf_ring,
            0,
            42,
            500_000,
        );
        let _ = kprobes.detach_kprobe(pid, &mut kernel_text);
        let _ = tracepoints.register_tracepoint("sched", "sched_switch", probe_prog);
        let tp_ret = tracepoints.fire_tracepoint("sched", "sched_switch", &mut regs_ctx);
        if patched_ok
            && kernel_text[0] == 0x55
            && trap_ret == Some(77)
            && tp_ret == Ok(77)
            && perf_ring.len() == 1
        {
            passed += 1;
        }
    }

    // 10. Test `btf_typeinfo`: build and parse binary BTF metadata (`BTF_MAGIC = 0xEB9F`).
    let mut btf_builder = BtfBlobBuilder::new();
    let u32_id = btf_builder.add_int_type("u32", 4, 0);
    let s64_id = btf_builder.add_int_type("s64", 8, BTF_INT_SIGNED);
    let _struct_id = btf_builder.add_struct_type(
        "xdp_md",
        16,
        &[("data", u32_id, 0), ("data_end", u32_id, 32), ("rx_ts", s64_id, 64)],
    );
    let blob = btf_builder.finish();
    if let Ok((hdr, types)) = BtfParser::parse(&blob) {
        if hdr.magic == BTF_MAGIC
            && types.len() == 3
            && types[2].kind == BtfKind::Struct
            && types[2].name == "xdp_md"
            && types[2].members.len() == 3
        {
            passed += 1;
        }
    }

    passed
}

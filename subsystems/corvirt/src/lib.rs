#![no_std]
//! `corvirt` — CorOS Hardware Virtualization & KVM-Style Hypervisor Subsystem.

extern crate alloc;

pub mod ept_npt_mmu;
pub mod hypercall_abi;
pub mod pci_passthrough;
pub mod svm_amd;
pub mod vcpu_scheduler;
pub mod virq_chip;
pub mod virtio_vhost;
pub mod vm_snapshot;
pub mod vmx_intel;
pub mod vpit_hpet;

use alloc::vec;
use ept_npt_mmu::{EptMemoryType, SlatPageTable, SlatPermissions, SlatTranslationResult};
use hypercall_abi::{hypercall_opcodes, CorVirtHypercallDispatcher, HypercallOutcome};
use pci_passthrough::{AssignedPciDevice, VirtualPciBar};
use svm_amd::{SvmAsidAllocator, SvmExitCode, VmcbControlArea, VmcbStateSaveArea};
use vcpu_scheduler::{VcpuContext, VcpuRunState};
use virq_chip::{DualPic8259, VirtualIoApic, VirtualLocalApic};
use virtio_vhost::{virtq_desc_flags, VhostSplitQueue, VirtqDesc};
use vm_snapshot::{
    deserialize_vm_checkpoint, evaluate_precopy_convergence, serialize_vm_checkpoint,
    DirtyRamPageChunk, PreCopyConvergenceDecision, VcpuSnapshotRecord,
};
use vmx_intel::{
    primary_proc_controls, secondary_proc_controls, VmExitReason, VmcsField, VmcsRegion,
    VmxCrFixedValidator,
};
use vpit_hpet::{VirtualHpet, VirtualPit8254};

/// Executes comprehensive self-tests across all 10 hardware virtualization modules
/// and returns the number of passed subsystem test suites (`10`).
pub fn run_self_tests() -> u32 {
    let mut passed_suites = 0u32;

    // 1. Intel VT-x VMCS & VM-Exit decoder verification
    {
        let validator = VmxCrFixedValidator::standard_vtx_profile(true);
        let mut vmcs = VmcsRegion::new(0x0000_0012);
        let _ = vmcs.vmwrite(
            VmcsField::PrimaryProcBasedVmExecControls,
            primary_proc_controls::ACTIVATE_SECONDARY_CONTROLS as u64,
        );
        let _ = vmcs.vmwrite(
            VmcsField::SecondaryProcBasedVmExecControls,
            (secondary_proc_controls::ENABLE_EPT | secondary_proc_controls::UNRESTRICTED_GUEST)
                as u64,
        );
        let _ = vmcs.vmwrite(VmcsField::EptPointer, 0x0000_0001_0000_001E);
        let valid_cr0 = validator.sanitize_guest_cr0(0x0000_0020, true);
        let valid_cr4 = validator.sanitize_guest_cr4(0x0000_2000);
        let _ = vmcs.vmwrite(VmcsField::GuestCr0, valid_cr0);
        let _ = vmcs.vmwrite(VmcsField::GuestCr4, valid_cr4);

        let decode_io = VmExitReason::decode(30, (0x03F8 << 16) | 0);
        if vmcs.verify_vm_entry_state(&validator).is_ok()
            && matches!(
                decode_io,
                VmExitReason::IoInstruction {
                    port: 0x03F8,
                    size_bytes: 1,
                    is_in: false,
                    ..
                }
            )
        {
            passed_suites += 1;
        }
    }

    // 2. AMD-V VMCB, ASID allocator & #VMEXIT decoder verification
    {
        let mut asid_alloc = SvmAsidAllocator::new(4);
        let (asid, _gen, _flush) = asid_alloc.allocate_asid();
        let mut vmcb_ctrl = VmcbControlArea::new(asid);
        vmcb_ctrl.configure_nested_paging(0x0000_0002_0000_0000, false);
        vmcb_ctrl.set_cr_intercept(3, true, true);
        let _save_area = VmcbStateSaveArea::default();
        let npf = SvmExitCode::decode(0x400, 0b00110, 0x0000_0000_FEE0_0000);

        if vmcb_ctrl.validate_consistency().is_ok()
            && matches!(
                npf,
                SvmExitCode::NestedPageFault {
                    fault_gpa: 0xFEE0_0000,
                    is_write: true,
                    ..
                }
            )
        {
            passed_suites += 1;
        }
    }

    // 3. Second-Level Address Translation (EPT/NPT) & Dirty Bitmap verification
    {
        let mut slat = SlatPageTable::new(256, true);
        let _ = slat.register_mmio_region(0xFEC0_0000, 0x1000, 7, false);
        let _ = slat.map_4k_page(
            0x0000_2000,
            0x0010_5000,
            SlatPermissions::READ_WRITE_EXEC,
            EptMemoryType::WriteBack,
        );
        let walk_res = slat.translate_gpa(0x0000_2123, true, true, false);
        let mmio_res = slat.translate_gpa(0xFEC0_0010, true, false, false);
        let dirty_gfns = slat.harvest_and_clear_dirty_gfns();

        if matches!(
            walk_res,
            SlatTranslationResult::Mapped {
                hpa: 0x0010_5123,
                dirty: true,
                ..
            }
        ) && matches!(
            mmio_res,
            SlatTranslationResult::MmioIntercept {
                device_id: 7,
                offset: 0x10
            }
        ) && dirty_gfns == vec![2]
        {
            passed_suites += 1;
        }
    }

    // 4. vCPU Scheduler, Halt-Polling & Paravirtual Steal-Time verification
    {
        let mut vcpu = VcpuContext::new(0);
        let _ = vcpu.enter_guest(5_000);
        vcpu.handle_hlt_exit(1);
        vcpu.notify_interrupt_wakeup(0x30, 25_000);
        vcpu.gprs.rax = 0x4000_0000;
        vcpu.emulate_cpuid_exit(2);

        if vcpu.run_state == VcpuRunState::Runnable
            && vcpu.steal_time.steal_time_ns == 5_000
            && (vcpu.steal_time.version_seq & 1) == 0
            && vcpu.gprs.rax == 0x4000_0001
        {
            passed_suites += 1;
        }
    }

    // 5. Virtual IRQ Chip (Dual 8259A PIC + I/O APIC + Local APIC) verification
    {
        let mut pic = DualPic8259::new();
        // Initialize Master PIC with ICW1..ICW4 at vector offset 0x20
        pic.master.write_command(0x11);
        pic.master.write_data(0x20);
        pic.master.write_data(0x04);
        pic.master.write_data(0x01);
        pic.master.write_data(0x00); // Unmask all master IRQs
        pic.raise_irq(1); // Keyboard IRQ 1 -> vector 0x21
        let pic_vec = pic.acknowledge_irq();

        let mut ioapic = VirtualIoApic::new(0);
        ioapic.mmio_write(0x00, 0x12); // Redirection entry 1 low dword
        ioapic.mmio_write(0x10, 0x0000_0031); // Unmasked, vector 0x31
        ioapic.mmio_write(0x00, 0x13); // Redirection entry 1 high dword
        ioapic.mmio_write(0x10, 0x0200_0000); // Dest APIC ID 2
        let routed = ioapic.assert_pin(1);

        let mut lapic = VirtualLocalApic::new(2);
        lapic.accept_interrupt(0x31, false);
        let claimed = lapic.claim_deliverable_vector();
        let eoi = lapic.write_eoi();

        if pic_vec == Some(0x21)
            && routed == Some((2, 0x31))
            && claimed == Some(0x31)
            && eoi == Some(0x31)
        {
            passed_suites += 1;
        }
    }

    // 6. Emulated 8254 PIT & Virtual HPET verification
    {
        let mut pit = VirtualPit8254::new();
        // Channel 0, Low/High byte, Mode 2 (Rate Generator), binary
        pit.write_command_port(0b00_11_010_0);
        pit.channels[0].write_data_byte(100);
        pit.channels[0].write_data_byte(0); // Reload value = 100
        let wraps = pit.channels[0].advance_ticks(250);

        let mut hpet = VirtualHpet::new();
        hpet.general_config |= 1; // Enable main counter
        hpet.configure_timer(0, 500, true, 2);
        let fired = hpet.advance_counter(600);

        if wraps == 2 && (fired & 1) == 1 && hpet.timers[0].comparator_value == 1_000 {
            passed_suites += 1;
        }
    }

    // 7. VirtIO vhost Split Queue (`vhost-blk` read/write chain) verification
    {
        let mut vq = VhostSplitQueue::new(8, false);
        let mut guest_ram = vec![0u8; 4096];
        let mut disk = vec![0u8; 4096];
        // Populate sector 1 (offset 512) on disk with pattern 0xA5
        for b in &mut disk[512..1024] {
            *b = 0xA5;
        }
        // Build VirtioBlkReqHeader at GPA 0: type=0 (IN/read), sector=1
        guest_ram[0..4].copy_from_slice(&0u32.to_le_bytes());
        guest_ram[8..16].copy_from_slice(&1u64.to_le_bytes());
        guest_ram[2048] = 0xFF; // Status byte initialized to 0xFF

        vq.descriptors[0] = VirtqDesc {
            addr_gpa: 0,
            len: 16,
            flags: virtq_desc_flags::VRING_DESC_F_NEXT,
            next: 1,
        };
        vq.descriptors[1] = VirtqDesc {
            addr_gpa: 1024,
            len: 512,
            flags: virtq_desc_flags::VRING_DESC_F_WRITE | virtq_desc_flags::VRING_DESC_F_NEXT,
            next: 2,
        };
        vq.descriptors[2] = VirtqDesc {
            addr_gpa: 2048,
            len: 1,
            flags: virtq_desc_flags::VRING_DESC_F_WRITE,
            next: 0,
        };
        vq.avail.publish_head(0);

        if let Ok(Some((head, kick))) = vq.process_vhost_blk_request(&mut guest_ram, &mut disk) {
            if head == 0 && kick && guest_ram[1024] == 0xA5 && guest_ram[2048] == 0 {
                passed_suites += 1;
            }
        }
    }

    // 8. VFIO PCIe Passthrough, BAR sizing probe & MSI-X remapping verification
    {
        let mut pdev =
            AssignedPciDevice::new(0x0100, 0x0018, 0x8086, 0x10FB, 0x0200_0001, 4, 0x50);
        pdev.register_bar(VirtualPciBar::new_mmio32(
            0,
            0x0002_0000,
            0xF800_0000,
            0xE000_0000,
            true,
        ));
        // Probe BAR0 size by writing 0xFFFF_FFFF
        pdev.write_config_dword(0x10, 0xFFFF_FFFF);
        let sized_mask = pdev.read_config_dword(0x10);
        // Relocate BAR0 to 0xE200_0000
        pdev.write_config_dword(0x10, 0xE200_0000);
        let relocated = pdev.read_config_dword(0x10);

        let route = pdev.configure_msix_entry(1, 0xFEE0_3000, 0x0000_0064, false);
        let remapped = pdev.translate_host_msix_irq(0x51);

        if sized_mask == (0xFFFE_0000 | 0x08)
            && relocated == (0xE200_0000 | 0x08)
            && route.is_some()
            && remapped == Some((3, 0x64))
        {
            passed_suites += 1;
        }
    }

    // 9. Live VM Checkpoint, CRC-32 verification & Pre-Copy Convergence verification
    {
        let vcpu_rec = VcpuSnapshotRecord {
            vcpu_id: 0,
            apic_id: 0,
            rip: 0xFFFF_8000_0010_0000,
            rsp: 0xFFFF_8000_0020_FF00,
            rflags: 0x202,
            rax: 42,
            cr0: 0x8005_0033,
            cr3: 0x0000_0000_0010_0000,
            cr4: 0x0000_26F0,
            efer: 0x0D01,
            tsc_offset: 1_000,
        };
        let zero_chunk = DirtyRamPageChunk::from_slice(10, &[0u8; 64]);
        let data_chunk = DirtyRamPageChunk::from_slice(11, &[0xCCu8; 64]);
        let stream = serialize_vm_checkpoint(&[vcpu_rec], &[zero_chunk, data_chunk], 1);
        let decoded = deserialize_vm_checkpoint(&stream);
        let conv = evaluate_precopy_convergence(200, 1_000, 20_000, 25, 2, 10);

        if let Ok((_hdr, recs, chunks)) = decoded {
            if recs.len() == 1
                && recs[0] == vcpu_rec
                && chunks.len() == 2
                && chunks[0].is_zero_page
                && !chunks[1].is_zero_page
                && matches!(conv, PreCopyConvergenceDecision::SwitchToStopAndCopy { .. })
            {
                passed_suites += 1;
            }
        }
    }

    // 10. KVM/CorVirt Paravirtual Hypercall ABI verification
    {
        let mut dispatcher = CorVirtHypercallDispatcher::new(1_000_000_000);
        let mut vcpu = VcpuContext::new(0);
        let mut lapics = [VirtualLocalApic::new(0), VirtualLocalApic::new(1)];

        // Dispatch HC_SEND_IPI_MASK to vCPU 1 with vector 0x45
        vcpu.gprs.rax = hypercall_opcodes::HC_SEND_IPI_MASK;
        vcpu.gprs.rbx = 0b10; // target vCPU 1
        vcpu.gprs.rcx = 0x45; // vector 0x45
        vcpu.gprs.rdx = 0; // edge-triggered
        let out_ipi = dispatcher.dispatch_hypercall(&mut vcpu, 0, 3, &mut lapics);

        // Dispatch HC_FLUSH_TLB_RANGE for 16 pages starting at 0xFFFF_8000_0000_0000
        vcpu.gprs.rax = hypercall_opcodes::HC_FLUSH_TLB_RANGE;
        vcpu.gprs.rbx = 0xFFFF_8000_0000_0000;
        vcpu.gprs.rcx = 16;
        vcpu.gprs.rdx = 1;
        let out_tlb = dispatcher.dispatch_hypercall(&mut vcpu, 0, 3, &mut lapics);

        if matches!(
            out_ipi,
            HypercallOutcome::DeliveredIpiCount {
                vector: 0x45,
                recipient_count: 1
            }
        ) && matches!(
            out_tlb,
            HypercallOutcome::FlushedTlbPages { page_count: 16, .. }
        ) && lapics[1].claim_deliverable_vector() == Some(0x45)
        {
            passed_suites += 1;
        }
    }

    passed_suites
}

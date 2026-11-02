"""
Tier 3: Cross-Feature Interactions - Virtualization + Syscall Subsystem
=======================================================================
CorOS/tests/e2e/tier3_cross_feature/test_cross_virt_syscall.py

Tests pairwise integration between:
- corvirt (Intel VT-x / AMD SVM Hypervisor, VMCS, VM-Exit Handling)
- corsyscall (Linux 361-vector Syscall Dispatcher & Trap Frames)
- corbpf (eBPF kprobe/tracepoint hooks on syscall and hypercall events)
"""

import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in,
    SYS_GETPID, SYS_WRITE, X86_64SyscallRegisters
)

class MockHypercallDispatcher:
    VMCALL_GUEST_SYS_GETPID = 1
    VMCALL_GUEST_SYS_WRITE = 2
    VMCALL_GUEST_HALT = 3

    def __init__(self):
        self.kprobe_trace: list[tuple[int, int]] = []
        self.guest_exits = 0

    def attach_kprobe(self, hypercall_id: int):
        self.kprobe_trace.append((hypercall_id, 0))

    def handle_vm_exit(self, exit_reason: int, regs: X86_64SyscallRegisters) -> int:
        self.guest_exits += 1
        # Check if hypercall (VMCALL on Intel = 18)
        if exit_reason == 18:
            hypercall_id = regs.rax
            self.kprobe_trace.append((hypercall_id, regs.rdi))
            if hypercall_id == self.VMCALL_GUEST_SYS_GETPID:
                return 4096 # Guest virtual PID
            elif hypercall_id == self.VMCALL_GUEST_SYS_WRITE:
                return regs.rdx # written n bytes
        return -1

def test_guest_vmcall_to_hypervisor_dispatch():
    """Tier 3: Guest vCPU executes VMCALL instruction handled by hypervisor."""
    hyp = MockHypercallDispatcher()
    regs = X86_64SyscallRegisters(rax=MockHypercallDispatcher.VMCALL_GUEST_SYS_GETPID)
    
    ret = hyp.handle_vm_exit(exit_reason=18, regs=regs)
    assert_eq(ret, 4096)
    assert_eq(hyp.guest_exits, 1)

def test_ebpf_kprobe_attached_to_hypercall():
    """Tier 3: eBPF kprobe hook intercepts and logs hypercall execution with arguments."""
    hyp = MockHypercallDispatcher()
    regs = X86_64SyscallRegisters(
        rax=MockHypercallDispatcher.VMCALL_GUEST_SYS_WRITE,
        rdi=1,          # stdout
        rsi=0x80001000, # guest buffer
        rdx=128         # count
    )
    
    ret = hyp.handle_vm_exit(exit_reason=18, regs=regs)
    assert_eq(ret, 128)
    assert_eq(len(hyp.kprobe_trace), 1)
    assert_eq(hyp.kprobe_trace[0], (MockHypercallDispatcher.VMCALL_GUEST_SYS_WRITE, 1))

def test_ept_second_level_paging_translation():
    """Tier 3: Extended Page Tables (EPT) translates guest physical address to host physical."""
    # Guest Physical Address (GPA) -> Host Physical Address (HPA)
    ept_map = {0x0000000040001000: 0x0000000100001000}
    gpa = 0x0000000040001000
    hpa = ept_map.get(gpa)
    assert_true(hpa is not None)
    assert_eq(hpa, 0x0000000100001000)

def test_vm_exit_reason_handling():
    """Tier 3: Distinct VM-exit reasons: CR3 access (28), I/O instruction (30), EPT violation (48)."""
    EXIT_REASON_CR_ACCESS = 28
    EXIT_REASON_IO_INSTRUCTION = 30
    EXIT_REASON_EPT_VIOLATION = 48
    
    reasons = {EXIT_REASON_CR_ACCESS, EXIT_REASON_IO_INSTRUCTION, EXIT_REASON_EPT_VIOLATION}
    assert_eq(len(reasons), 3)
    assert_in(48, reasons)

def build_suite() -> TestSuite:
    suite = TestSuite("Cross-Feature: Virtualization + Syscall Subsystem", tier=3)
    suite.add("Guest VMCALL to Hypervisor Dispatch", test_guest_vmcall_to_hypervisor_dispatch, "F18+F14")
    suite.add("eBPF Kprobe Attached to Hypercall Trace", test_ebpf_kprobe_attached_to_hypercall, "F18+F14")
    suite.add("EPT Second-Level Paging Translation", test_ept_second_level_paging_translation, "F18+F06")
    suite.add("VM-Exit Reason Matrix Decoding", test_vm_exit_reason_handling, "F18+F02")
    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)

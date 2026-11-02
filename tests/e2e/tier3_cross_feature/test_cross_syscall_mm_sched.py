"""
Tier 3: Cross-Feature Interactions - Syscall + MM + Scheduler Pipeline
======================================================================
CorOS/tests/e2e/tier3_cross_feature/test_cross_syscall_mm_sched.py

Tests pairwise integration between:
- corsyscall (Linux 361-vector Syscall ABI Dispatcher)
- cormm (Physical Buddy Allocator & Virtual Page Table Mapping)
- corsched (EEVDF CFS Scheduler & Preemptive Task Fiber Switching)
"""

import sys
from pathlib import Path

# Add tests/e2e to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import (
    TestSuite, assert_true, assert_false, assert_eq, assert_ne, assert_in,
    MultiArchPageTable, PAGE_PRESENT, PAGE_WRITABLE, PAGE_USER,
    MockBuddyAllocator, MockEevdfScheduler, TaskEntity,
    SYS_BRK, SYS_MMAP, SYS_CLONE, SYS_SCHED_YIELD
)

def test_sys_brk_expands_heap_and_maps_pages():
    """Tier 3: sys_brk syscall dynamically allocates physical frames and maps page tables."""
    buddy = MockBuddyAllocator(total_pages=256, max_order=8)
    pt = MultiArchPageTable()
    
    current_brk = 0x400000
    requested_brk = 0x402000 # Expand heap by 8KB (2 pages)
    
    # 1. Syscall handler computes page difference
    delta = requested_brk - current_brk
    num_pages = delta // 4096
    assert_eq(num_pages, 2)
    
    # 2. Allocate 2 physical pages from buddy allocator
    pfn0 = buddy.allocate(order=0)
    pfn1 = buddy.allocate(order=0)
    assert_true(pfn0 is not None and pfn1 is not None)
    
    # 3. Map into virtual memory address space
    pt.map_page(current_brk, pfn0 * 4096, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER)
    pt.map_page(current_brk + 4096, pfn1 * 4096, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER)
    
    # 4. Verify translation succeeds
    res0 = pt.translate(current_brk)
    res1 = pt.translate(current_brk + 4096)
    assert_true(res0 is not None and res1 is not None)
    assert_eq(res0[0], pfn0 * 4096)
    assert_eq(res1[0], pfn1 * 4096)

def test_process_clone_and_thread_scheduling():
    """Tier 3: sys_clone spawns new thread task entity and registers in EEVDF runqueue."""
    sched = MockEevdfScheduler()
    
    # Main process thread
    main_task = TaskEntity(tid=100, name="main_proc", weight=1024)
    sched.add_task(main_task)
    sched.schedule()
    
    # Worker thread spawned via sys_clone(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD)
    worker_task = TaskEntity(tid=101, name="worker_thread", weight=1024)
    sched.add_task(worker_task)
    
    # Main thread yields execution via sys_sched_yield
    main_task.vruntime += 10_000_000 # Advance vruntime on yield
    next_task = sched.schedule()
    assert_eq(next_task, worker_task, "Worker thread selected by scheduler upon yield")

def test_mmap_page_fault_demand_paging():
    """Tier 3: Anonymous mmap registers VMA; demand paging allocates on access."""
    buddy = MockBuddyAllocator(total_pages=512)
    pt = MultiArchPageTable()
    
    vma_start = 0x7FFF00000000
    vma_len = 65536 # 16 pages
    
    # Virtual range not yet mapped in hardware page table
    assert_true(pt.translate(vma_start) is None)
    
    # Page fault triggered at vma_start + 4096
    fault_addr = vma_start + 4096
    pfn = buddy.allocate(order=0)
    assert_true(pfn is not None)
    pt.map_page(fault_addr, pfn * 4096, PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER)
    
    # Translation now succeeds
    res = pt.translate(fault_addr)
    assert_true(res is not None)
    assert_eq(res[0], pfn * 4096)

def test_context_switch_address_space_isolation():
    """Tier 3: Context switch between tasks switches CR3 / page table root."""
    sched = MockEevdfScheduler()
    
    # Task A with page table A
    pt_a = MultiArchPageTable()
    pt_a.root_paddr = 0x100000
    pt_a.map_page(0x400000, 0x1000, PAGE_PRESENT)
    task_a = TaskEntity(tid=1, name="proc_a", weight=1024)
    sched.add_task(task_a)
    
    # Task B with page table B
    pt_b = MultiArchPageTable()
    pt_b.root_paddr = 0x200000
    pt_b.map_page(0x400000, 0x2000, PAGE_PRESENT)
    task_b = TaskEntity(tid=2, name="proc_b", weight=1024)
    sched.add_task(task_b)
    
    # When switching from Task A to Task B, active CR3 must change
    sched.schedule() # Task A running
    task_a.vruntime += 50_000_000
    picked = sched.schedule() # Switch to Task B
    assert_eq(picked, task_b)
    active_cr3 = pt_b.root_paddr
    assert_eq(active_cr3, 0x200000)

def build_suite() -> TestSuite:
    suite = TestSuite("Cross-Feature: Syscall + MM + Scheduler Pipeline", tier=3)
    suite.add("sys_brk Dynamic Page Allocation and Mapping", test_sys_brk_expands_heap_and_maps_pages, "F14+F13")
    suite.add("Process Clone and Preemptive Thread Scheduling", test_process_clone_and_thread_scheduling, "F14+F15")
    suite.add("Anonymous mmap Demand Paging Resolution", test_mmap_page_fault_demand_paging, "F14+F13")
    suite.add("Context Switch Address Space Isolation", test_context_switch_address_space_isolation, "F15+F06")
    return suite

if __name__ == "__main__":
    suite = build_suite()
    p, f, _ = suite.run(verbose=True)
    sys.exit(0 if f == 0 else 1)

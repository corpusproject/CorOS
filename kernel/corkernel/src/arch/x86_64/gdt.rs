//! CorOS-owned GDT and TSS. The GDT reserves user descriptors but does not
//! enable ring-3 execution. TSS IST1 is reserved for double fault.
use core::{arch::global_asm, mem::size_of, ptr};

const KERNEL_CODE: u16 = 0x08;
const KERNEL_DATA: u16 = 0x10;
const TSS_SELECTOR: u16 = 0x28;
const DOUBLE_FAULT_STACK_SIZE: usize = 32 * 1024;

#[repr(C, packed)]
struct TaskStateSegment {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

impl TaskStateSegment {
    const fn new() -> Self {
        Self { reserved0: 0, rsp: [0; 3], reserved1: 0, ist: [0; 7], reserved2: 0, reserved3: 0, io_map_base: size_of::<Self>() as u16 }
    }
}

#[repr(C, packed)]
struct DescriptorPointer { limit: u16, base: u64 }

#[repr(align(16))]
struct DoubleFaultStack([u8; DOUBLE_FAULT_STACK_SIZE]);

static mut GDT: [u64; 7] = [0; 7];
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static mut DF_STACK: DoubleFaultStack = DoubleFaultStack([0; DOUBLE_FAULT_STACK_SIZE]);
const _: [(); 104] = [(); size_of::<TaskStateSegment>()];

unsafe extern "efiapi" {
    fn coros_load_gdt(pointer: *const DescriptorPointer, tss_selector: u16);
}

global_asm!(r#"
    .global coros_load_gdt
coros_load_gdt:
    lgdt [rcx]
    push 0x08
    lea rax, [rip + .Lcoros_gdt_loaded]
    push rax
    retfq
.Lcoros_gdt_loaded:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    ltr dx
    ret
"#);

/// Installs a flat kernel GDT and a TSS with IST1 double-fault stack.
/// # Safety
/// Must run once on the bootstrap CPU with interrupts disabled before loading the IDT.
pub unsafe fn initialize() {
    let stack_top = ptr::addr_of_mut!(DF_STACK.0) as *mut u8 as u64 + DOUBLE_FAULT_STACK_SIZE as u64;
    let tss = ptr::addr_of_mut!(TSS);
    ptr::addr_of_mut!((*tss).ist[0]).write_unaligned(stack_top);
    ptr::addr_of_mut!((*tss).io_map_base).write_unaligned(size_of::<TaskStateSegment>() as u16);

    let base = tss as u64;
    let limit = (size_of::<TaskStateSegment>() - 1) as u64;
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89u64 << 40)
        | (((limit >> 16) & 0x0f) << 48)
        | (((base >> 24) & 0xff) << 56);
    let high = base >> 32;
    let gdt = ptr::addr_of_mut!(GDT);
    (*gdt)[0] = 0;
    (*gdt)[1] = 0x00af_9a00_0000_ffff; // ring-0 64-bit code
    (*gdt)[2] = 0x00cf_9200_0000_ffff; // ring-0 data
    (*gdt)[3] = 0x00af_fa00_0000_ffff; // reserved ring-3 code
    (*gdt)[4] = 0x00cf_f200_0000_ffff; // reserved ring-3 data
    (*gdt)[5] = low;
    (*gdt)[6] = high;
    let pointer = DescriptorPointer { limit: (size_of::<[u64; 7]>() - 1) as u16, base: gdt as u64 };
    // SAFETY: GDT/TSS descriptors and selector were just initialized above.
    unsafe { coros_load_gdt(&pointer, TSS_SELECTOR); }
}

pub const fn kernel_code_selector() -> u16 { KERNEL_CODE }
pub const fn kernel_data_selector() -> u16 { KERNEL_DATA }
pub const fn user_code_selector() -> u16 { 0x18 | 3 }
pub const fn user_data_selector() -> u16 { 0x20 | 3 }
pub const fn double_fault_ist_index() -> u8 { 1 }

pub unsafe fn set_kernel_rsp0(rsp0: u64) {
    let tss = ptr::addr_of_mut!(TSS);
    ptr::addr_of_mut!((*tss).rsp[0]).write_unaligned(rsp0);
}

pub unsafe fn get_kernel_rsp0() -> u64 {
    let tss = ptr::addr_of_mut!(TSS);
    ptr::addr_of_mut!((*tss).rsp[0]).read_unaligned()
}



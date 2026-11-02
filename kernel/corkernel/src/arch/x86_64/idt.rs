//! CorOS-owned IDT and normalized exception entry. Handlers diagnose and halt;
//! CPU exceptions are fatal; registered legacy PIC IRQs return through iretq.
use core::{arch::{global_asm, asm}, mem::size_of, ptr};
use super::{cpu, gdt};

#[repr(C)]
pub struct ExceptionFrame {
    // Push order reversed by the CPU stack: r15 .. r8, then rdi .. rax.
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64,
    pub rdi: u64, pub rsi: u64, pub rbp: u64, pub rbx: u64,
    pub rdx: u64, pub rcx: u64, pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub flags: u64,
    // RSP/SS are pushed by hardware only on privilege change or IST entry.
}
const _: [(); 160] = [(); size_of::<ExceptionFrame>()];

/// x86 exception vectors for which the processor pushes an error code.
/// Every other stub supplies a zero placeholder so `ExceptionFrame` has a
/// consistent vector/error-code prefix. Hardware behavior remains unverified.
pub const fn exception_has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10..=14 | 17 | 21 | 29 | 30)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFaultError(pub u64);
impl PageFaultError {
    pub const fn protection_violation(self) -> bool { self.0 & 1 != 0 }
    pub const fn write(self) -> bool { self.0 & 2 != 0 }
    pub const fn user(self) -> bool { self.0 & 4 != 0 }
    pub const fn reserved_bit(self) -> bool { self.0 & 8 != 0 }
    pub const fn instruction_fetch(self) -> bool { self.0 & 16 != 0 }
    pub const fn protection_key(self) -> bool { self.0 & (1 << 5) != 0 }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry { offset_low: u16, selector: u16, ist: u8, attributes: u8, offset_mid: u16, offset_high: u32, reserved: u32 }
impl IdtEntry {
    const MISSING: Self = Self { offset_low: 0, selector: 0, ist: 0, attributes: 0, offset_mid: 0, offset_high: 0, reserved: 0 };
    fn interrupt(handler: usize, ist: u8) -> Self {
        Self { offset_low: handler as u16, selector: gdt::kernel_code_selector(), ist: ist & 7, attributes: 0x8e, offset_mid: (handler >> 16) as u16, offset_high: (handler >> 32) as u32, reserved: 0 }
    }
}
#[repr(C, packed)] struct Idtr { limit: u16, base: u64 }
static mut IDT: [IdtEntry; 256] = [IdtEntry::MISSING; 256];

macro_rules! declare_stubs { ($($name:ident),+ $(,)?) => { unsafe extern "efiapi" { $(fn $name();)+ } }; }
declare_stubs!(
 coros_isr_0,coros_isr_1,coros_isr_2,coros_isr_3,coros_isr_4,coros_isr_5,coros_isr_6,coros_isr_7,
 coros_isr_8,coros_isr_9,coros_isr_10,coros_isr_11,coros_isr_12,coros_isr_13,coros_isr_14,coros_isr_15,
 coros_isr_16,coros_isr_17,coros_isr_18,coros_isr_19,coros_isr_20,coros_isr_21,coros_isr_22,coros_isr_23,
 coros_isr_24,coros_isr_25,coros_isr_26,coros_isr_27,coros_isr_28,coros_isr_29,coros_isr_30,coros_isr_31,
 coros_isr_32,coros_isr_33,coros_isr_34,coros_isr_35,coros_isr_36,coros_isr_37,coros_isr_38,coros_isr_39,
 coros_isr_40,coros_isr_41,coros_isr_42,coros_isr_43,coros_isr_44,coros_isr_45,coros_isr_46,coros_isr_47,
);

macro_rules! declare_unexpected_stubs {
    ($($name:ident),+ $(,)?) => {
        unsafe extern "efiapi" { $(fn $name();)+ }
        const UNEXPECTED_HANDLERS: [unsafe extern "efiapi" fn(); 208] = [$($name),+];
    };
}
declare_unexpected_stubs!(
    coros_isr_48,coros_isr_49,coros_isr_50,coros_isr_51,coros_isr_52,coros_isr_53,coros_isr_54,coros_isr_55,
    coros_isr_56,coros_isr_57,coros_isr_58,coros_isr_59,coros_isr_60,coros_isr_61,coros_isr_62,coros_isr_63,
    coros_isr_64,coros_isr_65,coros_isr_66,coros_isr_67,coros_isr_68,coros_isr_69,coros_isr_70,coros_isr_71,
    coros_isr_72,coros_isr_73,coros_isr_74,coros_isr_75,coros_isr_76,coros_isr_77,coros_isr_78,coros_isr_79,
    coros_isr_80,coros_isr_81,coros_isr_82,coros_isr_83,coros_isr_84,coros_isr_85,coros_isr_86,coros_isr_87,
    coros_isr_88,coros_isr_89,coros_isr_90,coros_isr_91,coros_isr_92,coros_isr_93,coros_isr_94,coros_isr_95,
    coros_isr_96,coros_isr_97,coros_isr_98,coros_isr_99,coros_isr_100,coros_isr_101,coros_isr_102,coros_isr_103,
    coros_isr_104,coros_isr_105,coros_isr_106,coros_isr_107,coros_isr_108,coros_isr_109,coros_isr_110,coros_isr_111,
    coros_isr_112,coros_isr_113,coros_isr_114,coros_isr_115,coros_isr_116,coros_isr_117,coros_isr_118,coros_isr_119,
    coros_isr_120,coros_isr_121,coros_isr_122,coros_isr_123,coros_isr_124,coros_isr_125,coros_isr_126,coros_isr_127,
    coros_isr_128,coros_isr_129,coros_isr_130,coros_isr_131,coros_isr_132,coros_isr_133,coros_isr_134,coros_isr_135,
    coros_isr_136,coros_isr_137,coros_isr_138,coros_isr_139,coros_isr_140,coros_isr_141,coros_isr_142,coros_isr_143,
    coros_isr_144,coros_isr_145,coros_isr_146,coros_isr_147,coros_isr_148,coros_isr_149,coros_isr_150,coros_isr_151,
    coros_isr_152,coros_isr_153,coros_isr_154,coros_isr_155,coros_isr_156,coros_isr_157,coros_isr_158,coros_isr_159,
    coros_isr_160,coros_isr_161,coros_isr_162,coros_isr_163,coros_isr_164,coros_isr_165,coros_isr_166,coros_isr_167,
    coros_isr_168,coros_isr_169,coros_isr_170,coros_isr_171,coros_isr_172,coros_isr_173,coros_isr_174,coros_isr_175,
    coros_isr_176,coros_isr_177,coros_isr_178,coros_isr_179,coros_isr_180,coros_isr_181,coros_isr_182,coros_isr_183,
    coros_isr_184,coros_isr_185,coros_isr_186,coros_isr_187,coros_isr_188,coros_isr_189,coros_isr_190,coros_isr_191,
    coros_isr_192,coros_isr_193,coros_isr_194,coros_isr_195,coros_isr_196,coros_isr_197,coros_isr_198,coros_isr_199,
    coros_isr_200,coros_isr_201,coros_isr_202,coros_isr_203,coros_isr_204,coros_isr_205,coros_isr_206,coros_isr_207,
    coros_isr_208,coros_isr_209,coros_isr_210,coros_isr_211,coros_isr_212,coros_isr_213,coros_isr_214,coros_isr_215,
    coros_isr_216,coros_isr_217,coros_isr_218,coros_isr_219,coros_isr_220,coros_isr_221,coros_isr_222,coros_isr_223,
    coros_isr_224,coros_isr_225,coros_isr_226,coros_isr_227,coros_isr_228,coros_isr_229,coros_isr_230,coros_isr_231,
    coros_isr_232,coros_isr_233,coros_isr_234,coros_isr_235,coros_isr_236,coros_isr_237,coros_isr_238,coros_isr_239,
    coros_isr_240,coros_isr_241,coros_isr_242,coros_isr_243,coros_isr_244,coros_isr_245,coros_isr_246,coros_isr_247,
    coros_isr_248,coros_isr_249,coros_isr_250,coros_isr_251,coros_isr_252,coros_isr_253,coros_isr_254,coros_isr_255
);

const HANDLERS: [unsafe extern "efiapi" fn(); 48] = [
 coros_isr_0,coros_isr_1,coros_isr_2,coros_isr_3,coros_isr_4,coros_isr_5,coros_isr_6,coros_isr_7,
 coros_isr_8,coros_isr_9,coros_isr_10,coros_isr_11,coros_isr_12,coros_isr_13,coros_isr_14,coros_isr_15,
 coros_isr_16,coros_isr_17,coros_isr_18,coros_isr_19,coros_isr_20,coros_isr_21,coros_isr_22,coros_isr_23,
 coros_isr_24,coros_isr_25,coros_isr_26,coros_isr_27,coros_isr_28,coros_isr_29,coros_isr_30,coros_isr_31,
 coros_isr_32,coros_isr_33,coros_isr_34,coros_isr_35,coros_isr_36,coros_isr_37,coros_isr_38,coros_isr_39,
 coros_isr_40,coros_isr_41,coros_isr_42,coros_isr_43,coros_isr_44,coros_isr_45,coros_isr_46,coros_isr_47,
];

// FXSAVE/FXRSTOR preserves x87/SSE only; AVX/extended state is prohibited.
global_asm!(r#"
.macro ISR_NOERR number
.global coros_isr_\number
coros_isr_\number:
    push 0
    push \number
    jmp coros_isr_common
.endm
.macro ISR_ERR number
.global coros_isr_\number
coros_isr_\number:
    push \number
    jmp coros_isr_common
.endm
ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR 8
ISR_NOERR 9
ISR_ERR 10
ISR_ERR 11
ISR_ERR 12
ISR_ERR 13
ISR_ERR 14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR 17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR 29
ISR_ERR 30
ISR_NOERR 31
ISR_NOERR 32
ISR_NOERR 33
ISR_NOERR 34
ISR_NOERR 35
ISR_NOERR 36
ISR_NOERR 37
ISR_NOERR 38
ISR_NOERR 39
ISR_NOERR 40
ISR_NOERR 41
ISR_NOERR 42
ISR_NOERR 43
ISR_NOERR 44
ISR_NOERR 45
ISR_NOERR 46
ISR_NOERR 47
ISR_NOERR 48
ISR_NOERR 49
ISR_NOERR 50
ISR_NOERR 51
ISR_NOERR 52
ISR_NOERR 53
ISR_NOERR 54
ISR_NOERR 55
ISR_NOERR 56
ISR_NOERR 57
ISR_NOERR 58
ISR_NOERR 59
ISR_NOERR 60
ISR_NOERR 61
ISR_NOERR 62
ISR_NOERR 63
ISR_NOERR 64
ISR_NOERR 65
ISR_NOERR 66
ISR_NOERR 67
ISR_NOERR 68
ISR_NOERR 69
ISR_NOERR 70
ISR_NOERR 71
ISR_NOERR 72
ISR_NOERR 73
ISR_NOERR 74
ISR_NOERR 75
ISR_NOERR 76
ISR_NOERR 77
ISR_NOERR 78
ISR_NOERR 79
ISR_NOERR 80
ISR_NOERR 81
ISR_NOERR 82
ISR_NOERR 83
ISR_NOERR 84
ISR_NOERR 85
ISR_NOERR 86
ISR_NOERR 87
ISR_NOERR 88
ISR_NOERR 89
ISR_NOERR 90
ISR_NOERR 91
ISR_NOERR 92
ISR_NOERR 93
ISR_NOERR 94
ISR_NOERR 95
ISR_NOERR 96
ISR_NOERR 97
ISR_NOERR 98
ISR_NOERR 99
ISR_NOERR 100
ISR_NOERR 101
ISR_NOERR 102
ISR_NOERR 103
ISR_NOERR 104
ISR_NOERR 105
ISR_NOERR 106
ISR_NOERR 107
ISR_NOERR 108
ISR_NOERR 109
ISR_NOERR 110
ISR_NOERR 111
ISR_NOERR 112
ISR_NOERR 113
ISR_NOERR 114
ISR_NOERR 115
ISR_NOERR 116
ISR_NOERR 117
ISR_NOERR 118
ISR_NOERR 119
ISR_NOERR 120
ISR_NOERR 121
ISR_NOERR 122
ISR_NOERR 123
ISR_NOERR 124
ISR_NOERR 125
ISR_NOERR 126
ISR_NOERR 127
ISR_NOERR 128
ISR_NOERR 129
ISR_NOERR 130
ISR_NOERR 131
ISR_NOERR 132
ISR_NOERR 133
ISR_NOERR 134
ISR_NOERR 135
ISR_NOERR 136
ISR_NOERR 137
ISR_NOERR 138
ISR_NOERR 139
ISR_NOERR 140
ISR_NOERR 141
ISR_NOERR 142
ISR_NOERR 143
ISR_NOERR 144
ISR_NOERR 145
ISR_NOERR 146
ISR_NOERR 147
ISR_NOERR 148
ISR_NOERR 149
ISR_NOERR 150
ISR_NOERR 151
ISR_NOERR 152
ISR_NOERR 153
ISR_NOERR 154
ISR_NOERR 155
ISR_NOERR 156
ISR_NOERR 157
ISR_NOERR 158
ISR_NOERR 159
ISR_NOERR 160
ISR_NOERR 161
ISR_NOERR 162
ISR_NOERR 163
ISR_NOERR 164
ISR_NOERR 165
ISR_NOERR 166
ISR_NOERR 167
ISR_NOERR 168
ISR_NOERR 169
ISR_NOERR 170
ISR_NOERR 171
ISR_NOERR 172
ISR_NOERR 173
ISR_NOERR 174
ISR_NOERR 175
ISR_NOERR 176
ISR_NOERR 177
ISR_NOERR 178
ISR_NOERR 179
ISR_NOERR 180
ISR_NOERR 181
ISR_NOERR 182
ISR_NOERR 183
ISR_NOERR 184
ISR_NOERR 185
ISR_NOERR 186
ISR_NOERR 187
ISR_NOERR 188
ISR_NOERR 189
ISR_NOERR 190
ISR_NOERR 191
ISR_NOERR 192
ISR_NOERR 193
ISR_NOERR 194
ISR_NOERR 195
ISR_NOERR 196
ISR_NOERR 197
ISR_NOERR 198
ISR_NOERR 199
ISR_NOERR 200
ISR_NOERR 201
ISR_NOERR 202
ISR_NOERR 203
ISR_NOERR 204
ISR_NOERR 205
ISR_NOERR 206
ISR_NOERR 207
ISR_NOERR 208
ISR_NOERR 209
ISR_NOERR 210
ISR_NOERR 211
ISR_NOERR 212
ISR_NOERR 213
ISR_NOERR 214
ISR_NOERR 215
ISR_NOERR 216
ISR_NOERR 217
ISR_NOERR 218
ISR_NOERR 219
ISR_NOERR 220
ISR_NOERR 221
ISR_NOERR 222
ISR_NOERR 223
ISR_NOERR 224
ISR_NOERR 225
ISR_NOERR 226
ISR_NOERR 227
ISR_NOERR 228
ISR_NOERR 229
ISR_NOERR 230
ISR_NOERR 231
ISR_NOERR 232
ISR_NOERR 233
ISR_NOERR 234
ISR_NOERR 235
ISR_NOERR 236
ISR_NOERR 237
ISR_NOERR 238
ISR_NOERR 239
ISR_NOERR 240
ISR_NOERR 241
ISR_NOERR 242
ISR_NOERR 243
ISR_NOERR 244
ISR_NOERR 245
ISR_NOERR 246
ISR_NOERR 247
ISR_NOERR 248
ISR_NOERR 249
ISR_NOERR 250
ISR_NOERR 251
ISR_NOERR 252
ISR_NOERR 253
ISR_NOERR 254
ISR_NOERR 255
coros_isr_common:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r12, rsp
    and rsp, -16
    sub rsp, 544
    fxsave64 [rsp + 32]
    mov rcx, r12
    call coros_interrupt_dispatch
    fxrstor64 [rsp + 32]
    mov rsp, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq
"#);

/// Installs distinct normalized stubs for all 256 vectors, then loads IDTR.
/// # Safety
/// Run once on the bootstrap CPU with interrupts disabled after `gdt::initialize`.
pub unsafe fn initialize() {
    let idt = ptr::addr_of_mut!(IDT);
    for (vector, handler) in HANDLERS.iter().enumerate() {
        (*idt)[vector] = IdtEntry::interrupt(*handler as *const () as usize, if vector == 8 { gdt::double_fault_ist_index() } else { 0 });
    }
    for (offset, handler) in UNEXPECTED_HANDLERS.iter().enumerate() {
        (*idt)[48 + offset] = IdtEntry::interrupt(*handler as *const () as usize, 0);
    }
    let descriptor = Idtr { limit: (size_of::<[IdtEntry; 256]>() - 1) as u16, base: idt as u64 };
    asm!("lidt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));
}

#[no_mangle]
pub unsafe extern "efiapi" fn coros_interrupt_dispatch(frame_ptr: *mut ExceptionFrame) {
    cpu::disable_interrupts();
    if frame_ptr.is_null() { cpu::halt_forever(); }
    // The assembly stub supplies a pointer to its saved register/CPU frame on
    // the current mapped kernel stack.
    let frame = &mut *frame_ptr;
    // Exceptions never reach IRQ dispatch and never receive controller EOI.
    if frame.vector >= 32 {
        super::interrupts::dispatch(frame);
        return;
    }

    // Hardware crash containment: Check if exception came from Ring 3 (CS & 3 == 3) or active user space simulation
    let is_user = (frame.code_segment & 3) == 3 || crate::task::usermode::is_user_execution_active();
    if is_user && (frame.vector == 14 || frame.vector == 13 || frame.vector == 6) {
        let cr2 = if frame.vector == 14 { cpu::read_cr2() } else { 0 };
        crate::task::usermode::record_user_crash(frame.vector, frame.error_code, frame.instruction_pointer, cr2);
        crate::task::usermode::recover_user_frame(frame);
        return;
    }

    fatal_exception(frame)
}

pub(super) fn fatal_exception(frame: &ExceptionFrame) -> ! {
    let boot = unsafe { ptr::addr_of!(crate::PANIC_BOOT_INFO).read() };
    let boot_info = if boot.is_null() { None } else { Some(unsafe { &*boot }) };
    unsafe { crate::diagnostics::logger::log(boot_info, crate::diagnostics::logger::LogLevel::Error, "COROS EXCEPTION - HALTING"); }
    crate::diagnostics::serial::write_u64("VECTOR: ", frame.vector);
    crate::diagnostics::serial::write_u64("ERROR: ", frame.error_code);
    crate::diagnostics::serial::write_u64("RIP: ", frame.instruction_pointer);
    crate::diagnostics::serial::write_u64("CS: ", frame.code_segment);
    crate::diagnostics::serial::write_u64("RFLAGS: ", frame.flags);
    if frame.vector == 14 {
        let address = cpu::read_cr2();
        let error = PageFaultError(frame.error_code);
        crate::diagnostics::serial::write_u64("CR2: ", address);
        crate::diagnostics::serial::write_str(if error.protection_violation() { "PAGE: PROTECTION\r\n" } else { "PAGE: NOT PRESENT\r\n" });
        crate::diagnostics::serial::write_str(if error.write() { "ACCESS: WRITE\r\n" } else { "ACCESS: READ\r\n" });
        crate::diagnostics::serial::write_str(if error.user() { "MODE: USER\r\n" } else { "MODE: SUPERVISOR\r\n" });
        if error.reserved_bit() { crate::diagnostics::serial::write_str("RESERVED BIT VIOLATION\r\n"); }
        if error.instruction_fetch() { crate::diagnostics::serial::write_str("INSTRUCTION FETCH\r\n"); }
        if error.protection_key() { crate::diagnostics::serial::write_str("PROTECTION KEY VIOLATION\r\n"); }
    }
    cpu::halt_forever()
}

const _: [(); 16] = [(); size_of::<IdtEntry>()];

#[cfg(test)]
mod tests {
    use super::{exception_has_error_code, PageFaultError};
    #[test]
    fn hardware_error_code_vector_classification_is_explicit() {
        for vector in [8, 10, 11, 12, 13, 14, 17, 21, 29, 30] {
            assert!(exception_has_error_code(vector));
        }
        for vector in [0, 7, 9, 15, 16, 20, 28, 31, 32, 255] {
            assert!(!exception_has_error_code(vector));
        }
    }
    #[test]
    fn decodes_page_fault_access_and_protection_bits() {
        let error = PageFaultError(1 | 2 | 4 | 8 | 16 | (1 << 5));
        assert!(error.protection_violation()); assert!(error.write()); assert!(error.user());
        assert!(error.reserved_bit()); assert!(error.instruction_fetch()); assert!(error.protection_key());
        let absent = PageFaultError(0);
        assert!(!absent.protection_violation()); assert!(!absent.write()); assert!(!absent.user());
    }
}

// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generation and validation of classic seccomp-BPF code for feature-tagged rules.
//!
//! libseccomp compiles the untagged rules of a filter into a *base* program. Every
//! `ret #default_action` of that program is rewritten by [`redirect_default_returns`] into an
//! unconditional jump to the end of the program, so that the base falls through into whatever is
//! appended after it: a [`suffix_prologue`] that re-checks the architecture, one
//! position-independent [`rule_fragment`] per enabled feature-tagged rule, and an [`epilogue`]
//! that finally returns the default action. [`validate`] mirrors the kernel checks on the composed
//! program.
//!
//! An instruction is `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }`, stored as one
//! little-endian `u64`: `code | jt << 16 | jf << 24 | k << 32`.

use crate::types::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, TargetArch};

/// `BPF_LD | BPF_W | BPF_ABS`: load the 32-bit word at `seccomp_data` offset `k` into `A`.
pub const BPF_LD_W_ABS: u16 = 0x20;
/// `BPF_JMP | BPF_JEQ | BPF_K`: jump to `pc + 1 + jt` if `A == k`, else to `pc + 1 + jf`.
pub const BPF_JEQ_K: u16 = 0x15;
/// `BPF_JMP | BPF_JGT | BPF_K`: jump to `pc + 1 + jt` if `A > k`, else to `pc + 1 + jf`.
pub const BPF_JGT_K: u16 = 0x25;
/// `BPF_JMP | BPF_JGE | BPF_K`: jump to `pc + 1 + jt` if `A >= k`, else to `pc + 1 + jf`.
pub const BPF_JGE_K: u16 = 0x35;
/// `BPF_JMP | BPF_JSET | BPF_K`: jump to `pc + 1 + jt` if `A & k != 0`, else to `pc + 1 + jf`.
pub const BPF_JSET_K: u16 = 0x45;
/// `BPF_JMP | BPF_JA`: unconditional jump to `pc + 1 + k`.
pub const BPF_JA: u16 = 0x05;
/// `BPF_RET | BPF_K`: return `k`.
pub const BPF_RET_K: u16 = 0x06;
/// `BPF_RET | BPF_A`: return `A`.
pub const BPF_RET_A: u16 = 0x16;
/// `BPF_ALU | BPF_AND | BPF_K`: `A &= k`.
pub const BPF_AND_K: u16 = 0x54;
/// `BPF_ALU | BPF_OR | BPF_K`: `A |= k`.
pub const BPF_OR_K: u16 = 0x44;

/// Offset of `seccomp_data.nr`.
pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
/// Offset of `seccomp_data.arch`.
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
/// `sizeof(struct seccomp_data)`; loads must stay below it.
pub const SECCOMP_DATA_SIZE: u32 = 64;
/// Offset of `seccomp_data.args[0]`.
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;

/// `AUDIT_ARCH_X86_64`.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `AUDIT_ARCH_AARCH64`.
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// On x86_64 a syscall number with this bit set uses the x32 ABI.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// `BPF_MAXINSNS`: the maximum number of instructions in a program.
pub const BPF_MAX_LEN: usize = 4096;

/// Offset of the low 32 bits of `seccomp_data.args[index]` (little-endian).
pub const fn seccomp_data_arg_lo_offset(index: u8) -> u32 {
    SECCOMP_DATA_ARGS_OFFSET + 8 * index as u32
}

/// Offset of the high 32 bits of `seccomp_data.args[index]` (little-endian).
pub const fn seccomp_data_arg_hi_offset(index: u8) -> u32 {
    seccomp_data_arg_lo_offset(index) + 4
}

/// The `AUDIT_ARCH_*` value the kernel reports in `seccomp_data.arch` for `arch`.
pub const fn audit_arch(arch: &TargetArch) -> u32 {
    match arch {
        TargetArch::X86_64 => AUDIT_ARCH_X86_64,
        TargetArch::Aarch64 => AUDIT_ARCH_AARCH64,
    }
}

/// Encode one `sock_filter` instruction.
pub const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> u64 {
    let code = code.to_le_bytes();
    let k = k.to_le_bytes();
    u64::from_le_bytes([code[0], code[1], jt, jf, k[0], k[1], k[2], k[3]])
}

/// Decode one `sock_filter` instruction into `(code, jt, jf, k)`.
pub const fn decode(insn: u64) -> (u16, u8, u8, u32) {
    let b = insn.to_le_bytes();
    (
        u16::from_le_bytes([b[0], b[1]]),
        b[2],
        b[3],
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    )
}

/// Split a 64-bit value into its `(high, low)` 32-bit halves.
fn halves(value: u64) -> (u32, u32) {
    // Truncation is the purpose of this function.
    #[allow(clippy::cast_possible_truncation)]
    ((value >> 32) as u32, value as u32)
}

/// BPF generation and validation errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum BpfError {
    /// The program contains no `ret #default_action` instruction
    NoDefaultReturn,
    /// Unexpected `ret A` instruction at {0}
    ReturnAccumulator(usize),
    /// Program of {0} instructions exceeds the BPF maximum length
    TooLong(usize),
    /// Empty program
    Empty,
    /// The last instruction of the program is not a return
    LastNotReturn,
    /// Jump at {0} targets an instruction outside of the program
    InvalidJump(usize),
    /// Load at {0} has an invalid offset
    InvalidLoad(usize),
    /// Unknown opcode {1} at {0}
    UnknownOpcode(usize, u16),
    /// Fragment of {0} instructions needs a jump that does not fit in a u8
    FragmentTooLong(usize),
    /// Invalid syscall argument index {0}
    InvalidArgIndex(u8),
    /// Several conditions on syscall argument {0}
    DuplicateArgIndex(u8),
}

/// Rewrite every `ret #default_action` (`BPF_RET_K` with `k == default_action`) of a program
/// produced by libseccomp into a `ja` to the instruction one past the program's end
/// (`k = program.len() - pc - 1`), so the program falls through into whatever is appended after
/// it.
///
/// libseccomp duplicates returns when it needs long jumps, so every copy is rewritten. The
/// bad-arch return of the base program is rewritten too when it coincides with the default
/// action, which is why [`suffix_prologue`] re-checks the architecture.
///
/// Returns the number of rewritten instructions; [`BpfError::NoDefaultReturn`] if there was
/// none, [`BpfError::ReturnAccumulator`] if the program contains a `ret A`, in which case the
/// program is left untouched.
pub fn redirect_default_returns(
    program: &mut [u64],
    default_action: u32,
) -> Result<usize, BpfError> {
    let len = program.len();
    if let Some(pc) = program.iter().position(|&i| decode(i).0 == BPF_RET_A) {
        return Err(BpfError::ReturnAccumulator(pc));
    }
    let mut count = 0;
    for (pc, instruction) in program.iter_mut().enumerate() {
        let (code, _, _, k) = decode(*instruction);
        if code == BPF_RET_K && k == default_action {
            let offset = u32::try_from(len - pc - 1).map_err(|_| BpfError::TooLong(len))?;
            *instruction = insn(BPF_JA, 0, 0, offset);
            count += 1;
        }
    }
    if count == 0 {
        return Err(BpfError::NoDefaultReturn);
    }
    Ok(count)
}

/// Code appended right after the redirected base program.
///
/// `ld [arch]; jeq #AUDIT_ARCH, 1, 0; ret #default_action`, and on x86_64 additionally
/// `ld [nr]; jset #X32_SYSCALL_BIT, 0, 1; ret #default_action`. Position independent; falls
/// through for a native syscall of the target architecture.
pub fn suffix_prologue(arch: &TargetArch, default_action: u32) -> Vec<u64> {
    let mut prologue = vec![
        insn(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
        insn(BPF_JEQ_K, 1, 0, audit_arch(arch)),
        insn(BPF_RET_K, 0, 0, default_action),
    ];
    if matches!(arch, TargetArch::X86_64) {
        prologue.extend([
            insn(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
            insn(BPF_JSET_K, 0, 1, X32_SYSCALL_BIT),
            insn(BPF_RET_K, 0, 0, default_action),
        ]);
    }
    prologue
}

/// `[ret #default_action]`: the end of the composed program.
pub fn epilogue(default_action: u32) -> Vec<u64> {
    vec![insn(BPF_RET_K, 0, 0, default_action)]
}

/// Jump target of a not yet laid out fragment instruction.
#[derive(Clone, Copy)]
enum Target {
    /// Continue with the next instruction.
    Next,
    /// Skip the next `n` instructions.
    Skip(u8),
    /// Leave the fragment (the condition did not match).
    End,
}

/// A fragment instruction whose jump targets are resolved once the fragment is complete.
struct Pending {
    code: u16,
    jt: Target,
    jf: Target,
    k: u32,
}

impl Pending {
    fn ld(offset: u32) -> Self {
        Self::new(BPF_LD_W_ABS, Target::Next, Target::Next, offset)
    }

    fn new(code: u16, jt: Target, jf: Target, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

/// Append the instructions checking one condition on the syscall arguments to `out`.
///
/// Every sequence starts with a load, so it never relies on the accumulator value at entry;
/// it continues with the next instruction when the condition matches and jumps to
/// [`Target::End`] otherwise. The semantics are the ones libseccomp gives the comparators built
/// by [`SeccompCondition::to_scmp_type`].
fn condition_code(cond: &SeccompCondition, out: &mut Vec<Pending>) {
    use Target::{End, Next, Skip};

    let lo_offset = seccomp_data_arg_lo_offset(cond.index);
    let hi_offset = seccomp_data_arg_hi_offset(cond.index);
    let (vhi, vlo) = halves(cond.val);
    let (mask, ne) = match cond.op {
        // libseccomp compares all 64 bits, so Firecracker turns a 32-bit `eq` into a masked
        // compare of the low half because musl leaves garbage in the upper half of some
        // arguments. A 64-bit `eq` is a masked compare with a full mask.
        SeccompCmpOp::Eq => (
            match cond.val_len {
                SeccompCmpArgLen::Dword => u64::from(u32::MAX),
                SeccompCmpArgLen::Qword => u64::MAX,
            },
            false,
        ),
        SeccompCmpOp::MaskedEq(mask) => (mask, false),
        SeccompCmpOp::Ne => (u64::MAX, true),
        SeccompCmpOp::Gt | SeccompCmpOp::Ge | SeccompCmpOp::Lt | SeccompCmpOp::Le => {
            // Unsigned 64-bit comparison: the high halves decide unless they are equal.
            let greater = matches!(cond.op, SeccompCmpOp::Gt | SeccompCmpOp::Ge);
            let strict = matches!(cond.op, SeccompCmpOp::Gt | SeccompCmpOp::Lt);
            out.push(Pending::ld(hi_offset));
            if greater {
                // hi > vhi: match; hi == vhi: compare lo; hi < vhi: mismatch.
                out.push(Pending::new(BPF_JGT_K, Skip(3), Next, vhi));
                out.push(Pending::new(BPF_JEQ_K, Next, End, vhi));
            } else {
                // hi > vhi: mismatch; hi == vhi: compare lo; hi < vhi: match.
                out.push(Pending::new(BPF_JGT_K, End, Next, vhi));
                out.push(Pending::new(BPF_JEQ_K, Next, Skip(2), vhi));
            }
            out.push(Pending::ld(lo_offset));
            out.push(match (greater, strict) {
                (true, true) => Pending::new(BPF_JGT_K, Next, End, vlo),
                (true, false) => Pending::new(BPF_JGE_K, Next, End, vlo),
                (false, true) => Pending::new(BPF_JGE_K, End, Next, vlo),
                (false, false) => Pending::new(BPF_JGT_K, End, Next, vlo),
            });
            return;
        }
    };

    if ne {
        // arg != val: a differing high half matches at once, otherwise the low half decides.
        out.push(Pending::ld(hi_offset));
        out.push(Pending::new(BPF_JEQ_K, Next, Skip(2), vhi));
        out.push(Pending::ld(lo_offset));
        out.push(Pending::new(BPF_JEQ_K, End, Next, vlo));
        return;
    }

    // (arg & mask) == (val & mask), half by half. libseccomp masks the value as well
    // (`_db_node_mask_fixup`), so a half with an empty mask always matches and is skipped.
    let (mhi, mlo) = halves(mask);
    for (offset, m, v) in [(hi_offset, mhi, vhi), (lo_offset, mlo, vlo)] {
        if m == 0 {
            continue;
        }
        out.push(Pending::ld(offset));
        if m != u32::MAX {
            out.push(Pending::new(BPF_AND_K, Next, Next, m));
        }
        out.push(Pending::new(BPF_JEQ_K, Next, End, v & m));
    }
}

/// One position-independent fragment for a rule:
/// `ld [nr]; jeq #syscall_nr, 0, END; <conditions>; ret #action`, where every condition jumps to
/// `END`, the fragment length, on mismatch, so a non-matching fragment falls through into whatever
/// follows it. All conditions must match for the action to be returned.
///
/// Returns [`BpfError::InvalidArgIndex`] for an argument index above 5,
/// [`BpfError::DuplicateArgIndex`] when two conditions check the same argument (libseccomp
/// rejects such rules too) and [`BpfError::FragmentTooLong`] if a jump offset would not fit in
/// a `u8`.
pub fn rule_fragment(
    syscall_nr: u32,
    conditions: &[SeccompCondition],
    action: u32,
) -> Result<Vec<u64>, BpfError> {
    if let Some(cond) = conditions.iter().find(|cond| cond.index > 5) {
        return Err(BpfError::InvalidArgIndex(cond.index));
    }
    for (i, cond) in conditions.iter().enumerate() {
        if conditions[..i]
            .iter()
            .any(|other| other.index == cond.index)
        {
            return Err(BpfError::DuplicateArgIndex(cond.index));
        }
    }

    let mut pending = vec![
        Pending::ld(SECCOMP_DATA_NR_OFFSET),
        Pending::new(BPF_JEQ_K, Target::Next, Target::End, syscall_nr),
    ];
    for cond in conditions {
        condition_code(cond, &mut pending);
    }
    pending.push(Pending::new(BPF_RET_K, Target::Next, Target::Next, action));

    let len = pending.len();
    let resolve = |pc: usize, target: Target| match target {
        Target::Next => Ok(0),
        Target::Skip(n) => Ok(n),
        Target::End => u8::try_from(len - pc - 1).map_err(|_| BpfError::FragmentTooLong(len)),
    };
    pending
        .iter()
        .enumerate()
        .map(|(pc, p)| Ok(insn(p.code, resolve(pc, p.jt)?, resolve(pc, p.jf)?, p.k)))
        .collect()
}

/// Mirror the kernel checks (`bpf_check_classic` and `seccomp_check_filter`) on a complete
/// program: `1 <= len <= 4096`, the last instruction is a return, every jump lands strictly
/// inside the program, loads are `ld [k]` with `k % 4 == 0 && k < 64`, and only the opcodes
/// defined in this module are used.
pub fn validate(program: &[u64]) -> Result<(), BpfError> {
    let len = program.len();
    if len == 0 {
        return Err(BpfError::Empty);
    }
    if len > BPF_MAX_LEN {
        return Err(BpfError::TooLong(len));
    }
    let last = decode(program[len - 1]).0;
    if last != BPF_RET_K && last != BPF_RET_A {
        return Err(BpfError::LastNotReturn);
    }
    for (pc, &instruction) in program.iter().enumerate() {
        let (code, jt, jf, k) = decode(instruction);
        match code {
            BPF_LD_W_ABS => {
                if k % 4 != 0 || k >= SECCOMP_DATA_SIZE {
                    return Err(BpfError::InvalidLoad(pc));
                }
            }
            BPF_JA => {
                if usize::try_from(k).map_or(true, |k| k >= len - pc - 1) {
                    return Err(BpfError::InvalidJump(pc));
                }
            }
            BPF_JEQ_K | BPF_JGT_K | BPF_JGE_K | BPF_JSET_K => {
                if pc + 1 + usize::from(jt) >= len || pc + 1 + usize::from(jf) >= len {
                    return Err(BpfError::InvalidJump(pc));
                }
            }
            BPF_RET_K | BPF_RET_A | BPF_AND_K | BPF_OR_K => {}
            _ => return Err(BpfError::UnknownOpcode(pc, code)),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    /// Returned by the sentinel appended after a fragment or prologue under test.
    const FALLTHROUGH: u32 = 0xDEAD_BEEF;

    const NR_WRITE: i32 = 1;
    const NR_OPEN: i32 = 2;
    const NR_CLOSE: i32 = 3;
    const NR_IOCTL: i32 = 16;
    const NR_EXIT: i32 = 60;
    const KVM_CHECK_EXTENSION: u64 = 44547;

    /// `struct seccomp_data` as the kernel hands it to the filter.
    pub(crate) struct SeccompData {
        pub(crate) nr: i32,
        pub(crate) arch: u32,
        pub(crate) instruction_pointer: u64,
        pub(crate) args: [u64; 6],
    }

    impl SeccompData {
        pub(crate) fn x86_64(nr: i32, args: [u64; 6]) -> Self {
            Self::new(AUDIT_ARCH_X86_64, nr, args)
        }

        pub(crate) fn new(arch: u32, nr: i32, args: [u64; 6]) -> Self {
            Self {
                nr,
                arch,
                instruction_pointer: 0xdead_0000_beef,
                args,
            }
        }

        /// The little-endian 32-bit word at `offset`.
        fn load(&self, offset: u32) -> u32 {
            let mut bytes = [0u8; 64];
            bytes[0..4].copy_from_slice(&self.nr.to_le_bytes());
            bytes[4..8].copy_from_slice(&self.arch.to_le_bytes());
            bytes[8..16].copy_from_slice(&self.instruction_pointer.to_le_bytes());
            for (i, arg) in self.args.iter().enumerate() {
                bytes[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
            }
            let offset = usize::try_from(offset).unwrap();
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
        }
    }

    /// Run `program` on `data` and return the value of the `ret` that ends it.
    pub(crate) fn simulate(program: &[u64], data: &SeccompData) -> u32 {
        let mut pc = 0;
        let mut acc = 0u32;
        loop {
            let (code, jt, jf, k) = decode(program[pc]);
            let jump = move |taken: bool| pc + 1 + usize::from(if taken { jt } else { jf });
            pc = match code {
                BPF_LD_W_ABS => {
                    acc = data.load(k);
                    pc + 1
                }
                BPF_AND_K => {
                    acc &= k;
                    pc + 1
                }
                BPF_OR_K => {
                    acc |= k;
                    pc + 1
                }
                BPF_JEQ_K => jump(acc == k),
                BPF_JGT_K => jump(acc > k),
                BPF_JGE_K => jump(acc >= k),
                BPF_JSET_K => jump(acc & k != 0),
                BPF_JA => pc + 1 + usize::try_from(k).unwrap(),
                BPF_RET_K => return k,
                BPF_RET_A => return acc,
                _ => panic!("unknown opcode {code:#x} at {pc}"),
            };
            assert!(pc < program.len(), "jump out of the program to {pc}");
        }
    }

    fn cond(index: u8, op: SeccompCmpOp, val: u64, val_len: SeccompCmpArgLen) -> SeccompCondition {
        SeccompCondition {
            index,
            op,
            val,
            val_len,
            comment: None,
        }
    }

    /// Run `code` followed by a sentinel return, so a fall-through is observable.
    fn run_with_sentinel(code: &[u64], data: &SeccompData) -> u32 {
        let mut program = code.to_vec();
        program.push(insn(BPF_RET_K, 0, 0, FALLTHROUGH));
        validate(&program).unwrap();
        simulate(&program, data)
    }

    /// Whether an ioctl rule with the given condition on `arg1` matches `arg1`.
    fn ioctl_matches(op: SeccompCmpOp, val_len: SeccompCmpArgLen, val: u64, arg1: u64) -> bool {
        let fragment = rule_fragment(
            u32::try_from(NR_IOCTL).unwrap(),
            &[cond(1, op, val, val_len)],
            SECCOMP_RET_ALLOW,
        )
        .unwrap();
        let data = SeccompData::x86_64(NR_IOCTL, [0, arg1, 0, 0, 0, 0]);
        match run_with_sentinel(&fragment, &data) {
            SECCOMP_RET_ALLOW => true,
            FALLTHROUGH => false,
            other => panic!("unexpected return {other:#x}"),
        }
    }

    #[test]
    fn test_insn_decode_roundtrip() {
        let encoded = insn(BPF_JEQ_K, 3, 7, 0xC000_003E);
        assert_eq!(encoded, 0xC000_003E_0703_0015);
        assert_eq!(decode(encoded), (BPF_JEQ_K, 3, 7, 0xC000_003E));
        assert_eq!(decode(insn(BPF_RET_K, 0, 0, 0)), (BPF_RET_K, 0, 0, 0));
        assert_eq!(
            decode(insn(u16::MAX, u8::MAX, u8::MAX, u32::MAX)),
            (u16::MAX, u8::MAX, u8::MAX, u32::MAX)
        );
    }

    #[test]
    fn test_offsets_and_arch() {
        assert_eq!(seccomp_data_arg_lo_offset(0), 16);
        assert_eq!(seccomp_data_arg_hi_offset(0), 20);
        assert_eq!(seccomp_data_arg_lo_offset(5), 56);
        assert_eq!(seccomp_data_arg_hi_offset(5), 60);
        assert_eq!(audit_arch(&TargetArch::X86_64), AUDIT_ARCH_X86_64);
        assert_eq!(audit_arch(&TargetArch::Aarch64), AUDIT_ARCH_AARCH64);

        let data = SeccompData::x86_64(NR_IOCTL, [0, 0x1122_3344_5566_7788, 0, 0, 0, 0]);
        assert_eq!(data.load(SECCOMP_DATA_NR_OFFSET), 16);
        assert_eq!(data.load(SECCOMP_DATA_ARCH_OFFSET), AUDIT_ARCH_X86_64);
        assert_eq!(data.load(seccomp_data_arg_lo_offset(1)), 0x5566_7788);
        assert_eq!(data.load(seccomp_data_arg_hi_offset(1)), 0x1122_3344);
    }

    #[test]
    fn test_fragment_eq() {
        use SeccompCmpArgLen::{Dword, Qword};
        use SeccompCmpOp::Eq;

        assert!(ioctl_matches(Eq, Dword, 0x5401, 0x5401));
        assert!(!ioctl_matches(Eq, Dword, 0x5401, 0x5402));
        // musl leaves garbage in the upper half: a 32-bit `eq` ignores it.
        assert!(ioctl_matches(Eq, Dword, 0x5401, 0xFFFF_FFFF_0000_5401));
        // ...but a 64-bit `eq` does not.
        assert!(ioctl_matches(Eq, Qword, 0x5401, 0x5401));
        assert!(!ioctl_matches(Eq, Qword, 0x5401, 0xFFFF_FFFF_0000_5401));
        assert!(!ioctl_matches(Eq, Qword, 0x5401, 0x5402));
        assert!(ioctl_matches(Eq, Qword, 0x1_0000_5401, 0x1_0000_5401));
        assert!(!ioctl_matches(Eq, Qword, 0x1_0000_5401, 0x5401));
        assert!(!ioctl_matches(Eq, Qword, 0x1_0000_5401, 0x2_0000_5401));
    }

    #[test]
    fn test_fragment_ne() {
        use SeccompCmpArgLen::{Dword, Qword};
        use SeccompCmpOp::Ne;

        for len in [Dword, Qword] {
            assert!(!ioctl_matches(Ne, len.clone(), 0x5401, 0x5401));
            assert!(ioctl_matches(Ne, len.clone(), 0x5401, 0x5402));
            // The comparison is always 64-bit wide.
            assert!(ioctl_matches(Ne, len.clone(), 0x5401, 0x1_0000_5401));
            assert!(ioctl_matches(Ne, len.clone(), 0x1_0000_5401, 0x5401));
            assert!(!ioctl_matches(Ne, len, 0x1_0000_5401, 0x1_0000_5401));
        }
    }

    #[test]
    fn test_fragment_ordered_qword() {
        use SeccompCmpArgLen::Qword;
        use SeccompCmpOp::{Ge, Gt, Le, Lt};

        // hi = 1, lo = 0x10
        const V: u64 = 0x1_0000_0010;
        // Candidates: at the boundary, just around it, and with differing high words only.
        let below = [V - 1, 0xFFFF_FFFF, 0];
        let above = [V + 1, 0x2_0000_0000, 0x1_FFFF_FFFF, u64::MAX];

        assert!(!ioctl_matches(Gt, Qword, V, V));
        assert!(ioctl_matches(Ge, Qword, V, V));
        assert!(!ioctl_matches(Lt, Qword, V, V));
        assert!(ioctl_matches(Le, Qword, V, V));
        for arg in below {
            assert!(!ioctl_matches(Gt, Qword, V, arg), "{arg:#x}");
            assert!(!ioctl_matches(Ge, Qword, V, arg), "{arg:#x}");
            assert!(ioctl_matches(Lt, Qword, V, arg), "{arg:#x}");
            assert!(ioctl_matches(Le, Qword, V, arg), "{arg:#x}");
        }
        for arg in above {
            assert!(ioctl_matches(Gt, Qword, V, arg), "{arg:#x}");
            assert!(ioctl_matches(Ge, Qword, V, arg), "{arg:#x}");
            assert!(!ioctl_matches(Lt, Qword, V, arg), "{arg:#x}");
            assert!(!ioctl_matches(Le, Qword, V, arg), "{arg:#x}");
        }
    }

    #[test]
    fn test_fragment_ordered_dword() {
        use SeccompCmpArgLen::Dword;
        use SeccompCmpOp::{Ge, Gt, Le, Lt};

        const V: u64 = 0x10;
        assert!(!ioctl_matches(Gt, Dword, V, V));
        assert!(ioctl_matches(Ge, Dword, V, V));
        assert!(!ioctl_matches(Lt, Dword, V, V));
        assert!(ioctl_matches(Le, Dword, V, V));
        for arg in [V - 1, 0] {
            assert!(!ioctl_matches(Gt, Dword, V, arg));
            assert!(!ioctl_matches(Ge, Dword, V, arg));
            assert!(ioctl_matches(Lt, Dword, V, arg));
            assert!(ioctl_matches(Le, Dword, V, arg));
        }
        // A set high word makes the argument larger, like with libseccomp's 64-bit compare.
        for arg in [V + 1, 0xFFFF_FFFF, 0x1_0000_0000, 0x1_0000_0000 | V] {
            assert!(ioctl_matches(Gt, Dword, V, arg), "{arg:#x}");
            assert!(ioctl_matches(Ge, Dword, V, arg), "{arg:#x}");
            assert!(!ioctl_matches(Lt, Dword, V, arg), "{arg:#x}");
            assert!(!ioctl_matches(Le, Dword, V, arg), "{arg:#x}");
        }
    }

    #[test]
    fn test_fragment_masked_eq() {
        use SeccompCmpArgLen::{Dword, Qword};
        use SeccompCmpOp::MaskedEq;

        // Mask in the low half only: the high half is ignored.
        for len in [Dword, Qword] {
            let m = MaskedEq(0xFF00);
            assert!(ioctl_matches(m, len.clone(), 0x1200, 0x1234));
            assert!(!ioctl_matches(
                MaskedEq(0xFF00),
                len.clone(),
                0x1200,
                0x1334
            ));
            assert!(ioctl_matches(
                MaskedEq(0xFF00),
                len.clone(),
                0x1200,
                0xFFFF_FFFF_0000_1234
            ));
            // libseccomp masks the value too: bits of `val` outside the mask do not matter.
            assert!(ioctl_matches(MaskedEq(0xFF00), len, 0x1234, 0x1200));
        }
        // Mask in the high half only: the low half is ignored.
        let m = 0xFF00_0000_0000_0000;
        assert!(ioctl_matches(
            MaskedEq(m),
            Qword,
            0x1200_0000_0000_0000,
            0x1234_0000_DEAD_BEEF
        ));
        assert!(!ioctl_matches(
            MaskedEq(m),
            Qword,
            0x1200_0000_0000_0000,
            0x1334_0000_DEAD_BEEF
        ));
        // Mask in both halves.
        let m = 0xFF00_0000_0000_FF00;
        let v = 0x1200_0000_0000_3400;
        assert!(ioctl_matches(MaskedEq(m), Qword, v, 0x12AB_CDEF_0123_3456));
        assert!(!ioctl_matches(MaskedEq(m), Qword, v, 0x12AB_CDEF_0123_3556));
        assert!(!ioctl_matches(MaskedEq(m), Qword, v, 0x13AB_CDEF_0123_3456));
        // Full mask in one half: no `and` is needed.
        let m = 0xFFFF_FFFF;
        assert!(ioctl_matches(
            MaskedEq(m),
            Qword,
            0x5401,
            0xFFFF_FFFF_0000_5401
        ));
        assert!(!ioctl_matches(MaskedEq(m), Qword, 0x5401, 0x5402));
        // Empty mask: no condition code at all, always matches.
        let fragment = rule_fragment(16, &[cond(1, MaskedEq(0), 0x5401, Qword)], 0).unwrap();
        assert_eq!(fragment.len(), 3);
        assert!(ioctl_matches(MaskedEq(0), Qword, 0x5401, 0xDEAD_BEEF));
    }

    #[test]
    fn test_fragment_two_conditions() {
        let fragment = rule_fragment(
            16,
            &[
                cond(
                    1,
                    SeccompCmpOp::Eq,
                    KVM_CHECK_EXTENSION,
                    SeccompCmpArgLen::Dword,
                ),
                cond(2, SeccompCmpOp::Eq, 131, SeccompCmpArgLen::Qword),
            ],
            SECCOMP_RET_ALLOW,
        )
        .unwrap();
        let run = |args| run_with_sentinel(&fragment, &SeccompData::x86_64(NR_IOCTL, args));
        assert_eq!(
            run([3, KVM_CHECK_EXTENSION, 131, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(run([3, KVM_CHECK_EXTENSION, 132, 0, 0, 0]), FALLTHROUGH);
        assert_eq!(run([3, KVM_CHECK_EXTENSION + 1, 131, 0, 0, 0]), FALLTHROUGH);
        assert_eq!(run([3, 0, 0, 0, 0, 0]), FALLTHROUGH);
    }

    #[test]
    fn test_fragment_no_conditions() {
        let fragment = rule_fragment(60, &[], SECCOMP_RET_ALLOW).unwrap();
        assert_eq!(
            fragment,
            vec![
                insn(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
                insn(BPF_JEQ_K, 0, 1, 60),
                insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            ]
        );
        let exit = SeccompData::x86_64(NR_EXIT, [0; 6]);
        assert_eq!(run_with_sentinel(&fragment, &exit), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_fragment_falls_through_for_other_syscall() {
        let fragment = rule_fragment(
            16,
            &[cond(1, SeccompCmpOp::Eq, 0x5401, SeccompCmpArgLen::Dword)],
            SECCOMP_RET_ALLOW,
        )
        .unwrap();
        // Same (matching) argument, different syscall number.
        let data = SeccompData::x86_64(NR_WRITE, [0, 0x5401, 0, 0, 0, 0]);
        assert_eq!(run_with_sentinel(&fragment, &data), FALLTHROUGH);
        // Garbage in the accumulator at entry must not matter.
        let mut program = vec![
            insn(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
            insn(BPF_OR_K, 0, 0, 0xFFFF_FFFF),
        ];
        program.extend(&fragment);
        let data = SeccompData::x86_64(NR_IOCTL, [0, 0x5401, 0, 0, 0, 0]);
        assert_eq!(run_with_sentinel(&program, &data), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_fragment_invalid_arg_index() {
        let conds = [cond(6, SeccompCmpOp::Eq, 0, SeccompCmpArgLen::Qword)];
        assert_eq!(
            rule_fragment(16, &conds, SECCOMP_RET_ALLOW),
            Err(BpfError::InvalidArgIndex(6))
        );
        // Index 5 is the last valid one and loads stay inside `seccomp_data`.
        let conds = [cond(5, SeccompCmpOp::Eq, 7, SeccompCmpArgLen::Qword)];
        let fragment = rule_fragment(16, &conds, SECCOMP_RET_ALLOW).unwrap();
        let data = SeccompData::x86_64(NR_IOCTL, [0, 0, 0, 0, 0, 7]);
        assert_eq!(run_with_sentinel(&fragment, &data), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_fragment_duplicate_arg_index() {
        let conds = [
            cond(1, SeccompCmpOp::Ge, 1, SeccompCmpArgLen::Dword),
            cond(2, SeccompCmpOp::Eq, 7, SeccompCmpArgLen::Dword),
            cond(1, SeccompCmpOp::Le, 9, SeccompCmpArgLen::Dword),
        ];
        assert_eq!(
            rule_fragment(16, &conds, SECCOMP_RET_ALLOW),
            Err(BpfError::DuplicateArgIndex(1))
        );
    }

    #[test]
    fn test_suffix_prologue() {
        let x86_64 = suffix_prologue(&TargetArch::X86_64, SECCOMP_RET_TRAP);
        assert_eq!(x86_64.len(), 6);
        let native = SeccompData::x86_64(NR_WRITE, [0; 6]);
        assert_eq!(run_with_sentinel(&x86_64, &native), FALLTHROUGH);
        let foreign = SeccompData {
            arch: AUDIT_ARCH_AARCH64,
            ..SeccompData::x86_64(NR_WRITE, [0; 6])
        };
        assert_eq!(run_with_sentinel(&x86_64, &foreign), SECCOMP_RET_TRAP);
        let x32_nr = i32::try_from(X32_SYSCALL_BIT).unwrap() | NR_WRITE;
        let x32 = SeccompData::x86_64(x32_nr, [0; 6]);
        assert_eq!(run_with_sentinel(&x86_64, &x32), SECCOMP_RET_TRAP);

        let aarch64 = suffix_prologue(&TargetArch::Aarch64, SECCOMP_RET_TRAP);
        assert_eq!(aarch64.len(), 3);
        assert_eq!(run_with_sentinel(&aarch64, &foreign), FALLTHROUGH);
        assert_eq!(run_with_sentinel(&aarch64, &native), SECCOMP_RET_TRAP);
        // No x32 ABI on aarch64.
        let aarch64_x32 = SeccompData {
            arch: AUDIT_ARCH_AARCH64,
            ..x32
        };
        assert_eq!(run_with_sentinel(&aarch64, &aarch64_x32), FALLTHROUGH);

        assert_eq!(
            epilogue(SECCOMP_RET_TRAP),
            vec![insn(BPF_RET_K, 0, 0, SECCOMP_RET_TRAP)]
        );
    }

    /// What libseccomp emits for an x86_64 filter allowing `write` and `exit`, with the default
    /// action duplicated the way its long jumps do and the bad-arch return at the very end.
    fn base_program(default_action: u32) -> Vec<u64> {
        vec![
            insn(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
            insn(BPF_JEQ_K, 0, 8, AUDIT_ARCH_X86_64),
            insn(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
            insn(BPF_JGT_K, 3, 0, 1),
            insn(BPF_JEQ_K, 0, 1, 1),
            insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            insn(BPF_RET_K, 0, 0, default_action),
            insn(BPF_JEQ_K, 0, 1, 60),
            insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            insn(BPF_RET_K, 0, 0, default_action),
            insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_THREAD),
        ]
    }

    #[test]
    fn test_redirect_default_returns() {
        let mut program = base_program(SECCOMP_RET_TRAP);
        validate(&program).unwrap();
        assert_eq!(
            redirect_default_returns(&mut program, SECCOMP_RET_TRAP),
            Ok(2)
        );
        let mut expected = base_program(SECCOMP_RET_TRAP);
        expected[6] = insn(BPF_JA, 0, 0, 4);
        expected[9] = insn(BPF_JA, 0, 0, 1);
        assert_eq!(program, expected);
        // Alone, the redirected program jumps past its end and is no longer valid.
        assert_eq!(validate(&program), Err(BpfError::InvalidJump(6)));

        // Nothing left to redirect.
        assert_eq!(
            redirect_default_returns(&mut program, SECCOMP_RET_TRAP),
            Err(BpfError::NoDefaultReturn)
        );
        // `ret A` is never emitted by libseccomp; refuse it without touching the program.
        let mut program = base_program(SECCOMP_RET_TRAP);
        program[8] = insn(BPF_RET_A, 0, 0, 0);
        let copy = program.clone();
        assert_eq!(
            redirect_default_returns(&mut program, SECCOMP_RET_TRAP),
            Err(BpfError::ReturnAccumulator(8))
        );
        assert_eq!(program, copy);
    }

    /// Redirect the base program and append prologue, fragments and epilogue.
    fn compose(default_action: u32, fragments: &[Vec<u64>]) -> (usize, Vec<u64>) {
        let mut program = base_program(default_action);
        let count = redirect_default_returns(&mut program, default_action).unwrap();
        program.extend(suffix_prologue(&TargetArch::X86_64, default_action));
        for fragment in fragments {
            program.extend(fragment);
        }
        program.extend(epilogue(default_action));
        validate(&program).unwrap();
        (count, program)
    }

    #[test]
    fn test_composed_program() {
        let open = rule_fragment(2, &[], SECCOMP_RET_ALLOW).unwrap();
        let ioctl = rule_fragment(
            16,
            &[cond(1, SeccompCmpOp::Eq, 0x5401, SeccompCmpArgLen::Dword)],
            SECCOMP_RET_ALLOW,
        )
        .unwrap();
        let (count, program) = compose(SECCOMP_RET_TRAP, &[open, ioctl]);
        assert_eq!(count, 2);
        let run = |nr, args| simulate(&program, &SeccompData::x86_64(nr, args));

        // Allowed by the base program.
        assert_eq!(run(NR_WRITE, [0; 6]), SECCOMP_RET_ALLOW);
        assert_eq!(run(NR_EXIT, [0; 6]), SECCOMP_RET_ALLOW);
        // Allowed only by a fragment.
        assert_eq!(run(NR_OPEN, [0; 6]), SECCOMP_RET_ALLOW);
        assert_eq!(run(NR_IOCTL, [0, 0x5401, 0, 0, 0, 0]), SECCOMP_RET_ALLOW);
        // Allowed by nothing.
        assert_eq!(run(NR_CLOSE, [0; 6]), SECCOMP_RET_TRAP);
        assert_eq!(run(NR_IOCTL, [0, 0x5402, 0, 0, 0, 0]), SECCOMP_RET_TRAP);
        // Foreign arch: the libseccomp arch check comes first and kills.
        let foreign = SeccompData {
            arch: AUDIT_ARCH_AARCH64,
            ..SeccompData::x86_64(NR_OPEN, [0; 6])
        };
        assert_eq!(simulate(&program, &foreign), SECCOMP_RET_KILL_THREAD);
        // x32 ABI: refused by the prologue even though the fragment would allow the nr.
        let x32_nr = i32::try_from(X32_SYSCALL_BIT).unwrap() | NR_OPEN;
        assert_eq!(run(x32_nr, [0; 6]), SECCOMP_RET_TRAP);
    }

    #[test]
    fn test_composed_program_default_kill() {
        // With the default action equal to the bad-arch action, that return is redirected too
        // and the prologue's arch re-check has to kill the foreign arch.
        let open = rule_fragment(2, &[], SECCOMP_RET_ALLOW).unwrap();
        let (count, program) = compose(SECCOMP_RET_KILL_THREAD, &[open]);
        assert_eq!(count, 3);
        let run = |nr| simulate(&program, &SeccompData::x86_64(nr, [0; 6]));
        assert_eq!(run(NR_WRITE), SECCOMP_RET_ALLOW);
        assert_eq!(run(NR_OPEN), SECCOMP_RET_ALLOW);
        assert_eq!(run(NR_CLOSE), SECCOMP_RET_KILL_THREAD);
        let foreign = SeccompData {
            arch: AUDIT_ARCH_AARCH64,
            ..SeccompData::x86_64(NR_OPEN, [0; 6])
        };
        assert_eq!(simulate(&program, &foreign), SECCOMP_RET_KILL_THREAD);
    }

    #[test]
    fn test_validate_rejects() {
        let ret = insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW);
        let ld_nr = insn(BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET);

        assert_eq!(validate(&[]), Err(BpfError::Empty));
        assert_eq!(validate(&[ret]), Ok(()));
        assert_eq!(validate(&vec![ret; BPF_MAX_LEN]), Ok(()));
        assert_eq!(
            validate(&vec![ret; BPF_MAX_LEN + 1]),
            Err(BpfError::TooLong(BPF_MAX_LEN + 1))
        );
        assert_eq!(validate(&[ret, ld_nr]), Err(BpfError::LastNotReturn));
        // Conditional jump past the end (on either branch).
        assert_eq!(
            validate(&[insn(BPF_JEQ_K, 1, 0, 1), ret]),
            Err(BpfError::InvalidJump(0))
        );
        assert_eq!(
            validate(&[insn(BPF_JEQ_K, 0, 1, 1), ret]),
            Err(BpfError::InvalidJump(0))
        );
        assert_eq!(validate(&[insn(BPF_JEQ_K, 0, 0, 1), ret]), Ok(()));
        // `ja` to exactly the end, and to the last instruction.
        assert_eq!(
            validate(&[insn(BPF_JA, 0, 0, 1), ret]),
            Err(BpfError::InvalidJump(0))
        );
        assert_eq!(validate(&[insn(BPF_JA, 0, 0, 0), ret]), Ok(()));
        assert_eq!(validate(&[insn(BPF_JA, 0, 0, 1), ret, ret]), Ok(()));
        // Misaligned and out-of-struct loads.
        assert_eq!(
            validate(&[insn(BPF_LD_W_ABS, 0, 0, 2), ret]),
            Err(BpfError::InvalidLoad(0))
        );
        assert_eq!(
            validate(&[insn(BPF_LD_W_ABS, 0, 0, 64), ret]),
            Err(BpfError::InvalidLoad(0))
        );
        assert_eq!(validate(&[insn(BPF_LD_W_ABS, 0, 0, 60), ret]), Ok(()));
        // Unknown opcode (`BPF_LD | BPF_W | BPF_LEN`).
        assert_eq!(
            validate(&[ld_nr, insn(0x80, 0, 0, 0), ret]),
            Err(BpfError::UnknownOpcode(1, 0x80))
        );
        // `ret A` is accepted by the kernel.
        assert_eq!(validate(&[ld_nr, insn(BPF_RET_A, 0, 0, 0)]), Ok(()));
    }
}

// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Classic BPF helpers for composing feature-gated filters out of libseccomp programs.
//!
//! Every part of a compiled filter with feature-tagged rules is a complete libseccomp program in
//! which [`redirect_default_returns`] has turned each `ret #default_action` into a jump to one
//! past its end, so that it falls through into the next part instead. An [`epilogue`] finally
//! returns the default action. Since every part does its own arch check, any subset of the
//! parts can be concatenated in any order.

pub use utils::seccomp::bpf::{BPF_JMP_JA, BPF_MAX_LEN, BPF_RET_A, BPF_RET_K, SockFilter};

/// BPF composition errors.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum BpfError {
    /// The program contains no `ret #default_action` instruction
    NoDefaultReturn,
    /// Unexpected `ret A` instruction at {0}
    ReturnAccumulator(usize),
    /// Program of {0} instructions exceeds the BPF maximum length
    TooLong(usize),
}

/// Rewrite every `ret #default_action` of a libseccomp program into a `ja` to the instruction
/// one past the program's end, so the program falls through into whatever is appended after it.
///
/// libseccomp duplicates returns when it needs long jumps, so every copy is rewritten. When the
/// bad-arch action coincides with the default action its return is rewritten too, which is
/// harmless: every following part repeats the arch check and the epilogue returns the same action.
///
/// Leaves the program unchanged on error.
pub fn redirect_default_returns(
    program: &mut [SockFilter],
    default_action: u32,
) -> Result<(), BpfError> {
    if program.len() > BPF_MAX_LEN {
        return Err(BpfError::TooLong(program.len()));
    }
    if let Some(pc) = program.iter().position(|i| i.code == BPF_RET_A) {
        return Err(BpfError::ReturnAccumulator(pc));
    }
    let is_default = |i: &SockFilter| i.code == BPF_RET_K && i.k == default_action;
    if !program.iter().any(is_default) {
        return Err(BpfError::NoDefaultReturn);
    }
    // The offset is the number of instructions remaining after this one.
    for (instruction, offset) in program.iter_mut().rev().zip(0..) {
        if is_default(instruction) {
            *instruction = SockFilter::stmt(BPF_JMP_JA, offset);
        }
    }
    Ok(())
}

/// `[ret #default_action]`: the end of the composed program.
pub fn epilogue(default_action: u32) -> SockFilter {
    SockFilter::stmt(BPF_RET_K, default_action)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use utils::seccomp::bpf::opcode;

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    const BPF_LD_W_ABS: u16 = opcode(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS);
    const BPF_JEQ_K: u16 = opcode(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K);
    const BPF_JGT_K: u16 = opcode(libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K);
    const BPF_JGE_K: u16 = opcode(libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K);
    const BPF_JSET_K: u16 = opcode(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K);
    const BPF_AND_K: u16 = opcode(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K);

    pub(crate) const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    pub(crate) const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
    /// On x86_64 a syscall number with this bit set uses the x32 ABI.
    pub(crate) const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    const NR_WRITE: i32 = 1;
    const NR_CLOSE: i32 = 3;
    const NR_EXIT: i32 = 60;

    /// `struct seccomp_data` as the kernel hands it to the filter.
    pub(crate) struct SeccompData {
        pub(crate) nr: i32,
        pub(crate) arch: u32,
        pub(crate) args: [u64; 6],
    }

    impl SeccompData {
        pub(crate) fn x86_64(nr: i32, args: [u64; 6]) -> Self {
            Self::new(AUDIT_ARCH_X86_64, nr, args)
        }

        pub(crate) fn new(arch: u32, nr: i32, args: [u64; 6]) -> Self {
            Self { nr, arch, args }
        }

        /// The little-endian 32-bit word at `offset`.
        fn load(&self, offset: u32) -> u32 {
            let mut bytes = [0u8; 64];
            bytes[0..4].copy_from_slice(&self.nr.to_le_bytes());
            bytes[4..8].copy_from_slice(&self.arch.to_le_bytes());
            bytes[8..16].copy_from_slice(&0xdead_0000_beef_u64.to_le_bytes());
            for (i, arg) in self.args.iter().enumerate() {
                bytes[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
            }
            let offset = usize::try_from(offset).unwrap();
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
        }
    }

    /// Run `program` on `data` and return the value of the `ret` that ends it.
    pub(crate) fn simulate(program: &[SockFilter], data: &SeccompData) -> u32 {
        assert!(program.len() <= BPF_MAX_LEN);
        let mut pc = 0;
        let mut acc = 0u32;
        loop {
            let SockFilter { code, jt, jf, k } = program[pc];
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
                BPF_JEQ_K => jump(acc == k),
                BPF_JGT_K => jump(acc > k),
                BPF_JGE_K => jump(acc >= k),
                BPF_JSET_K => jump(acc & k != 0),
                BPF_JMP_JA => pc + 1 + usize::try_from(k).unwrap(),
                BPF_RET_K => return k,
                _ => panic!("unknown opcode {code:#x} at {pc}"),
            };
            assert!(pc < program.len(), "jump out of the program to {pc}");
        }
    }

    #[test]
    fn test_instruction_bytes() {
        use zerocopy::IntoBytes;
        let instruction = insn(BPF_JEQ_K, 3, 7, 0xC000_003E);
        assert_eq!(
            instruction.as_bytes(),
            0xC000_003E_0703_0015u64.to_le_bytes()
        );
    }

    /// What libseccomp emits for an x86_64 filter allowing `write` and `exit`, with the default
    /// action duplicated the way its long jumps do and the bad-arch return at the very end.
    fn base_program(default_action: u32) -> Vec<SockFilter> {
        vec![
            insn(BPF_LD_W_ABS, 0, 0, 4),
            insn(BPF_JEQ_K, 0, 8, AUDIT_ARCH_X86_64),
            insn(BPF_LD_W_ABS, 0, 0, 0),
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
        assert_eq!(
            redirect_default_returns(&mut program, SECCOMP_RET_TRAP),
            Ok(())
        );
        let mut expected = base_program(SECCOMP_RET_TRAP);
        expected[6] = SockFilter::stmt(BPF_JMP_JA, 4);
        expected[9] = SockFilter::stmt(BPF_JMP_JA, 1);
        assert_eq!(program, expected);

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

    /// The redirected program followed by the epilogue gives the verdicts of the original program,
    /// also when the default action is the bad-arch kill and that return is redirected as well.
    #[test]
    fn test_redirected_program_falls_through() {
        for default_action in [SECCOMP_RET_TRAP, SECCOMP_RET_KILL_THREAD] {
            let original = base_program(default_action);
            let mut program = original.clone();
            redirect_default_returns(&mut program, default_action).unwrap();
            program.push(epilogue(default_action));
            for data in [
                SeccompData::x86_64(NR_WRITE, [0; 6]),
                SeccompData::x86_64(NR_EXIT, [0; 6]),
                SeccompData::x86_64(NR_CLOSE, [0; 6]),
                SeccompData::new(AUDIT_ARCH_AARCH64, NR_WRITE, [0; 6]),
            ] {
                assert_eq!(simulate(&program, &data), simulate(&original, &data));
            }
        }
    }
}

// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Classic BPF helpers for composing feature-gated filters out of libseccomp programs.
//!
//! Every part of a compiled filter with feature-tagged rules is a complete libseccomp program in
//! which [`redirect_default_returns`] has turned each `ret #default_action` into a jump to one
//! past its end, so that it falls through into the next part instead. An [`epilogue`] finally
//! returns the default action. Since every part does its own arch check, any subset of the
//! parts can be concatenated in any order.
//!
//! An instruction is `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }`, stored as one
//! little-endian `u64`: `code | jt << 16 | jf << 24 | k << 32`.

/// `BPF_JMP | BPF_JA`: unconditional jump to `pc + 1 + k`.
pub const BPF_JA: u16 = 0x05;
/// `BPF_RET | BPF_K`: return `k`.
pub const BPF_RET_K: u16 = 0x06;
/// `BPF_RET | BPF_A`: return `A`.
pub const BPF_RET_A: u16 = 0x16;

/// `BPF_MAXINSNS`: the maximum number of instructions in a program.
pub const BPF_MAX_LEN: usize = 4096;

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

/// `[ret #default_action]`: the end of the composed program.
pub fn epilogue(default_action: u32) -> Vec<u64> {
    vec![insn(BPF_RET_K, 0, 0, default_action)]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_JGT_K: u16 = 0x25;
    const BPF_JGE_K: u16 = 0x35;
    const BPF_JSET_K: u16 = 0x45;
    const BPF_AND_K: u16 = 0x54;

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
    pub(crate) fn simulate(program: &[u64], data: &SeccompData) -> u32 {
        assert!(program.len() <= BPF_MAX_LEN);
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
                BPF_JEQ_K => jump(acc == k),
                BPF_JGT_K => jump(acc > k),
                BPF_JGE_K => jump(acc >= k),
                BPF_JSET_K => jump(acc & k != 0),
                BPF_JA => pc + 1 + usize::try_from(k).unwrap(),
                BPF_RET_K => return k,
                _ => panic!("unknown opcode {code:#x} at {pc}"),
            };
            assert!(pc < program.len(), "jump out of the program to {pc}");
        }
    }

    #[test]
    fn test_insn_decode_roundtrip() {
        let encoded = insn(BPF_JEQ_K, 3, 7, 0xC000_003E);
        assert_eq!(encoded, 0xC000_003E_0703_0015);
        assert_eq!(decode(encoded), (BPF_JEQ_K, 3, 7, 0xC000_003E));
    }

    /// What libseccomp emits for an x86_64 filter allowing `write` and `exit`, with the default
    /// action duplicated the way its long jumps do and the bad-arch return at the very end.
    fn base_program(default_action: u32) -> Vec<u64> {
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
            Ok(2)
        );
        let mut expected = base_program(SECCOMP_RET_TRAP);
        expected[6] = insn(BPF_JA, 0, 0, 4);
        expected[9] = insn(BPF_JA, 0, 0, 1);
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
            program.extend(epilogue(default_action));
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

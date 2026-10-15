// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Classic seccomp-BPF instructions and the checks the kernel applies to a program.
//!
//! An instruction is `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }`, stored as one
//! little-endian `u64`: `code | jt << 16 | jf << 24 | k << 32`.

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

/// `sizeof(struct seccomp_data)`; loads must stay below it.
pub const SECCOMP_DATA_SIZE: u32 = 64;

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

/// Reasons for the kernel to reject a program, or for a part of one not to be position
/// independent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum ProgramError {
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
}

/// Mirror the kernel checks (`bpf_check_classic` and `seccomp_check_filter`) on a complete
/// program: `1 <= len <= 4096`, the last instruction is a return, every jump lands strictly
/// inside the program, loads are `ld [k]` with `k % 4 == 0 && k < 64`, and only the opcodes
/// defined in this module are used.
pub fn validate(program: &[u64]) -> Result<(), ProgramError> {
    let len = program.len();
    if len == 0 {
        return Err(ProgramError::Empty);
    }
    if len > BPF_MAX_LEN {
        return Err(ProgramError::TooLong(len));
    }
    let last = decode(program[len - 1]).0;
    if last != BPF_RET_K && last != BPF_RET_A {
        return Err(ProgramError::LastNotReturn);
    }
    check_instructions(program, len - 1)
}

/// Check one part of a program that is assembled by concatenating parts, like the base program
/// and the fragments of a filter: the instructions are the ones [`validate`] accepts, and every
/// jump lands inside the part or exactly at its end, i.e. on the first instruction of whatever
/// follows. A part that passes behaves the same whatever is appended to it, and never jumps into
/// the middle of another part.
pub fn validate_part(part: &[u64]) -> Result<(), ProgramError> {
    check_instructions(part, part.len())
}

/// Check the opcode and operands of every instruction of `program`, with jumps landing at most
/// on `last_target`.
fn check_instructions(program: &[u64], last_target: usize) -> Result<(), ProgramError> {
    for (pc, &instruction) in program.iter().enumerate() {
        let (code, jt, jf, k) = decode(instruction);
        let lands = |offset: usize| {
            (pc + 1)
                .checked_add(offset)
                .is_some_and(|t| t <= last_target)
        };
        match code {
            BPF_LD_W_ABS => {
                if k % 4 != 0 || k >= SECCOMP_DATA_SIZE {
                    return Err(ProgramError::InvalidLoad(pc));
                }
            }
            BPF_JA => {
                if !usize::try_from(k).is_ok_and(lands) {
                    return Err(ProgramError::InvalidJump(pc));
                }
            }
            BPF_JEQ_K | BPF_JGT_K | BPF_JGE_K | BPF_JSET_K => {
                if !lands(usize::from(jt)) || !lands(usize::from(jf)) {
                    return Err(ProgramError::InvalidJump(pc));
                }
            }
            BPF_RET_K | BPF_RET_A | BPF_AND_K | BPF_OR_K => {}
            _ => return Err(ProgramError::UnknownOpcode(pc, code)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

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
    fn test_validate_rejects() {
        let ret = insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW);
        let ld_nr = insn(BPF_LD_W_ABS, 0, 0, 0);

        assert_eq!(validate(&[]), Err(ProgramError::Empty));
        assert_eq!(validate(&[ret]), Ok(()));
        assert_eq!(validate(&vec![ret; BPF_MAX_LEN]), Ok(()));
        assert_eq!(
            validate(&vec![ret; BPF_MAX_LEN + 1]),
            Err(ProgramError::TooLong(BPF_MAX_LEN + 1))
        );
        assert_eq!(validate(&[ret, ld_nr]), Err(ProgramError::LastNotReturn));
        // Conditional jump past the end (on either branch).
        assert_eq!(
            validate(&[insn(BPF_JEQ_K, 1, 0, 1), ret]),
            Err(ProgramError::InvalidJump(0))
        );
        assert_eq!(
            validate(&[insn(BPF_JEQ_K, 0, 1, 1), ret]),
            Err(ProgramError::InvalidJump(0))
        );
        assert_eq!(validate(&[insn(BPF_JEQ_K, 0, 0, 1), ret]), Ok(()));
        // `ja` to exactly the end, and to the last instruction.
        assert_eq!(
            validate(&[insn(BPF_JA, 0, 0, 1), ret]),
            Err(ProgramError::InvalidJump(0))
        );
        assert_eq!(validate(&[insn(BPF_JA, 0, 0, 0), ret]), Ok(()));
        assert_eq!(validate(&[insn(BPF_JA, 0, 0, 1), ret, ret]), Ok(()));
        // A `ja` offset that overflows the program counter.
        assert_eq!(
            validate(&[insn(BPF_JA, 0, 0, u32::MAX), ret]),
            Err(ProgramError::InvalidJump(0))
        );
        // Misaligned and out-of-struct loads.
        assert_eq!(
            validate(&[insn(BPF_LD_W_ABS, 0, 0, 2), ret]),
            Err(ProgramError::InvalidLoad(0))
        );
        assert_eq!(
            validate(&[insn(BPF_LD_W_ABS, 0, 0, 64), ret]),
            Err(ProgramError::InvalidLoad(0))
        );
        assert_eq!(validate(&[insn(BPF_LD_W_ABS, 0, 0, 60), ret]), Ok(()));
        // Unknown opcode (`BPF_LD | BPF_W | BPF_LEN`).
        assert_eq!(
            validate(&[ld_nr, insn(0x80, 0, 0, 0), ret]),
            Err(ProgramError::UnknownOpcode(1, 0x80))
        );
        // `ret A` is accepted by the kernel.
        assert_eq!(validate(&[ld_nr, insn(BPF_RET_A, 0, 0, 0)]), Ok(()));
    }

    #[test]
    fn test_validate_part() {
        let ret = insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW);
        let ld_nr = insn(BPF_LD_W_ABS, 0, 0, 0);

        // A part need not end with a return, and may be empty.
        assert_eq!(validate_part(&[]), Ok(()));
        assert_eq!(validate_part(&[ld_nr]), Ok(()));
        // Jumps may land exactly at the end of the part, where the next part starts...
        assert_eq!(validate_part(&[insn(BPF_JEQ_K, 1, 0, 1), ret]), Ok(()));
        assert_eq!(validate_part(&[insn(BPF_JA, 0, 0, 1), ret]), Ok(()));
        // ...but not beyond it, into the middle of another part.
        assert_eq!(
            validate_part(&[insn(BPF_JEQ_K, 0, 2, 1), ret]),
            Err(ProgramError::InvalidJump(0))
        );
        assert_eq!(
            validate_part(&[ret, insn(BPF_JA, 0, 0, 1)]),
            Err(ProgramError::InvalidJump(1))
        );
        // Instructions are checked like in a complete program.
        assert_eq!(
            validate_part(&[insn(BPF_LD_W_ABS, 0, 0, 3)]),
            Err(ProgramError::InvalidLoad(0))
        );
        assert_eq!(
            validate_part(&[insn(0x80, 0, 0, 0)]),
            Err(ProgramError::UnknownOpcode(0, 0x80))
        );
    }
}
